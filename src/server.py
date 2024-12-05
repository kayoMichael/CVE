import argparse
import http.server
import webbrowser
import threading
import socket
import json
from functools import partial
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from urllib.parse import parse_qs, urlparse
from queue import Queue
from threading import Lock
import time

from cve_information.main import CVE

class GlobalState:
    def __init__(self):
        self.data = {}
        self.lock = Lock()

    def set(self, key, value):
        with self.lock:
            self.data[key] = value

    def get(self, key, default=None):
        with self.lock:
            return self.data.get(key, default)

global_state = GlobalState()
background_task_queue = Queue()

def process_background_tasks():
    while True:
        task = background_task_queue.get()
        if task is None:
            break
        try:
            cve_data = task['cve_data']
            global_state.set('processed_cve_data', cve_data)
            print(f"Processed CVE data stored globally: {len(cve_data) if cve_data is not None else 0} entries")

        except Exception as e:
            print(f"Error in background task: {e}")
        finally:
            background_task_queue.task_done()

class CustomHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, cve_codes, *args, **kwargs):
        self.cve_codes = cve_codes
        self.memo = None
        super().__init__(*args, **kwargs)

    def do_GET(self):
        parsed_url = urlparse(self.path)

        if parsed_url.path == '/api/cve':
            cve_data = None
            try:
                cve_object = CVE(self.cve_codes)
                cve_data = cve_object.fetch_cve_information()
                if cve_data.get('statusCode') == 400:
                    raise Exception("Internal Server Error!")
            except Exception as e:
                print(e)
                self.send_response(400)

            cve = cve_data.get('data')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.memo = cve
            self.wfile.write(json.dumps(cve).encode())

            background_task_queue.put({
                'cve_data': cve,
                'timestamp': time.time()
            })
            return

        elif parsed_url.path == '/api/ai':
            query_params = parse_qs(parsed_url.query)
            cve_id = query_params.get('cve_id', [None])[0]

            if cve_id:
                processed_data = global_state.get('processed_cve_data')
                if processed_data:
                    cve_data = next((cve for cve in processed_data if cve.get('cve_id') == cve_id), None)
                    if cve_data:
                        cve_object = CVE([cve_id])
                        response = cve_object.prompt_ai(cve_data)
                        self.send_response(200)
                        self.send_header('Content-Type', 'application/json')
                        self.end_headers()
                        self.wfile.write(json.dumps(response).encode())
                        return

            self.send_response(400)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            error_response = {"error": "Invalid or missing CVE ID"}
            self.wfile.write(json.dumps(error_response).encode())
            return

        return super().do_GET()

class ReloadHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path.endswith('index.html'):
            print("Detected change in index.html")


def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        s.listen(1)
        port = s.getsockname()[1]
    return port


def start_server(port, cve_codes):
    background_worker = threading.Thread(
        target=process_background_tasks,
        daemon=True,
        name="BackgroundWorker"
    )
    background_worker.start()

    handler = partial(CustomHandler, cve_codes, directory="src/web")
    httpd = http.server.HTTPServer(('localhost', port), handler)
    print(f"Serving on http://localhost:{port}")
    try:
        httpd.serve_forever()
    finally:
        background_task_queue.put(None)
        background_worker.join(timeout=5)


def watch_files():
    event_handler = ReloadHandler()
    observer = Observer()
    observer.schedule(event_handler, path='src/web', recursive=False)
    observer.start()
    return observer


def main(cve_codes):
    port = find_free_port()
    server_thread = threading.Thread(target=start_server, args=(port, cve_codes))
    server_thread.daemon = True
    server_thread.start()
    observer = watch_files()
    webbrowser.open(f'http://localhost:{port}/index.html')

    try:
        while True:
            input()
    except KeyboardInterrupt:
        print("\nShutting down...")
        observer.stop()
        observer.join()

if __name__ == '__main__':
    parse = argparse.ArgumentParser()
    parse.add_argument("file", help=".txt file with all of the CVE codes")
    file = parse.parse_args().file
    with open(file, "r") as f:
        cve_codes = f.read().splitlines()
    cve = CVE(cve_codes)
    cve.fetch_cve_information()
    main(cve_codes)