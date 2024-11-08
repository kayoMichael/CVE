import argparse
import http.server
import pdb
import webbrowser
import threading
import socket
import json
from functools import partial
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from urllib.parse import parse_qs, urlparse

from cve_information.main import CVE


class CustomHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, cve_codes, *args, **kwargs):
        self.cve_codes = cve_codes  # Store CVE codes instead of data
        super().__init__(*args, **kwargs)

    def do_GET(self):
        parsed_url = urlparse(self.path)

        if parsed_url.path == '/api/cve':
            # Create CVE object and fetch data when endpoint is called
            cve_object = CVE(self.cve_codes)
            cve_data = cve_object.fetch_cve_information()

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(cve_data).encode())
            return

        elif parsed_url.path == '/api/ai':
            query_params = parse_qs(parsed_url.query)
            cve_id = query_params.get('cve_id', [None])[0]

            if cve_id:
                cve_object = CVE([cve_id])
                cve_data = cve_object.fetch_cve_information()
                response = cve_object.prompt_ai(cve_data[0])
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(response).encode())
                return

            # If CVE ID is not provided or not found
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
    handler = partial(CustomHandler, cve_codes, directory="web")  # Pass cve_codes instead of data
    httpd = http.server.HTTPServer(('localhost', port), handler)
    print(f"Serving on http://localhost:{port}")
    httpd.serve_forever()


def watch_files():
    event_handler = ReloadHandler()
    observer = Observer()
    observer.schedule(event_handler, path='web', recursive=False)
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
    main(cve_codes)  # Pass only the CVE codes