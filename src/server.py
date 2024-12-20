import argparse
import http.server
import webbrowser
import threading
import socket
import json
from typing import List
from functools import partial
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from urllib.parse import parse_qs, urlparse
from queue import Queue
from threading import Lock
import time

from cve_information.main import CVE


class GlobalState:
    """
    Thread-safe global state manager for storing shared data across server threads.

    This class provides a thread-safe mechanism for storing and retrieving data
    that needs to be accessed by multiple server components.

    Attributes:
        data (dict): Dictionary storing the global state
        lock (threading.Lock): Thread lock for synchronization
    """

    def __init__(self):
        """Initialize the global state with an empty dictionary and a thread lock."""
        self.data = {}
        self.lock = Lock()

    def set(self, key: str, value: any) -> None:
        """
        Set a value in the global state in a thread-safe manner.

        Args:
            key (str): The key to store the value
            value (any): The value to store
        """
        with self.lock:
            self.data[key] = value

    def get(self, key: str, default: any = None) -> any:
        """
        Retrieve a value from the global state in a thread-safe manner.

        Args:
            key (str): The key to retrieve
            default (any, optional): Default value if key doesn't exist

        Returns:
            any: The value associated with the key or the default value
        """
        with self.lock:
            return self.data.get(key, default)


global_state = GlobalState()
background_task_queue = Queue()


def process_background_tasks() -> None:
    """
    Process tasks from the background queue continuously.

    This function runs in a separate thread and caches the relevant CVE Data by
    storing the initial CVE results in a global state. Allowing the api/cve to fetch from the cache on reload.
    """
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
    """
    Custom HTTP request handler for CVE data and AI analysis endpoints.

    This handler processes requests for CVE information and AI-powered
    analysis, serving both static files and API endpoints.

    Attributes:
        cve_codes (List[str]): List of CVE codes to process
        memo (dict): Memoization cache for processed CVE data
    """

    def __init__(self, cve_codes: List[str], *args, **kwargs):
        """
        Initialize the handler with CVE codes and base handler setup.

        Args:
            cve_codes (List[str]): List of CVE identifiers
            *args: Variable length argument list for parent class
            **kwargs: Arbitrary keyword arguments for parent class
        """
        self.cve_codes = cve_codes
        self.memo = None
        super().__init__(*args, **kwargs)

    def do_GET(self) -> None:
        """
        Handle GET requests for both API endpoints and static files.

        Processes requests for:
        - /api/cve: Fetch and process CVE information
        - /api/ai: Get AI-powered analysis for specific CVE
        - Other paths: Serve static files
        """
        parsed_url = urlparse(self.path)

        if parsed_url.path == '/api/cve':
            self._handle_cve_request()
        elif parsed_url.path == '/api/ai':
            self._handle_ai_request(parsed_url)
        else:
            super().do_GET()

    def _handle_cve_request(self) -> None:
        """Handle requests to the /api/cve endpoint."""
        try:
            cve_object = CVE(self.cve_codes)
            cve_data = cve_object.fetch_cve_information()
            if cve_data.get('statusCode') == 400:
                raise Exception("Internal Server Error!")

            cve_code = cve_data.get('data')
            self._send_json_response(200, cve_code)
            self.memo = cve_code

            background_task_queue.put({
                'cve_data': cve_code,
                'timestamp': time.time()
            })
        except Exception as e:
            print(e)
            self.send_response(400)

    def _handle_ai_request(self, parsed_url: urlparse) -> None:
        """
        Handle requests to the /api/ai endpoint.

        Args:
            parsed_url (urlparse): Parsed URL object containing query parameters
        """
        query_params = parse_qs(parsed_url.query)
        cve_id = query_params.get('cve_id', [None])[0]

        if not cve_id:
            self._send_json_response(400, {"error": "Invalid or missing CVE ID"})
            return

        processed_data = global_state.get('processed_cve_data')
        if not processed_data:
            self._send_json_response(400, {"error": "No processed CVE data available"})
            return

        cve_data = next((cve for cve in processed_data if cve.get('cve_id') == cve_id), None)
        if not cve_data:
            self._send_json_response(400, {"error": f"CVE ID {cve_id} not found in processed data"})
            return

        # Minimise the CVE Data given to the AI as prompt for better performance
        ai_prompt = {
            "cve_id": cve_data.get("cve_id"),
            "CVE description": cve_data.get('vulnerability').get("description"),
            "CVE Potential Solution (May Not exist so figure it out)": cve_data.get('vulnerability').get("solution"),
            "severity": cve_data.get('vulnerability').get("severity"),
            "vendor": cve_data.get('affected').get("vendor"),
            "product": cve_data.get('affected').get("product"),
            "versions": cve_data.get('affected').get("versions"),
            "references": cve_data.get('references'), # Although LLM (as of 2024) Cannot get Access to the URL, they can find context from the contents of the URL and tags
            "Common Weakness Enumeration": cve_data.get('problemTypes').get('description')
        }

        cve_object = CVE([cve_id])
        response = cve_object.prompt_ai(ai_prompt)
        self._send_json_response(200, response)

    def _send_json_response(self, status_code: int, data: dict) -> None:
        """
        Send a JSON response with the specified status code and data.

        Args:
            status_code (int): HTTP status code
            data (dict): Data to be sent as JSON
        """
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())


class ReloadHandler(FileSystemEventHandler):
    """File system event handler for development hot-reloading."""

    def on_modified(self, event):
        """
        Handle file modification events.

        Args:
            event: File system event object
        """
        if event.src_path.endswith('index.html'):
            print("Detected change in index.html")


def find_free_port() -> int:
    """
    Find an available port on the system.

    Returns:
        int: Available port number
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        s.listen(1)
        port = s.getsockname()[1]
    return port


def start_server(port: int, codes: List[str]) -> None:
    """
    Start the HTTP server and background task processor.

    Args:
        port (int): Port number to run the server on
        codes (List[str]): List of CVE codes to process
    """
    background_worker = threading.Thread(
        target=process_background_tasks,
        daemon=True,
        name="BackgroundWorker"
    )
    background_worker.start()

    handler = partial(CustomHandler, codes, directory="src/web")
    httpd = http.server.HTTPServer(('localhost', port), handler)
    print(f"Serving on http://localhost:{port}")
    try:
        httpd.serve_forever()
    finally:
        background_task_queue.put(None)
        background_worker.join(timeout=5)


def watch_files() -> Observer:
    """
    Set up file system watching for development hot-reloading.

    Returns:
        Observer: File system observer object
    """
    event_handler = ReloadHandler()
    observer = Observer()
    observer.schedule(event_handler, path='src/web', recursive=False)
    observer.start()
    return observer


def main(codes: List[str]) -> None:
    """
    Main entry point for the server application.

    Args:
        codes (List[str]): List of CVE codes to process
    """
    port = find_free_port()
    server_thread = threading.Thread(target=start_server, args=(port, codes))
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