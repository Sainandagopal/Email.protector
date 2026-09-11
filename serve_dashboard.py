import http.server
import socketserver
import os
import sys

PORT = 5173
DIRECTORY = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dashboard', 'dist')

class SPAServer(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def do_GET(self):
        # Resolve requested physical path
        requested_path = self.translate_path(self.path)
        # If path doesn't exist on disk, fallback to index.html for client-side SPA routing
        if not os.path.exists(requested_path) and not os.path.isfile(requested_path):
            self.path = '/index.html'
        try:
            return super().do_GET()
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            pass

    def do_HEAD(self):
        requested_path = self.translate_path(self.path)
        if not os.path.exists(requested_path) and not os.path.isfile(requested_path):
            self.path = '/index.html'
        try:
            return super().do_HEAD()
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            pass

    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Cache-Control', 'no-cache')
        super().end_headers()

    def log_message(self, format, *args):
        # Clean compact logging
        sys.stderr.write(f"[Dashboard SPA] {self.address_string()} - {format % args}\n")

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

if __name__ == '__main__':
    if not os.path.exists(DIRECTORY):
        print(f"Error: Dashboard dist directory not found at {DIRECTORY}", flush=True)
        sys.exit(1)
    
    try:
        with ThreadedTCPServer(("0.0.0.0", PORT), SPAServer) as httpd:
            print(f"SIH-Guard SOC Dashboard running live at http://localhost:{PORT}", flush=True)
            print("Press Ctrl+C to stop the dashboard server.", flush=True)
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                print("Dashboard server stopped.", flush=True)
    except OSError as e:
        if "address already in use" in str(e).lower() or e.errno in (48, 98, 10048):
            print(f"Port {PORT} is already in use. The dashboard may already be running at http://localhost:{PORT}", flush=True)
        else:
            raise
