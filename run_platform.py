"""
SIH-Guard: Unified Platform Launcher
Starts the FastAPI Cyber-Forensics Backend & Web Dashboard,
verifies server readiness, and opens the default web browser.
"""
import os
import sys
import time
import threading
import webbrowser
import urllib.request

# Ensure backend directory is in sys.path
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(ROOT_DIR, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)
os.environ["PYTHONPATH"] = BACKEND_DIR

import uvicorn
from app.main import app
from serve_dashboard import SPAServer, ThreadedTCPServer

BACKEND_PORT = 8000
DASHBOARD_PORT = 5173

def run_port_5173():
    """Run secondary dashboard server on port 5173."""
    try:
        dist_dir = os.path.join(ROOT_DIR, 'dashboard', 'dist')
        if os.path.exists(dist_dir):
            with ThreadedTCPServer(("0.0.0.0", DASHBOARD_PORT), SPAServer) as httpd:
                httpd.serve_forever()
    except Exception:
        pass

def wait_and_open_browser():
    """Wait until backend responds with HTTP 200, then open the browser."""
    print("[SIH-Guard] Initializing security engine and database...", flush=True)
    target_url = f"http://localhost:{BACKEND_PORT}"
    health_url = f"http://127.0.0.1:{BACKEND_PORT}/api/v1/health"

    for _ in range(40):
        time.sleep(0.4)
        try:
            with urllib.request.urlopen(health_url, timeout=1.0) as resp:
                if resp.getcode() == 200:
                    print(f"\n" + "=" * 58, flush=True)
                    print(f"  SIH-Guard Platform is LIVE and READY!", flush=True)
                    print(f"  * Web Dashboard: http://localhost:{BACKEND_PORT}", flush=True)
                    print(f"  * Alternative:   http://localhost:{DASHBOARD_PORT}", flush=True)
                    print(f"  * API Docs:      http://localhost:{BACKEND_PORT}/docs", flush=True)
                    print("=" * 58, flush=True)
                    print("[SIH-Guard] Opening website in your default browser...", flush=True)
                    print("[SIH-Guard] >> KEEP THIS WINDOW OPEN while using SIH-Guard <<\n", flush=True)
                    webbrowser.open(target_url)
                    return
        except Exception:
            continue

    print(f"[SIH-Guard] Opening browser to {target_url}...", flush=True)
    webbrowser.open(target_url)

if __name__ == "__main__":
    print("=" * 58, flush=True)
    print("  SIH-Guard: AI Email Threat & Cyber-Forensics Platform", flush=True)
    print("=" * 58, flush=True)

    # Start 5173 fallback server in background thread
    t_5173 = threading.Thread(target=run_port_5173, daemon=True)
    t_5173.start()

    # Start browser-opener thread that waits for health check
    t_browser = threading.Thread(target=wait_and_open_browser, daemon=True)
    t_browser.start()

    # Run Uvicorn on 0.0.0.0:8000
    try:
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=BACKEND_PORT,
            log_level="info",
            access_log=False
        )
    except KeyboardInterrupt:
        print("\n[SIH-Guard] Server stopped by user.", flush=True)
