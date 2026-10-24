import http.server
import threading
import time

jobs = 0

def background():
    global jobs
    while True:
        jobs += 1
        time.sleep(0.1)

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = {"/": "healthy", "/jobs": str(jobs), "/rare/export": "uncommon-path-ok"}.get(self.path)
        self.send_response(200 if body else 404)
        self.end_headers()
        self.wfile.write((body or "missing").encode())

threading.Thread(target=background, daemon=True).start()
http.server.HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
