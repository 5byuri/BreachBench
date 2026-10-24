"""Controlled API/database peers for network and credential enforcement tests."""
import hmac
import http.server
import os
import socketserver

if os.environ.get('PEER') == 'database':
    class Database(socketserver.StreamRequestHandler):
        def handle(self):
            supplied = self.rfile.readline(1024).strip()
            expected = open('/run/secrets/database/token', 'rb').read().strip()
            self.wfile.write(b'db-ok' if hmac.compare_digest(supplied, expected) else b'DENIED')
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    socketserver.ThreadingTCPServer(('0.0.0.0', 5432), Database).serve_forever()
else:
    class API(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'api-ok')
    http.server.HTTPServer(('0.0.0.0', 8080), API).serve_forever()
