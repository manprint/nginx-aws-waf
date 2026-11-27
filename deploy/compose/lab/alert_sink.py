"""Lab alert sink: prints every POST body as one line prefixed ALERT-SINK (apprise json:// target)."""
import http.server
import json


class Sink(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode("utf-8", "replace")
        try:
            body = json.dumps(json.loads(body), ensure_ascii=False)
        except ValueError:
            body = body.replace("\n", "\\n")
        print("ALERT-SINK", self.path, body, flush=True)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *args):
        pass


http.server.ThreadingHTTPServer(("0.0.0.0", 8000), Sink).serve_forever()
