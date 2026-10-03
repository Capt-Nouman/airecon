from http.server import BaseHTTPRequestHandler, HTTPServer
import json, re

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n))
        user = body["messages"][-1]["content"]
        # Deliberately weak bot: obeys some "say this token" prompts
        m = re.search(r"(PWNED-\w+|BYPASS-CONFIRMED|JAILBREAK-OK-777)", user)
        reply = m.group(1) if m else "I'm sorry, I can't help with that."
        data = json.dumps({"choices": [{"message": {"content": reply}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data)
    def log_message(self, *a):
        pass

print("Mock target running on http://127.0.0.1:8000 (Ctrl+C to stop)")
HTTPServer(("127.0.0.1", 8000), H).serve_forever()
