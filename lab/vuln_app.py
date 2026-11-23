"""Deliberately vulnerable lab app — ground-truth targets for OMEGA accuracy runs.

Planted (known) vulnerabilities, each with a unique marker:
  V1  SQLi (string-concat login, union-friendly echo)
  V2  Reflected XSS (unsanitized echo param)
  V3  Path traversal (raw path join, reads lab files)
  V4  OS command injection (echo via shell, marker echo)
  V5  SSTI (Jinja2 render_from_string on user input)
  V6  Open redirect (Location from param)
  V7  Exposed .env (plaintext secrets served)
  V8  Insecure cookie (no Secure/HttpOnly/SameSite on session)
  V9  Missing security headers (no CSP/HSTS/XFO/XCTO on all responses)
  V10 Directory listing enabled at /files/
NOT vulnerable (FP traps):
  F1  /safe-param — echoes param but HTML-escapes it
  F2  /api/users — returns JSON list, contains words 'user' and 'role'
  F3  /health — 200 plain 'ok'
"""
import os
import subprocess
import http.server
import socketserver
import urllib.parse

class _MiniTemplate:
    """Tiny {{expr}} substitution (lab SSTI target). Evaluates arithmetic
    expressions only — enough for the {{7*7}} probe class."""
    def __init__(self, src):
        self.src = src

    def render(self):
        import re
        out = self.src
        for m in reversed(list(re.finditer(r"\{\{([^}]+)\}\}", out))):
            expr = m.group(1).strip()
            if re.fullmatch(r"[0-9+\-*/(). ]+", expr):
                out = out[:m.start()] + str(eval(expr)) + out[m.end():]
        return out

Template = _MiniTemplate

LAB_DIR = os.path.dirname(os.path.abspath(__file__))
os.makedirs(os.path.join(LAB_DIR, "files"), exist_ok=True)
with open(os.path.join(LAB_DIR, "files", "notes.txt"), "w") as f:
    f.write("lab notes: nothing secret here\n")
USERS = {"admin": "admin123", "dev": "devpass"}
SESSION_COOKIE = "labsession=abc123; Path=/"

def page(body, status=200, extra=""):
    # V9: deliberately no security headers
    hdr = ("Content-Type", "text/html; charset=utf-8")
    return status, [hdr], (f"<html><body>{body}</body></html>").encode()

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, status, headers, body):
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(p.query)
        path = p.path

        if path == "/":
            # Homepage with links — crawler entry point (realistic app map)
            return self._send(*page(
                '<h1>Lab App</h1>'
                '<a href="/login">login</a><br>'
                '<a href="/echo?q=hi">echo</a><br>'
                '<a href="/file?name=files/notes.txt">file</a><br>'
                '<a href="/run?arg=hi">run</a><br>'
                '<a href="/render?t={{7*7}}">render</a><br>'
                '<a href="/redirect?to=/health">redirect</a><br>'
                '<a href="/files/">files</a><br>'
                '<a href="/api/users">api users</a><br>'
                '<a href="/safe-param?q=hi">safe param</a><br>'
                '<a href="/health">health</a>'))

        if path == "/login":
            # V1: string-concat SQL lookup simulation — here a real sqlite query
            # built by concatenation (vulnerable pattern), marker: lab-sqli
            import sqlite3
            db = sqlite3.connect(":memory:")
            db.execute("CREATE TABLE u (name TEXT, pw TEXT)")
            db.executemany("INSERT INTO u VALUES (?,?)", USERS.items())
            user = q.get("user", [""])[0]
            pw = q.get("pw", [""])[0]
            try:
                row = db.execute(
                    "SELECT name FROM u WHERE name='%s' AND pw='%s'" % (user, pw)
                ).fetchone()
            except sqlite3.Error as e:
                return self._send(500, [("Content-Type", "text/plain")],
                                  ("SQL error: %s" % e).encode())
            if row:
                return self._send(200, [("Set-Cookie", SESSION_COOKIE)],
                                  b"login ok lab-sqli-success")
            return self._send(401, [("Content-Type", "text/plain")], b"bad creds")

        if path == "/echo":
            # V2: reflected XSS — raw echo
            val = q.get("q", [""])[0]
            return self._send(*page(f"<div>you said: {val}</div>"))

        if path == "/file":
            # V3: traversal — raw join
            name = q.get("name", [""])[0]
            try:
                with open(os.path.join(LAB_DIR, name), "rb") as f:
                    return self._send(200, [("Content-Type", "text/plain")], f.read())
            except OSError:
                return self._send(404, [("Content-Type", "text/plain")], b"nope")

        if path == "/run":
            # V4: command injection — marker echo
            arg = q.get("arg", [""])[0]
            out = subprocess.run(f"echo {arg}", shell=True,
                                 capture_output=True, text=True)
            return self._send(200, [("Content-Type", "text/plain")],
                              out.stdout.encode())

        if path == "/render":
            # V5: SSTI via render_template_string equivalent
            val = q.get("t", [""])[0]
            return self._send(*page(Template(val).render()))

        if path == "/redirect":
            # V6: open redirect
            to = q.get("to", [""])[0]
            return self._send(302, [("Location", to)], b"")

        if path == "/.env":
            # V7: exposed secrets
            return self._send(200, [("Content-Type", "text/plain")],
                              b"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
                              b"SECRET_KEY=labsecret\n")

        if path == "/safe-param":
            # F1: escaped echo — must NOT be flagged as XSS
            import html
            val = html.escape(q.get("q", [""])[0])
            return self._send(*page(f"<div>you said: {val}</div>"))

        if path == "/api/users":
            # F2: plain JSON data — must NOT be flagged
            return self._send(200, [("Content-Type", "application/json")],
                              b'{"users":[{"user":"admin","role":"admin"}]}')

        if path == "/health":
            # F3: clean 200
            return self._send(200, [("Content-Type", "text/plain")], b"ok")

        if path.startswith("/files/"):
            # V10: directory listing
            if path == "/files/":
                items = os.listdir(os.path.join(LAB_DIR, "files"))
                links = "".join(f'<a href="/files/{i}">{i}</a><br>' for i in items)
                return self._send(*page(f"Directory listing:<br>{links}"))
            name = path[len("/files/"):]
            try:
                with open(os.path.join(LAB_DIR, "files", name), "rb") as f:
                    return self._send(200, [("Content-Type", "text/plain")], f.read())
            except OSError:
                return self._send(404, [("Content-Type", "text/plain")], b"nope")

        return self._send(404, [("Content-Type", "text/plain")], b"not found")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
    with Server(("127.0.0.1", port), Handler) as srv:
        print(f"lab app on 127.0.0.1:{port}", flush=True)
        srv.serve_forever()
