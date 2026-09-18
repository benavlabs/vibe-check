"""Tests for skills/vibe-check/scripts/check.py.

Run from the repo root:  python3 -m unittest discover tests
"""
import importlib.util
import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "skills" / "vibe-check" / "scripts" / "check.py"

_spec = importlib.util.spec_from_file_location("vibe_check", SCRIPT)
check = importlib.util.module_from_spec(_spec)
sys.modules["vibe_check"] = check
_spec.loader.exec_module(check)


# --------------------------------------------------------------------------- #
# Fixture servers
# --------------------------------------------------------------------------- #

GOOD_CSP = ("default-src 'self'; script-src 'self' 'nonce-abc123' 'unsafe-inline'; "
            "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
GOOD_HEADERS = {
    "Content-Security-Policy": GOOD_CSP,
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}
INDEX = b'<!doctype html><html><head><script src="/app.js"></script></head><body>hi</body></html>'


def good_site(path, headers):
    """A correctly configured SPA: every unknown path returns index.html with 200."""
    h = dict(GOOD_HEADERS)
    if path == "/":
        h["Set-Cookie"] = "session=abc; Path=/; HttpOnly; Secure; SameSite=Lax"
    if path == "/app.js":
        return 200, dict(h, **{"Content-Type": "application/javascript"}), b"console.log(1)\n"
    return 200, dict(h, **{"Content-Type": "text/html"}), INDEX


def bad_site(path, headers):
    origin = headers.get("Origin")
    h = {"X-Powered-By": "Express", "Access-Control-Allow-Origin": "*"}
    if path == "/":
        return 200, dict(h, **{
            "Content-Type": "text/html",
            "Content-Security-Policy": "frame-ancestors 'none'",
            "Set-Cookie": "session=abc; Path=/",
        }), INDEX
    if path == "/app.js":
        return 200, h, b"console.log(1)\n//# sourceMappingURL=app.js.map\n"
    if path == "/app.js.map":
        return 200, dict(h, **{"Content-Type": "application/json"}), \
            b'{"version":3,"sources":["src/App.tsx"],"mappings":"AAAA"}'
    if path == "/.env":
        return 200, {"Content-Type": "text/plain"}, \
            b"DATABASE_URL=postgres://u:p@db/app\nSTRIPE_SECRET_KEY=sk_test_123\n"
    if path == "/docs":
        return 200, {"Content-Type": "text/html"}, b'<html><div id="swagger-ui"></div></html>'
    if path == "/uploads/":
        return 200, {"Content-Type": "text/html"}, b"<html><title>Index of /uploads/</title></html>"
    if path == "/api/me":
        h = {"Access-Control-Allow-Origin": origin or "", "Access-Control-Allow-Credentials": "true"}
        return 200, dict(h, **{"Content-Type": "application/json"}), b'{"email":"a@b.c"}'
    return 404, {"Content-Type": "text/html"}, \
        b"<pre>Traceback (most recent call last):\n  File \"/usr/src/app/main.py\", line 3</pre>"


class _Server:
    def __init__(self, app):
        class Handler(BaseHTTPRequestHandler):
            def _serve(self, send_body=True):
                status, headers, body = app(self.path.split("?", 1)[0], self.headers)
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if send_body:
                    self.wfile.write(body)

            def do_GET(self):
                self._serve()

            def do_HEAD(self):
                self._serve(send_body=False)

            def do_OPTIONS(self):
                self._serve()

            def log_message(self, *args):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def scan(url, api=(), local=None):
    return check.Scanner(url, list(api), check.Client(timeout=5), local=local).run()


def by_status(findings, status):
    return [f"{f.category}: {f.title}" for f in findings if f.status == status]


def has(findings, status, category, text):
    return any(f.status == status and f.category == category and text in f.title for f in findings)


# --------------------------------------------------------------------------- #
# Unit tests
# --------------------------------------------------------------------------- #


class TestCspParsing(unittest.TestCase):
    def test_parse_first_directive_wins_and_lowercases(self):
        p = check.parse_csp("Default-Src 'Self'; script-src 'none'; script-src *")
        self.assertEqual(p["default-src"], ["'self'"])
        self.assertEqual(p["script-src"], ["'none'"])

    def test_script_src_problems(self):
        self.assertEqual(check.script_src_problems(["'self'"]), [])
        self.assertIn("'unsafe-eval'", check.script_src_problems(["'self'", "'unsafe-eval'"]))
        self.assertTrue(check.script_src_problems(["'self'", "'unsafe-inline'"]))
        # unsafe-inline is ignored by browsers when a nonce is present
        self.assertEqual(check.script_src_problems(["'self'", "'unsafe-inline'", "'nonce-x'"]), [])
        self.assertEqual(check.script_src_problems(["https://*.cdn.com"]), ["https://*.cdn.com"])
        self.assertEqual(check.script_src_problems(["https:"]), ["https:"])
        # strict-dynamic + nonce: host/scheme sources are ignored by CSP3 browsers
        self.assertEqual(check.script_src_problems(["'strict-dynamic'", "'nonce-x'", "https:"]), [])

    def test_frame_ancestors_do_not_fall_back(self):
        self.assertFalse(check.frame_ancestors_ok(check.parse_csp("default-src 'none'")))
        self.assertTrue(check.frame_ancestors_ok(check.parse_csp("frame-ancestors 'self'")))
        self.assertFalse(check.frame_ancestors_ok(check.parse_csp("frame-ancestors *")))

    def test_set_cookie(self):
        name, attrs = check.parse_set_cookie("sid=1; Path=/; HttpOnly; SameSite=Lax")
        self.assertEqual(name, "sid")
        self.assertIn("httponly", attrs)
        self.assertEqual(attrs["samesite"], "Lax")

    def test_local_detection(self):
        for host in ("localhost", "127.0.0.1", "192.168.1.5", "::1", "app.localhost"):
            self.assertTrue(check.is_local_host(host), host)
        self.assertFalse(check.is_local_host("app.sapari.io"))


# --------------------------------------------------------------------------- #
# Integration tests
# --------------------------------------------------------------------------- #


class TestBadSite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = _Server(bad_site)
        cls.findings = scan(cls.server.url, api=[cls.server.url + "/api/me"], local=False)

    @classmethod
    def tearDownClass(cls):
        cls.server.close()

    def test_partial_csp_is_not_a_pass(self):
        f = self.findings
        self.assertTrue(has(f, "FAIL", "headers", "default-src"))
        self.assertTrue(has(f, "FAIL", "headers", "script-src"))
        self.assertTrue(has(f, "FAIL", "headers", "base-uri"))
        self.assertTrue(has(f, "FAIL", "headers", "form-action"))
        self.assertTrue(has(f, "PASS", "headers", "frame-ancestors"))

    def test_exposed_env_redacts_values(self):
        env = [x for x in self.findings if x.category == "secrets" and "/.env " in x.title]
        self.assertEqual(len(env), 1, by_status(self.findings, "FAIL"))
        self.assertIn("STRIPE_SECRET_KEY", env[0].evidence)
        self.assertNotIn("sk_test_123", env[0].evidence)

    def test_other_findings(self):
        f = self.findings
        self.assertTrue(has(f, "FAIL", "secrets", "Directory listing"))
        self.assertTrue(has(f, "FAIL", "frontend", "Source maps are public"))
        self.assertTrue(has(f, "FAIL", "csrf", "session"))
        self.assertTrue(has(f, "WARN", "cors", "page: Access-Control-Allow-Origin is *"))
        self.assertTrue(has(f, "FAIL", "cors", "/api/me: any Origin is reflected back WITH credentials"))
        self.assertTrue(has(f, "FAIL", "errors", "Python traceback"))
        self.assertTrue(has(f, "FAIL", "errors", "/docs is public"))
        self.assertTrue(has(f, "WARN", "errors", "disclose software versions"))
        self.assertTrue(has(f, "FAIL", "headers", "X-Content-Type-Options"))

    def test_cli_json_and_exit_code(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = check.main([self.server.url, "--json", "--only", "headers"])
        self.assertEqual(code, 1)
        data = json.loads(buf.getvalue())
        self.assertTrue(data["local"])
        self.assertEqual({f["category"] for f in data["findings"]}, {"headers"})


class TestGoodSpa(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = _Server(good_site)
        cls.findings = scan(cls.server.url)  # auto local mode

    @classmethod
    def tearDownClass(cls):
        cls.server.close()

    def test_no_failures_despite_catch_all_200(self):
        self.assertEqual(by_status(self.findings, "FAIL"), [])

    def test_csp_passes(self):
        for part in ("default-src", "script-src", "object-src", "base-uri", "form-action", "frame-ancestors"):
            self.assertTrue(has(self.findings, "PASS", "headers", part), part)


class TestUnreachable(unittest.TestCase):
    def test_exit_code_2(self):
        import contextlib
        import io
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(check.main(["http://127.0.0.1:9", "--timeout", "2"]), 2)


class TestSkillInSync(unittest.TestCase):
    def test_checklist_copy_matches(self):
        root = (ROOT / "AI-CHECKLIST.md").read_text()
        copy = (ROOT / "skills" / "vibe-check" / "references" / "AI-CHECKLIST.md").read_text()
        self.assertEqual(root, copy, "Run: cp AI-CHECKLIST.md skills/vibe-check/references/")


if __name__ == "__main__":
    unittest.main()
