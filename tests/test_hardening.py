"""Regression coverage for the scanner's request boundary."""
import unittest
from unittest.mock import patch

from test_check import _Server, check


class TestTargetBoundary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.received = []

        def internal(path, headers):
            cls.received.append(path)
            return 200, {"Content-Type": "application/json"}, \
                b'{"version":3,"sources":["fixture"],"mappings":""}'

        cls.inner = _Server(internal)

        def target(path, headers):
            if path == "/":
                return 200, {"Content-Type": "text/html"}, \
                    b'<html><script src="/app.js"></script></html>'
            if path == "/app.js":
                return 200, {"SourceMap": cls.inner.url + "/map"}, b"console.log(1)"
            if path == "/redirect":
                return 302, {"Location": cls.inner.url + "/redirected"}, b""
            if path == "/same-origin":
                return 302, {"Location": "/"}, b""
            if path == "/file":
                return 302, {"Location": "file:///not-a-real-secret"}, b""
            return 404, {}, b""

        cls.outer = _Server(target)
        cls.client = check.Client(timeout=2)

    @classmethod
    def tearDownClass(cls):
        cls.outer.close()
        cls.inner.close()

    def setUp(self):
        self.received.clear()
        self.client.blocked.clear()

    def scanner(self, path="/", api=(), only=("csrf",)):
        return check.Scanner(self.outer.url + path, list(api), self.client, only=list(only))

    def test_cross_origin_redirect_is_blocked_before_connection(self):
        with self.assertRaises(check.ScanError):
            self.scanner("/redirect").run()
        self.assertEqual(self.received, [])
        self.assertEqual(self.client.blocked, [self.inner.url + "/redirected"])

    def test_source_map_cannot_reach_undeclared_local_service(self):
        findings = self.scanner(only=("frontend",)).run()
        self.assertEqual(self.received, [])
        self.assertTrue(any(f.status == check.WARN and "incomplete" in f.title for f in findings))
        self.assertFalse(any(f.status == check.PASS for f in findings))

    def test_explicit_api_origin_can_be_used(self):
        findings = self.scanner(api=(self.inner.url,), only=("frontend",)).run()
        self.assertEqual(self.received, ["/map"])
        self.assertTrue(any("Source maps are public" in f.title for f in findings))
        self.assertEqual(self.client.blocked, [])

    def test_same_origin_relative_redirect_still_works(self):
        scanner = self.scanner("/same-origin")
        scanner.run()
        self.assertEqual(scanner.page.url, self.outer.url + "/")
        self.assertEqual(self.client.blocked, [])

    def test_file_redirect_is_blocked(self):
        with self.assertRaises(check.ScanError):
            self.scanner("/file").run()
        self.assertEqual(self.client.blocked, ["file:///not-a-real-secret"])

    def test_disallowed_urls_never_reach_transport(self):
        self.scanner()
        for url in ("file:///not-a-real-secret", "ftp://localhost/x", "data:text/plain,hello",
                    self.outer.url.replace("//", "//user:password@"), "http://localhost:1/"):
            with self.subTest(url=url), patch.object(self.client, "_once") as transport:
                self.assertFalse(self.client.request(url).ok)
                transport.assert_not_called()

    def test_https_downgrade_requires_dedicated_nonfollowing_probe(self):
        check.Scanner("https://example.invalid", [], self.client)
        with patch.object(self.client, "_once") as transport:
            self.assertFalse(self.client.request("http://example.invalid/").ok)
            transport.assert_not_called()
            transport.return_value = check.Response("http://example.invalid/", 200, None, b"")
            self.assertTrue(self.client.request("http://example.invalid/", follow=False, http_probe=True).ok)
            transport.assert_called_once()
        with self.assertRaises(ValueError):
            self.client.request("http://example.invalid/", http_probe=True)

    def test_invalid_target_rejected_before_scanning(self):
        for url in ("https://example.invalid:bad", "https://", "https://user:pass@example.invalid",
                    "https://example.invalid/\n", "file:///fixture"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                check.Scanner(url, [], self.client)

    def test_default_ports_normalize_but_other_ports_differ(self):
        self.assertEqual(check.request_origin("https://EXAMPLE.invalid:443/x"),
                         check.request_origin("https://example.invalid/y"))
        self.assertNotEqual(check.request_origin("https://example.invalid:444/x"),
                            check.request_origin("https://example.invalid/y"))
        self.assertNotEqual(check.request_origin("https://example.invalid:0/x"),
                            check.request_origin("https://example.invalid/y"))
