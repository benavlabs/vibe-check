#!/usr/bin/env python3
"""vibe-check live scanner: black-box security checks against a running web app.

Covers the checklist categories that can be verified from outside the code:
  1. SECRETS_EXPOSURE   publicly served .env / .git / dumps, directory listing
  5. FRONTEND_SECRETS   public source maps
  7. CSRF               cookie flags (HttpOnly, Secure, SameSite)
  8. SECURITY_HEADERS   CSP (directive by directive), HSTS, X-Frame-Options,
                        X-Content-Type-Options, Referrer-Policy, HTTPS redirect
  9. CORS               wildcard / reflected / null origins
 15. ERROR_HANDLING     verbose error pages, debug and API-docs endpoints,
                        version-disclosing headers

Read-only: sends only GET, HEAD and OPTIONS requests (roughly 60-100 in total).
Only scan sites you own or are authorized to test.

Usage:
    python3 check.py https://yourapp.com
    python3 check.py https://yourapp.com --api https://api.yourapp.com/health
    python3 check.py https://yourapp.com --json
    python3 check.py http://localhost:3000        # local mode, reduced checks

Exit codes: 0 = no failures, 1 = at least one FAIL, 2 = target unreachable.
Requires Python 3.8+ and nothing else.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import http.client
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
from typing import Callable, Dict, Iterable, List, Optional, Tuple

VERSION = "1.0.0"
USER_AGENT = f"vibe-check/{VERSION} (+https://github.com/benavlabs/vibe-check)"
EVIL_ORIGIN = "https://evil.vibe-check.invalid"
PROBE_BYTES = 256 * 1024
JS_BYTES = 5 * 1024 * 1024
ONE_YEAR = 31536000

PASS, FAIL, WARN, INFO = "PASS", "FAIL", "WARN", "INFO"

CATEGORIES: Dict[str, str] = {
    "secrets": "1. SECRETS_EXPOSURE",
    "frontend": "5. FRONTEND_SECRETS",
    "csrf": "7. CSRF (cookie flags)",
    "headers": "8. SECURITY_HEADERS",
    "cors": "9. CORS",
    "errors": "15. ERROR_HANDLING",
}

CSP_BASELINE = (
    "default-src 'self'; script-src 'self'; object-src 'none'; "
    "base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
)


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #


@dataclass
class Response:
    url: str
    status: int
    headers: Optional[http.client.HTTPMessage]
    body: bytes
    error: Optional[str] = None
    chain: List["Response"] = field(default_factory=list, repr=False)

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def header(self, name: str) -> Optional[str]:
        return self.headers.get(name) if self.headers is not None else None

    def header_all(self, name: str) -> List[str]:
        if self.headers is None:
            return []
        return self.headers.get_all(name) or []


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D401 - urllib API
        return None


class Client:
    def __init__(self, timeout: float = 10.0, insecure: bool = False):
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self._opener = urllib.request.build_opener(
            _NoRedirect(), urllib.request.HTTPSHandler(context=ctx)
        )
        self.timeout = timeout
        self._lock = threading.Lock()
        self.count = 0

    def request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        follow: bool = True,
        max_bytes: int = PROBE_BYTES,
    ) -> Response:
        chain: List[Response] = []
        for _ in range(6):
            r = self._once(url, method, headers, max_bytes)
            chain.append(r)
            location = r.header("Location")
            if follow and r.ok and r.status in (301, 302, 303, 307, 308) and location:
                url = urllib.parse.urljoin(url, location)
                continue
            break
        final = chain[-1]
        final.chain = chain
        return final

    def _once(self, url, method, headers, max_bytes) -> Response:
        h = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        h.update(headers or {})
        with self._lock:
            self.count += 1
        try:
            req = urllib.request.Request(url, method=method, headers=h)
            resp = self._opener.open(req, timeout=self.timeout)
        except urllib.error.HTTPError as e:
            resp = e
        except (urllib.error.URLError, socket.timeout, ssl.SSLError, http.client.HTTPException,
                ValueError, OSError) as e:
            return Response(url, 0, None, b"", error=str(getattr(e, "reason", e)))
        try:
            body = resp.read(max_bytes) if method != "HEAD" else b""
        except Exception:  # truncated or reset body: headers are still useful
            body = b""
        finally:
            try:
                resp.close()
            except Exception:
                pass
        return Response(url, resp.getcode() or 0, resp.headers, body)


# --------------------------------------------------------------------------- #
# Parsing helpers
# --------------------------------------------------------------------------- #


class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts: List[str] = []
        self.styles: List[str] = []
        self.meta_csp: List[str] = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        rel = a.get("rel", "").lower().split()
        if tag == "script" and a.get("src"):
            self.scripts.append(a["src"])
        elif tag == "link" and a.get("href"):
            if "modulepreload" in rel or ("preload" in rel and a.get("as", "").lower() == "script"):
                self.scripts.append(a["href"])
            elif "stylesheet" in rel:
                self.styles.append(a["href"])
        elif tag == "meta" and a.get("http-equiv", "").lower() == "content-security-policy":
            if a.get("content"):
                self.meta_csp.append(a["content"])


def parse_csp(value: str) -> Dict[str, List[str]]:
    """Parse one serialized CSP policy into {directive: [lowercased sources]}."""
    policy: Dict[str, List[str]] = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue
        name = tokens[0].lower()
        if name not in policy:  # per spec, the first occurrence wins
            policy[name] = [t.lower() for t in tokens[1:]]
    return policy


def split_policies(raw_headers: Iterable[str]) -> List[str]:
    return [p.strip() for raw in raw_headers for p in raw.split(",") if p.strip()]


_SCHEME_ONLY = {"*", "http:", "https:", "data:", "blob:", "filesystem:", "ws:", "wss:"}


def weak_sources(values: List[str]) -> List[str]:
    """Sources that allow far more than the app's own origins."""
    return [
        t for t in values
        if t in _SCHEME_ONLY or t.startswith("*") or "://*" in t or t.startswith("http://")
    ]


def script_src_problems(values: List[str]) -> List[str]:
    has_nonce_or_hash = any(
        v.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for v in values
    )
    strict_dynamic = "'strict-dynamic'" in values
    problems = []
    if "'unsafe-eval'" in values:
        problems.append("'unsafe-eval'")
    # Browsers ignore 'unsafe-inline' when a nonce or hash is present (CSP2+)
    if "'unsafe-inline'" in values and not has_nonce_or_hash:
        problems.append("'unsafe-inline' (no nonce or hash)")
    # With 'strict-dynamic' + nonce/hash, CSP3 browsers ignore host and scheme sources
    if not (strict_dynamic and has_nonce_or_hash):
        problems.extend(weak_sources(values))
    return problems


def effective_sources(policy: Dict[str, List[str]], directive: str) -> Optional[List[str]]:
    if directive in policy:
        return policy[directive]
    if directive == "frame-src" and "child-src" in policy:
        return policy["child-src"]
    return policy.get("default-src")


def frame_ancestors_ok(policy: Dict[str, List[str]]) -> bool:
    values = policy.get("frame-ancestors")
    return values is not None and not weak_sources(values)


def parse_set_cookie(value: str) -> Tuple[str, Dict[str, str]]:
    parts = [p.strip() for p in value.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs: Dict[str, str] = {}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        if k.strip():
            attrs[k.strip().lower()] = v.strip()
    return name, attrs


def origin_of(url: str) -> str:
    p = urllib.parse.urlsplit(url)
    return f"{p.scheme}://{p.netloc}"


def is_local_host(host: Optional[str]) -> bool:
    host = (host or "").strip("[]").lower()
    if host in ("localhost", "0.0.0.0") or host.endswith((".localhost", ".local", ".test")):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private or ip.is_link_local


def looks_like_html(text: str) -> bool:
    head = text[:512].lstrip().lower()
    return head.startswith(("<!doctype", "<html", "<head", "<body")) or "<html" in head


def looks_like_sourcemap(body: bytes) -> bool:
    text = body[:65536].decode("utf-8", "replace").lstrip()
    if text.startswith(")]}'"):
        text = text[4:].lstrip()
    return text.startswith("{") and '"version"' in text and '"sources"' in text


_SOURCEMAP_COMMENT = re.compile(rb"//[#@]\s*sourceMappingURL=([^\s'\"]+)\s*(?:\*/)?\s*$")
_ENV_LINE = re.compile(r"(?m)^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=\s*\S")

# (path, what it is, signature regex). Signatures are what prevent false positives
# on SPAs and catch-all routes that answer 200 to every path.
SENSITIVE_FILES: List[Tuple[str, str, str]] = [
    (".env", "environment file", _ENV_LINE.pattern),
    (".env.local", "environment file", _ENV_LINE.pattern),
    (".env.production", "environment file", _ENV_LINE.pattern),
    (".env.prod", "environment file", _ENV_LINE.pattern),
    (".env.development", "environment file", _ENV_LINE.pattern),
    (".env.backup", "environment file", _ENV_LINE.pattern),
    (".env.bak", "environment file", _ENV_LINE.pattern),
    (".git/config", "git repository config", r"\[core\]"),
    (".git/HEAD", "git repository", r"^\s*ref: refs/"),
    (".npmrc", "npm config (may hold registry tokens)", r"_authToken|//registry"),
    (".aws/credentials", "AWS credentials", r"aws_secret_access_key"),
    (".htpasswd", "password file", r"(?m)^[\w.-]+:(\$(apr1|2[aby]|1|5|6)\$|\{SHA\})"),
    ("id_rsa", "SSH private key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ("backup.sql", "database dump", r"(?i)CREATE TABLE|INSERT INTO|-- (MySQL|MariaDB) dump|PostgreSQL database dump"),
    ("dump.sql", "database dump", r"(?i)CREATE TABLE|INSERT INTO|-- (MySQL|MariaDB) dump|PostgreSQL database dump"),
    ("database.sql", "database dump", r"(?i)CREATE TABLE|INSERT INTO|-- (MySQL|MariaDB) dump|PostgreSQL database dump"),
    ("db.sql", "database dump", r"(?i)CREATE TABLE|INSERT INTO|-- (MySQL|MariaDB) dump|PostgreSQL database dump"),
    ("docker-compose.yml", "docker-compose file (often holds env secrets)", r"(?m)^services:\s*$"),
    ("wp-config.php.bak", "WordPress config backup", r"DB_PASSWORD"),
    ("storage/logs/laravel.log", "Laravel log", r"\[\d{4}-\d\d-\d\d [\d:]+\] \w+\.(ERROR|INFO|DEBUG)"),
]

LISTING_DIRS = ["uploads/", "images/", "assets/", "static/", "files/", "media/",
                "downloads/", "docs/", "backup/", "backups/", "tmp/", "old/"]
_LISTING_SIG = re.compile(r"(?i)<title>\s*(index of|directory listing for)\s*/|<ListBucketResult")

_SWAGGER = r"(?i)swagger-ui"
_OPENAPI = r'"(openapi|swagger)"\s*:\s*"\d'
_PLAYGROUND = r"(?i)graphql-playground|graphiql|embeddable-sandbox|apollo sandbox"
DEBUG_ENDPOINTS: List[Tuple[str, str, str]] = [
    ("docs", "Swagger UI (FastAPI /docs)", _SWAGGER),
    ("redoc", "ReDoc API docs", r"(?i)<redoc|redoc\.standalone"),
    ("openapi.json", "OpenAPI schema", _OPENAPI),
    ("swagger.json", "OpenAPI schema", _OPENAPI),
    ("api-docs", "API docs", _SWAGGER + "|" + _OPENAPI),
    ("v3/api-docs", "OpenAPI schema (Spring)", _OPENAPI),
    ("swagger-ui.html", "Swagger UI", _SWAGGER),
    ("swagger-ui/", "Swagger UI", _SWAGGER),
    ("api/docs", "Swagger UI", _SWAGGER),
    ("graphql", "GraphQL playground", _PLAYGROUND),
    ("graphiql", "GraphiQL", _PLAYGROUND),
    ("actuator", "Spring Boot Actuator", r'"_links"\s*:\s*\{'),
    ("actuator/env", "Spring Boot Actuator /env (exposes secrets)", r'"propertySources"|"activeProfiles"'),
    ("phpinfo.php", "phpinfo()", r"(?i)<title>phpinfo\(\)|PHP Version \d"),
    ("info.php", "phpinfo()", r"(?i)<title>phpinfo\(\)|PHP Version \d"),
    ("server-status", "Apache server-status", r"(?i)Apache Server Status"),
    ("console", "Werkzeug debug console (remote code execution)", r"(?i)werkzeug|interactive console"),
    ("elmah.axd", "ELMAH error log", r"(?i)Error Log for"),
    ("_profiler/", "Symfony profiler", r"(?i)symfony profiler"),
    ("telescope", "Laravel Telescope", r"(?i)<title>\s*Telescope"),
    ("rails/info/properties", "Rails info page", r"(?i)Rails version"),
]

ERROR_SIGNATURES: List[Tuple[str, str]] = [
    ("Python traceback", r"Traceback \(most recent call last\)"),
    ("Django DEBUG page", r"Using the URLconf defined in|you have <code>DEBUG = True</code>"),
    ("Werkzeug debugger", r"(?i)werkzeug debugger|The debugger caught an exception"),
    ("Laravel/Whoops error page", r"Whoops, looks like something went wrong|Illuminate\\"),
    ("Rails error page", r"ActionController::RoutingError|(?s:Routing Error.{0,200}No route matches)"),
    ("Node.js stack trace", r"at \S+ \((?:/|[A-Za-z]:\\)[^)]*:\d+:\d+\)"),
    ("ASP.NET error page", r"Server Error in '/' Application"),
    ("Java stack trace", r"(?m)^\s*at [\w$.]+\([\w$]+\.java:\d+\)"),
    ("SQL error", r"(?i)SQLSTATE\[|You have an error in your SQL syntax|psycopg2\.|sqlite3\.OperationalError|ORA-\d{5}|PG::\w+Error"),
    ("server file path", r"(?:/home/|/var/www/|/usr/src/app/|/opt/app/|C:\\Users\\)[\w./\\-]+\.(?:py|js|ts|php|rb|java)\b"),
]

_SESSION_COOKIE = re.compile(
    r"(?i)sess|sid|auth|token|jwt|login|remember|refresh|access|identity|jsessionid|phpsessid"
)
_CSRF_COOKIE = re.compile(r"(?i)csrf|xsrf")


# --------------------------------------------------------------------------- #
# Scanner
# --------------------------------------------------------------------------- #


@dataclass
class Finding:
    category: str
    status: str
    title: str
    detail: str = ""
    fix: str = ""
    evidence: str = ""
    url: str = ""


class ScanError(Exception):
    pass


class Scanner:
    def __init__(self, url: str, api_urls: List[str], client: Client,
                 local: Optional[bool] = None, only: Optional[List[str]] = None):
        self.url = url
        self.api_urls = api_urls
        self.client = client
        self.local = is_local_host(urllib.parse.urlsplit(url).hostname) if local is None else local
        self.only = set(only or CATEGORIES)
        self.findings: List[Finding] = []

    # -- plumbing ---------------------------------------------------------- #

    def add(self, category, status, title, detail="", fix="", evidence="", url=""):
        self.findings.append(Finding(category, status, title, detail, fix, evidence, url))

    def fetch_many(self, urls: List[str], headers=None, max_bytes=PROBE_BYTES) -> List[Response]:
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            return list(ex.map(lambda u: self.client.request(u, headers=headers, max_bytes=max_bytes), urls))

    def run(self) -> List[Finding]:
        page = self.client.request(self.url, headers={"Accept": "text/html,*/*"})
        if not page.ok:
            raise ScanError(f"Could not reach {self.url}: {page.error}")
        self.page = page
        self.parser = _PageParser()
        try:
            self.parser.feed(page.text)
        except Exception:
            pass
        self.base = origin_of(page.url)
        self.origins: List[str] = []
        for o in [self.base] + [origin_of(u) for u in self.api_urls]:
            if o not in self.origins:
                self.origins.append(o)
        self.scripts = self._same_host(self.parser.scripts)[:15]
        styles = self._same_host(self.parser.styles)
        self.asset = (self.scripts or styles or [None])[0]

        steps: List[Tuple[str, Callable[[], None]]] = [
            ("secrets", self.check_secrets),
            ("frontend", self.check_frontend),
            ("csrf", self.check_cookies),
            ("headers", self.check_headers),
            ("cors", self.check_cors),
            ("errors", self.check_errors),
        ]
        for key, fn in steps:
            if key in self.only:
                fn()
        return self.findings

    def _same_host(self, refs: List[str]) -> List[str]:
        host = urllib.parse.urlsplit(self.page.url).hostname
        out: List[str] = []
        for ref in refs:
            u = urllib.parse.urljoin(self.page.url, ref)
            p = urllib.parse.urlsplit(u)
            if p.scheme in ("http", "https") and p.hostname == host and u not in out:
                out.append(u)
        return out

    # -- 1. secrets served over HTTP --------------------------------------- #

    def check_secrets(self):
        cat = "secrets"
        for origin in self.origins:
            urls = [f"{origin}/{path}" for path, _, _ in SENSITIVE_FILES]
            exposed = 0
            for (path, what, sig), r in zip(SENSITIVE_FILES, self.fetch_many(urls)):
                if not (r.ok and r.status in (200, 206)) or looks_like_html(r.text):
                    continue
                m = re.search(sig, r.text)
                if not m:
                    continue
                exposed += 1
                if what == "environment file":
                    keys = sorted(set(_ENV_LINE.findall(r.text)))[:12]
                    evidence = "variables: " + ", ".join(keys)
                else:
                    evidence = "matched: " + m.group(0)[:60]
                self.add(cat, FAIL, f"/{path} is publicly downloadable ({what})",
                         "Anyone can fetch this file. Treat every credential in it as leaked.",
                         fix="Rotate the exposed credentials now, then make sure only the build "
                             "output directory is served (never the project root).",
                         evidence=evidence, url=r.url)
            if not exposed:
                self.add(cat, PASS, f"No sensitive files served on {origin}",
                         f"Checked {len(SENSITIVE_FILES)} paths (.env*, .git, dumps, keys, logs).")

            urls = [f"{origin}/{d}" for d in LISTING_DIRS]
            listed = [r.url for r in self.fetch_many(urls)
                      if r.ok and r.status == 200 and _LISTING_SIG.search(r.text)]
            if listed:
                self.add(cat, FAIL, f"Directory listing enabled on {origin}",
                         "These folders show an index of every file inside them.",
                         fix="Disable autoindex (nginx `autoindex off`, Apache `Options -Indexes`, "
                             "remove Express serve-index, block ListBucket on public buckets).",
                         evidence=", ".join(listed))
            else:
                self.add(cat, PASS, f"No directory listing on {origin}",
                         f"Checked {len(LISTING_DIRS)} common folders.")

    # -- 5. source maps ----------------------------------------------------- #

    def check_frontend(self):
        cat = "frontend"
        if not self.scripts:
            self.add(cat, INFO, "No same-origin scripts found in the HTML",
                     "Source maps weren't checked. If the page loads its JS from another host "
                     "or builds it at runtime, check the Network tab manually.")
            return

        def probe(js_url: str) -> Optional[Tuple[str, str]]:
            js = self.client.request(js_url, max_bytes=JS_BYTES)
            if not (js.ok and js.status == 200):
                return None
            candidates = []
            hdr = js.header("SourceMap") or js.header("X-SourceMap")
            if hdr:
                candidates.append(urllib.parse.urljoin(js_url, hdr))
            m = _SOURCEMAP_COMMENT.search(js.body[-4096:])
            if m:
                ref = m.group(1).decode("utf-8", "replace")
                if ref.startswith("data:"):
                    return js_url, "inline source map embedded in the bundle"
                candidates.append(urllib.parse.urljoin(js_url, ref))
            candidates.append(js_url.split("#", 1)[0].split("?", 1)[0] + ".map")
            for c in dict.fromkeys(candidates):
                r = self.client.request(c, max_bytes=65536)
                if r.ok and r.status == 200 and looks_like_sourcemap(r.body):
                    return js_url, c
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
            hits = [h for h in ex.map(probe, self.scripts) if h]
        if not hits:
            self.add(cat, PASS, "No public source maps",
                     f"Checked {len(self.scripts)} script(s) and their .map files.")
            return
        self.add(cat, WARN if self.local else FAIL,
                 f"Source maps are public for {len(hits)} of {len(self.scripts)} script(s)",
                 "Anyone can rebuild your original frontend source (file names, comments, internal "
                 "API routes) from these." + (" Dev servers do this on purpose, so re-run against "
                                              "the production build." if self.local else ""),
                 fix="Turn off public source maps in the production build (Vite `build.sourcemap: false`, "
                     "Next.js `productionBrowserSourceMaps: false`, webpack `devtool: false`), or "
                     "upload them privately to your error tracker.",
                 evidence="; ".join(m for _, m in hits[:5]))

    # -- 7. cookies --------------------------------------------------------- #

    def check_cookies(self):
        cat = "csrf"
        https = self.page.url.startswith("https://")
        cookies = [c for r in self.page.chain for c in r.header_all("Set-Cookie")]
        if not cookies:
            self.add(cat, INFO, "No cookies set on the landing page",
                     "Session cookies are usually set after login. Check them in DevTools → "
                     "Application → Cookies (manual check #7).")
            return
        clean = []
        for raw in cookies:
            name, attrs = parse_set_cookie(raw)
            sensitive = bool(_SESSION_COOKIE.search(name)) and not _CSRF_COOKIE.search(name)
            samesite = attrs.get("samesite", "").lower()
            fails, warns = [], []
            if "secure" not in attrs and (https or samesite == "none"):
                (fails if sensitive or samesite == "none" else warns).append("missing Secure")
            if sensitive and "httponly" not in attrs:
                fails.append("missing HttpOnly (readable by any injected script)")
            if sensitive and not samesite:
                fails.append("missing SameSite (set Lax or Strict)")
            if samesite == "none" and sensitive:
                warns.append("SameSite=None (sent on cross-site requests; needs CSRF tokens)")
            if fails or warns:
                self.add(cat, FAIL if fails and not self.local else WARN,
                         f"Cookie `{name}`: " + ", ".join(fails + warns),
                         "Session/auth cookie." if sensitive else "Non-session cookie.",
                         fix="Set HttpOnly, Secure and SameSite=Lax (or Strict) on every auth cookie.",
                         evidence=raw.split(";", 1)[0].split("=", 1)[0] + "=…;" +
                                  (raw.split(";", 1)[1] if ";" in raw else ""))
            else:
                clean.append(name)
        if clean:
            self.add(cat, PASS, "Cookie flags OK: " + ", ".join(clean),
                     "Only cookies set on the landing page were checked; check post-login cookies manually.")

    # -- 8. headers --------------------------------------------------------- #

    def check_headers(self):
        cat = "headers"
        page = self.page
        header_raw = split_policies(page.header_all("Content-Security-Policy"))
        policies = [parse_csp(p) for p in header_raw]
        meta = [parse_csp(m) for m in self.parser.meta_csp]
        xfo = (page.header("X-Frame-Options") or "").strip().upper()
        xfo_ok = xfo in ("DENY", "SAMEORIGIN")
        fa_ok = any(frame_ancestors_ok(p) for p in policies)

        self._check_csp(policies, meta, header_raw,
                        page.header_all("Content-Security-Policy-Report-Only"), xfo_ok)

        # X-Frame-Options
        if xfo_ok:
            self.add(cat, PASS, f"X-Frame-Options: {xfo}")
        elif fa_ok:
            self.add(cat, WARN, "X-Frame-Options missing (CSP frame-ancestors covers modern browsers)",
                     fix="Add `X-Frame-Options: DENY` for older browsers.", evidence=xfo or "absent")
        else:
            self.add(cat, FAIL, "No clickjacking protection",
                     "Neither X-Frame-Options nor CSP frame-ancestors is set, so any site can frame yours.",
                     fix="Send `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'`.",
                     evidence=xfo or "absent")

        # X-Content-Type-Options
        xcto = (page.header("X-Content-Type-Options") or "").strip().lower()
        if xcto == "nosniff":
            self.add(cat, PASS, "X-Content-Type-Options: nosniff")
        else:
            self.add(cat, FAIL, "X-Content-Type-Options is not `nosniff`",
                     fix="Send `X-Content-Type-Options: nosniff`.", evidence=xcto or "absent")

        # Referrer-Policy (last recognized token wins)
        rp_tokens = [t.strip().lower() for t in (page.header("Referrer-Policy") or "").split(",") if t.strip()]
        rp = rp_tokens[-1] if rp_tokens else ""
        if rp in ("unsafe-url", "no-referrer-when-downgrade"):
            self.add(cat, FAIL, f"Referrer-Policy `{rp}` leaks full URLs to other sites",
                     fix="Send `Referrer-Policy: strict-origin-when-cross-origin`.", evidence=rp)
        elif rp:
            self.add(cat, PASS, f"Referrer-Policy: {rp}")
        else:
            self.add(cat, WARN, "Referrer-Policy missing",
                     "Modern browsers default to strict-origin-when-cross-origin, but set it explicitly.",
                     fix="Send `Referrer-Policy: strict-origin-when-cross-origin`.")

        self._check_hsts()
        self._check_https_redirect()
        self._check_asset_headers()

    def _check_csp(self, policies, meta, header_raw, report_only, xfo_ok):
        cat = "headers"
        if not policies and not meta:
            detail = "No Content-Security-Policy header, so injected scripts run with no restrictions."
            if report_only:
                detail += " A Report-Only policy exists, but report-only policies block nothing."
            self.add(cat, FAIL, "Content-Security-Policy is missing", detail,
                     fix=f"Start from `{CSP_BASELINE}` and add only the origins you use. "
                         "Roll it out as Content-Security-Policy-Report-Only first.")
            return
        evidence = " | ".join(header_raw or self.parser.meta_csp)
        if not policies:
            self.add(cat, WARN, "CSP is only set with a <meta> tag",
                     "frame-ancestors, sandbox and report-uri are ignored in <meta>.",
                     fix="Send the policy as an HTTP header.", evidence=evidence)
        all_p = policies + meta
        missing_fix = f"Baseline: `{CSP_BASELINE}`."

        def rule(ok: bool, title_ok: str, title_bad: str, detail: str, fix: str, status_bad=FAIL):
            if ok:
                self.add(cat, PASS, title_ok)
            else:
                self.add(cat, status_bad, title_bad, detail, fix=fix, evidence=evidence)

        rule(any("default-src" in p and not weak_sources(p["default-src"]) for p in all_p),
             "CSP default-src is restrictive",
             "CSP default-src is missing or allows any origin",
             "Every fetch directive you don't declare falls back to default-src. Without it, "
             "undeclared directives are unrestricted.",
             "Add `default-src 'self'` (or 'none'). " + missing_fix)

        script_problems: List[str] = []
        script_ok = False
        for p in all_p:
            eff = effective_sources(p, "script-src")
            probs = ["no script-src and no default-src"] if eff is None else script_src_problems(eff)
            if not probs:
                script_ok = True
            script_problems.extend(probs)
        rule(script_ok, "CSP script-src blocks inline and third-party scripts",
             "CSP does not stop injected scripts (script-src)",
             "Problems: " + ", ".join(dict.fromkeys(script_problems)) + ". This is the directive "
             "that actually stops XSS.",
             "Use `script-src 'self'` plus nonces or hashes for inline scripts. Never "
             "'unsafe-inline', 'unsafe-eval', *, data:, or bare https:.")

        rule(any(effective_sources(p, "object-src") in (["'none'"], []) for p in all_p),
             "CSP object-src is 'none'", "CSP object-src is not 'none'",
             "Plugins (<object>, <embed>) are allowed; they're a classic CSP bypass.",
             "Add `object-src 'none'`.")

        for d, why in (("base-uri", "An injected <base> tag can redirect every relative link and script."),
                       ("form-action", "Injected forms can post data (passwords) to any site.")):
            rule(any(d in p and not weak_sources(p[d]) for p in all_p),
                 f"CSP {d} is set", f"CSP {d} is missing or allows any origin",
                 why + f" {d} does NOT fall back to default-src; it must be declared.",
                 f"Add `{d} 'self'`.")

        fa = any(frame_ancestors_ok(p) for p in policies)
        rule(fa, "CSP frame-ancestors is set", "CSP frame-ancestors is missing",
             "frame-ancestors does not fall back to default-src and only works as a header."
             + (" X-Frame-Options covers it for now." if xfo_ok else ""),
             "Add `frame-ancestors 'none'` (or 'self').", status_bad=WARN if xfo_ok else FAIL)

        media_ok = {"data:", "blob:"}
        unrestricted = []
        for d in ("connect-src", "frame-src", "img-src", "style-src", "font-src", "media-src"):
            def restricted(p, d=d):
                eff = effective_sources(p, d)
                if eff is None:
                    return False
                allowed = media_ok if d in ("img-src", "font-src", "media-src") else set()
                return not [t for t in weak_sources(eff) if t not in allowed]
            if not any(restricted(p) for p in all_p):
                unrestricted.append(d)
        if unrestricted:
            critical = {"connect-src", "frame-src"} & set(unrestricted)
            self.add(cat, FAIL if critical else WARN,
                     "CSP leaves these unrestricted: " + ", ".join(unrestricted),
                     "connect-src stops injected scripts from sending stolen data out; frame-src stops "
                     "them from loading phishing iframes." if critical else
                     "Lower risk, but they should list only the origins you use.",
                     fix="Set default-src 'self' and list only the extra origins each directive needs.",
                     evidence=evidence)
        else:
            self.add(cat, PASS, "CSP fetch directives are restricted")

    def _check_hsts(self):
        cat = "headers"
        if self.local:
            self.add(cat, INFO, "HSTS skipped (local target)")
            return
        if not self.page.url.startswith("https://"):
            self.add(cat, FAIL, "Site is not served over HTTPS",
                     fix="Serve everything over HTTPS and redirect HTTP to it.", url=self.page.url)
            return
        v = self.page.header("Strict-Transport-Security")
        if not v:
            self.add(cat, FAIL, "Strict-Transport-Security is missing",
                     "Browsers will still try plain HTTP, which allows SSL-stripping attacks.",
                     fix=f"Send `Strict-Transport-Security: max-age={ONE_YEAR}; includeSubDomains`.")
            return
        m = re.search(r"max-age\s*=\s*\"?(\d+)", v, re.I)
        age = int(m.group(1)) if m else 0
        problems = []
        if age < ONE_YEAR:
            problems.append(f"max-age={age} (needs >= {ONE_YEAR})")
        if "includesubdomains" not in v.lower():
            problems.append("no includeSubDomains")
        if problems:
            self.add(cat, FAIL, "Strict-Transport-Security is too weak: " + ", ".join(problems),
                     fix=f"Send `Strict-Transport-Security: max-age={ONE_YEAR}; includeSubDomains`.",
                     evidence=v)
        else:
            note = "" if "preload" in v.lower() else (
                " `preload` is optional: add it only if every subdomain is HTTPS-only, since "
                "getting off the preload list takes months.")
            self.add(cat, PASS, "Strict-Transport-Security is strong", note.strip(), evidence=v)

    def _check_https_redirect(self):
        cat = "headers"
        if self.local or not self.page.url.startswith("https://"):
            return
        host = urllib.parse.urlsplit(self.page.url).netloc
        r = self.client.request(f"http://{host}/", follow=False)
        loc = r.header("Location") or ""
        if not r.ok:
            self.add(cat, PASS, "Plain HTTP is not served", f"Port 80 did not answer ({r.error}).")
        elif r.status in (301, 302, 307, 308) and loc.startswith("https://"):
            self.add(cat, PASS, f"HTTP redirects to HTTPS ({r.status})")
        else:
            self.add(cat, FAIL, f"Plain HTTP is served without redirecting (status {r.status})",
                     fix="Redirect all HTTP requests to HTTPS with a 301/308.", url=r.url)

    def _check_asset_headers(self):
        cat = "headers"
        if not self.asset:
            return
        r = self.client.request(self.asset, method="HEAD")
        if not r.ok or r.status >= 400:
            r = self.client.request(self.asset, max_bytes=1024)
        if not r.ok:
            return
        missing = []
        if (r.header("X-Content-Type-Options") or "").strip().lower() != "nosniff":
            missing.append("X-Content-Type-Options: nosniff")
        if not self.local and self.asset.startswith("https://") and not r.header("Strict-Transport-Security"):
            missing.append("Strict-Transport-Security")
        if missing:
            self.add(cat, WARN, "Static files are missing headers: " + ", ".join(missing),
                     "Static files are often served by the host/CDN and skip your app middleware.",
                     fix="Mirror the headers in hosting config (vercel.json, netlify.toml, _headers, nginx).",
                     url=self.asset)
        else:
            self.add(cat, PASS, "Static files carry the security headers", url=self.asset)

    # -- 9. CORS ------------------------------------------------------------ #

    def check_cors(self):
        cat = "cors"
        targets: List[Tuple[str, str]] = [(self.page.url, "page")]
        if self.asset:
            targets.append((self.asset, "static asset"))
        targets += [(u, "API") for u in self.api_urls]

        for url, kind in targets:
            if kind == "API":
                kind = f"API {urllib.parse.urlsplit(url).netloc}{urllib.parse.urlsplit(url).path}"
            r = self.client.request(url, headers={"Origin": EVIL_ORIGIN})
            if not r.ok:
                self.add(cat, INFO, f"CORS not checked on {kind}: {r.error}", url=url)
                continue
            acao = (r.header("Access-Control-Allow-Origin") or "").strip()
            creds = (r.header("Access-Control-Allow-Credentials") or "").strip().lower() == "true"
            if not acao:
                self.add(cat, PASS, f"{kind}: foreign origins are not allowed", url=url)
            elif acao == EVIL_ORIGIN:
                self.add(cat, FAIL,
                         f"{kind}: any Origin is reflected back" + (" WITH credentials" if creds else ""),
                         "Any website can read these responses" +
                         (" using the visitor's cookies, which means full account data theft." if creds else "."),
                         fix="Check Origin against an explicit allowlist before echoing it.",
                         evidence=f"Access-Control-Allow-Origin: {acao}", url=url)
            elif acao == "*":
                # Browsers never send cookies with a `*` response, so on public pages and files
                # this only exposes what anyone can already download. On APIs it's the wrong default.
                is_api = kind.startswith("API")
                self.add(cat, FAIL if is_api else WARN, f"{kind}: Access-Control-Allow-Origin is *",
                         "Any website can read this API's responses. Often added by the host/CDN, not the app."
                         if is_api else
                         "Low risk for public content (no cookies are sent with `*`), but it's usually "
                         "a host/CDN default nobody chose. Remove it so it can't spread to routes that matter.",
                         fix="Replace * with your own domains (check hosting config too).",
                         evidence="Access-Control-Allow-Origin: *", url=url)
            else:
                self.add(cat, PASS, f"{kind}: CORS allows only {acao}", url=url)

            n = self.client.request(url, headers={"Origin": "null"})
            if n.ok and (n.header("Access-Control-Allow-Origin") or "").strip() == "null":
                self.add(cat, FAIL, f"{kind}: the `null` origin is allowed",
                         "Sandboxed iframes and local files send Origin: null, so attackers can use it.",
                         fix="Remove `null` from the allowlist.", url=url)

            if kind.startswith("API"):
                pf = self.client.request(url, method="OPTIONS", headers={
                    "Origin": EVIL_ORIGIN,
                    "Access-Control-Request-Method": "DELETE",
                    "Access-Control-Request-Headers": "authorization",
                })
                acam = (pf.header("Access-Control-Allow-Methods") or "").strip()
                if pf.ok and acam == "*":
                    self.add(cat, WARN, "API preflight allows every method",
                             fix="List only the methods the API uses.",
                             evidence=f"Access-Control-Allow-Methods: {acam}", url=url)

    # -- 15. errors and debug endpoints ------------------------------------ #

    def check_errors(self):
        cat = "errors"
        for origin in self.origins:
            probes = [f"{origin}/vibe-check-{secrets.token_hex(6)}", f"{origin}/%"]
            leaks: Dict[str, List[str]] = {}
            for r in self.fetch_many(probes):
                for label, sig in ERROR_SIGNATURES:
                    if r.ok and re.search(sig, r.text):
                        leaks.setdefault(label, []).append(f"{r.url} (HTTP {r.status})")
                        break
            if leaks:
                for label, hits in leaks.items():
                    self.add(cat, FAIL, f"Error page leaks internals ({label})",
                             "Error responses show stack traces, file paths or queries.",
                             fix="Turn off debug mode in production and return a generic error body.",
                             evidence="; ".join(hits))
            else:
                self.add(cat, PASS, f"Error pages don't leak internals on {origin}")

            urls = [f"{origin}/{p}" for p, _, _ in DEBUG_ENDPOINTS]
            found = []
            for (path, what, sig), r in zip(DEBUG_ENDPOINTS,
                                            self.fetch_many(urls, headers={"Accept": "text/html,application/json,*/*"})):
                if r.ok and r.status == 200 and re.search(sig, r.text):
                    found.append((path, what, r.url))
            for path, what, url in found:
                self.add(cat, FAIL, f"/{path} is public ({what})",
                         "Debug and docs endpoints give attackers a map of your API; some hand over "
                         "secrets or code execution.",
                         fix="Disable it in production or put it behind admin auth "
                             "(FastAPI: `docs_url=None, redoc_url=None, openapi_url=None`).",
                         url=url)
            if not found:
                self.add(cat, PASS, f"No debug or API-docs endpoints on {origin}",
                         f"Checked {len(DEBUG_ENDPOINTS)} paths.")

            intro_q = urllib.parse.quote("{__schema{queryType{name}}}")
            for gql in ("graphql", "api/graphql"):
                r = self.client.request(f"{origin}/{gql}?query={intro_q}", headers={
                    "Accept": "application/json", "apollo-require-preflight": "true"})
                if r.ok and r.status == 200 and '"__schema"' in r.text:
                    self.add(cat, WARN, f"GraphQL introspection is enabled at /{gql}",
                             "Anyone can download your full schema. Fine for public APIs, not for private ones.",
                             fix="Disable introspection in production.", url=r.url)
                    break

        disclosed = []
        for name in ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"):
            v = self.page.header(name)
            if v and (name != "Server" or re.search(r"\d", v)):
                disclosed.append(f"{name}: {v}")
        if disclosed:
            self.add(cat, WARN, "Response headers disclose software versions",
                     fix="Remove X-Powered-By (Express: `app.disable('x-powered-by')`) and version numbers from Server.",
                     evidence="; ".join(disclosed))


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #

_COLORS = {PASS: "32", FAIL: "31", WARN: "33", INFO: "36"}


def render_text(target: str, local: bool, findings: List[Finding], requests: int, color: bool) -> str:
    def c(status: str, text: str) -> str:
        return f"\033[{_COLORS[status]}m{text}\033[0m" if color else text

    lines = [f"vibe-check live scan · {target}",
             "Only scan sites you own or are authorized to test.", ""]
    if local:
        lines += ["LOCAL TARGET: HSTS/HTTPS checks are skipped and dev servers behave differently "
                  "from production (headers set by your host, source maps). Re-run against the "
                  "deployed URL before trusting a PASS.", ""]
    for key, label in CATEGORIES.items():
        items = [f for f in findings if f.category == key]
        if not items:
            continue
        lines.append(label)
        for f in sorted(items, key=lambda f: [FAIL, WARN, INFO, PASS].index(f.status)):
            lines.append(f"  {c(f.status, f.status.ljust(4))}  {f.title}")
            for extra in (f.detail, f"evidence: {f.evidence}" if f.evidence else "",
                          f"url: {f.url}" if f.url and f.status != PASS else "",
                          f"fix: {f.fix}" if f.fix and f.status != PASS else ""):
                if extra:
                    lines.append(f"        {extra}")
        lines.append("")
    counts = {s: sum(f.status == s for f in findings) for s in (FAIL, WARN, PASS, INFO)}
    lines.append(f"Summary: {counts[FAIL]} failed, {counts[WARN]} warnings, {counts[PASS]} passed · "
                 f"{requests} requests")
    lines.append("Not covered here (needs code or accounts): database access/RLS, auth middleware, "
                 "IDOR, SSRF, rate limiting, SQLi, XSS, webhooks, uploads, password hashing, dependencies.")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Black-box security checks for a running web app (read-only).")
    ap.add_argument("url", help="page to scan, e.g. https://yourapp.com")
    ap.add_argument("--api", action="append", default=[], metavar="URL",
                    help="an API URL on another origin to also check (CORS, errors, debug endpoints). Repeatable.")
    ap.add_argument("--only", help="comma-separated subset: " + ",".join(CATEGORIES))
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--local", action="store_true", default=None,
                    help="force local mode (auto-detected for localhost and private IPs)")
    ap.add_argument("--timeout", type=float, default=10.0, help="per-request timeout in seconds (default 10)")
    ap.add_argument("--insecure", action="store_true", help="skip TLS certificate verification")
    args = ap.parse_args(argv)

    url = args.url if "://" in args.url else "https://" + args.url
    if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
        ap.error("only http and https URLs are supported")
    only = [o.strip() for o in args.only.split(",")] if args.only else None
    if only and set(only) - set(CATEGORIES):
        ap.error("unknown category in --only: " + ", ".join(sorted(set(only) - set(CATEGORIES))))

    client = Client(timeout=args.timeout, insecure=args.insecure)
    scanner = Scanner(url, args.api, client, local=args.local, only=only)
    try:
        findings = scanner.run()
    except ScanError as e:
        if args.json:
            print(json.dumps({"target": url, "error": str(e)}))
        else:
            print(f"error: {e}", file=sys.stderr)
        return 2

    if args.json:
        counts = {s.lower(): sum(f.status == s for f in findings) for s in (FAIL, WARN, PASS, INFO)}
        print(json.dumps({
            "target": url, "final_url": scanner.page.url, "local": scanner.local,
            "requests": client.count, "summary": counts,
            "findings": [dict(asdict(f), category_label=CATEGORIES[f.category]) for f in findings],
        }, indent=2))
    else:
        color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
        print(render_text(url, scanner.local, findings, client.count, color))
    return 1 if any(f.status == FAIL for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
