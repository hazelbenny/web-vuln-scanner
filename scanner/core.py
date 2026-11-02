"""Scanner engine. Passive checks always run; active checks (crawl, probes) only for verified targets."""
import socket
import ssl
import time
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse

import requests

A01 = "A01 Broken Access Control"
A02 = "A02 Cryptographic Failures"
A03 = "A03 Injection"
A05 = "A05 Security Misconfiguration"

MARKER = "vscan7\"<x>'"  # harmless marker, not an attack payload
SQL_ERRORS = [
    "you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark",
    "quoted string not properly terminated", "pg_query()", "sqlite3.operationalerror",
    "sqlstate", "odbc driver", "ora-00933",
]
HEADERS = {
    "Content-Security-Policy": ("Medium", A05, "Add a CSP, e.g. default-src 'self'."),
    "X-Frame-Options": ("Medium", A05, "Set to DENY or SAMEORIGIN (or use CSP frame-ancestors)."),
    "X-Content-Type-Options": ("Low", A05, "Set to nosniff."),
    "Strict-Transport-Security": ("Medium", A02, "Add max-age=31536000; includeSubDomains."),
    "Referrer-Policy": ("Low", A05, "Set to strict-origin-when-cross-origin or stricter."),
    "Permissions-Policy": ("Low", A05, "Disable unused features, e.g. camera=(), microphone=()."),
}
LEAKY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version"]
CSRF_NAMES = ("csrf", "token", "authenticity", "nonce")
SKIP_TYPES = ("submit", "button", "hidden", "file", "image", "reset", "checkbox", "radio")
SENSITIVE_PATHS = [  # (path, content check, severity, title)
    ("/.git/HEAD", lambda t: t.startswith("ref:"), "High", "Exposed Git repository"),
    ("/.env", lambda t: "=" in t and "<html" not in t.lower(), "High", "Exposed .env file"),
    ("/phpinfo.php", lambda t: "phpinfo()" in t, "Medium", "Exposed phpinfo page"),
    ("/server-status", lambda t: "Apache Server Status" in t, "Medium", "Exposed Apache server-status"),
]


class BudgetExceeded(Exception):
    pass


class PageParser(HTMLParser):
    """Collects links and forms from an HTML page."""

    def __init__(self):
        super().__init__()
        self.links, self.forms, self._form = [], [], None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method": a.get("method", "get").lower(), "inputs": []}
            self.forms.append(self._form)
        elif tag in ("input", "textarea", "select") and self._form is not None and a.get("name"):
            self._form["inputs"].append(
                {"name": a["name"], "type": a.get("type", "text").lower(), "value": a.get("value", "")})

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None


class Scanner:
    def __init__(self, url, full, log=print, delay=0.3, max_pages=15, max_requests=300):
        u = urlparse(url)
        self.start, self.host, self.scheme = url, u.hostname, u.scheme
        self.port = u.port or (443 if u.scheme == "https" else 80)
        self.base = f"{u.scheme}://{u.netloc}"
        self.full, self.log, self.delay = full, log, delay
        self.max_pages, self.max_requests = max_pages, max_requests
        self.findings, self.pages, self.count, self.tested = [], 1, 0, set()
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "VulnScanLab/1.0 (security assessment)"

    # ---------- helpers ----------
    def add(self, severity, category, owasp, url, issue, fix):
        item = dict(severity=severity, category=category, owasp=owasp, url=url, issue=issue, fix=fix)
        if item not in self.findings:
            self.findings.append(item)

    def send(self, method, url, **kw):
        if self.count >= self.max_requests:
            raise BudgetExceeded()
        self.count += 1
        time.sleep(self.delay)
        kw.setdefault("timeout", 8)
        kw.setdefault("allow_redirects", False)
        return self.session.request(method, url, **kw)

    def fetch(self, url):
        """GET following up to 5 redirects, but only within the target host. Returns the response chain."""
        chain = []
        for _ in range(5):
            r = self.send("GET", url)
            chain.append(r)
            if not (r.is_redirect and r.headers.get("Location")):
                break
            nxt = urljoin(url, r.headers["Location"])
            if urlparse(nxt).hostname != self.host:
                self.add("Info", "Redirect", A05, url, f"Redirects to external host {urlparse(nxt).hostname} (not followed)",
                         "Confirm this redirect is intended.")
                break
            url = nxt
        return chain

    # ---------- passive checks ----------
    def check_headers(self, resp):
        url = resp.url
        for header, (sev, owasp, fix) in HEADERS.items():
            if header == "Strict-Transport-Security" and self.scheme != "https":
                continue
            if header not in resp.headers:
                self.add(sev, "Security Headers", owasp, url, f"Missing {header}", fix)
        csp = resp.headers.get("Content-Security-Policy", "")
        if "unsafe-inline" in csp or "unsafe-eval" in csp:
            self.add("Low", "Security Headers", A05, url, "CSP allows unsafe-inline/unsafe-eval",
                     "Use nonces or hashes instead of unsafe-inline.")
        for header in LEAKY_HEADERS:
            if header in resp.headers:
                self.add("Info", "Information Disclosure", A05, url, f"{header} reveals '{resp.headers[header]}'",
                         "Remove or genericize version banners.")

    def check_cookies(self, chain):
        for r in chain:
            for raw in r.raw.headers.getlist("Set-Cookie"):
                name, flags = raw.split("=", 1)[0].strip(), raw.lower()
                if r.url.startswith("https") and "secure" not in flags:
                    self.add("Medium", "Cookies", A02, r.url, f"Cookie '{name}' missing Secure flag", "Add the Secure attribute.")
                if "httponly" not in flags:
                    self.add("Medium", "Cookies", A05, r.url, f"Cookie '{name}' missing HttpOnly flag", "Add the HttpOnly attribute.")
                if "samesite" not in flags:
                    self.add("Low", "Cookies", A01, r.url, f"Cookie '{name}' missing SameSite attribute", "Set SameSite=Lax or Strict.")

    def check_transport(self):
        if self.scheme != "https":
            self.add("Medium", "Transport", A02, self.start, "Site served over HTTP (no encryption)",
                     "Serve over HTTPS and redirect HTTP to HTTPS.")
            return
        try:
            with socket.create_connection((self.host, self.port), timeout=6) as s, \
                    ssl.create_default_context().wrap_socket(s, server_hostname=self.host) as tls:
                cert, version = tls.getpeercert(), tls.version()
            days = int((ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) / 86400)
            if days < 0:
                self.add("High", "TLS", A02, self.start, "TLS certificate has expired", "Renew the certificate.")
            elif days < 30:
                self.add("Medium", "TLS", A02, self.start, f"TLS certificate expires in {days} days", "Renew soon / enable auto-renewal.")
            if version in ("TLSv1", "TLSv1.1"):
                self.add("Medium", "TLS", A02, self.start, f"Outdated protocol negotiated: {version}", "Allow TLS 1.2+ only.")
        except ssl.SSLCertVerificationError as e:
            self.add("High", "TLS", A02, self.start, f"Certificate validation failed: {e.verify_message}", "Install a valid, trusted certificate.")
        except OSError as e:
            self.log(f"TLS check skipped: {e}")

    # ---------- active checks (verified targets only) ----------
    def check_cors(self):
        origin = "https://vscan-test.invalid"
        acao = self.send("GET", self.start, headers={"Origin": origin}).headers
        allow, creds = acao.get("Access-Control-Allow-Origin"), acao.get("Access-Control-Allow-Credentials", "").lower()
        if allow == origin and creds == "true":
            self.add("High", "CORS", A05, self.start, "Reflects arbitrary Origin with credentials allowed",
                     "Use a strict allowlist of origins.")
        elif allow in (origin, "*"):
            self.add("Low", "CORS", A05, self.start, f"Access-Control-Allow-Origin is '{allow}'", "Restrict to trusted origins.")

    def check_sensitive_paths(self):
        for path, is_real, sev, title in SENSITIVE_PATHS:
            r = self.send("GET", self.base + path)
            if r.status_code == 200 and is_real(r.text.strip()):
                self.add(sev, "Exposed Files", A05, self.base + path, title, "Block access to this path at the web server.")

    def probe(self, method, url, params, field, payload):
        data = {**params, field: payload}
        try:
            r = self.send(method, url, data=data) if method == "post" else self.send("GET", url, params=data)
            return r.text
        except requests.RequestException:
            return ""

    def test_inputs(self, method, url, params, fields):
        key = (method, url, tuple(sorted(fields)))
        if key in self.tested:
            return
        self.tested.add(key)
        for field in fields:
            if MARKER in self.probe(method, url, params, field, MARKER):
                self.add("Medium", "Input Validation", A03, url, f"Parameter '{field}' reflects input unencoded (possible reflected XSS)",
                         "HTML-encode output and add a CSP.")
            if any(e in self.probe(method, url, params, field, "'").lower() for e in SQL_ERRORS):
                self.add("High", "Input Validation", A03, url, f"Parameter '{field}' triggers a SQL error (possible SQL injection)",
                         "Use parameterized queries; disable verbose DB errors.")

    def check_form(self, page_url, form):
        action = urljoin(page_url, form["action"])
        types = [i["type"] for i in form["inputs"]]
        if "password" in types and action.startswith("http://"):
            self.add("High", "Forms", A02, page_url, f"Password form submits over HTTP ({action})", "Submit credentials over HTTPS only.")
        if form["method"] == "post" and not any(c in i["name"].lower() for i in form["inputs"] for c in CSRF_NAMES):
            self.add("Medium", "Forms", A01, page_url, f"POST form to {action} has no apparent CSRF token", "Add anti-CSRF tokens.")
        if urlparse(action).hostname != self.host:   # never probe other hosts
            return
        params = {i["name"]: i["value"] or "test" for i in form["inputs"]}
        self.test_inputs(form["method"], action, params, [i["name"] for i in form["inputs"] if i["type"] not in SKIP_TYPES])

    def process_page(self, resp):
        """Test forms and parameterised links on a page; return plain same-site links to crawl next."""
        if "html" not in resp.headers.get("Content-Type", ""):
            return []
        page = PageParser()
        page.feed(resp.text)
        for form in page.forms:
            self.check_form(resp.url, form)
        next_links = []
        for link in page.links:
            full = urljoin(resp.url, link).split("#")[0]
            parsed = urlparse(full)
            if parsed.hostname != self.host or parsed.scheme not in ("http", "https"):
                continue
            if parsed.query:
                params = dict(parse_qsl(parsed.query))
                self.test_inputs("get", urlunparse(parsed._replace(query="")), params, list(params))
            else:
                next_links.append(full)
        return next_links

    def crawl(self, first):
        seen, queue = {first.url}, self.process_page(first)
        while queue and len(seen) < self.max_pages:
            url = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            self.log(f"Crawling {url}")
            try:
                queue += self.process_page(self.fetch(url)[-1])
            except requests.RequestException:
                continue
        self.pages = len(seen)

    # ---------- entry point ----------
    def run(self):
        self.log(f"Mode: {'full (verified target)' if self.full else 'passive only (target not verified)'}")
        chain = self.fetch(self.start)
        self.check_headers(chain[-1])
        self.check_cookies(chain)
        self.log("Checking transport / TLS")
        self.check_transport()
        if self.full:
            try:
                self.log("Checking CORS and sensitive paths")
                self.check_cors()
                self.check_sensitive_paths()
                self.log("Crawling and testing inputs")
                self.crawl(chain[-1])
            except BudgetExceeded:
                self.add("Info", "Scan", A05, self.start, "Request budget reached; scan incomplete", "Raise max_requests if needed.")
        self.log(f"Done: {len(self.findings)} findings, {self.count} requests")
        return self.findings, self.pages