"""Async scanner core: eight safe, non-destructive checks.

Checks
------
(a) reflected XSS      - benign marker payload, detection only (no execution)
(b) error-based SQLi   - safe quote payloads, SQL error-pattern detection
(c) missing security headers
(d) cookie flags       - Secure / HttpOnly / SameSite
(e) open redirect
(f) directory listing
(g) server/software version disclosure
(h) CORS misconfiguration

Plus a small same-origin asyncio crawler (depth 1, max pages) so the passive
checks (c, d, g, h) also run against pages linked from the homepage.
"""

from __future__ import annotations

import asyncio
import html as html_lib
import re
import secrets
import time
from dataclasses import asdict, dataclass, field
from urllib.parse import urljoin, urlparse

import aiohttp

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

SEVERITIES = ("Info", "Low", "Medium", "High")


@dataclass
class Finding:
    id: str
    name: str
    severity: str  # Info / Low / Medium / High
    url: str
    vulnerable: bool
    evidence: str
    detail: str
    remediation: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    target: str
    scanned_at: str
    duration_seconds: float
    pages_crawled: list = field(default_factory=list)
    findings: list = field(default_factory=list)  # list[Finding]

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "scanned_at": self.scanned_at,
            "duration_seconds": round(self.duration_seconds, 2),
            "pages_crawled": self.pages_crawled,
            "summary": {
                "total": len(self.findings),
                "vulnerable": sum(1 for f in self.findings if f.vulnerable),
                "high": sum(1 for f in self.findings if f.vulnerable and f.severity == "High"),
                "medium": sum(1 for f in self.findings if f.vulnerable and f.severity == "Medium"),
                "low": sum(1 for f in self.findings if f.vulnerable and f.severity == "Low"),
                "info": sum(1 for f in self.findings if f.vulnerable and f.severity == "Info"),
            },
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Detection constants
# ---------------------------------------------------------------------------

SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning:\s*mysql",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"ora-\d{5}",
    r"syntax error.*\bquery\b",
    r"sqlite.*error",
    r"postgresql.*error",
    r"pg_query\(\)",
    r"supplied argument is not a valid mysql",
    r"mysql_fetch",
    r"microsoft ole db provider for sql server",
    r"odbc.*sql",
    r"sqlstate\[\d+\]",
    r"valid mysql result",
    r"unknown column",
    r"mysql server version for the right syntax",
]
SQL_ERROR_RE = re.compile("|".join(f"(?:{p})" for p in SQL_ERROR_PATTERNS), re.I)

SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        "Missing Strict-Transport-Security (HSTS) header; browsers will not "
        "force HTTPS for this site."
    ),
    "Content-Security-Policy": (
        "Missing Content-Security-Policy header; the site has no policy "
        "limiting where scripts and other resources may load from."
    ),
    "X-Content-Type-Options": (
        "Missing X-Content-Type-Options: nosniff; browsers may MIME-sniff "
        "responses and treat plain text as executable content."
    ),
    "X-Frame-Options": (
        "Missing X-Frame-Options header; the site may be framed by other "
        "pages (clickjacking risk)."
    ),
    "Referrer-Policy": (
        "Missing Referrer-Policy header; full URLs may leak to third parties "
        "in the Referer header."
    ),
    "Permissions-Policy": (
        "Missing Permissions-Policy header; powerful browser features "
        "(camera, microphone, geolocation) are not explicitly disabled."
    ),
}

VERSION_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator")
VERSION_RE = re.compile(r"\d+\.\d+(\.\d+)?")

DIR_LISTING_PATTERNS = [
    r"<title>\s*index of",
    r"directory listing for",
    r"index of /",
]
DIR_LISTING_RE = re.compile("|".join(DIR_LISTING_PATTERNS), re.I)

HREF_RE = re.compile(r"""href\s*=\s*["']([^"'#]+)["']""", re.I)

# Candidate paths probed for the active checks. Kept to common, generic
# locations so the scanner works on any site without prior knowledge.
XSS_PATHS = ["/search", "/"]
SQLI_PATHS = ["/search", "/product"]
REDIRECT_CANDIDATES = [
    ("/redirect", "url"),
    ("/login", "next"),
    ("/login", "returnUrl"),
    ("", "redirect"),
]
DIR_LISTING_PATHS = ["/files/", "/static/", "/uploads/", "/images/"]

EVIL_ORIGIN = "https://evil.example.com"
EVIL_URL = "https://evil.example.com/"

DEFAULT_TIMEOUT = 10
DEFAULT_MAX_PAGES = 20


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class Scanner:
    def __init__(self, base_url: str, timeout: int = DEFAULT_TIMEOUT,
                 max_pages: int = DEFAULT_MAX_PAGES, concurrency: int = 8):
        self.base_url = base_url.rstrip("/")
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_pages = max_pages
        self.semaphore = asyncio.Semaphore(concurrency)
        self.findings: list[Finding] = []
        self.pages_crawled: list[str] = []

    # -- low-level fetch ----------------------------------------------------
    async def fetch(self, session: aiohttp.ClientSession, url: str,
                    headers: dict | None = None,
                    allow_redirects: bool = True):
        """GET with the semaphore; returns (status, headers, text) or None."""
        async with self.semaphore:
            try:
                async with session.get(url, headers=headers or {},
                                       allow_redirects=allow_redirects,
                                       timeout=self.timeout) as resp:
                    text = await resp.text(errors="replace")
                    return resp.status, resp.headers, text
            except (aiohttp.ClientError, asyncio.TimeoutError):
                return None

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    # -- (a) reflected XSS --------------------------------------------------
    async def check_xss(self, session):
        marker = "wvsxss" + secrets.token_hex(4)
        payload = f"<b>{marker}</b>"
        for path in XSS_PATHS:
            url = f"{self.base_url}{path}?q={payload}"
            result = await self.fetch(session, url)
            if result is None:
                continue
            _, _, body = result
            # Vulnerable only if the raw tag is reflected unencoded.
            reflected = payload in body
            self.add(Finding(
                id="WVS-XSS-01",
                name="Reflected Cross-Site Scripting (XSS)",
                severity="Medium",
                url=url,
                vulnerable=reflected,
                evidence=f"Payload reflected verbatim: {payload}" if reflected
                         else "Payload not reflected verbatim (encoded or absent).",
                detail=("User input in the 'q' parameter is reflected in the "
                        "response without HTML-encoding, so an attacker can "
                        "inject markup/script via a crafted link."
                        if reflected else
                        "The 'q' parameter value is not reflected unencoded."),
                remediation="HTML-encode all user input on output (context-aware "
                            "encoding) and deploy a Content-Security-Policy.",
            ))
            if reflected:
                return  # one confirmed instance is enough

    # -- (b) error-based SQLi ----------------------------------------------
    async def check_sqli(self, session):
        # Safe payloads: a lone quote and a trivial tautology. We only look
        # for database error text in the response; no data is extracted.
        payloads = ["'", "1' OR '1'='1"]
        params = [("q", "/search"), ("id", "/product")]
        probed = False
        for param, path in params:
            for payload in payloads:
                url = f"{self.base_url}{path}?{param}={payload}"
                result = await self.fetch(session, url)
                if result is None:
                    continue
                probed = True
                _, _, body = result
                match = SQL_ERROR_RE.search(body)
                if match:
                    self.add(Finding(
                        id="WVS-SQLI-01",
                        name="Error-based SQL Injection",
                        severity="High",
                        url=url,
                        vulnerable=True,
                        evidence=f"Database error text in response: '{match.group(0)}'",
                        detail=("The parameter appears to reach a SQL query "
                                "unsanitised: a quote payload triggers a "
                                "database error message, indicating injection."),
                        remediation="Use parameterised queries / prepared "
                                    "statements everywhere; never concatenate "
                                    "user input into SQL; suppress database "
                                    "error details in responses.",
                    ))
                    return
        if probed:
            self.add(Finding(
                id="WVS-SQLI-01",
                name="Error-based SQL Injection",
                severity="High",
                url=f"{self.base_url}/search?q='",
                vulnerable=False,
                evidence="No SQL error text observed for quote/tautology probes.",
                detail="Safe quote payloads did not produce database error text.",
                remediation="Keep using parameterised queries; suppress database "
                            "error details in responses.",
            ))

    # -- (c) missing security headers ---------------------------------------
    async def check_headers(self, session, url: str):
        result = await self.fetch(session, url)
        if result is None:
            return
        _, headers, _ = result
        present = {k.lower() for k in headers.keys()}
        for header, detail in SECURITY_HEADERS.items():
            missing = header.lower() not in present
            self.add(Finding(
                id=f"WVS-HDR-{header.upper().replace('-', '')}",
                name=f"Missing security header: {header}",
                severity="Low",
                url=url,
                vulnerable=missing,
                evidence=f"Header '{header}' absent from response." if missing
                         else f"Header '{header}' present: {headers.get(header)}",
                detail=detail if missing else f"{header} is set.",
                remediation=f"Set the {header} header on all responses.",
            ))

    # -- (d) cookie flags ----------------------------------------------------
    async def check_cookies(self, session, url: str):
        result = await self.fetch(session, url)
        if result is None:
            return
        _, headers, _ = result
        raw_cookies = headers.getall("Set-Cookie", [])
        if not raw_cookies:
            self.add(Finding(
                id="WVS-Cookie-01",
                name="Cookie flags",
                severity="Info",
                url=url,
                vulnerable=False,
                evidence="No Set-Cookie header observed on this response.",
                detail="No cookies were set, so there are no flags to check.",
                remediation="When setting cookies, always use Secure, "
                            "HttpOnly and SameSite attributes.",
            ))
            return
        for raw in raw_cookies:
            name = raw.split(";", 1)[0].strip()
            lowered = raw.lower()
            missing = [flag for flag in ("secure", "httponly", "samesite")
                       if flag not in lowered]
            self.add(Finding(
                id="WVS-Cookie-01",
                name=f"Cookie missing flags: {name}",
                severity="Low",
                url=url,
                vulnerable=bool(missing),
                evidence=f"Set-Cookie: {raw}" + (
                    f" — missing: {', '.join(missing)}" if missing else
                    " — Secure, HttpOnly and SameSite all present."),
                detail=("Cookie lacks recommended flags: " + ", ".join(missing)
                        if missing else "Cookie carries all recommended flags."),
                remediation="Set cookies with Secure, HttpOnly and "
                            "SameSite=Lax (or Strict) attributes.",
            ))

    # -- (e) open redirect ---------------------------------------------------
    async def check_open_redirect(self, session):
        probed = False
        for path, param in REDIRECT_CANDIDATES:
            url = f"{self.base_url}{path}?{param}={EVIL_URL}"
            result = await self.fetch(session, url, allow_redirects=False)
            if result is None:
                continue
            probed = True
            status, headers, _ = result
            location = headers.get("Location", "")
            redirected = status in (301, 302, 303, 307, 308) and \
                urlparse(location).netloc == "evil.example.com"
            if redirected:
                self.add(Finding(
                    id="WVS-REDIR-01",
                    name="Open Redirect",
                    severity="Medium",
                    url=url,
                    vulnerable=True,
                    evidence=f"HTTP {status} with Location: {location}",
                    detail="An attacker-controlled URL parameter is used as "
                           "a redirect target without validation, enabling "
                           "phishing via a trusted-looking link.",
                    remediation="Allow-list redirect destinations (relative "
                                "paths or approved hosts only); never redirect "
                                "to raw user input.",
                ))
                return
        if probed:
            self.add(Finding(
                id="WVS-REDIR-01",
                name="Open Redirect",
                severity="Medium",
                url=f"{self.base_url}/redirect?url={EVIL_URL}",
                vulnerable=False,
                evidence="No redirect candidate honoured the external URL.",
                detail="Redirect parameters did not redirect to evil.example.com.",
                remediation="Keep allow-listing redirect destinations.",
            ))

    # -- (f) directory listing ----------------------------------------------
    async def check_dir_listing(self, session):
        probed = False
        for path in DIR_LISTING_PATHS:
            url = f"{self.base_url}{path}"
            result = await self.fetch(session, url)
            if result is None:
                continue
            probed = True
            status, _, body = result
            if status == 200 and DIR_LISTING_RE.search(body):
                self.add(Finding(
                    id="WVS-DIR-01",
                    name="Directory Listing Enabled",
                    severity="Low",
                    url=url,
                    vulnerable=True,
                    evidence="Response contains a directory index "
                             f"({DIR_LISTING_RE.search(body).group(0)!r}).",
                    detail="The web server lists directory contents, "
                           "exposing file names and structure to attackers.",
                    remediation="Disable directory listing (e.g. Options "
                                "-Indexes) and serve an index file or 403.",
                ))
                return
        if probed:
            self.add(Finding(
                id="WVS-DIR-01",
                name="Directory Listing Enabled",
                severity="Low",
                url=f"{self.base_url}/files/",
                vulnerable=False,
                evidence="No directory index observed on probed paths.",
                detail="Probed directory paths did not return a listing.",
                remediation="Keep directory listing disabled.",
            ))

    # -- (g) version disclosure ----------------------------------------------
    async def check_version_disclosure(self, session, url: str):
        result = await self.fetch(session, url)
        if result is None:
            return
        _, headers, _ = result
        disclosed = []
        for header in VERSION_HEADERS:
            value = headers.get(header)
            if value and VERSION_RE.search(value):
                disclosed.append(f"{header}: {value}")
        self.add(Finding(
            id="WVS-VER-01",
            name="Server / software version disclosure",
            severity="Low",
            url=url,
            vulnerable=bool(disclosed),
            evidence="; ".join(disclosed) if disclosed else
                     "No version number found in Server/X-Powered-By headers.",
            detail=("Version numbers help attackers pick known exploits for "
                    "that exact software build." if disclosed else
                    "Response headers do not reveal software versions."),
            remediation="Strip version numbers from Server and X-Powered-By "
                        "headers (and disable them where possible).",
        ))

    # -- (h) CORS misconfiguration -------------------------------------------
    async def check_cors(self, session, url: str):
        result = await self.fetch(
            session, url, headers={"Origin": EVIL_ORIGIN})
        if result is None:
            return
        _, headers, _ = result
        acao = headers.get("Access-Control-Allow-Origin", "")
        creds = headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
        reflected = acao == EVIL_ORIGIN
        wildcard_creds = acao == "*" and creds
        vulnerable = (reflected and creds) or wildcard_creds
        severity = "Medium" if vulnerable else "Low"
        self.add(Finding(
            id="WVS-CORS-01",
            name="CORS misconfiguration",
            severity=severity,
            url=url,
            vulnerable=vulnerable,
            evidence=(
                f"Access-Control-Allow-Origin: {acao!r}, "
                f"Access-Control-Allow-Credentials: {creds}"
            ),
            detail=(
                "The server reflects an arbitrary Origin and allows "
                "credentials, so a malicious site can read authenticated "
                "cross-origin responses."
                if vulnerable else
                "The server does not reflect arbitrary origins with "
                "credentials."
            ),
            remediation="Never reflect arbitrary Origin values; allow-list "
                        "trusted origins only and avoid "
                        "Access-Control-Allow-Credentials with '*'.",
        ))

    # -- crawler --------------------------------------------------------------
    async def crawl(self, session) -> list[str]:
        """Same-origin links from the homepage, depth 1, capped."""
        result = await self.fetch(session, self.base_url + "/")
        if result is None:
            self.pages_crawled = []
            return []
        _, _, body = result
        base_host = urlparse(self.base_url).netloc
        found = [self.base_url + "/"]
        for href in HREF_RE.findall(body):
            absolute = urljoin(self.base_url + "/", href)
            parsed = urlparse(absolute)
            if parsed.netloc == base_host and parsed.scheme in ("http", "https"):
                clean = absolute.split("#", 1)[0]
                if clean not in found:
                    found.append(clean)
            if len(found) >= self.max_pages:
                break
        self.pages_crawled = found
        return found

    # -- orchestration --------------------------------------------------------
    async def run(self) -> ScanResult:
        started = time.monotonic()
        scanned_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        jar = aiohttp.DummyCookieJar()  # keep raw Set-Cookie headers visible
        async with aiohttp.ClientSession(cookie_jar=jar) as session:
            pages = await self.crawl(session)
            if not pages:
                # Homepage unreachable: no check ran, so report that
                # honestly instead of emitting "OK" findings.
                self.add(Finding(
                    id="WVS-UNREACHABLE",
                    name="Target unreachable",
                    severity="Info",
                    url=self.base_url + "/",
                    vulnerable=False,
                    evidence="Could not fetch the target homepage "
                             "(connection error or timeout).",
                    detail="No checks could run because the target did not "
                           "respond. This is not a clean bill of health.",
                    remediation="Check the URL, network access, and whether "
                                "the target is up; then re-run the scan.",
                ))
                return ScanResult(
                    target=self.base_url,
                    scanned_at=scanned_at,
                    duration_seconds=time.monotonic() - started,
                    pages_crawled=[],
                    findings=self.findings,
                )
            # Active checks (state-changing probes are all safe GETs).
            await asyncio.gather(
                self.check_xss(session),
                self.check_sqli(session),
                self.check_open_redirect(session),
                self.check_dir_listing(session),
            )
            # Passive checks on every crawled page.
            for url in pages:
                await asyncio.gather(
                    self.check_headers(session, url),
                    self.check_cookies(session, url),
                    self.check_version_disclosure(session, url),
                    self.check_cors(session, url),
                )
        return ScanResult(
            target=self.base_url,
            scanned_at=scanned_at,
            duration_seconds=time.monotonic() - started,
            pages_crawled=self.pages_crawled,
            findings=self.findings,
        )


async def scan_target(base_url: str, timeout: int = DEFAULT_TIMEOUT,
                      max_pages: int = DEFAULT_MAX_PAGES) -> ScanResult:
    """Scan one target URL and return the full result."""
    return await Scanner(base_url, timeout=timeout, max_pages=max_pages).run()
