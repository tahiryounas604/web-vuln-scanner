"""Tests for web-vuln-scanner: every check against the fixture in both
vulnerable and patched modes, plus JSON/HTML reports and the CLI."""

import asyncio
import json
import subprocess
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fixture_app import create_server  # noqa: E402
from web_vuln_scanner.report import write_html_report, write_json_report  # noqa: E402
from web_vuln_scanner.scanner import scan_target  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures: one vulnerable server, one patched server, ephemeral ports
# ---------------------------------------------------------------------------

def _start(mode):
    server = create_server(mode, "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    return server, f"http://127.0.0.1:{port}"


@pytest.fixture(scope="module")
def vuln_url():
    server, url = _start("vulnerable")
    yield url
    server.shutdown()
    server.server_close()


@pytest.fixture(scope="module")
def patched_url():
    server, url = _start("patched")
    yield url
    server.shutdown()
    server.server_close()


def run_scan(url):
    return asyncio.run(scan_target(url))


def vuln_findings(result, finding_id, url=None):
    return [f for f in result.findings
            if f.id == finding_id and f.vulnerable
            and (url is None or f.url == url)]


def all_with_id(result, finding_id):
    return [f for f in result.findings if f.id == finding_id]


# ---------------------------------------------------------------------------
# (a) Reflected XSS
# ---------------------------------------------------------------------------

def test_xss_detected_on_vulnerable(vuln_url):
    result = run_scan(vuln_url)
    hits = vuln_findings(result, "WVS-XSS-01")
    assert hits, "XSS should be detected on the vulnerable fixture"
    assert "wvsxss" in hits[0].evidence
    assert hits[0].severity == "Medium"


def test_xss_not_detected_on_patched(patched_url):
    result = run_scan(patched_url)
    assert vuln_findings(result, "WVS-XSS-01") == []


# ---------------------------------------------------------------------------
# (b) Error-based SQLi
# ---------------------------------------------------------------------------

def test_sqli_detected_on_vulnerable(vuln_url):
    result = run_scan(vuln_url)
    hits = vuln_findings(result, "WVS-SQLI-01")
    assert hits, "SQLi error should be detected on the vulnerable fixture"
    assert hits[0].severity == "High"
    assert "sql syntax" in hits[0].evidence.lower()


def test_sqli_not_detected_on_patched(patched_url):
    result = run_scan(patched_url)
    assert vuln_findings(result, "WVS-SQLI-01") == []


# ---------------------------------------------------------------------------
# (c) Missing security headers
# ---------------------------------------------------------------------------

def test_missing_headers_on_vulnerable(vuln_url):
    result = run_scan(vuln_url)
    home = vuln_url + "/"
    for header in ("Strict-Transport-Security", "Content-Security-Policy",
                   "X-Content-Type-Options", "X-Frame-Options",
                   "Referrer-Policy", "Permissions-Policy"):
        fid = "WVS-HDR-" + header.upper().replace("-", "")
        hits = vuln_findings(result, fid, url=home)
        assert hits, f"{header} should be reported missing on vulnerable fixture"


def test_headers_present_on_patched(patched_url):
    result = run_scan(patched_url)
    home = patched_url + "/"
    for header in ("Strict-Transport-Security", "Content-Security-Policy",
                   "X-Content-Type-Options", "X-Frame-Options",
                   "Referrer-Policy", "Permissions-Policy"):
        fid = "WVS-HDR-" + header.upper().replace("-", "")
        assert vuln_findings(result, fid, url=home) == [], \
            f"{header} should NOT be reported missing on patched fixture"


# ---------------------------------------------------------------------------
# (d) Cookie flags
# ---------------------------------------------------------------------------

def test_cookie_flags_missing_on_vulnerable(vuln_url):
    result = run_scan(vuln_url)
    hits = vuln_findings(result, "WVS-Cookie-01", url=vuln_url + "/")
    assert hits, "Cookie flag finding expected on vulnerable fixture"
    assert "secure" in hits[0].evidence.lower()
    assert "httponly" in hits[0].evidence.lower()
    assert "samesite" in hits[0].evidence.lower()


def test_cookie_flags_present_on_patched(patched_url):
    result = run_scan(patched_url)
    assert vuln_findings(result, "WVS-Cookie-01", url=patched_url + "/") == []


# ---------------------------------------------------------------------------
# (e) Open redirect
# ---------------------------------------------------------------------------

def test_open_redirect_on_vulnerable(vuln_url):
    result = run_scan(vuln_url)
    hits = vuln_findings(result, "WVS-REDIR-01")
    assert hits, "Open redirect should be detected on vulnerable fixture"
    assert "evil.example.com" in hits[0].evidence


def test_open_redirect_not_on_patched(patched_url):
    result = run_scan(patched_url)
    assert vuln_findings(result, "WVS-REDIR-01") == []


# ---------------------------------------------------------------------------
# (f) Directory listing
# ---------------------------------------------------------------------------

def test_dir_listing_on_vulnerable(vuln_url):
    result = run_scan(vuln_url)
    hits = vuln_findings(result, "WVS-DIR-01")
    assert hits, "Directory listing should be detected on vulnerable fixture"
    assert hits[0].url.endswith("/files/")


def test_dir_listing_not_on_patched(patched_url):
    result = run_scan(patched_url)
    assert vuln_findings(result, "WVS-DIR-01") == []


# ---------------------------------------------------------------------------
# (g) Version disclosure
# ---------------------------------------------------------------------------

def test_version_disclosure_on_vulnerable(vuln_url):
    result = run_scan(vuln_url)
    hits = vuln_findings(result, "WVS-VER-01", url=vuln_url + "/")
    assert hits, "Version disclosure should be detected on vulnerable fixture"
    assert "1.2.3" in hits[0].evidence


def test_version_disclosure_not_on_patched(patched_url):
    result = run_scan(patched_url)
    assert vuln_findings(result, "WVS-VER-01", url=patched_url + "/") == []


# ---------------------------------------------------------------------------
# (h) CORS misconfiguration
# ---------------------------------------------------------------------------

def test_cors_misconfig_on_vulnerable(vuln_url):
    result = run_scan(vuln_url)
    hits = vuln_findings(result, "WVS-CORS-01", url=vuln_url + "/")
    assert hits, "CORS misconfig should be detected on vulnerable fixture"
    assert "evil.example.com" in hits[0].evidence


def test_cors_not_on_patched(patched_url):
    result = run_scan(patched_url)
    assert vuln_findings(result, "WVS-CORS-01", url=patched_url + "/") == []


# ---------------------------------------------------------------------------
# Crawler + full scans + reports
# ---------------------------------------------------------------------------

def test_crawler_finds_linked_pages(vuln_url):
    result = run_scan(vuln_url)
    crawled = result.pages_crawled
    assert vuln_url + "/" in crawled
    assert any(p.endswith("/search?q=hello") for p in crawled)
    assert any(p.endswith("/product?id=1") for p in crawled)
    assert any(p.endswith("/files/") for p in crawled)


def test_full_scan_vulnerable_reports(tmp_path, vuln_url):
    result = run_scan(vuln_url)
    assert result.to_dict()["summary"]["vulnerable"] >= 8
    json_path = write_json_report(result, tmp_path / "report.json")
    html_path = write_html_report(result, tmp_path / "report.html")
    assert json_path.exists() and html_path.exists()
    data = json.loads(json_path.read_text())
    assert data["target"] == vuln_url
    assert data["summary"]["high"] >= 1  # SQLi
    assert data["summary"]["medium"] >= 2  # XSS + open redirect
    assert all("id" in f and "remediation" in f for f in data["findings"])
    html = html_path.read_text()
    assert "VULNERABLE" in html
    assert vuln_url in html
    assert "Reflected Cross-Site Scripting" in html


def test_full_scan_patched_no_high_or_medium(patched_url):
    result = run_scan(patched_url)
    summary = result.to_dict()["summary"]
    assert summary["high"] == 0
    assert summary["medium"] == 0
    assert summary["vulnerable"] == 0


def test_unreachable_target_reports_honestly():
    # Nothing listening on port 9 (discard): no check may claim "OK".
    result = asyncio.run(scan_target("http://127.0.0.1:9", timeout=3))
    assert result.pages_crawled == []
    ids = [f.id for f in result.findings]
    assert ids == ["WVS-UNREACHABLE"]
    assert "did not respond" in result.findings[0].detail


def test_cli_end_to_end(tmp_path, vuln_url):
    out = tmp_path / "reports"
    proc = subprocess.run(
        [sys.executable, "-m", "web_vuln_scanner", "--url", vuln_url,
         "--output-dir", str(out)],
        capture_output=True, text=True, timeout=120,
        cwd=str(Path(__file__).resolve().parent.parent),
    )
    assert proc.returncode == 0, proc.stderr
    assert "Scanning" in proc.stdout
    assert (out / "report.json").exists()
    assert (out / "report.html").exists()
    data = json.loads((out / "report.json").read_text())
    assert data["summary"]["vulnerable"] >= 8
