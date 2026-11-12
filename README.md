# web-vuln-scanner

Safe, non-destructive OWASP Top 10-flavoured web vulnerability scanner.
Python CLI (asyncio + aiohttp). Give it a target URL and it runs eight
checks, then writes a JSON report and a self-contained HTML report.

> **Scan only targets you are authorised to test.** Unauthorised scanning
> may be illegal and can get your access revoked. This tool only ever sends
> safe, read-only GET probes — nothing is written, deleted, dumped, or
> executed on the target.

## Features

- **(a) Reflected XSS** — benign marker payload (`<b>wvsxss…</b>`); flags it
  only when reflected verbatim/unencoded. Detection only, nothing executes.
- **(b) Error-based SQLi** — safe quote/tautology probes; flags only when a
  database error message appears in the response. No data is extracted.
- **(c) Missing security headers** — Strict-Transport-Security,
  Content-Security-Policy, X-Content-Type-Options, X-Frame-Options,
  Referrer-Policy, Permissions-Policy.
- **(d) Cookie flags** — checks every `Set-Cookie` for Secure, HttpOnly
  and SameSite.
- **(e) Open redirect** — probes common redirect parameters with an
  external URL and checks for a real 3xx to that host.
- **(f) Directory listing** — probes `/files/`, `/static/`, `/uploads/`,
  `/images/` for an index listing.
- **(g) Server/software version disclosure** — version numbers in `Server`,
  `X-Powered-By`, `X-AspNet-Version`, `X-Generator`.
- **(h) CORS misconfiguration** — sends an evil `Origin` and flags it only
  when the origin is reflected *with* credentials (or `*` with credentials).
- **Same-origin crawler** — follows links from the homepage (depth 1,
  max 20 pages by default) so the passive checks (c, d, g, h) also run on
  linked pages.
- **Reports** — `report.json` (machine-readable) and `report.html`
  (self-contained, human-readable) with severity, evidence, detail and
  remediation for every check.
- **Test fixture** — `fixture_app.py`, a tiny intentionally-vulnerable
  local app with `--mode vulnerable` / `--mode patched`, used by the tests.
  Local use only; never expose it to a network.

## Install

Requires Python 3.10+.

```bash
git clone https://github.com/tahiryounas604/web-vuln-scanner.git
cd web-vuln-scanner
python3 -m pip install --break-system-packages -r requirements.txt
# or: python3 -m pip install -e .
```

## Usage

```bash
# Scan a target you are authorised to test
python3 -m web_vuln_scanner --url https://example.com --output-dir reports

# Options
python3 -m web_vuln_scanner --url http://localhost:8901 \
    --output-dir reports --timeout 10 --max-pages 20
```

Output: `reports/report.json` and `reports/report.html`, plus a terminal
summary listing every vulnerable finding.

Try it against the local fixture (safe — it is your own machine):

```bash
# Terminal 1: vulnerable app
python3 fixture_app.py --mode vulnerable --port 8901
# Terminal 2: scan it
python3 -m web_vuln_scanner --url http://127.0.0.1:8901 --output-dir reports

# Patched variant (expect zero High/Medium findings):
python3 fixture_app.py --mode patched --port 8902
python3 -m web_vuln_scanner --url http://127.0.0.1:8902 --output-dir reports
```

## Tests

```bash
python3 -m pytest tests/ -v
```

Every check is tested against the fixture in both vulnerable and patched
modes, plus report generation and a CLI end-to-end run.

## Honest limits

- **Detection only, surface level.** This is a scanner, not a full
  penetration test. It finds common misconfigurations and reflected
  issues; it does not prove exploitability and a clean scan does **not**
  mean the target is secure.
- **No stored/DOM XSS, no blind/time-based SQLi, no auth testing.**
  Authenticated areas are not scanned (no login/session support in v0.1).
- **Fixed probe paths.** XSS/SQLi probe `/search` and `/product`;
  redirect probes `/redirect`, `/login`; directory listing probes a
  short list of common paths. Custom parameter names and paths are not
  discovered in v0.1.
- **No JavaScript rendering.** Single-page apps whose content is rendered
  client-side are only checked at the raw-HTML level.
- **Crawler is shallow.** Depth 1, same-origin links only, max 20 pages.
- **No Go component in v0.1.** Go was not available in the build
  environment, so the concurrent crawler/prober is pure Python (asyncio).
  A Go prober may be added later if Go is available.
- **False positives/negatives possible.** Error-pattern SQLi detection
  depends on the app leaking error text; apps that fail silently will not
  be flagged. Verify every finding manually before reporting it.
- **Rate limits / WAFs.** Aggressive targets may block or rate-limit the
  probes; the scanner does not retry or evade.

## License

GPL-3.0 — see `LICENSE`.

## Author

Built by Tahir Younas — Penetration Tester & Application Security Engineer — https://www.linkedin.com/in/tahiryounas604 | Tytechlabs
