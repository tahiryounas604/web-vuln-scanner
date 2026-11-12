"""CLI entry point: python3 -m web_vuln_scanner --url <target>"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from .report import write_html_report, write_json_report
from .scanner import DEFAULT_MAX_PAGES, DEFAULT_TIMEOUT, scan_target


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="web-vuln-scanner",
        description="Safe, non-destructive OWASP Top 10-flavoured web "
                    "vulnerability scanner. Scan ONLY targets you are "
                    "authorised to test.")
    p.add_argument("--url", required=True,
                   help="Target base URL, e.g. http://localhost:8000")
    p.add_argument("--output-dir", default="reports",
                   help="Directory for report.json / report.html "
                        "(default: reports)")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                   help=f"Per-request timeout in seconds (default: {DEFAULT_TIMEOUT})")
    p.add_argument("--max-pages", type=int, default=DEFAULT_MAX_PAGES,
                   help=f"Max pages the crawler follows (default: {DEFAULT_MAX_PAGES})")
    p.add_argument("--version", action="version", version="web-vuln-scanner 0.1.0")
    return p


async def _run(args) -> int:
    if not args.url.startswith(("http://", "https://")):
        print("error: --url must start with http:// or https://", file=sys.stderr)
        return 2
    print(f"[*] Scanning {args.url} (safe probes only) ...")
    result = await scan_target(args.url, timeout=args.timeout,
                               max_pages=args.max_pages)
    out = Path(args.output_dir)
    json_path = write_json_report(result, out / "report.json")
    html_path = write_html_report(result, out / "report.html")
    s = result.to_dict()["summary"]
    print(f"[*] Pages crawled: {len(result.pages_crawled)}")
    print(f"[*] Findings: {s['total']} total, {s['vulnerable']} vulnerable "
          f"({s['high']} High, {s['medium']} Medium, {s['low']} Low, {s['info']} Info)")
    for f in result.findings:
        if f.vulnerable:
            print(f"  [!] {f.severity}: {f.name} — {f.url}")
    print(f"[*] JSON report: {json_path}")
    print(f"[*] HTML report: {html_path}")
    return 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
