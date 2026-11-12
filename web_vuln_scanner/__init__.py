"""web-vuln-scanner: safe, non-destructive OWASP Top 10-flavoured web checks.

Clean-room implementation. Probes are detection-only: benign marker payloads,
safe error-pattern probes, header/cookie inspection. Nothing is written,
deleted, dumped, or executed on the target. Scan only targets you are
authorised to test.
"""

from .scanner import Finding, ScanResult, scan_target
from .report import write_json_report, write_html_report

__version__ = "0.1.0"
__all__ = ["Finding", "ScanResult", "scan_target", "write_json_report", "write_html_report"]
