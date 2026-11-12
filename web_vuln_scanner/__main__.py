"""Allow `python3 -m web_vuln_scanner`."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
