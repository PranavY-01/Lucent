"""Developer tool: refresh src/lucent_ioc/data/tlds.txt from IANA.

This script uses the network. It is never imported by the lucent_ioc package; Lucent itself
makes no network calls. The file is written unmodified, exactly as IANA serves it.

Usage:
    python scripts/update_tlds.py
"""

from __future__ import annotations

import sys
import urllib.request
from pathlib import Path

IANA_URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
TARGET = Path(__file__).resolve().parent.parent / "src" / "lucent_ioc" / "data" / "tlds.txt"


def main() -> int:
    with urllib.request.urlopen(IANA_URL, timeout=30) as response:
        data = response.read()
    first_line = data.split(b"\n", 1)[0]
    if not first_line.startswith(b"# Version"):
        print(f"Unexpected content from {IANA_URL}; first line: {first_line[:80]!r}")
        return 1
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_bytes(data)
    entries = sum(1 for line in data.splitlines() if line and not line.startswith(b"#"))
    print(f"Wrote {TARGET} ({entries} TLDs; {first_line.decode('ascii', 'replace')})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
