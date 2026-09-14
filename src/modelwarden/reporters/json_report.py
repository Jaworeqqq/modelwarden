"""Machine-readable report in modelwarden's own JSON shape."""
from __future__ import annotations

import json
from collections import Counter
from typing import TextIO

from modelwarden import __version__
from modelwarden.core.engine import ScanResult
from modelwarden.core.findings import Rule


def render(result: ScanResult, rules: list[Rule], out: TextIO) -> None:
    counts = Counter(str(f.severity) for f in result.findings)
    document = {
        "tool": {"name": "modelwarden", "version": __version__},
        "summary": {"scanned": result.scanned, "skipped": result.skipped, "by_severity": counts},
        "findings": [f.to_dict() for f in result.findings],
    }
    json.dump(document, out, indent=2)
    out.write("\n")
