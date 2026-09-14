"""Human-readable report, one finding per line, most severe first."""
from __future__ import annotations

import os
from collections import Counter
from typing import TextIO

from modelwarden.core.engine import ScanResult
from modelwarden.core.findings import Rule, Severity

_COLORS = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[2m",
}
_RESET = "\033[0m"


def render(result: ScanResult, rules: list[Rule], out: TextIO) -> None:
    isatty = getattr(out, "isatty", lambda: False)
    color = isatty() and "NO_COLOR" not in os.environ

    def order(f):
        return (-f.severity, f.location.path, f.location.member or "", f.location.offset or 0)

    ordered = sorted(result.findings, key=order)
    for finding in ordered:
        label = f"{finding.severity.name:<8}"
        if color:
            label = f"{_COLORS[finding.severity]}{label}{_RESET}"
        out.write(f"{label} {finding.rule.id:<10} {finding.location}  {finding.message}\n")

    counts = Counter(f.severity for f in result.findings)
    parts = [f"{counts[s]} {s}" for s in sorted(Severity, reverse=True) if counts[s]]
    summary = ", ".join(parts) if parts else "no findings"
    if ordered:
        out.write("\n")
    out.write(f"{result.scanned} file(s) scanned, {result.skipped} skipped: {summary}\n")
