"""Output formats. Each reporter is `render(result, rules, out)`."""
from __future__ import annotations

from collections.abc import Callable
from typing import TextIO

from modelwarden.core.engine import ScanResult
from modelwarden.core.findings import Rule
from modelwarden.reporters import console, json_report, sarif

Reporter = Callable[[ScanResult, list[Rule], TextIO], None]

REPORTERS: dict[str, Reporter] = {
    "console": console.render,
    "json": json_report.render,
    "sarif": sarif.render,
}
