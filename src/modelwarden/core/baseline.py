"""Findings somebody has already seen, so a later scan reports what changed.

The first scan of an existing repository is a wall of findings, and a wall is what
makes a team switch the scanner off — not because the findings are wrong, but because
nobody can tell which of them is new today. A baseline records what was accepted at a
point in time; later runs report the difference and say how many were held back.

Identity comes from `Finding.fingerprint()`, the same value SARIF publishes, so a
finding suppressed here and an alert dismissed in GitHub agree on what "the same
finding" means. It deliberately ignores byte offsets: editing the top of a file must
not resurrect everything below it.

Nothing is suppressed silently. The count is always reported, and a baseline that
matches nothing is worth knowing about too — it usually means the paths moved.
"""
from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from modelwarden.core.findings import Finding

VERSION = 1


def save(path: Path, findings: Iterable[Finding]) -> int:
    """Write the findings as an accepted baseline. Returns how many were recorded."""
    entries = []
    seen: set[str] = set()
    for finding in findings:
        mark = finding.fingerprint()
        if mark in seen:
            continue
        seen.add(mark)
        # The context fields are for the human reading the diff of this file; only the
        # fingerprint is load-bearing.
        entries.append({
            "fingerprint": mark,
            "rule": finding.rule.id,
            "path": finding.location.path,
            "member": finding.location.member,
            "evidence": finding.evidence,
        })
    entries.sort(key=lambda e: (e["path"], e["rule"], e["fingerprint"]))
    document = {"version": VERSION, "findings": entries}
    path.write_text(json.dumps(document, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return len(entries)


def load(path: Path) -> set[str]:
    """Fingerprints from a baseline file, refusing a shape it does not understand.

    A malformed baseline raises rather than silently suppressing nothing or, worse,
    everything. A file the user pointed at and which quietly did not apply is the same
    failure this project refuses everywhere else.
    """
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or not isinstance(document.get("findings"), list):
        raise ValueError(f"{path}: not a modelwarden baseline (no 'findings' list)")
    version = document.get("version")
    if version != VERSION:
        raise ValueError(f"{path}: baseline version {version!r}, this build writes {VERSION}")
    marks = {
        entry.get("fingerprint")
        for entry in document["findings"]
        if isinstance(entry, dict) and isinstance(entry.get("fingerprint"), str)
    }
    if len(marks) != len(document["findings"]):
        raise ValueError(f"{path}: every entry needs a 'fingerprint' string")
    return marks


def apply(findings: list[Finding], known: set[str]) -> tuple[list[Finding], int]:
    """Findings not in the baseline, and how many were held back."""
    kept = [f for f in findings if f.fingerprint() not in known]
    return kept, len(findings) - len(kept)
