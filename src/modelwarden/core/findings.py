"""Data model shared by every scanner, probe and reporter."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError:
            choices = ", ".join(str(s) for s in cls)
            raise ValueError(f"unknown severity {value!r} (choose from: {choices})") from None

    def __str__(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Rule:
    """A detection rule. Findings point at a rule; reporters read its metadata."""

    id: str
    title: str
    description: str
    default_severity: Severity
    atlas: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()


@dataclass(frozen=True)
class Location:
    """Where a finding lives.

    `member` names an entry inside an archive. `offset` is a byte offset into the
    member when there is one, otherwise into the file.

    `line` is the 1-based line the finding sits on, and only text scanners set it. A
    byte offset is the honest unit for a model file, but SARIF consumers place an alert
    by line and ignore `byteOffset`, so without this every corpus finding lands on line
    1 of its document. It is carried on the finding rather than recomputed by a reporter
    because only the scanner still has the text: by reporting time the file may have
    changed, or be gone.
    """

    path: str
    member: str | None = None
    offset: int | None = None
    line: int | None = None

    def __str__(self) -> str:
        out = self.path
        if self.member:
            out += f"!{self.member}"
        if self.offset is not None:
            out += f"@{self.offset:#x}"
        return out


@dataclass(frozen=True)
class Finding:
    rule: Rule
    severity: Severity
    message: str
    location: Location
    evidence: str = ""

    def fingerprint(self) -> str:
        """A stable identity for this finding, across runs and unrelated edits.

        Built from the rule, the path, the archive member and the evidence — and
        deliberately **not** from the byte offset, which moves whenever anything earlier
        in the file changes. Including it would give the same finding a new identity
        after an unrelated edit: a baseline would stop matching and a dismissed alert
        would come back as new.

        Two findings agreeing on all four really are the same finding reported twice,
        so collapsing them is intended rather than a loss. Lives here rather than in a
        reporter because identity belongs to the finding: SARIF de-duplication and the
        baseline file must agree on it, and two copies would drift.
        """
        parts = (self.rule.id, self.location.path, self.location.member or "", self.evidence)
        return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()[:32]

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule.id,
            "title": self.rule.title,
            "severity": str(self.severity),
            "message": self.message,
            "path": self.location.path,
            "member": self.location.member,
            "offset": self.location.offset,
            "evidence": self.evidence,
            "atlas": list(self.rule.atlas),
            "owasp": list(self.rule.owasp),
        }
