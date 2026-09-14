"""SARIF 2.1.0, the format GitHub code scanning ingests."""
from __future__ import annotations

import json
from typing import TextIO
from urllib.parse import quote

from modelwarden import __version__
from modelwarden.core.engine import ScanResult
from modelwarden.core.findings import Finding, Rule, Severity

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# Where a reader goes to find out what a rule means. The same for every rule: the
# catalogue keeps rules in tables rather than headings, so there is no per-rule anchor
# to link to, and inventing one would produce a page of dead links.
HELP_URI = "https://github.com/Jaworeqqq/modelwarden/blob/main/docs/rules.md"

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# GitHub buckets security-severity as >=9 critical, >=7 high, >=4 medium, >0 low.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}


def build(result: ScanResult, rules: list[Rule]) -> dict:
    index = {rule.id: i for i, rule in enumerate(rules)}
    driver = {
        "name": "modelwarden",
        "version": __version__,
        "rules": [_rule(rule) for rule in rules],
    }
    results = [_result(f, index) for f in result.findings]
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{"tool": {"driver": driver}, "results": results}],
    }


def render(result: ScanResult, rules: list[Rule], out: TextIO) -> None:
    json.dump(build(result, rules), out, indent=2)
    out.write("\n")


def _rule(rule: Rule) -> dict:
    return {
        "id": rule.id,
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": rule.description},
        "helpUri": HELP_URI,
        "defaultConfiguration": {"level": _LEVEL[rule.default_severity]},
        "properties": {
            "tags": ["security", *rule.atlas, *rule.owasp],
            "security-severity": _SECURITY_SEVERITY[rule.default_severity],
        },
    }


def _result(finding: Finding, index: dict[str, int]) -> dict:
    loc = finding.location
    message = finding.message
    # A text scanner knows the line; a model-file scanner does not, and 1 is the only
    # honest placeholder SARIF allows (startLine is required and must be positive).
    region: dict[str, int] = {"startLine": loc.line or 1}
    if loc.member:
        # SARIF has no notion of a byte range inside an archive member.
        where = f" at offset {loc.offset:#x}" if loc.offset is not None else ""
        message += f" [archive member {loc.member}{where}]"
    elif loc.offset is not None:
        region["byteOffset"] = loc.offset

    return {
        "ruleId": finding.rule.id,
        "ruleIndex": index[finding.rule.id],
        "level": _LEVEL[finding.severity],
        "message": {"text": message},
        # Versioned name: changing how the hash is built must not silently merge old
        # alerts with new ones, so a future scheme becomes v2 rather than editing this.
        "partialFingerprints": {"modelwardenFindingV1": finding.fingerprint()},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": quote(loc.path)},
                "region": region,
            },
        }],
        "properties": {
            "severity": str(finding.severity),
            "security-severity": _SECURITY_SEVERITY[finding.severity],
            "member": loc.member,
            "evidence": finding.evidence,
        },
    }
