"""Rules raised by the engine itself rather than by a format scanner."""
from __future__ import annotations

from modelwarden.core.findings import Rule, Severity

UNRECOGNISED = Rule(
    "MW-GEN-001",
    "Unrecognised model file",
    "The file has a model-like extension but its content matches no supported format, "
    "so it was not analysed. Loaders choose a format by content, so an unknown format "
    "is a blind spot, not a clean result.",
    Severity.LOW,
)

NOT_ANALYSED = Rule(
    "MW-GEN-002",
    "Format recognised but not analysed",
    "The format was identified, but modelwarden has no scanner for it yet.",
    Severity.INFO,
)

READ_ERROR = Rule(
    "MW-GEN-003",
    "File could not be read",
    "An operating-system error prevented reading the file, so it was not analysed.",
    Severity.MEDIUM,
)

SCANNER_ERROR = Rule(
    "MW-GEN-004",
    "Scanner crashed",
    "An internal error stopped the analysis of this file. It is reported as HIGH so that "
    "a crafted file which crashes the scanner fails the gate instead of passing silently.",
    Severity.HIGH,
)

MULTIPLE_FORMATS = Rule(
    "MW-GEN-005",
    "File is more than one format at once",
    "The bytes satisfy two format definitions, so a scanner and a loader can disagree "
    "about which file this is. `zipfile` finds an archive by its tail, so a harmless "
    "pickle in front of a malicious archive reads as a pickle to anything checking the "
    "first bytes and as the archive to torch.load. Every matching format is scanned; "
    "the overlap itself is reported because one model file is one format.",
    Severity.HIGH,
)

UNCLASSIFIED = Rule(
    "MW-GEN-006",
    "File could not be classified within the scanner's limits",
    "Recognising a format means reading part of the file, and this file outran one of "
    "those bounded reads, so no format could be confirmed or ruled out. Until this rule "
    "existed that answer was indistinguishable from 'not a model': a poisoned MCP tool "
    "list padded past the limit lost its findings entirely and was counted as skipped, "
    "in silence. Whatever could not be classified was never scanned, which is a gap in "
    "the scan rather than a clean result.",
    Severity.MEDIUM,
)

ENGINE_RULES: tuple[Rule, ...] = (
    UNRECOGNISED, NOT_ANALYSED, READ_ERROR, SCANNER_ERROR, MULTIPLE_FORMATS,
    UNCLASSIFIED,
)
