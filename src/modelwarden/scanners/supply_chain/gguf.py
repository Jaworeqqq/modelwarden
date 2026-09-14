"""GGUF (llama.cpp): metadata key/values, tensor descriptors, then aligned tensor data.

Two attack surfaces. Length and count fields that a parser trusts: llama.cpp's
GGUF reader had heap overflows driven by exactly those. And the Jinja chat
template, which some runtimes render outside Jinja's sandbox.
"""
from __future__ import annotations

import math
import os
import re
import struct
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

from modelwarden.core.detect import Format
from modelwarden.core.findings import Finding, Location, Rule, Severity
from modelwarden.scanners.supply_chain.pickle import ATLAS, OWASP

MALFORMED = Rule(
    "MW-SC-040",
    "Malformed GGUF structure",
    "The file violates the GGUF specification (unsupported version, bad alignment, "
    "misaligned tensor offsets, too many dimensions, duplicate keys, unknown value "
    "types). Parsing stops at the first such problem.",
    Severity.MEDIUM, ATLAS, OWASP,
)
OUT_OF_BOUNDS = Rule(
    "MW-SC-041",
    "GGUF size field out of bounds",
    "A count, length, dimension or tensor offset cannot fit in the file or overflows "
    "64-bit size arithmetic. That is the input shape behind the heap overflows found "
    "in llama.cpp's GGUF parser.",
    Severity.HIGH, ATLAS, OWASP,
)
TEMPLATE_ESCAPE = Rule(
    "MW-SC-042",
    "Chat template reaches Python internals",
    "The Jinja chat template accesses dunder attributes or process-level names. "
    "Runtimes that render templates outside Jinja's sandbox execute this as code when "
    "the model is loaded (llama-cpp-python 0.2.30-0.2.71, CVE-2024-34359).",
    Severity.HIGH, ATLAS, OWASP,
)
TEMPLATE_EVASION = Rule(
    "MW-SC-043",
    "Chat template uses evasion constructs",
    "The chat template uses the attr filter, escaped underscores, underscore string "
    "arithmetic or Jinja globals that chat templates do not need. These are the usual "
    "ways to rebuild dunder names past a naive filter.",
    Severity.MEDIUM, ATLAS, OWASP,
)
GGUF_RULES = (MALFORMED, OUT_OF_BOUNDS, TEMPLATE_ESCAPE, TEMPLATE_EVASION)

# gguf_metadata_value_type -> struct code, for fixed-size scalars.
_SCALARS = {
    0: "B", 1: "b", 2: "H", 3: "h", 4: "I", 5: "i", 6: "f", 7: "?", 10: "Q", 11: "q", 12: "d",
}
_STRING, _ARRAY = 8, 9

MAX_DIMS = 4             # GGML_MAX_DIMS
MAX_NAME = 64            # tensor name limit in the specification
MAX_ARRAY_DEPTH = 8      # the spec allows nesting; unbounded nesting is a recursion bomb
DEFAULT_ALIGNMENT = 32
# Smallest possible encodings, used to reject counts the file cannot possibly hold.
_MIN_KV = 8 + 4 + 1      # key length, value type, 1-byte value
_MIN_TENSOR = 8 + 4 + 4 + 8  # name length, n_dims, type, offset

TEMPLATE_KEY = "tokenizer.chat_template"  # plus named variants: tokenizer.chat_template.<name>

# Only template code is checked. Text outside {{ }} and {% %} is emitted verbatim,
# and default system prompts are full of words like "self" or "config".
_CODE = re.compile(r"\{\{.*?\}\}|\{%.*?%\}", re.DOTALL)
_ESCAPES = [
    (re.compile(r"__\w+__"), "dunder attribute"),
    (re.compile(r"\b(?:popen|subprocess|importlib|builtins|eval|exec)\b|\bos\s*\."),
     "process-level name"),
]
_EVASIONS = [
    (re.compile(r"\|\s*attr\b|\battr\s*\("), "attr filter"),
    (re.compile(r"\\x5f|\\u005f|\\137|\\N\{LOW LINE\}", re.IGNORECASE), "escaped underscore"),
    (re.compile(r"""['"]_+['"]\s*[*~]"""), "underscore string arithmetic"),
    (re.compile(r"\b(?:lipsum|cycler|joiner|self|config|request|url_for)\b"), "Jinja global"),
]


class _Fatal(Exception):
    def __init__(self, rule: Rule, offset: int | None, message: str):
        super().__init__(message)
        self.rule, self.offset = rule, offset


class _Reader:
    def __init__(self, fh: BinaryIO, size: int, order: str):
        self.fh, self.size, self.order = fh, size, order

    def tell(self) -> int:
        return self.fh.tell()

    def scalar(self, code: str):
        offset, n = self.tell(), struct.calcsize(code)
        data = self.fh.read(n)
        if len(data) < n:
            raise _Fatal(MALFORMED, offset, "file ends inside the metadata")
        return struct.unpack(self.order + code, data)[0]

    def count(self, what: str, min_item: int) -> int:
        offset = self.tell()
        value = self.scalar("Q")
        remaining = self.size - self.tell()
        if value * min_item > remaining:
            raise _Fatal(OUT_OF_BOUNDS, offset,
                         f"{what} is {value}, but only {remaining} bytes remain in the file")
        return value

    def string(self, what: str = "string length") -> tuple[int, bytes]:
        n = self.count(what, 1)
        return self.tell(), self.fh.read(n)

    def skip(self, n: int) -> None:
        self.fh.seek(n, os.SEEK_CUR)


class GGUFScanner:
    name = "gguf"
    formats = frozenset({Format.GGUF})
    rules = GGUF_RULES

    def scan(self, path: Path, display: str) -> Iterator[Finding]:
        with path.open("rb") as fh:
            yield from scan_stream(fh, path.stat().st_size, display)


def scan_stream(
    fh: BinaryIO, size: int, display: str, member: str | None = None
) -> Iterator[Finding]:
    """Scan a GGUF read from any seekable stream, so a member of an archive counts too."""
    templates: list[tuple[str, int, str]] = []
    fatal: _Fatal | None = None
    fh.seek(4)  # magic, already checked by detection
    try:
        _parse(fh, size, templates)
    except _Fatal as exc:
        fatal = exc

    # Templates read before a structural error are still analysed.
    for key, offset, text in templates:
        yield from template_findings(key, offset, text, display, member)
    if fatal:
        where = Location(display, member, fatal.offset)
        yield Finding(fatal.rule, fatal.rule.default_severity, str(fatal), where)


def _parse(fh: BinaryIO, size: int, templates: list[tuple[str, int, str]]) -> None:
    raw = fh.read(4)
    if len(raw) < 4:
        raise _Fatal(MALFORMED, 4, "file ends before the version field")
    # Version 3 allows big-endian files; the magic is the same, the version is swapped.
    little, big = struct.unpack("<I", raw)[0], struct.unpack(">I", raw)[0]
    if little in (2, 3):
        order = "<"
    elif big in (2, 3):
        order = ">"
    else:
        version = little if little < big else big
        raise _Fatal(MALFORMED, 4, f"GGUF version {version} is not supported (only 2 and 3)")

    r = _Reader(fh, size, order)
    tensor_count = r.count("tensor count", _MIN_TENSOR)
    kv_count = r.count("metadata count", _MIN_KV)

    alignment: object = DEFAULT_ALIGNMENT
    seen: set[str] = set()
    for _ in range(kv_count):
        key_offset = r.tell()
        _, raw_key = r.string("key length")
        key = raw_key.decode("utf-8", "replace")
        if key in seen:
            # Parsers disagree on which duplicate wins; a scanner and a loader may
            # end up looking at different values.
            raise _Fatal(MALFORMED, key_offset, f"duplicate metadata key {key!r}")
        seen.add(key)
        vtype = r.scalar("I")
        if key.startswith(TEMPLATE_KEY) and vtype == _STRING:
            start, value = r.string()
            templates.append((key, start, value.decode("utf-8", "replace")))
        elif key == "general.alignment" and vtype in _SCALARS:
            alignment = r.scalar(_SCALARS[vtype])
        else:
            _skip_value(r, vtype, key_offset, depth=0)

    if not (isinstance(alignment, int) and alignment >= 8 and alignment % 8 == 0
            and alignment & (alignment - 1) == 0):
        raise _Fatal(MALFORMED, None, f"general.alignment {alignment!r} is not a power of two "
                                      "and a multiple of 8")

    tensors: list[tuple[str, int, int]] = []
    for _ in range(tensor_count):
        info_offset = r.tell()
        _, raw_name = r.string("tensor name length")
        name = raw_name.decode("utf-8", "replace")
        if len(raw_name) > MAX_NAME:
            raise _Fatal(MALFORMED, info_offset, f"tensor name is {len(raw_name)} bytes, "
                                                 f"the limit is {MAX_NAME}")
        n_dims = r.scalar("I")
        if n_dims > MAX_DIMS:
            raise _Fatal(MALFORMED, info_offset, f"tensor {name!r} has {n_dims} dimensions, "
                                                 f"the limit is {MAX_DIMS}")
        dims = [r.scalar("Q") for _ in range(n_dims)]
        if math.prod(dims) >= 2**63:
            raise _Fatal(OUT_OF_BOUNDS, info_offset,
                         f"tensor {name!r}: dimensions {dims} overflow a 64-bit element count")
        r.scalar("I")  # ggml type; valid ids change between llama.cpp releases
        data_offset = r.scalar("Q")
        if data_offset % alignment:
            raise _Fatal(MALFORMED, info_offset, f"tensor {name!r}: data offset {data_offset} "
                                                 f"is not aligned to {alignment}")
        tensors.append((name, data_offset, info_offset))

    data_start = -(-r.tell() // alignment) * alignment
    data_len = size - data_start
    for name, data_offset, info_offset in tensors:
        if data_offset > data_len:
            raise _Fatal(OUT_OF_BOUNDS, info_offset,
                         f"tensor {name!r}: data offset {data_offset} is past the end of the "
                         f"{data_len}-byte data section")


def _skip_value(r: _Reader, vtype: int, key_offset: int, depth: int) -> None:
    if vtype in _SCALARS:
        r.skip(struct.calcsize(_SCALARS[vtype]))
    elif vtype == _STRING:
        r.skip(r.count("string length", 1))
    elif vtype == _ARRAY:
        if depth >= MAX_ARRAY_DEPTH:
            raise _Fatal(MALFORMED, key_offset, f"arrays nested deeper than {MAX_ARRAY_DEPTH}")
        etype = r.scalar("I")
        if etype in _SCALARS:
            item = struct.calcsize(_SCALARS[etype])
            r.skip(r.count("array length", item) * item)
        elif etype == _STRING:
            for _ in range(r.count("array length", 8)):
                r.skip(r.count("string length", 1))
        elif etype == _ARRAY:
            for _ in range(r.count("array length", 12)):
                _skip_value(r, _ARRAY, key_offset, depth + 1)
        else:
            raise _Fatal(MALFORMED, key_offset, f"unknown array element type {etype}")
    else:
        raise _Fatal(MALFORMED, key_offset, f"unknown metadata value type {vtype}")


def template_findings(
    key: str, offset: int, text: str, display: str, member: str | None = None
) -> Iterator[Finding]:
    escapes: dict[str, str] = {}
    evasions: dict[str, str] = {}
    for block in (m.group() for m in _CODE.finditer(text)):
        for patterns, found in ((_ESCAPES, escapes), (_EVASIONS, evasions)):
            for pattern, label in patterns:
                if label not in found and pattern.search(block):
                    found[label] = " ".join(block.split())[:80]

    # One finding per template: once it reaches Python internals, the evasion
    # tricks it used are part of that story, not a second, weaker finding.
    if escapes:
        rule, found = TEMPLATE_ESCAPE, {**escapes, **evasions}
    elif evasions:
        rule, found = TEMPLATE_EVASION, evasions
    else:
        return
    message = f"{key} uses {', '.join(found)}"
    evidence = next(iter(found.values()))
    yield Finding(rule, rule.default_severity, message, Location(display, member, offset),
                  evidence)
