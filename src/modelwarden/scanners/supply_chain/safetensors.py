"""safetensors: an 8-byte header length, a JSON header, then one flat byte buffer.

The format has no code-execution path, which is its whole point. What is left is
parser attack surface: the header size, offsets that overlap or point outside the
buffer, and bytes no tensor claims, where a second payload can hide.
"""
from __future__ import annotations

import math
import struct
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

from modelwarden.core.detect import NUMPY_MAGIC, ZIP_MAGIC, Format, has_pickle_header
from modelwarden.core.findings import Finding, Location, Rule, Severity
from modelwarden.scanners.supply_chain._json import load_strict
from modelwarden.scanners.supply_chain.pickle import (
    ATLAS,
    OWASP,
    PICKLE_RULES,
    analyse,
    findings_for,
)

HEADER_TOO_LARGE = Rule(
    "MW-SC-030",
    "safetensors header too large",
    "The header declares more bytes than the reference implementation accepts. Parsers "
    "without that limit allocate and parse whatever size the file claims.",
    Severity.MEDIUM, ("AML.T0029",), OWASP,
)
BAD_HEADER = Rule(
    "MW-SC-031",
    "Malformed safetensors header",
    "The JSON header is invalid, has duplicate keys (parsers disagree on which one wins) "
    "or describes tensors with invalid fields.",
    Severity.MEDIUM, ATLAS, OWASP,
)
BAD_LAYOUT = Rule(
    "MW-SC-032",
    "Inconsistent tensor layout",
    "Tensor offsets fall outside the buffer, overlap, or do not match dtype and shape. "
    "Loaders that trust the header read the wrong bytes or out of bounds.",
    Severity.MEDIUM, ATLAS, OWASP,
)
UNCLAIMED = Rule(
    "MW-SC-033",
    "Bytes not claimed by any tensor",
    "Part of the buffer belongs to no tensor. The reference loader rejects such files, and "
    "the region can carry a payload for other parsers (polyglot files).",
    Severity.LOW, ATLAS, OWASP,
)

MAX_HEADER = 100_000_000  # the reference (Rust) implementation's limit

DTYPE_SIZES = {
    "BOOL": 1, "U8": 1, "I8": 1, "F8_E4M3": 1, "F8_E5M2": 1, "F8_E8M0": 1,
    "I16": 2, "U16": 2, "F16": 2, "BF16": 2,
    "I32": 4, "U32": 4, "F32": 4,
    "I64": 8, "U64": 8, "F64": 8, "C64": 8,
}
# Sub-byte types are packed; their size cannot be checked per element.
SUB_BYTE = frozenset({"F4", "F6_E2M3", "F6_E3M2"})


class SafetensorsScanner:
    name = "safetensors"
    formats = frozenset({Format.SAFETENSORS})
    rules = (HEADER_TOO_LARGE, BAD_HEADER, BAD_LAYOUT, UNCLAIMED, *PICKLE_RULES)

    def scan(self, path: Path, display: str) -> Iterator[Finding]:
        with path.open("rb") as fh:
            yield from scan_stream(fh, path.stat().st_size, display)


def scan_stream(
    fh: BinaryIO, size: int, display: str, member: str | None = None
) -> Iterator[Finding]:
    """Scan safetensors read from any seekable stream, so a member of an archive counts too."""
    header_loc = Location(display, member, 8)
    fh.seek(0)
    (length,) = struct.unpack("<Q", fh.read(8))
    if length > MAX_HEADER:
        message = (f"header declares {length} bytes, "
                   f"the reference loader stops at {MAX_HEADER}")
        yield Finding(HEADER_TOO_LARGE, HEADER_TOO_LARGE.default_severity, message,
                      Location(display, member, 0))
        return
    try:
        header = load_strict(fh.read(length))
    except (ValueError, RecursionError) as exc:  # includes UnicodeDecodeError
        yield Finding(BAD_HEADER, BAD_HEADER.default_severity,
                      f"header is not valid JSON: {exc}", header_loc)
        return
    if not isinstance(header, dict):
        yield Finding(BAD_HEADER, BAD_HEADER.default_severity,
                      "header is not a JSON object", header_loc)
        return
    yield from _check(header, fh, 8 + length, size - 8 - length, display, member)


def _check(
    header: dict, fh: BinaryIO, data_start: int, data_len: int, display: str,
    member: str | None = None,
) -> Iterator[Finding]:
    header_loc = Location(display, member, 8)

    def bad(message: str, severity: Severity = BAD_HEADER.default_severity) -> Finding:
        return Finding(BAD_HEADER, severity, message, header_loc)

    def layout(message: str) -> Finding:
        return Finding(BAD_LAYOUT, BAD_LAYOUT.default_severity, message, header_loc)

    spans: list[tuple[int, int, str]] = []
    for name, entry in header.items():
        if name == "__metadata__":
            if not (isinstance(entry, dict) and all(isinstance(v, str) for v in entry.values())):
                yield bad("__metadata__ must map strings to strings")
            continue
        problem = _entry_problem(entry)
        if problem:
            yield bad(f"tensor {name!r}: {problem}")
            continue

        dtype, shape = entry["dtype"], entry["shape"]
        begin, end = entry["data_offsets"]
        if not begin <= end <= data_len:
            yield layout(f"tensor {name!r}: offsets [{begin}, {end}] fall outside "
                         f"the {data_len}-byte buffer")
            continue
        itemsize = DTYPE_SIZES.get(dtype)
        if itemsize is None:
            if dtype not in SUB_BYTE:
                message = f"tensor {name!r}: unknown dtype {dtype!r}, size not verified"
                yield bad(message, Severity.LOW)
        elif end - begin != math.prod(shape) * itemsize:
            expected = math.prod(shape) * itemsize
            yield layout(f"tensor {name!r}: {end - begin} bytes for shape {shape} of {dtype}, "
                         f"expected {expected}")
        spans.append((begin, end, name))

    cursor, owner = 0, None
    for begin, end, name in sorted(spans):
        if begin < cursor:
            yield layout(f"tensors {owner!r} and {name!r} overlap")
        elif begin > cursor:
            yield from _unclaimed(fh, data_start, cursor, begin, display, member)
        if end >= cursor:
            cursor, owner = end, name
    if cursor < data_len:
        yield from _unclaimed(fh, data_start, cursor, data_len, display, member)


def _entry_problem(entry: object) -> str | None:
    if not isinstance(entry, dict):
        return "entry is not an object"
    if not isinstance(entry.get("dtype"), str):
        return "dtype is not a string"
    shape = entry.get("shape")
    if not (isinstance(shape, list) and all(_uint(d) for d in shape)):
        return "shape is not a list of non-negative integers"
    offsets = entry.get("data_offsets")
    if not (isinstance(offsets, list) and len(offsets) == 2 and all(_uint(o) for o in offsets)):
        return "data_offsets is not a pair of non-negative integers"
    return None


def _uint(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _unclaimed(
    fh: BinaryIO, data_start: int, begin: int, end: int, display: str,
    member: str | None = None,
) -> Iterator[Finding]:
    offset = data_start + begin
    fh.seek(offset)
    head = fh.read(16)
    where = Location(display, member, offset)
    size = end - begin

    if has_pickle_header(head):
        yield Finding(UNCLAIMED, Severity.MEDIUM,
                      f"{size} bytes claimed by no tensor start with a pickle header", where)
        fh.seek(offset)
        yield from findings_for(analyse(fh), display, member)
    elif head.startswith((ZIP_MAGIC, NUMPY_MAGIC)):
        message = f"{size} bytes claimed by no tensor start with an embedded file header"
        yield Finding(UNCLAIMED, Severity.MEDIUM, message, where)
    else:
        yield Finding(UNCLAIMED, UNCLAIMED.default_severity,
                      f"{size} bytes are not claimed by any tensor", where)
