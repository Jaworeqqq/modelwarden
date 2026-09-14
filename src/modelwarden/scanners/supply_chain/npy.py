"""NumPy .npy: a header dict, then raw array data, or a pickle when the dtype is object."""
from __future__ import annotations

import ast
import struct
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

from modelwarden.core.detect import NUMPY_MAGIC, Format
from modelwarden.core.findings import Finding, Location, Rule, Severity
from modelwarden.scanners.supply_chain.pickle import (
    ATLAS,
    OWASP,
    PICKLE_RULES,
    analyse,
    findings_for,
)

OBJECT_ARRAY = Rule(
    "MW-SC-020",
    "NumPy object array",
    "The array has an object dtype, so its data section is a pickle. numpy.load refuses it "
    "unless allow_pickle=True, and code that passes that flag runs whatever it contains.",
    Severity.MEDIUM, ATLAS, OWASP,
)
BAD_HEADER = Rule(
    "MW-SC-021",
    "Malformed NumPy header",
    "The .npy header cannot be parsed, so the array was not analysed.",
    Severity.MEDIUM, ATLAS, OWASP,
)
NPY_RULES = (OBJECT_ARRAY, BAD_HEADER)

MAX_HEADER = 10_000  # numpy.load's default max_header_size since numpy 1.24


class NumpyScanner:
    name = "numpy"
    formats = frozenset({Format.NUMPY})
    rules = (*NPY_RULES, *PICKLE_RULES)

    def scan(self, path: Path, display: str) -> Iterator[Finding]:
        with path.open("rb") as fh:
            yield from scan_stream(fh, display)


def scan_stream(fh: BinaryIO, display: str, member: str | None = None) -> Iterator[Finding]:
    start = fh.tell()

    def bad(detail: str) -> Finding:
        where = Location(display, member, start)
        return Finding(BAD_HEADER, BAD_HEADER.default_severity, detail, where)

    preamble = fh.read(8)
    if len(preamble) < 8 or not preamble.startswith(NUMPY_MAGIC):
        yield bad("missing .npy magic")
        return
    major, minor = preamble[6], preamble[7]
    if major == 1:
        length_format, encoding = "<H", "latin1"
    elif major in (2, 3):
        length_format, encoding = "<I", "latin1" if major == 2 else "utf-8"
    else:
        yield bad(f"unsupported .npy version {major}.{minor}")
        return

    raw_length = fh.read(struct.calcsize(length_format))
    if len(raw_length) != struct.calcsize(length_format):
        yield bad("truncated header")
        return
    (length,) = struct.unpack(length_format, raw_length)
    if length > MAX_HEADER:
        yield bad(f"header is {length} bytes; numpy.load refuses more than {MAX_HEADER} unless "
                  "max_header_size is raised or allow_pickle is set")
        return

    try:
        header = ast.literal_eval(fh.read(length).decode(encoding))
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError) as exc:
        yield bad(f"header is not a Python literal ({type(exc).__name__})")
        return
    if not isinstance(header, dict) or "descr" not in header:
        yield bad("header has no 'descr' key")
        return
    if not _has_object(header["descr"]):
        return

    message = f"object array (descr {header['descr']!r}): the data section is a pickle"
    yield Finding(OBJECT_ARRAY, OBJECT_ARRAY.default_severity, message,
                  Location(display, member, fh.tell()))
    yield from findings_for(analyse(fh), display, member)


def _has_object(descr: object) -> bool:
    if isinstance(descr, str):
        return "O" in descr
    if isinstance(descr, list):
        # Structured dtype: [(name, dtype[, shape]), ...]. Only the dtype part
        # counts; a field called "Offset" is not an object field.
        return any(
            isinstance(f, (list, tuple)) and len(f) >= 2 and _has_object(f[1]) for f in descr
        )
    return False
