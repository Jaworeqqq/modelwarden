"""Zip containers: torch.save checkpoints, NumPy .npz, TorchScript and Keras archives.

Members are classified by content, not by name. torch.load only unpickles
`<prefix>/data.pkl`, but custom loaders open whatever they like.

**By the same detector the engine uses on a file**, which was not always true. This
module used to carry its own classifier: three checks on the first sixteen bytes — npy,
or hdf5, or a pickle by header or name — and `None` for everything else, where `None`
meant no finding of any kind. Measured against that version, five of seven payload
classes survived being moved inside an archive: ONNX with a custom operator domain,
GGUF with a template escape, safetensors hiding a pickle, a nested zip, and a
headerless protocol-0 pickle under a name that is not `*.pkl`. `core.detect` answered
all five for a file on disk; the only reason it did not answer them here is that it
took a path. So the fix was to give it a stream, not to widen a second classifier. A
second detector is a second set of blind spots.
"""
from __future__ import annotations

import io
import re
import struct
import zipfile
import zlib
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import BinaryIO

from modelwarden.core import detect
from modelwarden.core.detect import NUMPY_MAGIC, ZIP_MAGIC, Format, has_pickle_header
from modelwarden.core.findings import Finding, Location, Rule, Severity
from modelwarden.core.rules import NOT_ANALYSED, UNCLASSIFIED
from modelwarden.scanners.supply_chain import gguf, hdf5, keras, npy, onnx, safetensors
from modelwarden.scanners.supply_chain.pickle import (
    ATLAS,
    OWASP,
    PICKLE_RULES,
    analyse,
    findings_for,
)

BAD_ARCHIVE = Rule(
    "MW-SC-010",
    "Zip archive cannot be opened",
    "The file starts with a zip header but Python's zipfile rejects it. Loaders with a "
    "more lenient zip reader may still load it, so it cannot be treated as clean.",
    Severity.HIGH, ATLAS, OWASP,
)
UNREADABLE_MEMBER = Rule(
    "MW-SC-011",
    "Archive member fails integrity checks",
    "Reading the member failed (bad CRC, broken header, unsupported compression). Its raw "
    "bytes were analysed anyway, because loaders that skip the check still load it.",
    Severity.HIGH, ATLAS, OWASP,
)
EMBEDDED_CODE = Rule(
    "MW-SC-012",
    "Archive contains Python source",
    "TorchScript archives ship code/*.py that torch.jit.load compiles and runs. "
    "Review it like any other code you execute.",
    Severity.MEDIUM, ATLAS, OWASP,
)

# torch.save stores tensor bytes as `<prefix>/data/<key>`. torch reads them as raw
# buffers and never unpickles them; parsing them would turn float data that happens
# to start with 0x80 0x02 into false "malformed pickle" findings.
_STORAGE = re.compile(r"(?:.*/)?data/\d+")
_HEAD = 16
# Whole members are held in memory (raw fallback, Keras config, compressed HDF5);
# larger ones are only reported.
RAW_FALLBACK_LIMIT = 64 * 1024 * 1024
_READ_ERRORS = (zipfile.BadZipFile, zlib.error, EOFError, NotImplementedError, RuntimeError)
# How far a zip inside a zip inside a zip is followed. Past anything a real toolchain
# produces, and short enough that a crafted nest cannot spend the scan.
MAX_NESTING = 4
# Total decompressed bytes one archive may materialise. RAW_FALLBACK_LIMIT bounds a
# single member and not the walk: a thousand members, or a nest, each pass their own
# check. A zip bomb is exactly that shape, so the ceiling has to be cumulative.
TOTAL_BUFFER_LIMIT = 512 * 1024 * 1024


class _Budget:
    """What is left of TOTAL_BUFFER_LIMIT, carried through the whole nest."""

    def __init__(self, total: int = TOTAL_BUFFER_LIMIT):
        self.remaining = total

    def take(self, size: int) -> bool:
        if size > self.remaining:
            return False
        self.remaining -= size
        return True
# A Keras v3 archive always carries both; config.json alone is just a file.
_KERAS_MARKERS = frozenset({"config.json", "metadata.json"})


class ZipScanner:
    name = "zip"
    formats = frozenset({Format.ZIP})
    rules = (
        BAD_ARCHIVE, UNREADABLE_MEMBER, EMBEDDED_CODE,
        # Every rule reachable from inside an archive, because a member is now
        # dispatched to whichever scanner owns its format.
        *PICKLE_RULES, *npy.NPY_RULES, *keras.KERAS_RULES, *hdf5.HDF5_RULES,
        *gguf.GGUF_RULES, *onnx.ONNX_RULES, *safetensors.SafetensorsScanner.rules,
        UNCLASSIFIED, NOT_ANALYSED,
    )

    def scan(self, path: Path, display: str) -> Iterator[Finding]:
        with path.open("rb") as fh:
            yield from scan_zip(fh, display)


def scan_zip(
    fh: BinaryIO, display: str, prefix: str = "", depth: int = 0,
    budget: _Budget | None = None,
) -> Iterator[Finding]:
    """Scan a zip read from any seekable stream. `prefix` labels members of nested archives."""
    budget = budget if budget is not None else _Budget()
    try:
        archive = zipfile.ZipFile(fh)
    except zipfile.BadZipFile as exc:
        where = Location(display, prefix.rstrip("/") or None)
        yield Finding(BAD_ARCHIVE, BAD_ARCHIVE.default_severity,
                      f"zipfile rejects the archive: {exc}", where)
        return
    with archive:
        is_keras = _KERAS_MARKERS <= set(archive.namelist())
        for info in archive.infolist():
            if info.is_dir() or _STORAGE.fullmatch(info.filename):
                continue
            member = prefix + info.filename
            if info.filename.endswith(".py"):
                yield Finding(EMBEDDED_CODE, EMBEDDED_CODE.default_severity,
                              "archive ships Python source", Location(display, member))
            if is_keras and info.filename == "config.json":
                yield from _keras_config(archive, info, fh, display, member)
            else:
                yield from _member(archive, info, fh, display, member, depth, budget)


def embedded_blob(data: bytes, display: str, member: str) -> Iterator[Finding]:
    """A blob found inside a member, such as a torch.save archive in a Keras config."""
    if data.startswith(ZIP_MAGIC):
        yield from scan_zip(io.BytesIO(data), display, member + "/")
    elif has_pickle_header(data[:_HEAD]):
        yield from findings_for(analyse(io.BytesIO(data), end=len(data)), display, member)


def _member(
    archive: zipfile.ZipFile, info: zipfile.ZipInfo, fh: BinaryIO, display: str, member: str,
    depth: int, budget: _Budget,
) -> list[Finding]:
    """One member, classified by content and handed to whichever scanner owns the format."""
    size = info.file_size
    if size <= RAW_FALLBACK_LIMIT and budget.take(size):
        try:
            # Reading the member in full is also the CRC check: zipfile raises at the
            # end of it, which is how a patched payload becomes MW-SC-011 instead of
            # being scanned in silence.
            data = archive.read(info)
        except _READ_ERRORS as exc:
            found = [_unreadable(display, member, exc)]
            raw = _raw_member(fh, info)
            if raw is not None:
                found.extend(_dispatch(io.BytesIO(raw), len(raw), display, member, depth, budget))
            return found
        return _dispatch(io.BytesIO(data), len(data), display, member, depth, budget)

    # Too large to hold, or the archive's budget is spent. A stored member needs no
    # buffer at all: it is already a byte range of the archive and a window over it
    # seeks like a file. That trades the CRC check for being able to look inside,
    # which is the trade large stored HDF5 members have always been given.
    if info.compress_type == zipfile.ZIP_STORED and (start := _data_offset(fh, info)) is not None:
        return _dispatch(_Window(fh, start, size), size, display, member, depth, budget)

    return _too_large(archive, info, display, member)


def _too_large(
    archive: zipfile.ZipFile, info: zipfile.ZipInfo, display: str, member: str
) -> list[Finding]:
    """A member that cannot be held in memory and cannot be windowed: compressed and huge.

    Detection needs to seek and this member gives no way to, but two formats are read
    front to back and never needed one. Scanning them sequentially is what this module
    did for *every* member before it learned to detect properly, so dropping it here
    would have traded a wide silence for a narrower one — a 90 MB deflated pickle is
    exactly the member worth reading.
    """
    try:
        with archive.open(info) as stream:
            head = stream.read(_HEAD)
            sequential = has_pickle_header(head) or info.filename.endswith((".pkl", ".pickle"))
            if sequential or head.startswith(NUMPY_MAGIC):
                with archive.open(info) as body:
                    if sequential:
                        return list(findings_for(analyse(body, end=info.file_size),
                                                 display, member))
                    return list(npy.scan_stream(body, display, member))
    except _READ_ERRORS as exc:
        return [_unreadable(display, member, exc)]

    reason = (f"member is {info.file_size} bytes, over the {RAW_FALLBACK_LIMIT}-byte limit "
              "for holding one in memory" if info.file_size > RAW_FALLBACK_LIMIT else
              "the archive's cumulative decompression budget was spent before this member")
    return [Finding(UNCLASSIFIED, UNCLASSIFIED.default_severity,
                    f"{reason}, and it is compressed, so it could not be classified",
                    Location(display, member))]


def _dispatch(
    stream: BinaryIO, size: int, display: str, member: str, depth: int, budget: _Budget,
) -> list[Finding]:
    """Every format the member plausibly is, scanned — the engine's rule, one layer down.

    Collected eagerly per format because the scanners are generators sharing one
    stream: a lazy second format would read from wherever the first one stopped.
    """
    found: list[Finding] = []
    for fmt in detect.inspect_stream(stream, size).formats:
        found.extend(_scan_as(fmt, stream, size, display, member, depth, budget))
    return found


def _scan_as(
    fmt: Format, stream: BinaryIO, size: int, display: str, member: str, depth: int,
    budget: _Budget,
) -> Iterable[Finding]:
    if fmt is Format.PICKLE:
        stream.seek(0)
        return findings_for(analyse(stream, end=size), display, member)
    if fmt is Format.NUMPY:
        stream.seek(0)
        return npy.scan_stream(stream, display, member)
    if fmt is Format.HDF5:
        return hdf5.scan_hdf5(stream, size, display, member)
    if fmt is Format.SAFETENSORS:
        return safetensors.scan_stream(stream, size, display, member)
    if fmt is Format.GGUF:
        return gguf.scan_stream(stream, size, display, member)
    if fmt is Format.ONNX:
        stream.seek(0)
        return onnx.scan_onnx(stream.read(size), display, member)
    if fmt is Format.ZIP:
        if depth >= MAX_NESTING:
            return [Finding(NOT_ANALYSED, Severity.MEDIUM,
                            f"archive nested more than {MAX_NESTING} deep, not followed",
                            Location(display, member))]
        return list(scan_zip(stream, display, member + "/", depth + 1, budget))
    # MCP tool lists and client configurations are recognised by core.detect and
    # deliberately not scanned here: they are not members a model loader opens, and
    # JSON inside a checkpoint is that checkpoint's configuration rather than a tool
    # list somebody approved. A Keras config.json is handled before this, by name.
    return []


def _keras_config(
    archive: zipfile.ZipFile, info: zipfile.ZipInfo, fh: BinaryIO, display: str, member: str
) -> list[Finding]:
    found: list[Finding] = []
    if info.file_size > RAW_FALLBACK_LIMIT:
        message = f"config.json is {info.file_size} bytes, too large to analyse"
        return [Finding(UNREADABLE_MEMBER, UNREADABLE_MEMBER.default_severity, message,
                        Location(display, member))]
    try:
        with archive.open(info) as stream:
            data = stream.read()
    except _READ_ERRORS as exc:
        found.append(_unreadable(display, member, exc))
        data = _raw_member(fh, info)
    if data is not None:
        found.extend(keras.scan_config(data, display, member, embedded_blob))
    return found


def _unreadable(display: str, member: str, exc: Exception) -> Finding:
    return Finding(UNREADABLE_MEMBER, UNREADABLE_MEMBER.default_severity,
                   f"member cannot be read cleanly ({exc}), analysing raw bytes",
                   Location(display, member))


def _data_offset(fh: BinaryIO, info: zipfile.ZipInfo) -> int | None:
    """Where the member's bytes start, from its local header (not the central directory)."""
    fh.seek(info.header_offset)
    local = fh.read(30)
    if len(local) < 30 or not local.startswith(b"PK\x03\x04"):
        return None
    name_len, extra_len = struct.unpack("<HH", local[26:30])
    return info.header_offset + 30 + name_len + extra_len


def _raw_member(fh: BinaryIO, info: zipfile.ZipInfo) -> bytes | None:
    """Member bytes read straight from the local header, bypassing the CRC check."""
    if max(info.compress_size, info.file_size) > RAW_FALLBACK_LIMIT:
        return None
    start = _data_offset(fh, info)
    if start is None:
        return None
    fh.seek(start)
    raw = fh.read(info.compress_size)
    if info.compress_type == zipfile.ZIP_STORED:
        return raw
    if info.compress_type == zipfile.ZIP_DEFLATED:
        try:
            return zlib.decompressobj(-15).decompress(raw, RAW_FALLBACK_LIMIT)
        except zlib.error:
            return None
    return None


class _Window:
    """Read-only, seekable view of `size` bytes of `fh` starting at `start`."""

    def __init__(self, fh: BinaryIO, start: int, size: int):
        self._fh, self._start, self._size, self._pos = fh, start, size, 0

    def seek(self, pos: int, whence: int = 0) -> int:
        base = {0: 0, 1: self._pos, 2: self._size}[whence]
        self._pos = max(0, base + pos)
        return self._pos

    def tell(self) -> int:
        return self._pos

    def read(self, n: int = -1) -> bytes:
        remaining = max(0, self._size - self._pos)
        n = remaining if n < 0 else min(n, remaining)
        self._fh.seek(self._start + self._pos)
        data = self._fh.read(n)
        self._pos += len(data)
        return data
