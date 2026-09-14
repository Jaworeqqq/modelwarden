"""Zip containers: torch.save checkpoints, NumPy .npz, TorchScript and Keras archives.

Members are classified by content, not by name. torch.load only unpickles
`<prefix>/data.pkl`, but custom loaders open whatever they like.
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

from modelwarden.core.detect import HDF5_MAGIC, NUMPY_MAGIC, ZIP_MAGIC, Format, has_pickle_header
from modelwarden.core.findings import Finding, Location, Rule, Severity
from modelwarden.scanners.supply_chain import hdf5, keras, npy
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
# A Keras v3 archive always carries both; config.json alone is just a file.
_KERAS_MARKERS = frozenset({"config.json", "metadata.json"})


class ZipScanner:
    name = "zip"
    formats = frozenset({Format.ZIP})
    rules = (
        BAD_ARCHIVE, UNREADABLE_MEMBER, EMBEDDED_CODE,
        *PICKLE_RULES, *npy.NPY_RULES, *keras.KERAS_RULES, *hdf5.HDF5_RULES,
    )

    def scan(self, path: Path, display: str) -> Iterator[Finding]:
        with path.open("rb") as fh:
            yield from scan_zip(fh, display)


def scan_zip(fh: BinaryIO, display: str, prefix: str = "") -> Iterator[Finding]:
    """Scan a zip read from any seekable stream. `prefix` labels members of nested archives."""
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
                yield from _member(archive, info, fh, display, member)


def embedded_blob(data: bytes, display: str, member: str) -> Iterator[Finding]:
    """A blob found inside a member, such as a torch.save archive in a Keras config."""
    if data.startswith(ZIP_MAGIC):
        yield from scan_zip(io.BytesIO(data), display, member + "/")
    elif has_pickle_header(data[:_HEAD]):
        yield from findings_for(analyse(io.BytesIO(data), end=len(data)), display, member)


def _member(
    archive: zipfile.ZipFile, info: zipfile.ZipInfo, fh: BinaryIO, display: str, member: str
) -> list[Finding]:
    try:
        with archive.open(info) as stream:
            kind = _kind(info.filename, stream.read(_HEAD))
        if kind is None:
            return []
        if kind == "hdf5":
            return _hdf5_member(archive, info, fh, display, member)
        with archive.open(info) as stream:
            return list(_analyse(kind, stream, info.file_size, display, member))
    except _READ_ERRORS as exc:
        found = [_unreadable(display, member, exc)]
        data = _raw_member(fh, info)
        if data is not None and (kind := _kind(info.filename, data[:_HEAD])):
            found.extend(_analyse(kind, io.BytesIO(data), len(data), display, member))
        return found


def _hdf5_member(
    archive: zipfile.ZipFile, info: zipfile.ZipInfo, fh: BinaryIO, display: str, member: str
) -> list[Finding]:
    # HDF5 needs random access. A stored member is read in place through a window on
    # the archive, however large; a compressed one has to fit in memory.
    if info.compress_type == zipfile.ZIP_STORED and (start := _data_offset(fh, info)) is not None:
        view: BinaryIO = _Window(fh, start, info.file_size)  # type: ignore[assignment]
    elif info.file_size <= RAW_FALLBACK_LIMIT:
        view = io.BytesIO(archive.read(info))
    else:
        message = f"compressed HDF5 member of {info.file_size} bytes is too large to analyse"
        return [Finding(hdf5.NOT_ANALYSED, hdf5.NOT_ANALYSED.default_severity, message,
                        Location(display, member))]
    return list(hdf5.scan_hdf5(view, info.file_size, display, member))


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


def _kind(name: str, head: bytes) -> str | None:
    if head.startswith(NUMPY_MAGIC):
        return "npy"
    if head.startswith(HDF5_MAGIC):
        return "hdf5"
    if name.endswith((".pkl", ".pickle")) or has_pickle_header(head):
        return "pickle"
    return None


def _analyse(kind: str, fh: BinaryIO, size: int, display: str, member: str) -> Iterable[Finding]:
    if kind == "npy":
        return npy.scan_stream(fh, display, member)
    if kind == "hdf5":
        return hdf5.scan_hdf5(fh, size, display, member)
    return findings_for(analyse(fh, end=size), display, member)


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
