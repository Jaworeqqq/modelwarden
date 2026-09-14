"""gzip, bzip2, xz and raw zlib wrappers: a model file with a coat on.

`joblib.dump(..., compress=3)` writes a zlib stream with a pickle inside it, and
`joblib.load` picks its decompressor by magic and unpickles whatever comes out.
`pickle.load(gzip.open(path))` is an ordinary line to write. Either way the pickle
executes on load exactly as it would bare, so a scanner that stops at the wrapper
reports a clean result on a live payload.

Measured before this module existed: `model.pkl.gz`, `model.pkl.bz2` and `model.pkl.xz`
carrying `os.system` were **counted as skipped and reported nothing at all**, and a
zlib-wrapped one under a `.joblib` name got MW-GEN-001 — low, which is under the
default `--fail-on high`, so a gate passed it.

**Cost control, because unwrapping is not free.** Every `.tar.gz` in a tree is also a
compressed file, and decompressing each one in full to discover it holds a tarball
would make scanning a source directory expensive. So a prefix is decompressed first and
classified; only if those bytes look like a format worth scanning is the rest unpacked.
A tarball spends `PROBE_LIMIT` bytes of work and is then skipped in silence, which is
the correct answer for a file no model loader will open.

What that costs in return: a zip inside a gzip is not found, because `zipfile` locates
an archive by its tail and a prefix has none. Named here rather than discovered later.
"""
from __future__ import annotations

import bz2
import lzma
import zlib
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

from modelwarden.core.detect import Format, compression_of
from modelwarden.core.findings import Finding, Location
from modelwarden.core.rules import UNCLASSIFIED
from modelwarden.scanners.supply_chain import gguf, hdf5, npy, onnx, safetensors
from modelwarden.scanners.supply_chain._dispatch import Budget, dispatch
from modelwarden.scanners.supply_chain.pickle import PICKLE_RULES

# Enough to classify: every format this scanner owns is recognised from a head, and the
# pickle opcode walk settles well inside it.
PROBE_LIMIT = 1024 * 1024
# The whole unpacked file has to be held to be scanned, so this is the ceiling on one.
MAX_DECOMPRESSED = 64 * 1024 * 1024
_CHUNK = 256 * 1024

_ERRORS = (zlib.error, OSError, EOFError, ValueError)


def _decompressor(kind: str):
    if kind == "gzip":
        return zlib.decompressobj(16 + zlib.MAX_WBITS)
    if kind == "zlib":
        return zlib.decompressobj()
    if kind == "bzip2":
        return bz2.BZ2Decompressor()
    return lzma.LZMADecompressor()


def _unpack(fh: BinaryIO, kind: str, limit: int) -> tuple[bytes, bool]:
    """Up to `limit` decompressed bytes, and whether the stream ended inside them.

    Bounded by output rather than by input, because that is the axis a decompression
    bomb moves along: a few kilobytes in, gigabytes out.
    """
    engine = _decompressor(kind)
    fh.seek(0)
    out = bytearray()
    while len(out) < limit:
        chunk = fh.read(_CHUNK)
        if not chunk:
            break
        out.extend(engine.decompress(chunk, limit - len(out)))
        if getattr(engine, "eof", False):
            return bytes(out), True
    return bytes(out), bool(getattr(engine, "eof", False))


def scan_stream(
    fh: BinaryIO, size: int, display: str, member: str | None = None,
    depth: int = 0, budget: Budget | None = None,
) -> Iterator[Finding]:
    """Unwrap, and scan what is inside with the detector every other container uses."""
    import io

    budget = budget if budget is not None else Budget()
    fh.seek(0)
    kind = compression_of(fh.read(16))
    if kind is None:  # pragma: no cover - detection already answered this
        return
    inner = f"{member}/{kind}" if member else kind
    where = Location(display, inner)

    try:
        probe, done = _unpack(fh, kind, PROBE_LIMIT)
    except _ERRORS as exc:
        yield Finding(UNCLASSIFIED, UNCLASSIFIED.default_severity,
                      f"{kind} stream could not be decompressed ({exc}), "
                      "so nothing in it was checked", where)
        return

    if not probe:
        yield Finding(UNCLASSIFIED, UNCLASSIFIED.default_severity,
                      f"{kind} stream decompressed to nothing, so nothing in it was checked",
                      where)
        return

    from modelwarden.core import detect

    # Classify the prefix. Its own length stands in for the size, which is honest for a
    # prefix: the pickle probe answers "undecided" rather than "not a pickle" when the
    # opcode stream runs past what it was given.
    if not detect.inspect_stream(io.BytesIO(probe), len(probe)).formats:
        return  # a tarball, a text file, a log: nothing a model loader opens

    if done:
        data = probe
    else:
        if not budget.take(MAX_DECOMPRESSED):
            yield Finding(UNCLASSIFIED, UNCLASSIFIED.default_severity,
                          f"the budget for decompressed bytes was spent before this {kind} "
                          "stream, so nothing in it was checked", where)
            return
        try:
            data, done = _unpack(fh, kind, MAX_DECOMPRESSED)
        except _ERRORS as exc:
            yield Finding(UNCLASSIFIED, UNCLASSIFIED.default_severity,
                          f"{kind} stream could not be decompressed ({exc}), "
                          "so nothing in it was checked", where)
            return
        if not done:
            yield Finding(UNCLASSIFIED, UNCLASSIFIED.default_severity,
                          f"{kind} stream unpacks to more than {MAX_DECOMPRESSED} bytes, "
                          "so nothing in it was checked", where)
            return

    yield from dispatch(io.BytesIO(data), len(data), display, inner, depth + 1, budget)


class CompressedScanner:
    name = "compressed"
    formats = frozenset({Format.COMPRESSED})
    # Everything reachable through the wrapper, because what comes out is dispatched to
    # whichever scanner owns it.
    rules = (
        UNCLASSIFIED, *PICKLE_RULES, *npy.NPY_RULES, *hdf5.HDF5_RULES,
        *gguf.GGUF_RULES, *onnx.ONNX_RULES, *safetensors.SafetensorsScanner.rules,
    )

    def scan(self, path: Path, display: str) -> Iterator[Finding]:
        with path.open("rb") as fh:
            yield from scan_stream(fh, path.stat().st_size, display)
