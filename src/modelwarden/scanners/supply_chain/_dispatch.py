"""One place that maps a detected format to the scanner that reads it from a stream.

A container is anything that hands the scanner bytes it did not read off disk: a zip
member, a gzip stream, whatever comes next. Every one of them needs the same two steps
— classify the bytes, then hand them to whichever scanner owns the format — and the
cost of each container doing that for itself is already on the record. `archive.py`
carried its own three-way classifier and five payload classes out of seven survived
being placed inside a zip. The fix was to stop having a second classifier; adding a
third container with a third copy would rebuild the same defect on purpose.

So the dispatch lives here, and both `archive` and `compressed` call it. Anything that
learns to unwrap a new container gets every format for free, and gets them right.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import BinaryIO

from modelwarden.core import detect
from modelwarden.core.detect import Format
from modelwarden.core.findings import Finding, Location, Severity
from modelwarden.core.rules import NOT_ANALYSED

# How far a container inside a container inside a container is followed. Past anything
# a real toolchain produces, and short enough that a crafted nest cannot spend the scan.
MAX_NESTING = 4
# Total decompressed bytes one top-level file may materialise. A per-member limit
# bounds one step and not the walk: a thousand members, or a nest, each pass their own
# check. A decompression bomb is exactly that shape, so the ceiling has to be
# cumulative and carried through the recursion.
TOTAL_BUFFER_LIMIT = 512 * 1024 * 1024


class Budget:
    """What is left of TOTAL_BUFFER_LIMIT, carried through the whole nest."""

    def __init__(self, total: int = TOTAL_BUFFER_LIMIT):
        self.remaining = total

    def take(self, size: int) -> bool:
        if size > self.remaining:
            return False
        self.remaining -= size
        return True


def dispatch(
    stream: BinaryIO, size: int, display: str, member: str | None, depth: int, budget: Budget,
) -> list[Finding]:
    """Every format the bytes plausibly are, scanned — the engine's rule, one layer down.

    Collected eagerly per format because the scanners are generators sharing one
    stream: a lazy second format would read from wherever the first one stopped.
    """
    found: list[Finding] = []
    for fmt in detect.inspect_stream(stream, size).formats:
        found.extend(scan_as(fmt, stream, size, display, member, depth, budget))
    return found


def scan_as(
    fmt: Format, stream: BinaryIO, size: int, display: str, member: str | None, depth: int,
    budget: Budget,
) -> Iterable[Finding]:
    # Imported inside the function: these modules import this one back, and the cycle
    # only exists at call time. Same reason core.detect imports its sniffers lazily.
    from modelwarden.scanners.supply_chain import archive, gguf, hdf5, npy, onnx, safetensors
    from modelwarden.scanners.supply_chain.pickle import analyse, findings_for

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
    if fmt is Format.COMPRESSED:
        from modelwarden.scanners.supply_chain import compressed

        return compressed.scan_stream(stream, size, display, member, depth, budget)
    if fmt is Format.ZIP:
        if depth >= MAX_NESTING:
            return [Finding(NOT_ANALYSED, Severity.MEDIUM,
                            f"container nested more than {MAX_NESTING} deep, not followed",
                            Location(display, member))]
        prefix = f"{member}/" if member else ""
        return list(archive.scan_zip(stream, display, prefix, depth + 1, budget))
    # MCP tool lists and client configurations are recognised by core.detect and
    # deliberately not scanned here: they are not members a model loader opens, and
    # JSON inside a checkpoint is that checkpoint's configuration rather than a tool
    # list somebody approved. A Keras config.json is handled by archive.py, by name.
    return []
