"""Format detection by content, never by file extension — and never just one guess.

Loaders decide by content: `torch.load` checks for a zip, and `pickle.load` never
looks at the file name. A scanner that trusts extensions is bypassed by renaming
`model.pkl` to `model.safetensors`.

Deciding by content is necessary and not sufficient. A file can be two formats at
once, and then the only question that matters is which one the *loader* will read.
`zipfile` finds an archive by its central directory at the tail, so a file that opens
as a zip need not begin with `PK`: put a harmless pickle in front of a malicious
archive and a scanner reading sixteen bytes from the start sees a pickle, while
`torch.load` sees the archive and runs what is inside it. Measured against this
package before the change: five such files out of six, all reported clean.

So detection returns every format a file plausibly is, in the order a loader would
resolve them, and the engine scans all of them. A single guess is structurally
unsound: being wrong once means reporting on a file nobody will ever load.
"""
from __future__ import annotations

import enum
import io
import pickletools
import struct
import zipfile
from dataclasses import dataclass
from pathlib import Path

ZIP_MAGIC = b"PK\x03\x04"
NUMPY_MAGIC = b"\x93NUMPY"
GGUF_MAGIC = b"GGUF"
HDF5_MAGIC = b"\x89HDF\r\n\x1a\n"

# Protocol 2+ pickles open with PROTO (0x80) followed by the protocol number.
PICKLE_PROTOCOLS = range(2, 6)

# Protocol 0/1 pickles have no header. They are recognised by parsing the opcode
# stream up to STOP, but only within this many leading bytes.
HEADERLESS_PROBE_LIMIT = 16 * 1024 * 1024


class Format(enum.Enum):
    ZIP = "zip"
    PICKLE = "pickle"
    NUMPY = "numpy"
    SAFETENSORS = "safetensors"
    GGUF = "gguf"
    HDF5 = "hdf5"
    ONNX = "onnx"
    MCP_TOOLS = "mcp-tools"
    MCP_CONFIG = "mcp-config"
    UNKNOWN = "unknown"


# A tools/list result is JSON, so it is recognised by shape rather than by magic.
MCP_SNIFF_LIMIT = 16 * 1024 * 1024


# ONNX is a protobuf ModelProto with no magic bytes. It is recognised by its
# shape: field 1 (ir_version) as a varint, then field 7 (graph) or 8 (opset).
ONNX_SNIFF_LIMIT = 64 * 1024


def has_pickle_header(head: bytes) -> bool:
    return len(head) >= 2 and head[0] == 0x80 and head[1] in PICKLE_PROTOCOLS


def opens_as_zip(path: Path) -> bool:
    """Whether `zipfile` can open it, which is how a loader decides.

    Deliberately not a magic-byte check. `zipfile` locates an archive by the end of
    central directory record at the *tail*, so an archive can be preceded by
    arbitrary bytes and still load. That gap is the polyglot bypass.
    """
    try:
        with zipfile.ZipFile(path) as archive:
            archive.namelist()
    except (zipfile.BadZipFile, OSError, ValueError, NotImplementedError):
        return False
    return True


@dataclass(frozen=True)
class Detection:
    """What a file is — and, where that could not be settled, what stopped it.

    `undecided` carries the difference between "this is not that format" and "the
    scanner stopped looking". Classification runs over bounded reads, and a file large
    enough to outrun one of them used to be answered "no format at all", which for an
    unlisted extension meant silence: padding a poisoned MCP tool list past the limit
    removed its findings and left `skipped: 1` behind. A reason recorded here is
    reported instead, because a limit that bit is a gap in the scan.
    """

    formats: list[Format]
    undecided: tuple[str, ...] = ()


def inspect(path: Path) -> Detection:
    """Every format this file plausibly is, and every limit that cut the search short."""
    size = path.stat().st_size
    with path.open("rb") as fh:
        head = fh.read(16)

    matches: list[Format] = []
    undecided: list[str] = []
    # First, because it is what a loader resolves first and what a front-magic check
    # misses. The magic test stays as well: a corrupt archive still belongs to the zip
    # scanner, which reports that it could not be opened rather than ignoring it.
    if head.startswith(ZIP_MAGIC) or opens_as_zip(path):
        matches.append(Format.ZIP)
    if head.startswith(NUMPY_MAGIC):
        matches.append(Format.NUMPY)
    if head.startswith(GGUF_MAGIC):
        matches.append(Format.GGUF)
    if hdf5_superblock_offset(path, size) is not None:
        matches.append(Format.HDF5)
    # Before the pickle check: a safetensors header length can start with 0x80.
    if _looks_like_safetensors(head, size):
        matches.append(Format.SAFETENSORS)
    if has_pickle_header(head):
        matches.append(Format.PICKLE)
    elif head:
        verdict = _parses_as_pickle(path, size)
        if verdict is None:
            undecided.append(
                f"the opcode stream had not reached STOP within the first "
                f"{HEADERLESS_PROBE_LIMIT} bytes, so a headerless pickle is not ruled out"
            )
        elif verdict:
            matches.append(Format.PICKLE)
    if head.lstrip()[:1] in (b"{", b"["):
        if size > MCP_SNIFF_LIMIT:
            undecided.append(
                f"JSON of {size} bytes is over the {MCP_SNIFF_LIMIT}-byte limit for "
                "recognising MCP tool lists and client configurations"
            )
        else:
            json_format = _looks_like_mcp_json(path, size)
            if json_format is not None:
                matches.append(json_format)
    if not matches and _looks_like_onnx(path):
        matches.append(Format.ONNX)
    return Detection(matches, tuple(undecided))


def detect_all(path: Path) -> list[Format]:
    """Every format this file plausibly is, most loader-authoritative first."""
    return inspect(path).formats


def detect(path: Path) -> Format:
    """The format a loader would settle on, or UNKNOWN."""
    matches = detect_all(path)
    return matches[0] if matches else Format.UNKNOWN


def _looks_like_safetensors(head: bytes, size: int) -> bool:
    # 8-byte little-endian header length, then a JSON object. The length has to
    # fit in the file, otherwise any JSON file with "{" at byte 8 would match.
    if len(head) < 9:
        return False
    (length,) = struct.unpack("<Q", head[:8])
    return head[8:9] == b"{" and 2 <= length <= size - 8


def hdf5_superblock_offset(path: Path, size: int | None = None) -> int | None:
    """Where the HDF5 superblock starts, or None if this is not an HDF5 file."""
    from modelwarden.scanners.supply_chain.hdf5 import superblock_offset

    if size is None:
        size = path.stat().st_size
    with path.open("rb") as fh:
        return superblock_offset(fh, size)


def _looks_like_mcp_json(path: Path, size: int) -> Format | None:
    """Tell a tools/list result from a client configuration, or neither."""
    import json

    from modelwarden.scanners.agents.mcp import extract_tools
    from modelwarden.scanners.agents.mcp_config import extract_servers

    if size > MCP_SNIFF_LIMIT:
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, RecursionError, OSError):
        return None

    if extract_servers(document) is not None:
        return Format.MCP_CONFIG

    tools = extract_tools(document)
    # Every entry must look like a Tool: a name, plus a description or an input schema.
    if tools and all(
        isinstance(t, dict) and isinstance(t.get("name"), str)
        and ("description" in t or "inputSchema" in t)
        for t in tools
    ):
        return Format.MCP_TOOLS
    return None


def _looks_like_onnx(path: Path) -> bool:
    # Avoid importing the scanner at module load; detection stays dependency-free.
    from modelwarden.scanners.supply_chain._protobuf import ProtobufError, iter_fields

    with path.open("rb") as fh:
        head = fh.read(ONNX_SNIFF_LIMIT)
    seen_ir_version = False
    seen_graph_or_opset = False
    try:
        # allow_truncated, because the graph of a real model is very nearly the whole
        # file: the canonical all-MiniLM-L6-v2 export declares a graph of 90,387,579
        # bytes in a 90,387,606-byte file. A strict walk refuses that field for running
        # past the prefix and the sniffer concludes "not ONNX", so every model larger
        # than the sniff limit was reported as an unrecognised file — LOW, exit 0.
        for field_number, wire_type, _value in iter_fields(head, allow_truncated=True):
            if field_number == 1 and wire_type == 0:  # ir_version, varint
                seen_ir_version = True
            elif field_number in (7, 8) and wire_type == 2:  # graph or opset_import
                seen_graph_or_opset = True
            elif field_number == 1:
                return False  # ir_version present but not a varint: not a ModelProto
    except ProtobufError:
        # Truncated because we only read a prefix: enough if the head already matched.
        return seen_ir_version and seen_graph_or_opset
    return seen_ir_version and seen_graph_or_opset


def _parses_as_pickle(path: Path, size: int) -> bool | None:
    """True, False, or None where the prefix ran out before the opcode stream did.

    The third answer is the point. A bad opcode means this is not a pickle; reaching
    the edge of the prefix mid-stream means the question was never answered, and
    returning False for both let a 16 MB protocol-0 pickle pass as an unknown file.
    """
    with path.open("rb") as fh:
        data = fh.read(HEADERLESS_PROBE_LIMIT)
    opcodes = 0
    try:
        for opcode, _arg, _pos in pickletools.genops(io.BytesIO(data)):
            opcodes += 1
            if opcode.name == "STOP":
                return opcodes >= 2
    except ValueError:
        return None if size > len(data) and opcodes >= 2 else False
    return None if size > len(data) and opcodes >= 2 else False
