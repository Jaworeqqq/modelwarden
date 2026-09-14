"""ONNX: a protobuf ModelProto. The attack surface is external_data paths and custom ops.

A tensor with data_location EXTERNAL names a file in external_data[location].
onnx.load reads that file, and every path-traversal CVE against onnx is a
location that escapes the model directory: "../../../etc/passwd", an absolute
path, or (in later bypasses) a symlink or hardlink pointing out of tree. The
scanner reads paths from the protobuf and never opens them, so it catches the
"../" and absolute cases directly and flags anything it cannot prove is contained.

Custom operator domains are reported too: a non-standard op needs a matching
runtime library, which is code that runs at inference.
"""
from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path, PurePosixPath, PureWindowsPath

from modelwarden.core.detect import Format
from modelwarden.core.findings import Finding, Location, Rule, Severity
from modelwarden.scanners.supply_chain._protobuf import (
    ProtobufError,
    message_fields,
    text,
)
from modelwarden.scanners.supply_chain.pickle import ATLAS, OWASP

EXTERNAL_ESCAPE = Rule(
    "MW-SC-070",
    "ONNX external data escapes the model directory",
    "A tensor's external_data location is an absolute path or reaches outside the model "
    "directory with '..'. onnx.load reads that file (CVE-2022-25882, CVE-2024-27318).",
    Severity.HIGH, ATLAS, OWASP,
)
EXTERNAL_DATA = Rule(
    "MW-SC-071",
    "ONNX tensor stored in an external file",
    "A tensor's data lives in a separate file read on load. The path stays within the "
    "model directory, but on load it must still be checked for symlinks and hardlinks "
    "pointing out of tree (CVE-2026-27489, CVE-2026-34446, CVE-2026-34447).",
    Severity.LOW, ATLAS, OWASP,
)
CUSTOM_OP = Rule(
    "MW-SC-072",
    "ONNX custom operator domain",
    "A node uses an operator outside the standard ONNX domains, so loading the model "
    "requires a matching custom runtime library, which is code that runs at inference.",
    Severity.MEDIUM, ATLAS, OWASP,
)
MALFORMED = Rule(
    "MW-SC-073",
    "Malformed ONNX protobuf",
    "The protobuf could not be parsed, so the model was not analysed.",
    Severity.MEDIUM, ATLAS, OWASP,
)
ONNX_RULES = (EXTERNAL_ESCAPE, EXTERNAL_DATA, CUSTOM_OP, MALFORMED)

# ModelProto / GraphProto / NodeProto / TensorProto field numbers (onnx.proto3).
_MODEL_OPSET_IMPORT, _MODEL_GRAPH, _MODEL_FUNCTIONS = 8, 7, 25
_OPSET_DOMAIN = 1
_GRAPH_NODE, _GRAPH_INITIALIZER, _GRAPH_SPARSE_INITIALIZER = 1, 5, 15
_NODE_OP_TYPE, _NODE_DOMAIN, _NODE_ATTRIBUTE = 4, 7, 5
_ATTR_G, _ATTR_T, _ATTR_GRAPHS, _ATTR_TENSORS = 6, 5, 11, 10
_SPARSE_VALUES = 1
_TENSOR_EXTERNAL_DATA, _TENSOR_DATA_LOCATION, _TENSOR_NAME = 13, 14, 8
_LOCATION_EXTERNAL = 1
# Standard operator-set domains. Everything else needs a third-party runtime.
STANDARD_DOMAINS = frozenset({
    "", "ai.onnx", "ai.onnx.ml", "ai.onnx.training", "ai.onnx.preview.training",
})
MAX_DEPTH = 64  # subgraph nesting; a self-referential protobuf cannot exceed the byte length anyway


class ONNXScanner:
    name = "onnx"
    formats = frozenset({Format.ONNX})
    rules = ONNX_RULES

    def scan(self, path: Path, display: str) -> Iterator[Finding]:
        yield from scan_onnx(path.read_bytes(), display)


def scan_onnx(data: bytes, display: str, member: str | None = None) -> Iterator[Finding]:
    where = Location(display, member)
    try:
        model = message_fields(data)
        yield from _model(model, display, member)
    except ProtobufError as exc:
        yield Finding(MALFORMED, MALFORMED.default_severity, f"cannot parse protobuf: {exc}", where)


def _model(model: dict[int, list[object]], display: str, member: str | None) -> Iterator[Finding]:
    declared: set[str] = set()
    for opset in model.get(_MODEL_OPSET_IMPORT, []):
        if isinstance(opset, (bytes, bytearray)):
            declared.add(text(message_fields(opset), _OPSET_DOMAIN) or "")

    used: set[str] = set()
    for graph in model.get(_MODEL_GRAPH, []):
        if isinstance(graph, (bytes, bytearray)):
            yield from _graph(graph, display, member, depth=0, used=used)
    for func in model.get(_MODEL_FUNCTIONS, []):
        if isinstance(func, (bytes, bytearray)):
            yield from _nodes(message_fields(func), display, member, used)

    # What the model says it needs, checked against what the walk actually reached.
    #
    # A node's domain lives in one field header, and one flipped bit turns that header
    # into a different field: the domain string stays in the file byte for byte, but the
    # walk no longer attributes it to anything, and the file remains a valid protobuf
    # consuming every byte. Three byte-accounting discriminators were tried against that
    # mutant and all three failed, because clean and mutated files are identical on every
    # such metric. This is the semantic one, and it reads the model's own declaration:
    # importing an operator set is a statement that loading needs that runtime, whether
    # or not a node was reached that uses it.
    #
    # The orphan condition is what keeps it quiet. A model that genuinely uses a custom
    # operator reports it from the node walk above and is excluded here, so nothing is
    # reported twice. Measured across every fixture and a real 86 MB model: all declare
    # the empty domain only, and none of them fires this.
    where = Location(display, member)
    for domain in sorted(declared - STANDARD_DOMAINS - used):
        message = (f"model imports operator domain {domain!r}, which no node uses -- "
                   "the domain is declared but the walk reached nothing that needs it")
        yield Finding(CUSTOM_OP, CUSTOM_OP.default_severity, message, where, domain)


def _graph(
    data: bytes, display: str, member: str | None, depth: int, used: set[str]
) -> Iterator[Finding]:
    if depth > MAX_DEPTH:
        return
    graph = message_fields(data)
    where = Location(display, member)

    for raw in graph.get(_GRAPH_INITIALIZER, []):
        if isinstance(raw, (bytes, bytearray)):
            yield from _tensor(raw, where)
    for raw in graph.get(_GRAPH_SPARSE_INITIALIZER, []):
        if isinstance(raw, (bytes, bytearray)):
            for values in message_fields(raw).get(_SPARSE_VALUES, []):
                if isinstance(values, (bytes, bytearray)):
                    yield from _tensor(values, where)

    yield from _nodes(graph, display, member, used)
    # Attributes can hold subgraphs (If, Loop, Scan) and tensors of their own.
    for raw in graph.get(_GRAPH_NODE, []):
        if isinstance(raw, (bytes, bytearray)):
            yield from _node_subgraphs(message_fields(raw), display, member, depth, used)


def _nodes(
    container: dict[int, list[object]], display: str, member: str | None, used: set[str]
) -> Iterator[Finding]:
    where = Location(display, member)
    seen: set[str] = set()
    for raw in container.get(_GRAPH_NODE, []):
        if not isinstance(raw, (bytes, bytearray)):
            continue
        node = message_fields(raw)
        domain = text(node, _NODE_DOMAIN) or ""
        # Recorded before the skip below, so a standard domain still counts as reached.
        used.add(domain)
        if domain in STANDARD_DOMAINS or domain in seen:
            continue
        seen.add(domain)
        op = text(node, _NODE_OP_TYPE) or "?"
        message = f"custom operator domain {domain!r} (e.g. {op})"
        yield Finding(CUSTOM_OP, CUSTOM_OP.default_severity, message, where, domain)


def _node_subgraphs(
    node: dict[int, list[object]], display: str, member: str | None, depth: int, used: set[str]
) -> Iterator[Finding]:
    for raw in node.get(_NODE_ATTRIBUTE, []):
        if not isinstance(raw, (bytes, bytearray)):
            continue
        attr = message_fields(raw)
        for sub in (*attr.get(_ATTR_G, []), *attr.get(_ATTR_GRAPHS, [])):
            if isinstance(sub, (bytes, bytearray)):
                yield from _graph(sub, display, member, depth + 1, used)
        for tensor in (*attr.get(_ATTR_T, []), *attr.get(_ATTR_TENSORS, [])):
            if isinstance(tensor, (bytes, bytearray)):
                yield from _tensor(tensor, Location(display, member))


def _tensor(data: bytes, where: Location) -> Iterator[Finding]:
    tensor = message_fields(data)
    if _LOCATION_EXTERNAL not in {v for v in tensor.get(_TENSOR_DATA_LOCATION, [])}:
        return
    name = text(tensor, _TENSOR_NAME) or "?"
    location = _external_location(tensor)
    if location is None:
        yield Finding(EXTERNAL_DATA, EXTERNAL_DATA.default_severity,
                      f"tensor {name!r} is external but names no location", where)
        return
    if _escapes(location):
        message = (f"tensor {name!r} loads external data from {location!r}, "
                   "outside the model directory")
        yield Finding(EXTERNAL_ESCAPE, EXTERNAL_ESCAPE.default_severity, message, where, location)
    else:
        message = f"tensor {name!r} loads external data from {location!r}"
        yield Finding(EXTERNAL_DATA, EXTERNAL_DATA.default_severity, message, where, location)


def _external_location(tensor: dict[int, list[object]]) -> str | None:
    for entry in tensor.get(_TENSOR_EXTERNAL_DATA, []):
        if isinstance(entry, (bytes, bytearray)):
            kv = message_fields(entry)
            if text(kv, 1) == "location":  # StringStringEntryProto key
                return text(kv, 2)
    return None


def _escapes(location: str) -> bool:
    """True when the location is absolute or climbs above the model directory."""
    if PurePosixPath(location).is_absolute() or PureWindowsPath(location).is_absolute():
        return True
    # Normalise "/" and "\" and resolve ".." against the segments seen so far.
    depth = 0
    for part in location.replace("\\", "/").split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            depth -= 1
            if depth < 0:
                return True
        else:
            depth += 1
    return False
