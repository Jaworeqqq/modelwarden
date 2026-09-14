"""Static analysis of pickle streams. Nothing here ever unpickles.

pickle is a stack machine: GLOBAL and STACK_GLOBAL import any attribute of any
module, and REDUCE calls it. Loading a pickle means running a program, so the
only safe analysis is to read the opcode stream without executing it.
"""
from __future__ import annotations

import pickletools
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from modelwarden.core.detect import Format
from modelwarden.core.findings import Finding, Location, Rule, Severity
from modelwarden.core.policy import user_allowed
from modelwarden.scanners.supply_chain.unsafe_globals import UPSTREAM_SAFE, dangerous_severity

ATLAS = ("AML.T0010.003", "AML.T0011.000")
OWASP = ("LLM03:2025",)

IMPORT = Rule(
    "MW-SC-001",
    "Pickle imports a callable",
    "Loading the pickle imports a module attribute; together with REDUCE this runs "
    "arbitrary code. Severity comes from the import policy (classify_global).",
    Severity.HIGH, ATLAS, OWASP,
)
UNRESOLVED = Rule(
    "MW-SC-002",
    "Pickle import cannot be resolved statically",
    "STACK_GLOBAL operands are not literal strings, or EXT1/2/4 loads a callable from "
    "copyreg's extension registry. The target is only known at load time, which is "
    "exactly how scanners are evaded.",
    Severity.HIGH, ATLAS, OWASP,
)
MALFORMED = Rule(
    "MW-SC-003",
    "Malformed pickle stream",
    "Parsing stopped before a clean STOP. Unpicklers execute opcodes as they read them, "
    "so everything before the error would still run, and loaders more lenient than the "
    "scanner are a known bypass.",
    Severity.MEDIUM, ATLAS, OWASP,
)
PICKLE_RULES = (IMPORT, UNRESOLVED, MALFORMED)

_MARK = object()
_UNKNOWN = object()

_STRING_OPS = frozenset({
    "STRING", "BINSTRING", "SHORT_BINSTRING",
    "UNICODE", "BINUNICODE", "SHORT_BINUNICODE", "BINUNICODE8",
})
_GET_OPS = frozenset({"GET", "BINGET", "LONG_BINGET"})
_PUT_OPS = frozenset({"PUT", "BINPUT", "LONG_BINPUT"})
_EXT_OPS = frozenset({"EXT1", "EXT2", "EXT4"})


@dataclass(frozen=True)
class ImportRef:
    module: str
    name: str
    offset: int | None
    opcode: str
    chunk: int  # index of the pickle within a stream of back-to-back pickles


@dataclass(frozen=True)
class Unresolved:
    offset: int | None
    opcode: str
    detail: str
    chunk: int


@dataclass
class PickleReport:
    imports: list[ImportRef] = field(default_factory=list)
    unresolved: list[Unresolved] = field(default_factory=list)
    error: tuple[int | None, str] | None = None
    chunks: int = 0


class MalformedPickle(ValueError):
    def __init__(self, offset: int | None, message: str):
        super().__init__(message)
        self.offset = offset


def analyse(stream: BinaryIO, end: int | None = None) -> PickleReport:
    """Walk the pickles in `stream`, starting at its current position.

    Pickles can sit back to back (legacy torch.save writes several), so walking
    continues after STOP until `end`; without `end` only the first one is read.
    Only a broken opcode stream is absorbed into the report. I/O errors propagate,
    because the container (e.g. a zip with a bad CRC) is the caller's to report.
    """
    report = PickleReport()
    chunk = 0
    while True:
        try:
            _walk(stream, chunk, report)
        except MalformedPickle as exc:
            # A broken first pickle is a finding. Past the first one, a parse error
            # usually just means raw tensor bytes follow the pickles.
            if chunk == 0:
                report.error = (exc.offset, str(exc))
            break
        report.chunks += 1
        chunk += 1
        if end is None or stream.tell() >= end:
            break
    return report


def _walk(stream: BinaryIO, chunk: int, report: PickleReport) -> None:
    stack: list[object] = []
    memo: dict[int, object] = {}
    offset: int | None = None
    try:
        for opcode, arg, offset in pickletools.genops(stream):
            name = opcode.name
            if name in _STRING_OPS:
                stack.append(arg)
            elif name in ("GLOBAL", "INST"):
                module, _, attr = arg.partition(" ")
                report.imports.append(ImportRef(module, attr, offset, name, chunk))
                _apply(stack, opcode)
            elif name == "STACK_GLOBAL":
                attr, module = _pop(stack), _pop(stack)
                if isinstance(module, str) and isinstance(attr, str):
                    report.imports.append(ImportRef(module, attr, offset, name, chunk))
                else:
                    detail = "operands are not literal strings"
                    report.unresolved.append(Unresolved(offset, name, detail, chunk))
                stack.append(_UNKNOWN)
            elif name in _EXT_OPS:
                detail = f"extension registry code {arg}"
                report.unresolved.append(Unresolved(offset, name, detail, chunk))
                stack.append(_UNKNOWN)
            elif name in _GET_OPS:
                if arg not in memo:
                    raise ValueError(f"memo key {arg} was never stored")
                stack.append(memo[arg])
            elif name in _PUT_OPS:
                memo[arg] = _peek(stack)
            elif name == "MEMOIZE":
                memo[len(memo)] = _peek(stack)
            else:
                _apply(stack, opcode)
    except ValueError as exc:
        raise MalformedPickle(offset, str(exc)) from exc


def _apply(stack: list[object], opcode: pickletools.OpcodeInfo) -> None:
    """Generic stack effect, driven by pickletools' own opcode metadata."""
    before = opcode.stack_before
    if opcode.name == "POP" and stack and stack[-1] is _MARK:
        stack.pop()
        return
    if pickletools.markobject in before:
        # The topmost MARK and everything above it are consumed together.
        while True:
            if not stack:
                raise ValueError(f"{opcode.name} without a matching MARK")
            if stack.pop() is _MARK:
                break
        count = before.index(pickletools.markobject)
    else:
        count = len(before)
    for _ in range(count):
        _pop(stack)
    for item in opcode.stack_after:
        stack.append(_MARK if item is pickletools.markobject else _UNKNOWN)


def _pop(stack: list[object]) -> object:
    # Like the C unpickler: nothing below the last MARK can be popped.
    if not stack or stack[-1] is _MARK:
        raise ValueError("stack underflow")
    return stack.pop()


def _peek(stack: list[object]) -> object:
    if not stack or stack[-1] is _MARK:
        raise ValueError("memo store with nothing to store")
    return stack[-1]


def findings_for(report: PickleReport, path: str, member: str | None = None) -> Iterator[Finding]:
    by_global: dict[tuple[str, str], list[ImportRef]] = {}
    for ref in report.imports:
        by_global.setdefault((ref.module, ref.name), []).append(ref)

    for (module, name), refs in by_global.items():
        severity = classify_global(module, name)
        if severity is None:
            continue
        first = refs[0]
        message = f"pickle imports {module}.{name} via {first.opcode}"
        if len(refs) > 1:
            message += f" ({len(refs)} occurrences)"
        if first.chunk:
            message += f" in pickle #{first.chunk + 1} of the stream"
        # module:name is unambiguous where module.name is not: ("torch", "hub.load").
        evidence = f"{module}:{name}"
        yield Finding(IMPORT, severity, message, Location(path, member, first.offset), evidence)

    for item in report.unresolved:
        where = Location(path, member, item.offset)
        message = f"{item.opcode}: {item.detail}"
        yield Finding(UNRESOLVED, UNRESOLVED.default_severity, message, where)

    if report.error:
        offset, detail = report.error
        where = Location(path, member, offset)
        message = f"pickle stream is malformed ({detail}); opcodes before it were still analysed"
        yield Finding(MALFORMED, MALFORMED.default_severity, message, where)


class PickleScanner:
    name = "pickle"
    formats = frozenset({Format.PICKLE})
    rules = PICKLE_RULES

    def scan(self, path: Path, display: str) -> Iterator[Finding]:
        size = path.stat().st_size
        with path.open("rb") as fh:
            report = analyse(fh, end=size)
        yield from findings_for(report, display)


# --- Import policy -----------------------------------------------------------
#
# Everything above finds WHAT a pickle imports. The policy below decides how bad
# that is. It is the part that makes or breaks the scanner, in both directions.

# Globals that ordinary checkpoints need. Match exact (module, name) pairs:
# protocol 4 resolves dotted names attribute by attribute, so ("torch", "Size")
# is harmless while ("torch", "hub.load") downloads and runs code.
SAFE_GLOBALS: frozenset[tuple[str, str]] = frozenset({
    ("collections", "OrderedDict"),
    ("torch._utils", "_rebuild_tensor"),
    ("torch._utils", "_rebuild_tensor_v2"),
    ("torch._utils", "_rebuild_parameter"),
    ("torch._utils", "_rebuild_parameter_with_state"),
    ("torch", "Size"),
    ("torch", "UntypedStorage"),
    *(("torch", f"{kind}Storage") for kind in (
        "Float", "Double", "Half", "BFloat16", "Long", "Int", "Short",
        "Char", "Byte", "Bool", "ComplexFloat", "ComplexDouble",
    )),
    ("numpy", "dtype"),
    ("numpy", "ndarray"),
    ("numpy.core.multiarray", "_reconstruct"),
    ("numpy.core.multiarray", "scalar"),
    ("numpy._core.multiarray", "_reconstruct"),
    ("numpy._core.multiarray", "scalar"),
    ("_codecs", "encode"),  # protocol 2 encodes bytes objects through it
    ("builtins", "set"),
    ("builtins", "frozenset"),
    ("builtins", "slice"),
    ("builtins", "complex"),
    ("builtins", "bytearray"),
    ("copyreg", "_reconstructor"),
})

# Plus picklescan's maintained list of what checkpoints need (unsafe_globals.py).
SAFE_GLOBALS = SAFE_GLOBALS | UPSTREAM_SAFE

# Python 2 names that protocol 0-2 pickles still use for the same modules.
_ALIASES = {"__builtin__": "builtins", "copy_reg": "copyreg"}


def classify_global(module: str, name: str) -> Severity | None:
    """Decide how bad it is for a pickle (or a Keras config) to import `module.name`.

    An allowlist: anything not known to be needed is HIGH, because a denylist
    lets every gadget nobody listed through (picklescan was bypassed by
    `pip.main`, `runpy._run_code`, `numpy.testing._private.utils.runstring`).

    - built-in allowlist, exact (module, name) pairs -> None (no finding)
    - known dangerous -> CRITICAL; the user's allowlist cannot silence these
    - allowed by the user (--allow) -> INFO, so it stays visible in reports
    - anything else -> HIGH

    The known-dangerous list is picklescan's `_unsafe_globals` plus a few
    additions (unsafe_globals.py). It matches on dotted-path boundaries, so "os"
    covers "os.path" but not "osmium", and ("torch", "hub.load") is judged as
    torch.hub.load. Exact matching of the allowlist means walking attributes
    from a safe global, like ("collections", "OrderedDict.__init__"), is unknown.
    """
    module = _ALIASES.get(module, module)
    if (module, name) in SAFE_GLOBALS:
        return None
    severity = dangerous_severity(module, name)
    if severity is not None:
        return severity
    if user_allowed(module, name):
        return Severity.INFO
    return Severity.HIGH
