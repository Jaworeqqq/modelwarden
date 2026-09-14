"""Detection measured against gadgets other security projects publish.

Every other test here checks the scanner against samples this project invented,
which only ever proves the scanner agrees with its author. These pairs come from
somewhere else: picklescan's fixture generator (MIT) and the advisory-linked bypass
suite in fickling (LGPL-3.0, used here as a list of names and nothing else). Each
one defeated some scanner at some point, and several carry a GHSA of their own.

Nothing is downloaded and nothing is executed. Each pickle is assembled locally from
raw opcodes, exactly as builders.py does for every other test, and the conftest
tripwire forbids unpickling anywhere in the suite.
"""
import pickle
import struct

import builders as b
import pytest

from modelwarden.core.engine import scan_paths
from modelwarden.core.findings import Severity
from modelwarden.scanners.supply_chain.pickle import classify_global

# Callables reachable through __reduce__, as published by picklescan and fickling.
GADGETS = [
    ("builtins", "eval"), ("os", "system"), ("http.client", "HTTPSConnection"),
    ("requests", "get"), ("aiohttp", "ClientSession"), ("socket", "create_connection"),
    ("subprocess", "run"), ("sys", "exit"), ("pickle", "loads"),
    ("runpy", "_run_code"), ("bdb", "Bdb"), ("pip", "main"),
    ("pydoc", "pipepager"), ("venv", "create"), ("timeit", "timeit"),
    ("pkgutil", "resolve_name"), ("torch", "load"),
    ("torch.utils.collect_env", "run"),
    ("torch.utils.bottleneck.__main__", "run_cprofile"),
    ("torch._dynamo.guards", "GuardBuilder"),
    ("torch.fx.experimental.symbolic_shapes", "ShapeEnv"),
    ("torch.utils.data.datapipes.utils.decoder", "basichandlers"),
    ("torch._inductor.codecache", "compile_file"),
    ("trace", "Trace"), ("profile", "Profile"), ("code", "InteractiveInterpreter"),
    ("pgen2.grammar", "Grammar"), ("idlelib.tree", "ObjectTreeItem"),
    ("idlelib.autocomplete", "AutoComplete"), ("idlelib.calltip", "Calltip"),
    # Bypasses with advisories of their own.
    ("builtins", "__import__"), ("_operator", "methodcaller"), ("ftplib", "FTP"),
    ("imaplib", "IMAP4"), ("nntplib", "NNTP"), ("poplib", "POP3"), ("smtplib", "SMTP"),
    ("telnetlib", "Telnet"), ("_xxsubinterpreters", "run_string"), ("marshal", "loads"),
    ("types", "CodeType"), ("ctypes", "CDLL"), ("importlib", "import_module"),
    ("multiprocessing", "Process"), ("cProfile", "run"), ("pty", "spawn"),
    ("distutils.file_util", "write_file"),
]


def worst(findings):
    return max((f.severity for f in findings), default=None)


@pytest.mark.parametrize(("module", "name"), GADGETS, ids=lambda v: v.replace(".", "_"))
def test_every_published_gadget_is_reported(module, name, tmp_path):
    path = b.write(tmp_path / "model.pkl", b.global_call(module, name))
    level = worst(scan_paths([path]).findings)
    assert level is not None and level >= Severity.HIGH


@pytest.mark.parametrize(
    "build",
    [b.global_call, b.proto0_call, b.stack_global_call, b.stack_global_via_memo],
    ids=["GLOBAL", "protocol0", "STACK_GLOBAL", "STACK_GLOBAL_via_memo"],
)
def test_one_gadget_through_every_opcode_path(build, tmp_path):
    # A denylist that only reads GLOBAL misses the same import written four other ways.
    path = b.write(tmp_path / "model.pkl", build("os", "system"))
    assert worst(scan_paths([path]).findings) is Severity.CRITICAL


def framed(body: bytes, declared: int) -> bytes:
    """A FRAME whose declared length disagrees with the opcodes inside it.

    Reported upstream as python/cpython#154848: `pickle.load` and a scanner reading
    the same bytes can disagree about where an opcode ends.
    """
    return pickle.PROTO + b"\x05" + pickle.FRAME + struct.pack("<Q", declared) + body


@pytest.mark.parametrize(
    ("label", "payload"),
    [
        ("global-module", framed(pickle.GLOBAL + b"macos\nsystem\n", 4)),
        ("global-attr", framed(pickle.GLOBAL + b"os\nsystem\n", 7)),
        ("short-binunicode", framed(b"\x8c\x14" + b"A" * 20, 3)),
        ("binint", framed(pickle.BININT + struct.pack("<i", 7), 2)),
    ],
)
def test_a_frame_that_straddles_its_own_boundary_is_not_silent(label, payload, tmp_path):
    # The point is not which rule fires but that something does. A parser trick that
    # makes the scanner read different bytes than the loader must fail closed.
    path = b.write(tmp_path / "model.pkl", payload)
    found = scan_paths([path]).findings
    assert found, f"{label} produced no finding at all"
    assert "MW-SC-003" in {f.rule.id for f in found}


def test_a_safe_global_stays_safe():
    # _codecs.encode is how protocol 2 writes bytes objects. fickling allowlists it
    # too; agreeing with another scanner on a benign pair is worth pinning.
    assert classify_global("_codecs", "encode") is None


def test_the_allowlist_does_not_widen_to_dotted_names():
    # A dotted attribute under an allowlisted pair is not itself allowlisted.
    assert classify_global("collections", "OrderedDict") is None
    assert classify_global("collections", "OrderedDict.fromkeys") is Severity.HIGH


@pytest.mark.parametrize(
    ("module", "name", "expected"),
    [
        ("os", "system", Severity.CRITICAL),
        ("os", "systemfoo", Severity.CRITICAL),   # inside a module marked dangerous whole
        ("os.path", "join", Severity.CRITICAL),   # likewise, and deliberately so
        ("osfoo", "system", Severity.HIGH),       # not inside it: unknown, not dangerous
    ],
)
def test_dangerous_modules_match_on_dotted_boundaries(module, name, expected):
    assert classify_global(module, name) is expected
