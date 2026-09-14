"""Known-dangerous and known-safe pickle imports, from maintained upstream lists.

PICKLESCAN_UNSAFE and PICKLESCAN_SAFE are verbatim copies of `_unsafe_globals`
and `_safe_globals` from picklescan (src/picklescan/scanner.py, snapshot taken
2026-09-10; MIT License, Copyright (c) 2022 Matthieu Maitre, see
THIRD_PARTY_NOTICES.md). Keep them verbatim so new upstream releases can be
diffed in, and put modelwarden's own entries in MODELWARDEN_UNSAFE.

Values are "*" for a whole module, or a set of attribute names, where a dotted
name is an attribute path ("InteractiveInterpreter.runcode").
"""
from __future__ import annotations

from collections.abc import Mapping

from modelwarden.core.findings import Severity

PICKLESCAN_UNSAFE: dict[str, str | set[str]] = {
    "__builtin__": {"eval", "compile", "getattr", "apply", "exec", "open", "breakpoint"},
    "builtins": {"eval", "compile", "getattr", "apply", "exec", "open", "breakpoint"},
    "cloudpickle.cloudpickle": {
        "_builtin_type", "_make_function", "_function_setstate",
        "_make_cell", "_make_empty_cell", "subimport",
    },
    "types": {"CodeType"},
    "aiohttp": "*",
    "asyncio": "*",
    "bdb": "*",
    "commands": "*",
    "ctypes": "*",
    "functools": {"partial"},
    "httplib": "*",
    "logging": {"FileHandler"},
    "_io": {"FileIO"},
    "numpy.f2py": "*",
    "numpy.testing._private.utils": "*",
    "nt": "*",
    "posix": "*",
    "_operator": {"attrgetter", "itemgetter", "methodcaller"},
    "operator": {"attrgetter", "itemgetter", "methodcaller"},
    "os": "*",
    "requests.api": "*",
    "runpy": "*",
    "shutil": "*",
    "socket": "*",
    "ssl": "*",
    "subprocess": "*",
    "sys": "*",
    "code": {"InteractiveInterpreter.runcode"},
    "cProfile": "*",
    "distutils.file_util": "*",
    "doctest": {"debug_script"},
    "ensurepip": {"_run_pip"},
    "idlelib.autocomplete": {"AutoComplete.get_entity", "AutoComplete.fetch_completions"},
    "idlelib.calltip": {"Calltip.fetch_tip", "get_entity"},
    "idlelib.debugobj": {"ObjectTreeItem.SetText"},
    "idlelib.pyshell": {"ModifiedInterpreter.runcode", "ModifiedInterpreter.runcommand"},
    "idlelib.run": {"Executive.runcode"},
    "imaplib": {"IMAP4_stream"},
    "lib2to3.pgen2.grammar": {"Grammar.loads"},
    "lib2to3.pgen2.pgen": {"ParserGenerator.make_label"},
    "pdb": "*",
    "pickle": "*",
    "_pickle": "*",
    "pip": "*",
    "pkgutil": {"resolve_name"},
    "pty": "*",
    "profile": "*",
    "pydoc": "*",
    "test": "*",
    "timeit": "*",
    "torch._dynamo.guards": {"GuardBuilder.get"},
    "torch._inductor.codecache": {"compile_file"},
    "torch.fx.experimental.symbolic_shapes": {"ShapeEnv.evaluate_guards_expression"},
    "torch.jit.unsupported_tensor_ops": {"execWrapper"},
    "torch.serialization": {"load"},
    "torch.utils._config_module": {"ConfigModule.load_config"},
    "torch.utils.bottleneck.__main__": {"run_cprofile", "run_autograd_prof"},
    "torch.utils.collect_env": {"run"},
    "torch.utils.data.datapipes.utils.decoder": {"basichandlers"},
    "trace": {"Trace.run", "Trace.runctx"},
    "urllib.request": "*",
    "uuid": "*",
    "venv": "*",
    "webbrowser": "*",
    "_osx_support": "*",
    "_aix_support": "*",
    "_pyrepl": "*",
}

PICKLESCAN_SAFE: dict[str, set[str]] = {
    "collections": {"OrderedDict"},
    "torch": {
        "LongStorage",
        "FloatStorage",
        "HalfStorage",
        "QUInt2x4Storage",
        "QUInt4x2Storage",
        "QInt32Storage",
        "QInt8Storage",
        "QUInt8Storage",
        "ComplexFloatStorage",
        "ComplexDoubleStorage",
        "DoubleStorage",
        "BFloat16Storage",
        "BoolStorage",
        "CharStorage",
        "ShortStorage",
        "IntStorage",
        "ByteStorage",
    },
    "numpy": {
        "dtype",
        "ndarray",
    },
    "numpy._core.multiarray": {
        "_reconstruct",
    },
    "numpy.core.multiarray": {
        "_reconstruct",
    },
    "torch._utils": {"_rebuild_tensor_v2"},
}

# Not in picklescan's list. modelscan's unsafe_globals (protectai/modelscan) was used
# as a cross-check: picklescan covers every one of its entries except __import__.
_ATTRIBUTE_GADGETS = {"__import__", "setattr", "delattr", "vars", "globals", "locals"}
MODELWARDEN_UNSAFE: dict[str, str | set[str]] = {
    "__builtin__": _ATTRIBUTE_GADGETS,
    "builtins": _ATTRIBUTE_GADGETS,
    "torch.hub": "*",        # hub.load downloads a repository and runs its hubconf.py
    "importlib": "*",        # import_module reaches any module by name
    "marshal": "*",          # loads raw code objects
    "multiprocessing": "*",  # starts processes
}


def _paths(*sources: Mapping[str, str | set[str]]) -> frozenset[str]:
    """Every entry as one dotted path: "os" for a whole module, "functools.partial" for a name."""
    paths: set[str] = set()
    for source in sources:
        for module, names in source.items():
            if names == "*":
                paths.add(module)
            else:
                paths.update(f"{module}.{name}" for name in names)
    return frozenset(paths)


_UNSAFE_PATHS = _paths(PICKLESCAN_UNSAFE, MODELWARDEN_UNSAFE)

UPSTREAM_SAFE: frozenset[tuple[str, str]] = frozenset(
    (module, name) for module, names in PICKLESCAN_SAFE.items() for name in names
)


def dangerous_severity(module: str, name: str) -> Severity | None:
    """CRITICAL when module.name is, or lies inside, a known-dangerous entry.

    Matching is on dotted-path boundaries: "os" covers "os.path.join" but not
    "osmium", and "functools.partial" does not cover "functools.partialmethod".
    A protocol 4 name is judged by its full path, so ("torch", "serialization.load")
    matches the entry for torch.serialization.load.
    """
    parts = f"{module}.{name}".split(".")
    if any(".".join(parts[:i]) in _UNSAFE_PATHS for i in range(1, len(parts) + 1)):
        return Severity.CRITICAL
    return None
