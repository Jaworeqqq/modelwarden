"""Test setup: import the package from src/ and forbid deserialisation.

The scanner must never unpickle what it scans. Instead of trusting code review,
every test runs with pickle's loading entry points replaced by tripwires
(test_boundary.py adds a static check for imports that would dodge them).
"""
import pickle
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))
sys.path.insert(0, str(HERE))  # for `import builders`


# `--jobs` moves work between processes, and multiprocessing's transport is itself
# pickle: the parent sends Paths, the worker sends Findings back. That is modelwarden's
# own data, never bytes taken from a scanned file, so the claim being defended is the
# narrower one the docstring makes -- nothing *under scan* is deserialised.
#
# The exemption is deliberately given to the transport rather than to the worker: a
# forked worker inherits these tripwires, so the scanning code stays covered on both
# sides of the fork. `pickle.loads` is captured here, before the fixture replaces it.
_TRANSPORT = ("multiprocessing", "concurrent.futures")
_real_loads = pickle.loads


def _forbidden(*args, **kwargs):
    caller = sys._getframe(1).f_globals.get("__name__", "")
    if caller.startswith(_TRANSPORT):
        return _real_loads(*args, **kwargs)
    raise AssertionError("modelwarden tried to unpickle scanned data")


class _Tripwire:
    def __init__(self, *args, **kwargs):
        _forbidden()


@pytest.fixture(autouse=True)
def forbid_unpickling(monkeypatch):
    monkeypatch.setattr(pickle, "load", _forbidden)
    monkeypatch.setattr(pickle, "loads", _forbidden)
    monkeypatch.setattr(pickle, "Unpickler", _Tripwire)
    monkeypatch.setattr(pickle, "_Unpickler", _Tripwire)


@pytest.fixture
def stub_policy(monkeypatch):
    """Minimal import policy, so container tests don't depend on the real one."""
    from modelwarden.core.findings import Severity
    from modelwarden.scanners.supply_chain import pickle as pickle_scan

    def classify(module, name):
        return Severity.CRITICAL if module in {"os", "posix", "nt"} else None

    monkeypatch.setattr(pickle_scan, "classify_global", classify)
