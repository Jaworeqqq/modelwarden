"""NumPy files written by real numpy (tests/fixtures/npy, see generate.py).

The synthetic cases live in test_containers.py; these guard against real numpy
output drifting away from what the scanner expects.
"""
from pathlib import Path

import pytest

from modelwarden.core.engine import scan_paths
from modelwarden.core.findings import Severity

FIXTURES = Path(__file__).parent / "fixtures" / "npy"


def findings(name):
    return scan_paths([FIXTURES / name]).findings


def rule_ids(name):
    return sorted(f.rule.id for f in findings(name))


@pytest.mark.parametrize(
    "name",
    ["float32.npy", "fortran.npy", "structured.npy", "arrays.npz", "arrays-compressed.npz"],
)
def test_ordinary_arrays_are_clean(name):
    assert rule_ids(name) == []


@pytest.mark.parametrize(("name", "member"), [("object.npy", None), ("object.npz", "obj.npy")])
def test_object_arrays_are_reported(name, member):
    # numpy.load refuses these without allow_pickle=True, because the data is a pickle.
    [finding] = findings(name)
    assert (finding.rule.id, finding.severity) == ("MW-SC-020", Severity.MEDIUM)
    assert finding.location.member == member


def test_header_above_numpy_own_limit():
    # A legitimate 2000-field dtype, but numpy.load refuses it by default.
    [finding] = findings("big-header.npy")
    assert finding.rule.id == "MW-SC-021"
    assert "numpy.load refuses" in finding.message
