"""Opcode-level analysis: what a pickle imports, independent of the import policy."""
import io
import pickle
from collections import OrderedDict

import builders as b
import pytest

from modelwarden.core.findings import Severity
from modelwarden.scanners.supply_chain.pickle import analyse, findings_for


def run(data: bytes):
    report = analyse(io.BytesIO(data), end=len(data))
    return report, {(ref.module, ref.name) for ref in report.imports}


@pytest.mark.parametrize(
    "payload",
    [
        b.global_call("os", "system"),
        b.proto0_call("os", "system"),
        b.stack_global_call("os", "system"),
        b.stack_global_via_memo("os", "system"),
    ],
    ids=["global", "protocol0", "stack_global", "stack_global_via_memo"],
)
def test_import_is_found_whatever_the_encoding(payload):
    report, found = run(payload)
    assert ("os", "system") in found
    assert report.error is None


def test_dotted_protocol4_name_is_kept_whole():
    _, found = run(b.stack_global_call("torch", "hub.load"))
    assert ("torch", "hub.load") in found


def test_module_computed_at_load_time_is_unresolved():
    report, found = run(b.stack_global_computed())
    assert ("builtins", "str") in found
    assert [u.opcode for u in report.unresolved] == ["STACK_GLOBAL"]


def test_extension_registry_is_unresolved():
    report, _ = run(b.ext_call())
    assert [u.opcode for u in report.unresolved] == ["EXT1"]


@pytest.mark.parametrize(
    ("payload", "opcode"),
    [(b.stack_global_computed(), "STACK_GLOBAL"), (b.ext_call(), "EXT1")],
    ids=["computed module name", "extension registry"],
)
def test_an_unresolved_import_becomes_a_finding(payload, opcode):
    """The two tests above check the analyser; this checks that the analysis reaches
    the report. An audit found MW-SC-002 named in no test: the opcode walk was
    covered and the step that turns `report.unresolved` into a HIGH finding was not,
    so the rule could have stopped being emitted without a test noticing.
    """
    report, _ = run(payload)
    unresolved = [f for f in findings_for(report, "x.pkl") if f.rule.id == "MW-SC-002"]
    assert [f.severity for f in unresolved] == [Severity.HIGH]
    assert opcode in unresolved[0].message


def test_payload_after_a_benign_pickle_is_found():
    report, found = run(b.plain_data() + b.global_call("os", "system"))
    assert ("os", "system") in found
    assert report.chunks == 2
    assert report.imports[-1].chunk == 1


def test_truncated_stream_keeps_imports_seen_before_the_error():
    report, found = run(b.global_call("os", "system")[:-1])  # no STOP
    assert ("os", "system") in found
    assert report.error is not None


def test_raw_bytes_after_the_pickle_are_not_an_error():
    report, _ = run(b.plain_data() + b"\x00\xff" * 8)
    assert report.error is None
    assert report.chunks == 1


def test_stack_underflow_is_malformed():
    report, _ = run(b"R.")  # REDUCE on an empty stack
    assert report.error is not None


def _recursive():
    items = []
    items.append(items)
    return items


SAMPLES = [
    {"a": [1, 2.5, None, True]},
    OrderedDict(x=1),
    {1, 2},
    frozenset({3}),
    b"bytes" * 10,
    bytearray(b"xy"),
    ("t", ("nested",)),
    2**100,
    "ünïcode",
]


@pytest.mark.parametrize("protocol", range(pickle.HIGHEST_PROTOCOL + 1))
def test_real_pickles_parse_cleanly(protocol):
    # Guards the stack emulation: a wrong stack effect for any opcode would turn
    # ordinary pickles into "malformed" or "unresolved" false positives.
    for obj in [*SAMPLES, _recursive()]:
        data = pickle.dumps(obj, protocol=protocol)
        report, _ = run(data)
        assert report.error is None, (obj, report.error)
        assert not report.unresolved, obj
