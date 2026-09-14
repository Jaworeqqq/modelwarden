"""ONNX: files written by the real onnx package (tests/fixtures/onnx, see generate.py)."""
from pathlib import Path

import builders as b
import pytest

from modelwarden.core.detect import Format, detect
from modelwarden.core.engine import scan_paths
from modelwarden.core.findings import Severity
from modelwarden.scanners.supply_chain.onnx import _escapes

FIXTURES = Path(__file__).parent / "fixtures" / "onnx"


def findings(path):
    return scan_paths([path]).findings


def rule_ids(path):
    return sorted(f.rule.id for f in findings(path))


def test_real_onnx_is_detected_by_content():
    # No magic bytes: detection sniffs the ModelProto shape.
    assert detect(FIXTURES / "clean.onnx") is Format.ONNX


def test_clean_model_has_no_findings():
    assert rule_ids(FIXTURES / "clean.onnx") == []


def test_external_data_within_the_directory_is_low():
    [finding] = findings(FIXTURES / "extdata-ok.onnx")
    assert (finding.rule.id, finding.severity) == ("MW-SC-071", Severity.LOW)
    assert finding.evidence == "weights.bin"


@pytest.mark.parametrize(
    "name", ["extdata-parent", "extdata-absolute", "extdata-subdir-escape"],
)
def test_external_data_escaping_the_directory_is_high(name):
    [finding] = findings(FIXTURES / f"{name}.onnx")
    assert (finding.rule.id, finding.severity) == ("MW-SC-070", Severity.HIGH)


def test_custom_operator_domain():
    # Exactly one finding: this model declares ai.evil *and* uses it, so the node walk
    # reports it and the orphan check below must stay quiet rather than report it twice.
    [finding] = findings(FIXTURES / "custom-domain.onnx")
    assert (finding.rule.id, finding.evidence) == ("MW-SC-072", "ai.evil")


def test_a_domain_the_model_imports_but_no_node_uses(tmp_path):
    """One flipped bit used to silence MW-SC-072 entirely, and this is the case.

    Byte 23 is the NodeProto.domain field header. Flipping bit 1 turns field 7 wire 2
    into field 7 wire 0, so the walk reads a varint where the domain was: "ai.evil"
    stays in the file byte for byte, the protobuf still parses and still consumes every
    byte, and no node carries a domain any more. Three byte-accounting discriminators
    were tried against that and all three failed, because on every such metric the
    mutant and the clean file are identical.

    What survives untouched is the model's own opset_import. Importing an operator set
    is a statement that loading needs that runtime, so an imported domain no node uses
    is reported on its own.
    """
    mutant = bytearray((FIXTURES / "custom-domain.onnx").read_bytes())
    mutant[23] ^= 1 << 1
    path = b.write(tmp_path / "custom-domain.onnx", bytes(mutant))

    [finding] = findings(path)
    assert (finding.rule.id, finding.evidence) == ("MW-SC-072", "ai.evil")


def test_the_orphan_check_is_silent_on_every_clean_fixture():
    """The false-positive side, which is the half that decides whether a rule ships.

    Measured when the check was written: every fixture here and a real 86 MB
    all-MiniLM-L6-v2 declare the empty domain only, so none of them fires it.
    """
    for path in sorted(FIXTURES.glob("*.onnx")):
        if path.name == "custom-domain.onnx":
            continue
        assert "MW-SC-072" not in rule_ids(path), path.name


@pytest.mark.parametrize(
    ("location", "escapes"),
    [
        ("weights.bin", False),
        ("sub/weights.bin", False),
        ("./data/w.bin", False),
        ("a/../b.bin", False),          # stays inside
        ("../secret", True),
        ("a/../../secret", True),
        ("/etc/passwd", True),
        ("C:\\Windows\\x", True),
        ("\\\\server\\share", True),
        ("foo/../../bar", True),
    ],
)
def test_escape_detection(location, escapes):
    assert _escapes(location) is escapes


def test_malformed_protobuf(tmp_path):
    # Detects as ONNX (ir_version varint + a well-formed graph field), but the graph's
    # own bytes are a truncated varint, so the full parse fails.
    data = b"\x08\x0d" + b"\x3a\x02\x08\xff"  # ir_version=13; graph = {field1: <truncated>}
    path = b.write(tmp_path / "model.onnx", data)
    assert detect(path) is Format.ONNX
    assert rule_ids(path) == ["MW-SC-073"]


def test_non_onnx_protobuf_is_not_detected(tmp_path):
    # Field 1 is length-delimited, not a varint: not a ModelProto.
    path = b.write(tmp_path / "x.onnx", b"\x0a\x03abc")
    assert detect(path) is Format.UNKNOWN


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _model_with_graph(body: bytes) -> bytes:
    """A ModelProto: ir_version=6, then field 7 carrying `body` as the graph."""
    return b"\x08\x06" + b"\x3a" + _varint(len(body)) + body


def test_a_model_whose_graph_outgrows_the_sniff_limit_is_still_detected(tmp_path):
    """The shape every real export has, and the one no committed fixture had.

    Detection reads a bounded prefix, and a real graph is nearly the whole file, so
    the graph's payload always runs past that prefix. Refusing the field there made
    the sniffer answer "not ONNX": the canonical 90 MB all-MiniLM-L6-v2 export was
    reported as `MW-GEN-001 content of this .onnx file matches no supported format`,
    severity LOW, exit 0 — a blind spot dressed as a clean result, with three ONNX
    rules sitting unreachable behind it.

    The fixtures in tests/fixtures/onnx are real files written by the onnx package,
    so the "confront it with the real library" step had been done. They are all
    small, so their graph fits the prefix, and the missing dimension was size.
    """
    from modelwarden.core.detect import ONNX_SNIFF_LIMIT

    filler = ONNX_SNIFF_LIMIT * 2
    graph = b"\x12" + _varint(filler) + b"a" * filler  # GraphProto.name, oversized
    path = b.write(tmp_path / "big.onnx", _model_with_graph(graph))

    assert path.stat().st_size > ONNX_SNIFF_LIMIT
    assert detect(path) is Format.ONNX
    assert rule_ids(path) == []  # and the full parse still reads it as clean


def test_tolerating_truncation_does_not_make_every_large_file_a_model(tmp_path):
    # The risk the fix introduces, pinned: a huge length-delimited field alone is not
    # a ModelProto. ir_version as a varint is still required.
    data = b"\x3a" + _varint(1 << 20) + b"a" * 128
    path = b.write(tmp_path / "x.onnx", data)
    assert detect(path) is Format.UNKNOWN
