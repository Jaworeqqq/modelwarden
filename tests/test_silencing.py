"""A known defect, pinned: one bit can make a finding disappear without a word.

Fuzzing measured this rather than guessing it. Across ten finding-bearing fixtures,
198 single-bit flips leave the file detected, parsed, its evidence still present in
the bytes, and the scan completely silent — no finding and no MW-SC-064, because
nothing is malformed. The structures parse; they just describe less of the file than
it contains, and the walker believes them.

`_symbol_node` is the clearest instance: `count` comes straight from the node header
and the loop runs that many times, so a smaller count is a shorter, valid, silent
walk. ONNX fails the same way one layer down, where a length prefix or a field key
decides how much of a submessage is read.

Open defects here are marked `xfail(strict=True)` on purpose. Asserting today's
behaviour would record the bug as correctness; asserting the fix would break a released
build. This way the defect is written down, and the day somebody fixes it the marker
fails and says so.

That is exactly how the ONNX case closed. It sat here as a strict xfail with three
refuted discriminators recorded beside it; when the orphan-opset check landed, the
marker turned a silent pass into a failure and said the defect was gone. The case is a
plain parameter now.
"""
import pathlib

import builders as b
import pytest

from modelwarden.core.detect import detect_all
from modelwarden.core.engine import scan_paths

FIXTURES = b.HDF5_FIXTURES.parent


def flip(data: bytes, offset: int, bit: int) -> bytes:
    out = bytearray(data)
    out[offset] ^= 1 << bit
    return bytes(out)


# (fixture, byte, bit, the rule it should still report, the evidence that survives)
#
# Every bit here was swept rather than assumed: an earlier version of this table
# guessed bit 0 for extstorage-v3.h5, the case XPASSed, and strict=True turned that
# into a failure. What the sweep also showed is how narrow the gap is in HDF5 — at
# both offsets the other seven bits all produce MW-SC-064, so the walker is loud
# about every corruption there except one. ONNX is the reverse: five of the eight
# bits at byte 23 silence it and only three raise MW-SC-073.
SILENCED = [
    ("hdf5/extstorage-v0.h5", 142, 0, "MW-SC-061", b"/nonexistent/secret.bin"),
    ("hdf5/extstorage-v3.h5", 94, 3, "MW-SC-061", b"/nonexistent/secret.bin"),
    ("onnx/custom-domain.onnx", 23, 1, "MW-SC-072", b"ai.evil"),
]

# The same byte, the bits that do not silence. These pin the contrast: the defect is
# one specific value being believed, not general fragility at that offset.
LOUD = [
    ("hdf5/extstorage-v0.h5", 142, 1, "MW-SC-064"),
    ("hdf5/extstorage-v3.h5", 94, 0, "MW-SC-064"),
    ("onnx/custom-domain.onnx", 23, 0, "MW-SC-073"),
]


@pytest.mark.parametrize(("name", "offset", "bit", "rule", "evidence"), SILENCED,
                         ids=[s[0].split("/")[-1] for s in SILENCED])
def test_the_mutant_still_parses_and_keeps_its_evidence(name, offset, bit, rule, evidence,
                                                        tmp_path):
    """The precondition. Without this the silence would just mean "broken file"."""
    seed = (FIXTURES / name).read_bytes()
    path = b.write(tmp_path / pathlib.Path(name).name, flip(seed, offset, bit))
    assert detect_all(path), "the mutant is no longer recognised as any format"
    assert evidence in path.read_bytes(), "the mutation destroyed the evidence"
    assert scan_paths([path]).scanned == 1, "the mutant was skipped rather than parsed"


@pytest.mark.parametrize(("name", "offset", "bit", "rule"), LOUD,
                         ids=[s[0].split("/")[-1] for s in LOUD])
def test_a_neighbouring_bit_at_the_same_byte_is_reported(name, offset, bit, rule, tmp_path):
    """The contrast that makes the defect precise rather than vague.

    Corrupting the same byte a different way is caught and reported as malformed.
    The walker is not blind at these offsets — it believes exactly one value.
    """
    seed = (FIXTURES / name).read_bytes()
    path = b.write(tmp_path / pathlib.Path(name).name, flip(seed, offset, bit))
    assert rule in {f.rule.id for f in scan_paths([path]).findings}


@pytest.mark.parametrize(
    ("name", "offset", "bit", "rule", "evidence"),
    # The ONNX case was the last one open. Byte-accounting could never close it — the
    # mutant is a well-formed protobuf consuming every byte — so what closed it reads
    # the model's own declaration instead: an imported operator domain that no node
    # uses (MW-SC-072).
    SILENCED,
    ids=[s[0].split("/")[-1] for s in SILENCED],
)
def test_one_bit_should_not_silence_a_finding(name, offset, bit, rule, evidence, tmp_path):
    seed = (FIXTURES / name).read_bytes()
    assert rule in {f.rule.id for f in scan_paths([FIXTURES / name]).findings}

    path = b.write(tmp_path / pathlib.Path(name).name, flip(seed, offset, bit))
    found = {f.rule.id for f in scan_paths([path]).findings}
    # Either the finding survives, or the walker says it could not follow the file.
    assert found & {rule, "MW-SC-064", "MW-SC-073"}, (
        f"{name} byte {offset} bit {bit}: {evidence!r} is still in the file and "
        f"nothing at all was reported"
    )
