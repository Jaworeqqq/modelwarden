"""Zip, NumPy and safetensors containers. The import policy is stubbed."""
import bz2
import gzip
import lzma
import os
import struct
import zipfile
import zlib

import builders as b
import pytest

from modelwarden.core.engine import scan_paths
from modelwarden.core.findings import Severity

pytestmark = pytest.mark.usefixtures("stub_policy")


def rule_ids(path):
    return sorted(f.rule.id for f in scan_paths([path]).findings)


def findings(path):
    return scan_paths([path]).findings


# --- zip / torch.save ---------------------------------------------------------

def test_payload_in_data_pkl(tmp_path):
    path = b.torch_zip(tmp_path / "model.pt", b.global_call("os", "system"))
    [finding] = findings(path)
    assert finding.rule.id == "MW-SC-001"
    assert finding.location.member == "archive/data.pkl"


def test_benign_archive_with_pickle_like_storage_is_clean(tmp_path):
    path = b.torch_zip(tmp_path / "model.pt", b.plain_data())
    assert rule_ids(path) == []


def test_pickle_under_an_unexpected_name_is_found_by_header(tmp_path):
    extra = {"archive/extra/config.bin": b.global_call("os", "system")}
    path = b.torch_zip(tmp_path / "model.pt", b.plain_data(), extra)
    assert rule_ids(path) == ["MW-SC-001"]


def test_member_with_bad_crc_is_reported_and_still_scanned(tmp_path):
    path = b.torch_zip(tmp_path / "model.pt", b.global_call("os", "system"))
    data = path.read_bytes()
    assert data.count(b.PAYLOAD.encode()) == 1
    path.write_bytes(data.replace(b.PAYLOAD.encode(), b"echo-mX"))
    assert rule_ids(path) == ["MW-SC-001", "MW-SC-011"]


def test_torchscript_source_is_flagged(tmp_path):
    extra = {"archive/code/__torch__/model.py": b"def forward(self, x):\n    return x\n"}
    path = b.torch_zip(tmp_path / "model.pt", b.plain_data(), extra)
    assert rule_ids(path) == ["MW-SC-012"]


def test_broken_zip_is_not_clean(tmp_path):
    path = b.write(tmp_path / "model.pt", b"PK\x03\x04" + b"\x00" * 64)
    assert rule_ids(path) == ["MW-SC-010"]


def test_npz_with_object_array(tmp_path):
    path = tmp_path / "arrays.npz"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("arr_0.npy", b.npy("|O", b.global_call("os", "system")))
    assert rule_ids(path) == ["MW-SC-001", "MW-SC-020"]


# --- NumPy ----------------------------------------------------------------------

def test_object_array_payload(tmp_path):
    path = b.write(tmp_path / "a.npy", b.npy("|O", b.global_call("os", "system")))
    assert rule_ids(path) == ["MW-SC-001", "MW-SC-020"]


def test_numeric_array_is_clean(tmp_path):
    path = b.write(tmp_path / "a.npy", b.npy("<f4", b"\x00" * 4))
    assert rule_ids(path) == []


def test_structured_field_named_like_object_is_clean(tmp_path):
    path = b.write(tmp_path / "a.npy", b.npy([("Offset", "<f4")], b"\x00" * 4))
    assert rule_ids(path) == []


def test_structured_object_field_is_flagged(tmp_path):
    path = b.write(tmp_path / "a.npy", b.npy([("x", "<f4"), ("y", "|O")], b.plain_data()))
    assert rule_ids(path) == ["MW-SC-020"]


def test_oversized_npy_header(tmp_path):
    path = b.write(tmp_path / "a.npy", b"\x93NUMPY\x02\x00" + struct.pack("<I", 50_000) + b" " * 16)
    assert rule_ids(path) == ["MW-SC-021"]


# --- safetensors ----------------------------------------------------------------

def test_valid_safetensors_is_clean(tmp_path):
    path = b.write(tmp_path / "m.safetensors", b.safetensors({"w": b.f32(2, 0)}, b"\x00" * 8))
    assert rule_ids(path) == []


@pytest.mark.parametrize(
    ("tensors", "data"),
    [
        ({"w": b.f32(4, 0)}, b"\x00" * 8),                    # past the end of the buffer
        ({"w": b.f32(2, 0), "v": b.f32(2, 4)}, b"\x00" * 12),  # overlap
        ({"w": {"dtype": "F32", "shape": [3], "data_offsets": [0, 8]}}, b"\x00" * 8),  # size
    ],
    ids=["out_of_range", "overlap", "size_mismatch"],
)
def test_inconsistent_layout(tmp_path, tensors, data):
    path = b.write(tmp_path / "m.safetensors", b.safetensors(tensors, data))
    assert "MW-SC-032" in rule_ids(path)


def test_trailing_bytes_are_unclaimed(tmp_path):
    path = b.write(tmp_path / "m.safetensors", b.safetensors({"w": b.f32(1, 0)}, b"\x00" * 12))
    [finding] = findings(path)
    assert (finding.rule.id, finding.severity) == ("MW-SC-033", Severity.LOW)


def test_pickle_hidden_between_tensors(tmp_path):
    hidden = b.global_call("os", "system")
    tensors = {"a": b.f32(1, 0), "z": b.f32(1, 4 + len(hidden))}
    data = b"\x00" * 4 + hidden + b"\x00" * 4
    path = b.write(tmp_path / "m.safetensors", b.safetensors(tensors, data))
    assert rule_ids(path) == ["MW-SC-001", "MW-SC-033"]


def test_duplicate_header_keys(tmp_path):
    entry = '{"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}'
    header = f'{{"w": {entry}, "w": {entry}}}'.encode()
    path = b.write(tmp_path / "m.safetensors", b.safetensors({}, b"\x00" * 4, raw_header=header))
    assert rule_ids(path) == ["MW-SC-031"]


def test_header_bomb(tmp_path):
    # A sparse file: the declared size is real, but nothing is written to disk.
    length = 200_000_000
    path = b.write(tmp_path / "m.safetensors", struct.pack("<Q", length) + b"{")
    os.truncate(path, 8 + length)
    assert rule_ids(path) == ["MW-SC-030"]


# --- compressed wrappers ----------------------------------------------------------
#
# `joblib.dump(..., compress=3)` writes a zlib stream with a pickle inside, and
# `pickle.load(gzip.open(path))` is an ordinary line to write. The payload executes on
# load exactly as it would bare. Before this existed, .pkl.gz / .bz2 / .xz carrying
# os.system were counted as skipped and reported nothing, and a zlib one under a
# .joblib name got MW-GEN-001 — low, under the default --fail-on, so a gate passed it.

@pytest.mark.parametrize(
    ("suffix", "pack"),
    [
        (".pkl.gz", gzip.compress),
        (".joblib", zlib.compress),   # what joblib writes at compress=3
        (".pkl.bz2", bz2.compress),
        (".pkl.xz", lzma.compress),
    ],
    ids=["gzip", "zlib", "bzip2", "xz"],
)
def test_a_pickle_behind_a_compressor_is_still_reported(suffix, pack, tmp_path):
    path = b.write(tmp_path / f"model{suffix}", pack(b.global_call("os", "system")))
    assert "MW-SC-001" in rule_ids(path)


def test_the_finding_names_the_wrapper_it_came_from(tmp_path):
    path = b.write(tmp_path / "model.pkl.gz", gzip.compress(b.global_call("os", "system")))
    [finding] = [f for f in findings(path) if f.rule.id == "MW-SC-001"]
    assert finding.location.member == "gzip"


@pytest.mark.parametrize(
    ("name", "payload"),
    [
        ("notes.txt.gz", b"just some release notes\n" * 40),
        ("config.json.gz", b'{"lr": 0.001, "epochs": 10}'),
        ("weights.pt.gz", None),  # a benign torch state dict, filled in below
    ],
)
def test_an_honest_compressed_file_stays_clean(name, payload, tmp_path):
    data = b.torch_state_dict() if payload is None else payload
    assert rule_ids(b.write(tmp_path / name, gzip.compress(data))) == []


def test_a_truncated_compressed_stream_is_not_clean(tmp_path):
    # Fail closed: a wrapper that cannot be opened has had nothing checked inside it.
    whole = gzip.compress(b.global_call("os", "system"))
    path = b.write(tmp_path / "model.pkl.gz", whole[:-6])
    assert "MW-GEN-006" in rule_ids(path)


def test_a_stream_that_unpacks_past_the_ceiling_is_not_clean(tmp_path, monkeypatch):
    from modelwarden.scanners.supply_chain import compressed

    monkeypatch.setattr(compressed, "PROBE_LIMIT", 4)
    monkeypatch.setattr(compressed, "MAX_DECOMPRESSED", 8)
    path = b.write(tmp_path / "model.pkl.gz", gzip.compress(b.global_call("os", "system")))
    assert "MW-GEN-006" in rule_ids(path)


def test_an_archive_of_blobs_is_not_mistaken_for_a_pickle(tmp_path):
    """A filename is a complete pickle if you squint, and the detector used to squint.

    `blob0.bin` reads as BUILD, LIST, OBJ, BUILD, POP, STOP — six valid opcodes ending
    at byte 5, none of them carrying an argument. A 60 MB tar of random blobs was
    classified as a pickle on the strength of its first member's name and reported
    MW-SC-003, with no container involved at all. Requiring one argument-bearing opcode
    separates a stream that produces a value from a stream that merely parses.
    """
    import io
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for i in range(3):
            blob = bytes(range(256)) * 8
            info = tarfile.TarInfo(f"blob{i}.bin")
            info.size = len(blob)
            tar.addfile(info, io.BytesIO(blob))
    raw = buf.getvalue()
    assert raw[:9] == b"blob0.bin"
    assert rule_ids(b.write(tmp_path / "source.tar", raw)) == []
    assert rule_ids(b.write(tmp_path / "source.tar.gz", gzip.compress(raw))) == []
