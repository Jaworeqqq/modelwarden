"""Zip, NumPy and safetensors containers. The import policy is stubbed."""
import os
import struct
import zipfile

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
