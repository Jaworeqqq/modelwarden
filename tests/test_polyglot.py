"""Files that are two formats at once, and the loader-versus-scanner gap they open.

`zipfile` finds an archive by its central directory at the tail, so an archive can
be preceded by arbitrary bytes and still open. Every front below once hid the same
malicious archive completely: the scanner read the front, `torch.load` would read
the archive. These tests exist so that cannot come back.
"""
import io
import zipfile

import builders as b
import pytest

from modelwarden.core.detect import Format, detect_all
from modelwarden.core.engine import scan_paths


def malicious_zip() -> bytes:
    """What torch.save writes, with a payload in the pickle it stores."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("archive/data.pkl", b.global_call("os", "system"))
        archive.writestr("archive/version", "3\n")
    return buf.getvalue()


def fronts() -> dict[str, bytes]:
    return {
        "pickle": b.plain_data(),
        "torch-state-dict": b.torch_state_dict(),
        "numpy": b.npy("|u1", b"\x00"),
        "gguf": b.gguf([b.gg_kv_str("general.name", "x")]),
        "hdf5": (b.HDF5_FIXTURES / "plain-v3.h5").read_bytes(),
        "safetensors": b.safetensors({"w": b.f32(1, 0)}, b"\x00" * 4),
    }


@pytest.mark.parametrize("front", sorted(fronts()))
def test_a_decoy_in_front_does_not_hide_the_archive(front, tmp_path):
    path = b.write(tmp_path / "model.pt", fronts()[front] + malicious_zip())
    ids = {f.rule.id for f in scan_paths([path]).findings}
    assert "MW-SC-001" in ids, f"the payload behind a {front} front went unreported"
    assert "MW-GEN-005" in ids


@pytest.mark.parametrize("front", sorted(fronts()))
def test_the_archive_is_resolved_first(front, tmp_path):
    # A loader resolves the zip, so the scanner must put it first rather than settling
    # on whatever the first sixteen bytes happen to look like.
    path = b.write(tmp_path / "model.pt", fronts()[front] + malicious_zip())
    formats = detect_all(path)
    assert formats[0] is Format.ZIP
    assert len(formats) > 1


def test_an_ordinary_file_matches_exactly_one_format(tmp_path):
    # The rule must have nothing to say about honest files; across the committed
    # fixtures none matches two formats.
    for name, data in (("plain.pkl", b.plain_data()), ("model.pt", malicious_zip())):
        path = b.write(tmp_path / name, data)
        assert len(detect_all(path)) == 1
        assert "MW-GEN-005" not in {f.rule.id for f in scan_paths([path]).findings}


def test_a_benign_polyglot_is_still_reported(tmp_path):
    # No payload anywhere: the overlap alone is the finding, because one model file
    # is one format and this is two.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("archive/data.pkl", b.plain_data())
    path = b.write(tmp_path / "model.pt", b.plain_data() + buf.getvalue())
    ids = {f.rule.id for f in scan_paths([path]).findings}
    assert ids == {"MW-GEN-005"}


def test_a_corrupt_archive_still_reaches_the_zip_scanner(tmp_path):
    # Matching on tail structure alone would drop archives that cannot be opened, and
    # those are exactly the ones worth reporting.
    broken = b"PK\x03\x04" + b"\x00" * 40
    path = b.write(tmp_path / "model.pt", broken)
    assert Format.ZIP in detect_all(path)
    assert "MW-SC-010" in {f.rule.id for f in scan_paths([path]).findings}
