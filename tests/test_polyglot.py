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


SSTI = "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}"


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


# --- the same gap, one layer down -------------------------------------------------
#
# Detection at the top of a file was fixed first; members of an archive kept their own
# three-way classifier (npy, hdf5, pickle-by-header-or-name) and returned nothing at
# all for everything else. Measured against that version, five of the seven payload
# classes below reported nothing after being moved inside a zip. The two that already
# worked are kept as controls: a table where every row is expected to fail proves
# nothing about the harness.

FIXTURES = b.HDF5_FIXTURES.parent


def hidden_pickle_safetensors() -> bytes:
    payload = b.global_call("os", "system")
    tensors = {"a": b.f32(1, 0), "z": b.f32(1, 4 + len(payload))}
    return b.safetensors(tensors, b"\x00" * 4 + payload + b"\x00" * 4)


BURIED = {
    # control: the member kind the old classifier did recognise
    "hdf5": ("x/m.h5", (FIXTURES / "hdf5/extlink-v3.h5").read_bytes(), "MW-SC-060"),
    "onnx": ("x/m.onnx", (FIXTURES / "onnx/custom-domain.onnx").read_bytes(), "MW-SC-072"),
    "gguf": ("x/m.gguf", b.gguf([b.gg_kv_str("tokenizer.chat_template", SSTI)]), "MW-SC-042"),
    "safetensors": ("x/w.safetensors", hidden_pickle_safetensors(), "MW-SC-001"),
    "nested-zip": ("x/inner.pt", malicious_zip(), "MW-SC-001"),
    # No header and a name that is not *.pkl, so neither of the old checks fired.
    "headerless-pickle": ("x/data", b.proto0_call("os", "system"), "MW-SC-001"),
}


@pytest.mark.parametrize("kind", sorted(BURIED))
def test_a_payload_inside_an_archive_is_still_reported(kind, tmp_path):
    name, blob, rule = BURIED[kind]
    path = b.torch_zip(tmp_path / "model.pt", b.torch_state_dict(), {name: blob})
    ids = {f.rule.id for f in scan_paths([path]).findings}
    assert rule in ids, f"a {kind} payload buried in an archive went unreported"


@pytest.mark.parametrize("kind", sorted(BURIED))
def test_a_buried_payload_is_located_in_its_member(kind, tmp_path):
    # Reporting the archive is not enough to act on: the finding has to name the member
    # that carries the payload, or nobody can tell which file to remove.
    name, blob, rule = BURIED[kind]
    path = b.torch_zip(tmp_path / "model.pt", b.torch_state_dict(), {name: blob})
    located = [f for f in scan_paths([path]).findings if f.rule.id == rule]
    assert located and all(f.location.member and name in f.location.member for f in located)


def test_a_nest_of_archives_stops_at_the_depth_limit(tmp_path):
    from modelwarden.scanners.supply_chain.archive import MAX_NESTING

    blob = malicious_zip()
    for _ in range(MAX_NESTING + 2):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as archive:
            archive.writestr("archive/inner.pt", blob)
        blob = buf.getvalue()
    path = b.write(tmp_path / "nest.pt", blob)
    ids = {f.rule.id for f in scan_paths([path]).findings}
    # Not followed to the bottom, and not silent about stopping.
    assert "MW-GEN-002" in ids


def test_a_compressed_member_too_large_to_hold_is_still_read_as_a_pickle(tmp_path, monkeypatch):
    """The fallback that keeps a wide silence from becoming a narrow one.

    Detection needs to seek, and a large compressed member gives no way to. Pickles are
    read front to back and never needed one, which is how every member was scanned
    before this module learned to detect properly — so the sequential path stays.
    """
    from modelwarden.scanners.supply_chain import archive as archive_mod

    monkeypatch.setattr(archive_mod, "RAW_FALLBACK_LIMIT", 8)
    path = tmp_path / "model.pt"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("archive/data.pkl", b.global_call("os", "system"))
    assert "MW-SC-001" in {f.rule.id for f in scan_paths([path]).findings}


def test_a_compressed_member_that_cannot_be_classified_is_not_silent(tmp_path, monkeypatch):
    from modelwarden.scanners.supply_chain import archive as archive_mod

    monkeypatch.setattr(archive_mod, "RAW_FALLBACK_LIMIT", 8)
    path = tmp_path / "model.pt"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("archive/data.pkl", b.plain_data())
        archive.writestr("archive/x/m.onnx", (FIXTURES / "onnx/custom-domain.onnx").read_bytes())
    ids = {f.rule.id for f in scan_paths([path]).findings}
    assert "MW-GEN-006" in ids, "a member nothing could be read from was reported as clean"
