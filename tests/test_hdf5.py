"""HDF5: files written by real h5py and Keras (tests/fixtures/hdf5, see generate.py)."""
import struct
import zipfile

import builders as b
import pytest

from modelwarden.core.detect import Format, detect
from modelwarden.core.engine import scan_paths

FIXTURES = b.HDF5_FIXTURES
VERSIONS = ["v0", "v3"]  # superblock v0 + object header v1, superblock v3 + object header v2


def findings(path):
    return scan_paths([path]).findings


def rule_ids(path):
    return sorted(f.rule.id for f in findings(path))


@pytest.mark.parametrize("version", VERSIONS)
def test_plain_file_is_clean(version):
    assert rule_ids(FIXTURES / f"plain-{version}.h5") == []


@pytest.mark.parametrize("version", VERSIONS)
@pytest.mark.parametrize(
    ("name", "rule", "evidence"),
    [
        ("extlink", "MW-SC-060", "/nonexistent/secret.h5:/data"),
        ("extstorage", "MW-SC-061", "/nonexistent/secret.bin"),
        ("vds", "MW-SC-062", "/nonexistent/secret.h5"),
    ],
)
def test_structures_that_read_other_files(name, rule, evidence, version):
    [finding] = findings(FIXTURES / f"{name}-{version}.h5")
    assert (finding.rule.id, finding.evidence) == (rule, evidence)


@pytest.mark.parametrize("version", VERSIONS)
def test_shape_bomb(version):
    [finding] = findings(FIXTURES / f"shapebomb-{version}.h5")
    assert finding.rule.id == "MW-SC-063"
    assert finding.message.startswith("/bomb declares 8000000000000 bytes")


def test_legacy_keras_model_is_clean():
    assert rule_ids(FIXTURES / "keras-plain.h5") == []


def test_legacy_keras_lambda_is_found_in_model_config():
    [finding] = findings(FIXTURES / "keras-lambda.h5")
    assert (finding.rule.id, finding.location.member) == ("MW-SC-052", "/model_config")


@pytest.mark.parametrize("compression", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
def test_weights_inside_a_keras_archive_are_walked(tmp_path, compression):
    weights = (FIXTURES / "extlink-v3.h5").read_bytes()
    model = b.keras_model(b.keras_layer("Dense", "dense"))
    path = b.keras_archive(tmp_path / "model.keras", model, weights, compression)
    [finding] = findings(path)
    assert (finding.rule.id, finding.location.member) == ("MW-SC-060", "model.weights.h5")


def test_external_link_hidden_in_dense_storage():
    # Thirty-two links push a group's links into a fractal heap. The external link
    # among them was invisible while only "not checked" was reported.
    found = {f.rule.id: f for f in findings(FIXTURES / "dense-links.h5")}
    assert "MW-SC-065" not in found
    assert found["MW-SC-060"].evidence == "/nonexistent/secret.h5:/data"
    assert "/many/leak" in found["MW-SC-060"].message


def test_a_lambda_hidden_in_dense_attributes_is_found():
    # The model_config that real Keras wrote into keras-lambda.h5, moved into dense
    # storage by padding the root group with 32 more attributes. Only the storage shape
    # differs. While the fractal heap went unread this file reported MW-SC-065 and
    # nothing else: the Lambda was invisible, which is what made it worth reading.
    [finding] = findings(FIXTURES / "keras-lambda-dense.h5")
    assert (finding.rule.id, finding.location.member) == ("MW-SC-052", "/model_config")


def test_a_lambda_behind_a_two_level_index_is_found():
    # 512 attributes push the name index to depth 2, where every child pointer carries a
    # second count sized from the subtree beneath it. That width is derived rather than
    # read from a field, so this fixture is what checks the derivation.
    [finding] = findings(FIXTURES / "keras-lambda-deep.h5")
    assert (finding.rule.id, finding.location.member) == ("MW-SC-052", "/model_config")


def test_dense_attributes_are_read():
    # Thirty-two attributes put them in a fractal heap whose root is an indirect block,
    # indexed by a B-tree one level deep. Both shapes were unread, so the file was only
    # reported as "not checked" and anything hidden among the attributes was invisible.
    assert rule_ids(FIXTURES / "dense-attrs.h5") == []


def test_every_dense_attribute_message_reaches_the_parser(monkeypatch):
    # The file above is clean, so no finding can show that the attributes were read
    # rather than skipped. This counts the messages that arrive at the parser.
    from modelwarden.scanners.supply_chain import hdf5

    seen = []

    def capture(self, body, offset, path):
        name_size = struct.unpack_from("<H", body, 2)[0]
        head = 9 if body[0] == 3 else 8  # version 3 adds a character-set byte
        seen.append((path, body[0], body[head:head + name_size].rstrip(b"\0").decode()))

    monkeypatch.setattr(hdf5._Walker, "_attribute", capture)
    findings(FIXTURES / "dense-attrs.h5")
    # Counting calls would pass on 32 slices of garbage; the names prove the decode.
    assert {name for _, _, name in seen} == {f"attr{i:02d}" for i in range(32)}
    assert {path for path, _, _ in seen} == {"/x"}
    assert {version for _, version, _ in seen} == {3}


@pytest.mark.parametrize("user_block", [512, 1024])
def test_file_behind_a_user_block(user_block):
    # The superblock starts at 512 or 1024; looking only at offset 0 finds nothing,
    # yet libhdf5 loads the file and the external link inside it works.
    path = FIXTURES / f"userblock-{user_block}.h5"
    assert detect(path) is Format.HDF5
    found = {f.rule.id: f for f in findings(path)}
    assert sorted(found) == ["MW-SC-060", "MW-SC-066"]
    assert found["MW-SC-060"].evidence == "/nonexistent/secret.h5:/data"
    assert "#!/bin/sh" in found["MW-SC-066"].evidence


def test_address_outside_the_file_is_malformed(tmp_path):
    data = bytearray((FIXTURES / "plain-v3.h5").read_bytes())
    data[36:44] = struct.pack("<Q", 10**9)  # root group object header address
    assert rule_ids(b.write(tmp_path / "model.h5", bytes(data))) == ["MW-SC-064"]


def test_truncated_file_is_malformed(tmp_path):
    data = (FIXTURES / "keras-plain.h5").read_bytes()[:1024]
    assert rule_ids(b.write(tmp_path / "model.h5", data)) == ["MW-SC-064"]


def test_four_byte_addresses_are_not_analysed(tmp_path):
    data = bytearray((FIXTURES / "plain-v0.h5").read_bytes())
    data[13] = 4  # size of offsets
    assert rule_ids(b.write(tmp_path / "model.h5", bytes(data))) == ["MW-SC-065"]
