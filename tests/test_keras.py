"""Keras v3 archives: what config.json makes Keras resolve. The import policy is stubbed."""
import base64
import zipfile

import builders as b
import pytest

from modelwarden.core.engine import scan_paths
from modelwarden.core.findings import Severity

pytestmark = pytest.mark.usefixtures("stub_policy")

LAMBDA_FN = {"class_name": "__lambda__", "config": {"value": ["4wEAAAAA", None, None]}}


def findings(tmp_path, config):
    return scan_paths([b.keras_archive(tmp_path / "model.keras", config)]).findings


def rule_ids(tmp_path, config):
    return sorted(f.rule.id for f in findings(tmp_path, config))


def fn(module, name):
    return {"module": module, "class_name": "function", "config": name, "registered_name": None}


def test_benign_model_is_clean(tmp_path):
    model = b.keras_model(b.keras_layer("Dense", "dense", units=4, activation="relu"))
    assert rule_ids(tmp_path, model) == []


def test_foreign_module_goes_through_the_import_policy(tmp_path):
    layer = b.keras_layer("Dense", "dense", activation=fn("os", "system"))
    [finding] = findings(tmp_path, b.keras_model(layer))
    assert (finding.rule.id, finding.severity) == ("MW-SC-050", Severity.CRITICAL)
    assert finding.evidence == "os:system"
    assert finding.location.member == "config.json"


def test_registered_function_as_keras_writes_it_is_not_an_import(tmp_path):
    # Verbatim shape of Keras 3.15 output for a function registered under package "mw".
    activation = {"module": "builtins", "class_name": "function",
                  "config": "mw>scaled_relu", "registered_name": "function"}
    layer = b.keras_layer("Dense", "custom_act", activation=activation)
    assert rule_ids(tmp_path, b.keras_model(layer)) == []


def test_registry_key_is_not_an_import_even_under_a_dangerous_module(tmp_path):
    layer = b.keras_layer("Dense", "dense", activation=fn("os", "pkg>system"))
    assert rule_ids(tmp_path, b.keras_model(layer)) == []


def test_module_allowed_by_the_policy_is_quiet(tmp_path):
    layer = b.keras_layer("Dense", "dense", activation=fn("collections", "OrderedDict"))
    assert rule_ids(tmp_path, b.keras_model(layer)) == []


@pytest.mark.parametrize(
    ("module", "name"),
    [("keras.config", "enable_unsafe_deserialization"), ("keras.utils", "get_file")],
)
def test_loader_and_filesystem_functions(tmp_path, module, name):
    layer = b.keras_layer("Dense", "dense", activation=fn(module, name))
    assert rule_ids(tmp_path, b.keras_model(layer)) == ["MW-SC-051"]


def test_lambda_layer_is_reported_once(tmp_path):
    layer = b.keras_layer("Lambda", "my_lambda", function=LAMBDA_FN)
    [finding] = findings(tmp_path, b.keras_model(layer))
    assert finding.rule.id == "MW-SC-052"
    assert "'my_lambda'" in finding.message


def test_lambda_outside_a_lambda_layer(tmp_path):
    layer = b.keras_layer("Dense", "dense", activation=LAMBDA_FN)
    assert rule_ids(tmp_path, b.keras_model(layer)) == ["MW-SC-052"]


def test_legacy_lambda_without_module(tmp_path):
    layer = {"class_name": "Lambda",
             "config": {"name": "l", "function": "4wEAAAAA", "function_type": "lambda"}}
    assert rule_ids(tmp_path, b.keras_model(layer)) == ["MW-SC-052"]


def test_torch_module_wrapper_blob_is_scanned(tmp_path):
    blob = b.torch_zip(tmp_path / "inner.pt", b.global_call("os", "system")).read_bytes()
    layer = {"module": "keras.layers", "class_name": "TorchModuleWrapper",
             "config": {"name": "torch_wrapper", "module": base64.b64encode(blob).decode()}}
    found = findings(tmp_path, b.keras_model(layer))
    assert sorted(f.rule.id for f in found) == ["MW-SC-001", "MW-SC-053"]
    inner = next(f for f in found if f.rule.id == "MW-SC-001")
    assert inner.location.member.startswith("config.json#$.config.layers[0]")
    assert inner.location.member.endswith("/archive/data.pkl")


def test_torch_module_wrapper_with_invalid_base64(tmp_path):
    layer = {"module": "keras.layers", "class_name": "TorchModuleWrapper",
             "config": {"name": "w", "module": "not base64!"}}
    assert rule_ids(tmp_path, b.keras_model(layer)) == ["MW-SC-053"]


def test_tfsm_layer(tmp_path):
    layer = b.keras_layer("TFSMLayer", "tfsm", filepath="/tmp/attacker_savedmodel")
    [finding] = findings(tmp_path, b.keras_model(layer))
    assert finding.rule.id == "MW-SC-054"
    assert "/tmp/attacker_savedmodel" in finding.message


@pytest.mark.parametrize(("name", "escapes"), [("../../x", True), ("..", True),
                                               ("/abs", True), ("block..1", False)])
def test_name_traversal(tmp_path, name, escapes):
    ids = rule_ids(tmp_path, b.keras_model(b.keras_layer("Dense", name)))
    assert ids == (["MW-SC-055"] if escapes else [])


@pytest.mark.parametrize("body", [b"{not json", b'{"class_name": "A", "class_name": "B"}'])
def test_malformed_config(tmp_path, body):
    assert rule_ids(tmp_path, body) == ["MW-SC-056"]


def test_config_json_outside_a_keras_archive_is_ignored(tmp_path):
    path = tmp_path / "bundle.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("config.json", '{"module": "os", "class_name": "function", "config": "system"}')
    assert scan_paths([path]).findings == []


def test_config_with_bad_crc_is_still_analysed(tmp_path):
    layer = b.keras_layer("Dense", "crc_marker", activation=fn("os", "system"))
    path = b.keras_archive(tmp_path / "model.keras", b.keras_model(layer))
    data = path.read_bytes()
    assert data.count(b"crc_marker") == 1
    path.write_bytes(data.replace(b"crc_marker", b"crc_markeX"))
    assert sorted(f.rule.id for f in scan_paths([path]).findings) == ["MW-SC-011", "MW-SC-050"]
