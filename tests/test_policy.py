"""The import policy (classify_global): an allowlist that users can extend."""
import json
import os
import subprocess
import sys
from pathlib import Path

import builders as b
import pytest

from modelwarden.cli import main
from modelwarden.core.engine import scan_paths
from modelwarden.core.findings import Severity
from modelwarden.core.policy import allowing, parse_allow_entry, read_allow_file
from modelwarden.scanners.supply_chain.pickle import SAFE_GLOBALS, classify_global
from modelwarden.scanners.supply_chain.unsafe_globals import dangerous_severity

DANGEROUS = [
    ("os", "system"),
    ("posix", "system"),
    ("nt", "system"),
    ("subprocess", "Popen"),
    ("builtins", "eval"),
    ("builtins", "exec"),
    ("__builtin__", "eval"),
    ("runpy", "_run_code"),
    ("torch", "hub.load"),
    ("numpy", "testing._private.utils.runstring"),
]

SAFE = [
    ("collections", "OrderedDict"),
    ("torch._utils", "_rebuild_tensor_v2"),
    ("torch", "FloatStorage"),
    ("numpy.core.multiarray", "_reconstruct"),
    ("_codecs", "encode"),
    ("__builtin__", "set"),
    ("copy_reg", "_reconstructor"),
]


@pytest.mark.parametrize(("module", "name"), DANGEROUS)
def test_code_execution_gadgets_are_high(module, name):
    severity = classify_global(module, name)
    assert severity is not None and severity >= Severity.HIGH


@pytest.mark.parametrize(("module", "name"), SAFE)
def test_checkpoint_building_blocks_are_quiet(module, name):
    assert classify_global(module, name) is None


@pytest.mark.parametrize(
    ("module", "name"),
    [
        ("os", "system"),
        ("os.path", "join"),              # submodule of a dangerous module
        ("urllib.request", "urlopen"),
        ("__builtin__", "getattr"),       # Python 2 alias
        ("torch", "hub.load"),            # dotted name judged by its full path
        ("numpy", "testing._private.utils.runstring"),
    ],
)
def test_known_dangerous_is_critical(module, name):
    assert classify_global(module, name) is Severity.CRITICAL


@pytest.mark.parametrize(
    ("module", "name"),
    [
        ("mylib", "Thing"),
        ("sklearn.linear_model._base", "LinearRegression"),
        ("osmium", "Reader"),                    # "os" matches on package boundaries only
        ("collections", "OrderedDict.__init__"),  # walking attributes from a safe global
        ("builtins", "set.__init__"),
    ],
)
def test_unknown_is_high(module, name):
    assert classify_global(module, name) is Severity.HIGH


@pytest.mark.parametrize(
    ("module", "name"),
    [
        ("functools", "partial"),
        ("operator", "attrgetter"),
        ("_operator", "methodcaller"),
        ("types", "CodeType"),
        ("torch.serialization", "load"),
        ("torch", "serialization.load"),            # same entry, reached as a dotted name
        ("code", "InteractiveInterpreter.runcode"),
        ("logging", "FileHandler"),
        ("cloudpickle.cloudpickle", "subimport"),
        ("builtins", "__import__"),                  # the one entry only modelscan lists
    ],
)
def test_upstream_unsafe_entries_are_critical(module, name):
    assert classify_global(module, name) is Severity.CRITICAL


@pytest.mark.parametrize(
    ("module", "name"),
    [
        ("functools", "reduce"),
        ("functools", "partialmethod"),  # "functools.partial" must not match as a string prefix
        ("types", "SimpleNamespace"),
        ("logging", "getLogger"),
        ("code", "compile_command"),
    ],
)
def test_only_listed_members_of_a_module_are_dangerous(module, name):
    assert classify_global(module, name) is Severity.HIGH


def test_allowlist_and_dangerous_list_do_not_overlap():
    # The allowlist is checked first, so an overlap would silence a known gadget.
    assert [g for g in SAFE_GLOBALS if dangerous_severity(*g) is not None] == []


def test_picklescan_safe_globals_are_allowed():
    assert classify_global("torch", "QInt8Storage") is None


def test_user_allowlist_downgrades_to_info_for_one_scan_only():
    with allowing({("mylib", "Thing")}):
        assert classify_global("mylib", "Thing") is Severity.INFO
    assert classify_global("mylib", "Thing") is Severity.HIGH


def test_user_allowlist_cannot_silence_known_dangerous():
    with allowing({("os", "system")}):
        assert classify_global("os", "system") is Severity.CRITICAL


@pytest.mark.parametrize("text", ["mylib", ":Thing", "mylib:", "a:b:c", ""])
def test_malformed_allow_entries(text):
    with pytest.raises(ValueError):
        parse_allow_entry(text)


def test_allow_file(tmp_path):
    path = tmp_path / "allow.txt"
    path.write_text("# expected custom classes\nmylib:Thing\n\n  other.mod:Cls  # trailing\n")
    assert read_allow_file(path) == {("mylib", "Thing"), ("other.mod", "Cls")}
    path.write_text("mylib:Thing\nbroken\n")
    with pytest.raises(ValueError, match=r":2: "):
        read_allow_file(path)


def test_cli_allow_turns_high_into_info(tmp_path, capsys):
    path = b.write(tmp_path / "model.pkl", b.global_call("mylib", "Thing"))
    assert main(["scan", str(path)]) == 1
    capsys.readouterr()
    assert main(["scan", str(path), "--allow", "mylib:Thing", "--format", "json"]) == 0
    [finding] = json.loads(capsys.readouterr().out)["findings"]
    assert (finding["severity"], finding["evidence"]) == ("info", "mylib:Thing")


def test_cli_allow_file_and_its_errors(tmp_path):
    path = b.write(tmp_path / "model.pkl", b.global_call("mylib", "Thing"))
    allow = tmp_path / "allow.txt"
    allow.write_text("mylib:Thing\n")
    assert main(["scan", str(path), "--allow-file", str(allow)]) == 0
    assert main(["scan", str(path), "--allow-file", str(tmp_path / "missing.txt")]) == 2
    with pytest.raises(SystemExit) as exc:
        main(["scan", str(path), "--allow", "no-colon"])
    assert exc.value.code == 2


def test_benign_torch_checkpoint_has_no_findings(tmp_path):
    path = b.torch_zip(tmp_path / "model.pt", b.torch_state_dict())
    assert scan_paths([path]).findings == []


def test_malicious_torch_checkpoint_fails_the_default_gate(tmp_path):
    path = b.torch_zip(tmp_path / "model.pt", b.global_call("os", "system"))
    assert main(["scan", str(path)]) == 1


def test_cli_as_a_real_process(tmp_path):
    path = b.write(tmp_path / "model.bin", b.stack_global_via_memo("posix", "system"))
    src = Path(__file__).resolve().parents[1] / "src"
    env = {**os.environ, "PYTHONPATH": str(src)}
    proc = subprocess.run(
        [sys.executable, "-m", "modelwarden", "scan", str(path), "--format", "json"],
        capture_output=True, text=True, env=env, check=False,
    )
    assert proc.returncode == 1, proc.stderr
    [finding] = json.loads(proc.stdout)["findings"]
    assert (finding["severity"], finding["evidence"]) == ("critical", "posix:system")
