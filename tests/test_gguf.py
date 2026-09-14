"""GGUF: header bounds, tensor descriptors and chat-template injection."""
import struct

import builders as b
import pytest

from modelwarden.core.engine import scan_paths
from modelwarden.core.findings import Severity

BENIGN_TEMPLATE = (
    "{%- set ns = namespace(system='') -%}"
    "{%- for message in messages -%}"
    "{%- if message['role'] == 'system' -%}{%- set ns.system = message['content'] | trim -%}"
    "{%- elif message['role'] == 'user' -%}<|user|>{{ message['content'] }}<|end|>"
    "{%- else -%}{{ raise_exception('Unknown role: ' + message['role']) }}{%- endif -%}"
    "{%- endfor -%}{%- if add_generation_prompt -%}<|assistant|>{%- endif -%}"
    # Prose outside code blocks is emitted verbatim and must not trigger anything.
    " Introduce your self, check the config, never use __import__ or eval."
)
SSTI = "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}"
EVASION = "{{ ''|attr('\\x5f\\x5fclass\\x5f\\x5f') }}"


def model(template: str = BENIGN_TEMPLATE, key: str = "tokenizer.chat_template",
          order: str = "<", extra: list[bytes] = ()) -> bytes:
    kvs = [
        b.gg_kv_str("general.architecture", "llama", order),
        b.gg_kv_u32("general.alignment", 32, order),
        b.gg_kv_str_array("tokenizer.ggml.tokens", ["<s>", "hello"], order),
        b.gg_kv_str(key, template, order),
        *extra,
    ]
    return b.gguf(kvs, [b.gg_tensor("tok_embd.weight", [4], 0, order)], b"\x00" * 16, order=order)


def findings(tmp_path, data: bytes):
    return scan_paths([b.write(tmp_path / "model.gguf", data)]).findings


def rule_ids(tmp_path, data: bytes):
    return sorted(f.rule.id for f in findings(tmp_path, data))


@pytest.mark.parametrize("order", ["<", ">"], ids=["little_endian", "big_endian"])
def test_benign_model_is_clean(tmp_path, order):
    assert rule_ids(tmp_path, model(order=order)) == []


def test_template_reaching_python_internals(tmp_path):
    [finding] = findings(tmp_path, model(SSTI))
    assert (finding.rule.id, finding.severity) == ("MW-SC-042", Severity.HIGH)
    assert "__init__" in finding.evidence


def test_named_template_variant_is_checked(tmp_path):
    data = model(extra=[b.gg_kv_str("tokenizer.chat_template.tool_use", SSTI)])
    assert rule_ids(tmp_path, data) == ["MW-SC-042"]


def test_template_evasion_without_literal_dunders(tmp_path):
    [finding] = findings(tmp_path, model(EVASION))
    assert finding.rule.id == "MW-SC-043"
    assert finding.message.endswith("attr filter, escaped underscore")


def test_nested_arrays_are_valid(tmp_path):
    inner = struct.pack("<IQ", 0, 2) + b"\x01\x02"
    nested = b.gg_kv("custom.nested", 9, struct.pack("<IQ", 9, 1) + inner)
    assert rule_ids(tmp_path, model(extra=[nested])) == []


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b.gguf([b.gg_kv("general.name", 8, struct.pack("<Q", 2**40) + b"abc")]), "MW-SC-041"),
        (b.gguf([], kv_count=2**40), "MW-SC-041"),
        (b.gguf([], [b.gg_tensor("t", [2**32, 2**32])]), "MW-SC-041"),
        (b.gguf([], [b.gg_tensor("t", [4], offset=1024)], b"\x00" * 16), "MW-SC-041"),
        (b.gguf([], [b.gg_tensor("t", [1, 1, 1, 1, 1])]), "MW-SC-040"),
        (b.gguf([], [b.gg_tensor("t", [4], offset=4)], b"\x00" * 32), "MW-SC-040"),
        (b.gguf([b.gg_kv_u32("general.alignment", 12)]), "MW-SC-040"),
        (b.gguf([b.gg_kv_str("a", "x"), b.gg_kv_str("a", "y")]), "MW-SC-040"),
        (b.gguf([b.gg_kv("general.name", 99, b"")]), "MW-SC-040"),
        (b.gguf([], version=1), "MW-SC-040"),
        (b"GGUF\x03\x00\x00\x00\x00\x00", "MW-SC-040"),
    ],
    ids=[
        "string_past_eof", "absurd_kv_count", "dimension_overflow", "offset_past_eof",
        "five_dimensions", "misaligned_offset", "bad_alignment", "duplicate_key",
        "unknown_value_type", "version_1", "truncated_header",
    ],
)
def test_structural_problems(tmp_path, data, expected):
    assert rule_ids(tmp_path, data) == [expected]


def test_template_before_a_fatal_error_is_still_reported(tmp_path):
    broken = b.gg_kv("general.name", 8, struct.pack("<Q", 2**40))
    data = b.gguf([b.gg_kv_str("tokenizer.chat_template", SSTI), broken])
    assert rule_ids(tmp_path, data) == ["MW-SC-041", "MW-SC-042"]
