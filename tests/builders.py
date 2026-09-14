"""Hand-assembled pickles and model containers for tests.

Malicious samples are built from raw opcodes at test time instead of being
committed: no binary that antivirus or GitHub would flag lives in the repo.
The payloads are never executed, and the conftest tripwire forbids unpickling.
"""
from __future__ import annotations

import json
import pickle
import struct
import zipfile
from pathlib import Path

PROTO2 = b"\x80\x02"
PROTO4 = b"\x80\x04"
PAYLOAD = "echo-mw"  # unique marker, lets tests find and corrupt the payload bytes


def sbu(text: str) -> bytes:
    """SHORT_BINUNICODE (protocol 4)."""
    data = text.encode()
    return b"\x8c" + bytes([len(data)]) + data


def bu(text: str) -> bytes:
    """BINUNICODE (protocol 1+)."""
    data = text.encode()
    return b"X" + struct.pack("<I", len(data)) + data


def global_call(module: str, name: str, arg: str = PAYLOAD) -> bytes:
    """GLOBAL + REDUCE, what a `__reduce__` payload compiles to."""
    return PROTO2 + f"c{module}\n{name}\n".encode() + b"(" + bu(arg) + b"tR."


def proto0_call(module: str, name: str, arg: str = PAYLOAD) -> bytes:
    """Protocol 0: no header at all, pure ASCII."""
    return f"c{module}\n{name}\n(S'{arg}'\ntR.".encode()


def stack_global_call(module: str, name: str, arg: str = PAYLOAD) -> bytes:
    """Protocol 4 STACK_GLOBAL with the strings pushed right before it."""
    return PROTO4 + sbu(module) + sbu(name) + b"\x93" + sbu(arg) + b"\x85R."


def stack_global_via_memo(module: str, name: str, arg: str = PAYLOAD) -> bytes:
    """STACK_GLOBAL whose operands come back from the memo (BINGET), not from
    the opcodes just before it, so a scanner has to track the memo."""
    return (
        PROTO4
        + sbu(module) + b"\x94" + b"0"  # push, MEMOIZE -> memo[0], POP
        + sbu(name) + b"\x94" + b"0"    # push, MEMOIZE -> memo[1], POP
        + b"h\x00h\x01\x93"             # BINGET 0, BINGET 1, STACK_GLOBAL
        + sbu(arg) + b"\x85R."
    )


def stack_global_computed(arg: str = PAYLOAD) -> bytes:
    """The module name is produced at load time by calling str('os'), so its
    value cannot be known without executing the pickle."""
    return (
        PROTO4
        + sbu("builtins") + sbu("str") + b"\x93" + sbu("os") + b"\x85R"
        + sbu("system") + b"\x93" + sbu(arg) + b"\x85R."
    )


def ext_call() -> bytes:
    """EXT1 fetches a callable from copyreg's extension registry by number."""
    return PROTO2 + b"\x82\x01" + b"(" + bu(PAYLOAD) + b"tR."


def plain_data() -> bytes:
    """A pickle with no imports at all (dict/list/int are built-in opcodes)."""
    return pickle.dumps({"weights": [1, 2, 3]}, protocol=2)


def torch_state_dict() -> bytes:
    """Roughly what torch.save writes into data.pkl for a one-tensor state_dict."""
    storage_pid = (
        b"(" + bu("storage") + b"ctorch\nFloatStorage\n" + bu("0") + bu("cpu") + b"K\x02tQ"
    )
    tensor = (
        b"ctorch._utils\n_rebuild_tensor_v2\n"
        + b"(" + storage_pid
        + b"K\x00" + b"K\x02\x85" + b"K\x01\x85" + b"\x89"  # offset, size, stride, requires_grad
        + b"ccollections\nOrderedDict\n)R"                   # backward hooks
        + b"tR"
    )
    return PROTO2 + b"ccollections\nOrderedDict\n)R" + bu("weight") + tensor + b"s."


def torch_zip(path: Path, data_pkl: bytes, extra: dict[str, bytes] | None = None) -> Path:
    """A torch.save-style zip. Stored, not deflated, so tests can patch bytes."""
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("archive/data.pkl", data_pkl)
        zf.writestr("archive/version", "3\n")
        # Tensor bytes that happen to start like a pickle header. torch never
        # unpickles storages, and neither must the scanner.
        zf.writestr("archive/data/0", b"\x80\x02" + b"\x00" * 6)
        for name, data in (extra or {}).items():
            zf.writestr(name, data)
    return path


def npy(descr: str, data: bytes, shape: tuple[int, ...] = (1,)) -> bytes:
    header = repr({"descr": descr, "fortran_order": False, "shape": shape}).encode("latin1")
    header += b" " * (63 - (10 + len(header)) % 64) + b"\n"
    return b"\x93NUMPY\x01\x00" + struct.pack("<H", len(header)) + header + data


def f32(n: int, begin: int) -> dict:
    return {"dtype": "F32", "shape": [n], "data_offsets": [begin, begin + 4 * n]}


def safetensors(tensors: dict[str, dict], data: bytes, raw_header: bytes | None = None) -> bytes:
    header = raw_header if raw_header is not None else json.dumps(tensors).encode()
    return struct.pack("<Q", len(header)) + header + data


def gg_str(value: str | bytes, order: str = "<") -> bytes:
    data = value.encode() if isinstance(value, str) else value
    return struct.pack(order + "Q", len(data)) + data


def gg_kv(key: str, vtype: int, payload: bytes, order: str = "<") -> bytes:
    return gg_str(key, order) + struct.pack(order + "I", vtype) + payload


def gg_kv_str(key: str, value: str, order: str = "<") -> bytes:
    return gg_kv(key, 8, gg_str(value, order), order)


def gg_kv_u32(key: str, value: int, order: str = "<") -> bytes:
    return gg_kv(key, 4, struct.pack(order + "I", value), order)


def gg_kv_str_array(key: str, items: list[str], order: str = "<") -> bytes:
    body = struct.pack(order + "IQ", 8, len(items)) + b"".join(gg_str(i, order) for i in items)
    return gg_kv(key, 9, body, order)


def gg_tensor(name: str, dims: list[int], offset: int = 0, order: str = "<") -> bytes:
    return (
        gg_str(name, order)
        + struct.pack(order + "I", len(dims))
        + b"".join(struct.pack(order + "Q", d) for d in dims)
        + struct.pack(order + "IQ", 0, offset)  # ggml type 0 = F32
    )


def gguf(
    kvs: list[bytes],
    tensors: list[bytes] = (),
    data: bytes = b"",
    version: int = 3,
    order: str = "<",
    kv_count: int | None = None,
) -> bytes:
    head = (
        b"GGUF"
        + struct.pack(order + "I", version)
        + struct.pack(order + "QQ", len(tensors), len(kvs) if kv_count is None else kv_count)
        + b"".join(kvs)
        + b"".join(tensors)
    )
    return head + b"\x00" * (-len(head) % 32) + data


def keras_layer(class_name: str, name: str, module: str = "keras.layers", **config) -> dict:
    return {
        "module": module,
        "class_name": class_name,
        "config": {"name": name, **config},
        "registered_name": None,
    }


def keras_model(*layers: dict) -> dict:
    return {
        "module": "keras",
        "class_name": "Sequential",
        "config": {"name": "sequential", "layers": list(layers)},
        "registered_name": None,
    }


HDF5_FIXTURES = Path(__file__).parent / "fixtures" / "hdf5"


def keras_archive(
    path: Path,
    config: dict | bytes,
    weights: bytes | None = None,
    compression: int = zipfile.ZIP_STORED,
) -> Path:
    """A Keras v3 archive. Stored by default, so tests can patch bytes.

    The weights default to a real, clean HDF5 file written by h5py.
    """
    body = config if isinstance(config, bytes) else json.dumps(config).encode()
    if weights is None:
        weights = (HDF5_FIXTURES / "plain-v3.h5").read_bytes()
    with zipfile.ZipFile(path, "w", compression=compression) as zf:
        zf.writestr("metadata.json", json.dumps({"keras_version": "3.10.0"}))
        zf.writestr("config.json", body)
        zf.writestr("model.weights.h5", weights)
    return path


def write(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path
