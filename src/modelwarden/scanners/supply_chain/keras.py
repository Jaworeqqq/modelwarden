"""Keras v3 `.keras` archives: config.json describes the model as serialized objects.

On load, Keras resolves every object's `module` and `class_name` to Python code
and calls it with `config`. Each code-execution bypass of Keras' safe_mode has
been a way to make that resolution reach something other than a layer. That is
the same shape as a pickle GLOBAL, so foreign modules go through the same
import policy.
"""
from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Callable, Iterable, Iterator

from modelwarden.core.findings import Finding, Location, Rule, Severity
from modelwarden.scanners.supply_chain import pickle as import_policy
from modelwarden.scanners.supply_chain._json import load_strict
from modelwarden.scanners.supply_chain.pickle import ATLAS, OWASP

# (blob, display path, member label) -> findings; supplied by the zip scanner.
Embedded = Callable[[bytes, str, str], Iterable[Finding]]

FOREIGN_MODULE = Rule(
    "MW-SC-050",
    "Keras config references a non-Keras module",
    "Keras before 3.9 imports any module named in config.json and calls the named "
    "attribute, even with safe_mode=True (CVE-2025-1550). Severity comes from the same "
    "import policy as pickle globals.",
    Severity.HIGH, ATLAS, OWASP,
)
LOADER_FUNCTION = Rule(
    "MW-SC-051",
    "Keras config calls a loader or filesystem API",
    "The config invokes a Keras function that changes how the rest of the file is loaded "
    "or touches the filesystem: keras.config.enable_unsafe_deserialization "
    "(CVE-2025-9906) or keras.utils.get_file (CVE-2025-8747).",
    Severity.HIGH, ATLAS, OWASP,
)
LAMBDA = Rule(
    "MW-SC-052",
    "Serialized Python code (Lambda)",
    "Lambda layers and __lambda__ objects carry marshalled Python bytecode. safe_mode is "
    "meant to refuse them and has been bypassed (CVE-2025-9906, CVE-2026-12481).",
    Severity.HIGH, ATLAS, OWASP,
)
TORCH_WRAPPER = Rule(
    "MW-SC-053",
    "TorchModuleWrapper embeds a pickle",
    "The config carries a base64 torch.save blob that Keras loads with "
    "torch.load(weights_only=False) (CVE-2025-49655, CVE-2026-12484). The blob is "
    "analysed like any other PyTorch checkpoint.",
    Severity.HIGH, ATLAS, OWASP,
)
TFSM_LAYER = Rule(
    "MW-SC-054",
    "TFSMLayer loads an external SavedModel",
    "TFSMLayer loads a TensorFlow SavedModel from a path stored in the config, and its "
    "code runs during inference regardless of safe_mode (CVE-2026-1462).",
    Severity.HIGH, ATLAS, OWASP,
)
NAME_TRAVERSAL = Rule(
    "MW-SC-055",
    "Object name escapes the archive directory",
    "A layer or object name is a '..' path component or an absolute path. Keras builds "
    "directories from these names when saving and loading (CVE-2026-12479).",
    Severity.MEDIUM, ATLAS, OWASP,
)
BAD_CONFIG = Rule(
    "MW-SC-056",
    "Malformed Keras config",
    "config.json is not valid JSON or has duplicate keys, so it was not analysed.",
    Severity.MEDIUM, ATLAS, OWASP,
)
KERAS_RULES = (
    FOREIGN_MODULE, LOADER_FUNCTION, LAMBDA, TORCH_WRAPPER, TFSM_LAYER, NAME_TRAVERSAL, BAD_CONFIG,
)

KERAS_PACKAGES = frozenset({"keras", "keras_hub", "keras_cv", "keras_nlp"})
LOADER_FUNCTIONS = frozenset({"enable_unsafe_deserialization", "get_file"})
# Values Keras encodes as {"class_name": "__x__", ...}: data, not code references.
_VALUE_TYPES = frozenset({
    "__bytes__", "__numpy__", "__tensor__", "__keras_tensor__",
    "__slice__", "__ellipsis__", "__typespec__",
})
_SEPARATORS = re.compile(r"[\\/]")


def scan_config(data: bytes, display: str, member: str, embedded: Embedded) -> Iterator[Finding]:
    where = Location(display, member)
    try:
        config = load_strict(data)
    except (ValueError, RecursionError) as exc:
        yield Finding(BAD_CONFIG, BAD_CONFIG.default_severity, f"config.json: {exc}", where)
        return

    lambda_layers: list[str] = []
    for path, obj in _objects(config):
        class_name, module, inner = obj["class_name"], obj.get("module"), obj.get("config")
        if class_name in _VALUE_TYPES:
            continue
        label = _label(class_name, inner, path)

        if class_name == "__lambda__":
            # Already reported as part of the Lambda layer that contains it.
            if not any(path.startswith(layer) for layer in lambda_layers):
                message = f"serialized lambda at {path}"
                yield Finding(LAMBDA, LAMBDA.default_severity, message, where)
            continue
        if class_name == "Lambda":
            lambda_layers.append(path)
            yield Finding(LAMBDA, LAMBDA.default_severity, f"{label} carries Python code", where)
        elif class_name == "TorchModuleWrapper":
            yield from _torch_wrapper(inner, label, path, display, member, embedded)
        elif class_name == "TFSMLayer":
            target = inner.get("filepath") if isinstance(inner, dict) else None
            message = f"{label} loads a SavedModel from {target!r}"
            yield Finding(TFSM_LAYER, TFSM_LAYER.default_severity, message, where)

        # Functions are serialized as class_name "function" with the name in config.
        name = inner if class_name == "function" and isinstance(inner, str) else class_name
        foreign = isinstance(module, str) and module and module.split(".")[0] not in KERAS_PACKAGES
        if foreign and _importable(name):
            severity = import_policy.classify_global(module, name)
            if severity is not None:
                message = f"{label} resolves {module}.{name}"
                yield Finding(FOREIGN_MODULE, severity, message, where, f"{module}:{name}")
        elif name in LOADER_FUNCTIONS:
            qualified = f"{module}.{name}" if module else name
            message = f"{label} calls {qualified}"
            yield Finding(LOADER_FUNCTION, LOADER_FUNCTION.default_severity, message, where)

        object_name = inner.get("name") if isinstance(inner, dict) else None
        if isinstance(object_name, str) and _escapes(object_name):
            message = f"{label} has a name that escapes its directory"
            yield Finding(NAME_TRAVERSAL, NAME_TRAVERSAL.default_severity, message, where)


def _objects(root: object) -> Iterator[tuple[str, dict]]:
    """Every serialized object (a dict with a string class_name), parents first."""
    stack: list[tuple[str, object]] = [("$", root)]
    while stack:
        path, node = stack.pop()
        if isinstance(node, dict):
            if isinstance(node.get("class_name"), str):
                yield path, node
            children = [(f"{path}.{key}", value) for key, value in node.items()]
        elif isinstance(node, list):
            children = [(f"{path}[{i}]", value) for i, value in enumerate(node)]
        else:
            continue
        stack.extend(reversed(children))


def _label(class_name: str, inner: object, path: str) -> str:
    name = inner.get("name") if isinstance(inner, dict) else None
    if isinstance(name, str):
        return f"{class_name} {name!r} at {path}"
    return f"{class_name} at {path}"


def _importable(name: str) -> bool:
    """Whether import + getattr could resolve `name` at all.

    Keras writes registered custom functions as module "builtins" with a registry
    key such as "mw>scaled_relu". That is a lookup among objects the loading
    program registered, not an import, and no getattr can reach code through it.
    """
    return all(part.isidentifier() for part in name.split("."))


def _escapes(name: str) -> bool:
    return name.startswith(("/", "\\")) or ".." in _SEPARATORS.split(name)


def _torch_wrapper(
    inner: object, label: str, path: str, display: str, member: str, embedded: Embedded
) -> Iterator[Finding]:
    where = Location(display, member)
    blob = inner.get("module") if isinstance(inner, dict) else None
    if not isinstance(blob, str):
        message = f"{label} has no embedded module"
        yield Finding(TORCH_WRAPPER, TORCH_WRAPPER.default_severity, message, where)
        return
    try:
        data = base64.b64decode(blob, validate=True)
    except (binascii.Error, ValueError):
        message = f"{label} embeds a module that is not valid base64"
        yield Finding(TORCH_WRAPPER, TORCH_WRAPPER.default_severity, message, where)
        return
    message = f"{label} embeds a {len(data)}-byte torch.save blob"
    yield Finding(TORCH_WRAPPER, TORCH_WRAPPER.default_severity, message, where)
    yield from embedded(data, display, f"{member}#{path}")
