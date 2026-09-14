"""MCP tool definitions: what a server tells the model it can do.

A client shows the user a tool's name, sometimes its title. The model reads the
whole definition: description, parameter descriptions, annotations. Everything the
model reads and the user does not is a place to hide instructions, which is the
technique published as a "tool poisoning attack".

Deliberately absent: a general "this description instructs the model" rule.
Legitimate servers do instruct the model — the official reference `fetch` server
tells it to stop refusing internet access and to inform the user it now has it —
so only specific, named techniques are reported. Measured against the tool
descriptions of the official reference servers, none of which are reported.
"""
from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Iterator
from pathlib import Path

from modelwarden.core.detect import Format
from modelwarden.core.findings import Finding, Location, Rule, Severity
from modelwarden.core.policy import pinned
from modelwarden.core.text import OVERRIDE as _OVERRIDE
from modelwarden.core.text import SENSITIVE_PATH as _SENSITIVE_PATH
from modelwarden.core.text import hidden_codepoints

ATLAS = ("AML.T0051.001", "AML.T0053")
OWASP = ("LLM01:2025",)

HIDDEN_CHARACTERS = Rule(
    "MW-MCP-001",
    "Invisible characters in a tool definition",
    "The definition contains characters that render as nothing or reorder text: tag "
    "characters, zero-width spaces, bidirectional overrides. The model reads them, the "
    "user does not see them, which is how instructions are hidden in plain sight.",
    Severity.HIGH, ATLAS, OWASP,
)
CONCEALMENT = Rule(
    "MW-MCP-002",
    "Tool description tells the model to hide something from the user",
    "The description instructs the model not to tell, mention or show something. A tool "
    "that needs the user kept in the dark is the clearest marker of a tool poisoning "
    "attack; no legitimate tool needs this.",
    Severity.HIGH, ATLAS, OWASP,
)
SENSITIVE_PATH = Rule(
    "MW-MCP-003",
    "Tool description names credential files",
    "The description points the model at private keys, environment files or credential "
    "stores. Combined with a parameter to pass their contents, this is the published "
    "exfiltration pattern for poisoned tools.",
    Severity.HIGH, ATLAS, OWASP,
)
SHADOWING = Rule(
    "MW-MCP-004",
    "Tool description gives instructions about other tools",
    "The description tells the model how to behave when using a different tool, or all "
    "tools. One server can then change what another, trusted server does: the technique "
    "published as tool shadowing.",
    Severity.HIGH, ATLAS, OWASP,
)
INSTRUCTION_BLOCK = Rule(
    "MW-MCP-005",
    "Tool description carries a marked-up instruction block",
    "The description contains an <IMPORTANT>-style pseudo-tag or an HTML comment. Those "
    "read as emphasis or as nothing in a user interface, while the model reads the text "
    "inside them as part of its instructions.",
    Severity.MEDIUM, ATLAS, OWASP,
)
TRUST_HINT = Rule(
    "MW-MCP-006",
    "Tool annotations contradict what the tool does",
    "The server declares readOnlyHint or a non-destructive hint for a tool whose own name "
    "or description describes writing, deleting or sending. Annotations are the server's "
    "claim about itself and clients use them to decide what to allow without asking.",
    Severity.MEDIUM, ATLAS, ("LLM06:2025",),
)
IDENTITY = Rule(
    "MW-MCP-007",
    "Suspicious tool identity",
    "Two tools share a name, or a name contains non-ASCII characters that can imitate "
    "another tool's name. Clients and models pick tools by name.",
    Severity.MEDIUM, ATLAS, OWASP,
)
MALFORMED = Rule(
    "MW-MCP-008",
    "Malformed MCP tool list",
    "The file is not valid JSON, or the tools are not objects, so it was not analysed.",
    Severity.MEDIUM, ATLAS, OWASP,
)
PRECEDENCE = Rule(
    "MW-MCP-013",
    "Tool definition claims precedence over instructions already in force",
    "The definition says it supersedes, replaces or overrides earlier instructions, "
    "guidance or rules. A server may legitimately tell the model how to use its own "
    "tool; it has no standing to unseat what the operator told the model beforehand. "
    "This is the injection core — 'ignore all previous instructions' — arriving through "
    "a field the user never reads.",
    Severity.HIGH, ATLAS, OWASP,
)
DEFINITION_CHANGED = Rule(
    "MW-MCP-010",
    "Tool definition changed since the lockfile",
    "A tool the user already approved now describes itself differently. A server can "
    "serve a harmless definition until it is trusted and change it afterwards, the "
    "technique published as an MCP rug pull.",
    Severity.HIGH, ATLAS, OWASP,
)
UNPINNED_TOOL = Rule(
    "MW-MCP-011",
    "Tool is not in the lockfile",
    "The server offers a tool that was not present when the lockfile was written. It has "
    "never been reviewed, and the model can call it.",
    Severity.MEDIUM, ATLAS, OWASP,
)
MISSING_TOOL = Rule(
    "MW-MCP-012",
    "Tool from the lockfile is gone",
    "A pinned tool is no longer offered. Usually a legitimate change, reported so that a "
    "lockfile and a server that have drifted apart are visible.",
    Severity.LOW, ATLAS, OWASP,
)
MCP_RULES = (
    HIDDEN_CHARACTERS, CONCEALMENT, SENSITIVE_PATH, SHADOWING,
    INSTRUCTION_BLOCK, TRUST_HINT, IDENTITY, MALFORMED, PRECEDENCE,
    DEFINITION_CHANGED, UNPINNED_TOOL, MISSING_TOOL,
)

LOCK_VERSION = 1

# "do not tell the user", "without informing them", "never mention this".
_CONCEALMENT = re.compile(
    r"(?i)\b(?:do\s*not|don'?t|never|avoid|without)\b(?:\W+\w+){0,4}?\W+"
    r"(?:tell|telling|inform|informing|mention|mentioning|reveal|revealing|disclose|"
    r"disclosing|notify|notifying|show|showing|display|displaying|explain|explaining)\b"
)
_SECRECY = re.compile(
    r"(?i)\b(?:keep\s+(?:this|it)\s+(?:secret|hidden|quiet)|"
    r"hidden\s+from\s+the\s+user|behind\s+the\s+user'?s\s+back|silently\b)"
)
_ALL_TOOLS = re.compile(
    r"(?i)\b(?:all|every|any|other|each)\s+(?:other\s+)?tools?\b|\bfor\s+all\s+tools\b"
)
_DIRECTIVE = re.compile(r"(?i)\b(?:must|always|first|before|whenever|make sure|be sure|ensure)\b")
# A claim that this definition displaces instructions that are already in force.
# Distinct from MW-MCP-004: shadowing redirects the model toward another tool, this
# unseats the operator. The sibling for documents is corpus._AUTHORITY, which needs a
# claimant ("this document supersedes ...") because prose about precedence is ordinary
# — a tool definition has no comparable reason to discuss it. The verb alone is not
# enough: it has to reach an object that names instructions already given, which is
# what keeps honest replacement language ("in place of your default approach") clear.
_PRECEDENCE = re.compile(
    r"(?i)\b(?:replaces?|supersedes?|overrides?|take[sn]?\s+precedence\s+over|"
    r"invalidates?|cancels?|ignores?|disregards?)\b[^.\n]{0,40}?"
    r"\b(?:earlier|previous|prior|preceding|existing|all\s+other|any\s+other)\b"
    r"[^.\n]{0,30}?\b(?:instruction|instructions|guidance|guidelines?|rules?|prompt|"
    r"prompts|direction|directions|polic(?:y|ies)|constraints?)\b"
)
_INSTRUCTION_BLOCK = re.compile(
    r"(?i)<\s*/?\s*(?:important|system|secret|instruction|admin|note\s+to\s+(?:ai|assistant|model))"
    r"\b[^>]*>|<!--|\[\s*(?:important|system)\s*\]"
)
# Verbs that mean the tool changes something or sends it somewhere.
_MUTATING = re.compile(
    r"(?i)\b(?:writes?|writing|deletes?|deleting|removes?|removing|creates?|creating|"
    r"updates?|updating|modif(?:y|ies|ying)|sends?|sending|posts?|posting|uploads?|"
    r"uploading|installs?|installing|executes?|executing|runs?|running|renames?|"
    r"renaming|moves?|moving|drops?|dropping|overwrites?|overwriting)\b"
)
_MUTATING_NAME = re.compile(
    r"(?i)(?:^|[_\-])(?:write|delete|remove|create|update|send|post|put|patch|upload|"
    r"install|exec|execute|run|rename|move|drop|kill|set)(?:$|[_\-])"
)


class MCPToolsScanner:
    name = "mcp-tools"
    formats = frozenset({Format.MCP_TOOLS})
    rules = MCP_RULES

    def scan(self, path: Path, display: str) -> Iterator[Finding]:
        yield from scan_tools(path.read_bytes(), display)


def scan_tools(data: bytes, display: str, member: str | None = None) -> Iterator[Finding]:
    """Scan a tools/list result, a JSON-RPC response wrapping one, or a bare tool array."""
    where = Location(display, member)
    try:
        document = json.loads(data.decode("utf-8"))
    except (ValueError, RecursionError) as exc:
        yield Finding(MALFORMED, MALFORMED.default_severity, f"cannot parse JSON: {exc}", where)
        return

    tools = extract_tools(document)
    if tools is None:
        yield Finding(MALFORMED, MALFORMED.default_severity, "no tool list in this document", where)
        return

    names = [t.get("name") for t in tools if isinstance(t, dict) and isinstance(t.get("name"), str)]
    yield from _identity(names, where)
    for index, tool in enumerate(tools):
        if not isinstance(tool, dict):
            yield Finding(MALFORMED, MALFORMED.default_severity,
                          f"tool #{index} is not an object", where)
            continue
        yield from _tool(tool, index, names, where)
    yield from _against_lock(tools, where)


def canonical(obj: object) -> bytes:
    """Byte form used for hashing: key order and spacing cannot change the digest."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fingerprint(tool: dict) -> dict:
    """A whole-definition digest plus one per field the model reads."""
    return {
        "sha256": _digest(canonical(tool)),
        "fields": {field: _digest(text.encode("utf-8")) for field, text in _text_fields(tool)},
    }


def build_lock(tools: list) -> dict:
    pinned_tools = {
        tool["name"]: fingerprint(tool)
        for tool in tools
        if isinstance(tool, dict) and isinstance(tool.get("name"), str)
    }
    return {"version": LOCK_VERSION, "tools": pinned_tools}


def _against_lock(tools: list, where: Location) -> Iterator[Finding]:
    lock = pinned()
    if lock is None:
        return
    locked = lock.get("tools", {})
    present: set[str] = set()

    for tool in tools:
        if not isinstance(tool, dict) or not isinstance(tool.get("name"), str):
            continue
        name = tool["name"]
        present.add(name)
        entry = locked.get(name)
        if not isinstance(entry, dict):
            yield Finding(UNPINNED_TOOL, UNPINNED_TOOL.default_severity,
                          f"tool {name!r} is not in the lockfile", where, name)
            continue
        current = fingerprint(tool)
        if current["sha256"] == entry.get("sha256"):
            continue
        changed = _changed_fields(current["fields"], entry.get("fields"))
        detail = ", ".join(changed) if changed else "fields a client does not display"
        yield Finding(DEFINITION_CHANGED, DEFINITION_CHANGED.default_severity,
                      f"tool {name!r} changed since the lockfile: {detail}", where, name)

    for name in sorted(set(locked) - present):
        yield Finding(MISSING_TOOL, MISSING_TOOL.default_severity,
                      f"tool {name!r} from the lockfile is no longer offered", where, name)


def _changed_fields(current: dict, locked: object) -> list[str]:
    if not isinstance(locked, dict):
        return []
    changed = [field for field, digest in current.items() if locked.get(field) != digest]
    changed += [field for field in locked if field not in current]
    return sorted(set(changed))


def extract_tools(document: object) -> list | None:
    if isinstance(document, list):
        return document
    if isinstance(document, dict):
        for holder in (document, document.get("result")):
            if isinstance(holder, dict) and isinstance(holder.get("tools"), list):
                return holder["tools"]
    return None


def _label(tool: dict, index: int) -> str:
    name = tool.get("name")
    return f"tool {name!r}" if isinstance(name, str) else f"tool #{index}"


def _tool(tool: dict, index: int, names: list[str], where: Location) -> Iterator[Finding]:
    label = _label(tool, index)
    fields = list(_text_fields(tool))

    for field, text in fields:
        codepoints = hidden_codepoints(text)
        if codepoints:
            message = f"{label}: {field} contains invisible characters {', '.join(codepoints)}"
            yield Finding(HIDDEN_CHARACTERS, HIDDEN_CHARACTERS.default_severity, message, where,
                          ", ".join(codepoints))
        if _CONCEALMENT.search(text) or _SECRECY.search(text):
            match = (_CONCEALMENT.search(text) or _SECRECY.search(text)).group()
            yield Finding(CONCEALMENT, CONCEALMENT.default_severity,
                          f"{label}: {field} asks the model to keep something from the user "
                          f"({match.strip()!r})", where, match.strip())
        found = _SENSITIVE_PATH.search(text)
        if found:
            yield Finding(SENSITIVE_PATH, SENSITIVE_PATH.default_severity,
                          f"{label}: {field} names {found.group().strip()!r}", where,
                          found.group().strip())
        claim = _PRECEDENCE.search(text) or _OVERRIDE.search(text)
        if claim:
            yield Finding(PRECEDENCE, PRECEDENCE.default_severity,
                          f"{label}: {field} claims to displace instructions already in "
                          f"force ({claim.group().strip()!r})", where, claim.group().strip())
        if _INSTRUCTION_BLOCK.search(text):
            marker = _INSTRUCTION_BLOCK.search(text).group()
            yield Finding(INSTRUCTION_BLOCK, INSTRUCTION_BLOCK.default_severity,
                          f"{label}: {field} contains {marker!r}", where, marker)
        yield from _shadowing(text, field, label, tool.get("name"), names, where)

    yield from _trust_hints(tool, label, fields, where)


def _shadowing(
    text: str, field: str, label: str, own_name: object, names: list[str], where: Location
) -> Iterator[Finding]:
    if _ALL_TOOLS.search(text) and _DIRECTIVE.search(text):
        phrase = _ALL_TOOLS.search(text).group()
        yield Finding(SHADOWING, SHADOWING.default_severity,
                      f"{label}: {field} gives directions about {phrase.strip()!r}", where,
                      phrase.strip())
        return
    for other in names:
        if other == own_name or len(other) < 4:
            continue
        # A directive that names a sibling tool: "before calling send_email, ...".
        if _mentions_tool(text, other) and _DIRECTIVE.search(text):
            yield Finding(SHADOWING, SHADOWING.default_severity,
                          f"{label}: {field} gives directions about the {other!r} tool", where,
                          other)
            return


def _mentions_tool(text: str, other: str) -> bool:
    """Whether the text refers to the tool `other`, rather than reusing an English word.

    A distinctive name (send_email, browser_navigate) is unambiguous on its own. A name
    that is also an ordinary word — Read, Write, Edit — counts only where the text marks
    it as a tool: quoted, or next to "call"/"use"/"the ... tool". Without this, a
    description saying "read the file first" is read as a directive about the Read tool.
    """
    name = re.escape(other)
    if re.search(r"[_\-]", other) or len(other) > 12:
        return re.search(rf"(?i)\b{name}\b", text) is not None
    marked = (
        rf"(?i)`{name}`|\"{name}\"|'{name}'|\b{name}\b\s+tool\b|"
        rf"\b(?:call|calls|calling|invoke|invokes|invoking|use|uses|using|run|runs|running)\s+"
        rf"(?:the\s+)?{name}\b"
    )
    return re.search(marked, text) is not None


def _trust_hints(tool: dict, label: str, fields: list, where: Location) -> Iterator[Finding]:
    annotations = tool.get("annotations")
    if not isinstance(annotations, dict):
        return
    read_only = annotations.get("readOnlyHint") is True
    non_destructive = annotations.get("destructiveHint") is False
    if not (read_only or non_destructive):
        return
    name = tool.get("name") if isinstance(tool.get("name"), str) else ""
    description = next((text for field, text in fields if field == "description"), "")
    if _MUTATING_NAME.search(name) or _MUTATING.search(description):
        claim = "readOnlyHint" if read_only else "destructiveHint: false"
        yield Finding(TRUST_HINT, TRUST_HINT.default_severity,
                      f"{label}: declares {claim} but describes changing or sending data",
                      where, claim)


def _identity(names: list[str], where: Location) -> Iterator[Finding]:
    seen: set[str] = set()
    for name in names:
        if name in seen:
            yield Finding(IDENTITY, IDENTITY.default_severity,
                          f"tool name {name!r} appears more than once", where, name)
        seen.add(name)
        odd = sorted({f"U+{ord(c):04X} {unicodedata.name(c, '?')}" for c in name if ord(c) > 0x7F})
        if odd:
            yield Finding(IDENTITY, IDENTITY.default_severity,
                          f"tool name {name!r} is not ASCII: {'; '.join(odd)}", where, name)


def _text_fields(tool: dict, prefix: str = "") -> Iterator[tuple[str, str]]:
    """Every piece of text in a tool definition that the model reads."""
    for key in ("name", "title", "description"):
        value = tool.get(key)
        if isinstance(value, str):
            yield f"{prefix}{key}", value
    annotations = tool.get("annotations")
    if isinstance(annotations, dict) and isinstance(annotations.get("title"), str):
        yield f"{prefix}annotations.title", annotations["title"]
    for schema_key in ("inputSchema", "outputSchema"):
        schema = tool.get(schema_key)
        if isinstance(schema, dict):
            yield from _schema_text(schema, f"{prefix}{schema_key}")


def _schema_text(schema: dict, prefix: str, depth: int = 0) -> Iterator[tuple[str, str]]:
    if depth > 16:
        return
    for key in ("description", "title", "$comment"):
        value = schema.get(key)
        if isinstance(value, str):
            yield f"{prefix}.{key}", value
    for container in ("properties", "$defs", "definitions", "patternProperties"):
        holder = schema.get(container)
        if isinstance(holder, dict):
            for name, sub in holder.items():
                if isinstance(sub, dict):
                    yield from _schema_text(sub, f"{prefix}.{container}.{name}", depth + 1)
    for container in ("items", "additionalProperties", "not"):
        sub = schema.get(container)
        if isinstance(sub, dict):
            yield from _schema_text(sub, f"{prefix}.{container}", depth + 1)
    for container in ("oneOf", "anyOf", "allOf", "prefixItems"):
        holder = schema.get(container)
        if isinstance(holder, list):
            for i, sub in enumerate(holder):
                if isinstance(sub, dict):
                    yield from _schema_text(sub, f"{prefix}.{container}[{i}]", depth + 1)
