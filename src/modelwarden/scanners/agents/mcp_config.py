"""MCP client configuration: which servers a client launches, and with what.

`.mcp.json`, `claude_desktop_config.json` and their siblings map a server name to
either a local launch (`command`, `args`, `env`) or a remote endpoint (`url`,
`headers`). Whoever controls that file controls which code the client starts and
which tool descriptions reach the model, so the file is worth reading before it is
trusted, and it is routinely committed to a repository or synced between machines.

The rules here judge the launch, not the server: a scanner cannot tell what a
package does, but it can tell that the package is not pinned, that the transport
is unencrypted, or that a token is sitting in the file in plain text.
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path

from modelwarden.core.detect import Format
from modelwarden.core.findings import Finding, Location, Rule, Severity

ATLAS = ("AML.T0010.001", "AML.T0053")
OWASP = ("LLM03:2025",)

UNPINNED_SERVER = Rule(
    "MW-MCP-020",
    "MCP server launched without a pinned version",
    "The server is started through a package runner that resolves the newest version at "
    "launch, so the code that runs can change between launches without the config "
    "changing. Reported as low because this is how almost every published setup looks.",
    Severity.LOW, ATLAS, OWASP,
)
CONFIG_SECRET = Rule(
    "MW-MCP-021",
    "Secret stored in the client configuration",
    "An environment value or HTTP header holds what looks like a real token rather than a "
    "placeholder. These files are committed to repositories and synced between machines.",
    Severity.HIGH, ATLAS, ("LLM02:2025",),
)
PLAINTEXT_TRANSPORT = Rule(
    "MW-MCP-022",
    "MCP server reached over plain HTTP",
    "Tool definitions and tool results travel unencrypted. Anyone on the path can read "
    "them and, more to the point, rewrite the tool descriptions the model is about to "
    "follow. Loopback addresses are not reported.",
    Severity.HIGH, ATLAS, OWASP,
)
SHELL_LAUNCH = Rule(
    "MW-MCP-023",
    "MCP server launched through a shell or inline code",
    "The command is a shell or an interpreter running code given on the command line. "
    "What actually runs is then written in the config itself rather than in a package "
    "someone can review.",
    Severity.HIGH, ATLAS, OWASP,
)
UNTRUSTED_LOCATION = Rule(
    "MW-MCP-024",
    "MCP server launched from a temporary or download directory",
    "The executable lives somewhere any process can replace it, such as /tmp or a "
    "downloads folder, so what launches tomorrow need not be what was reviewed today.",
    Severity.MEDIUM, ATLAS, OWASP,
)
MALFORMED_CONFIG = Rule(
    "MW-MCP-025",
    "Malformed MCP client configuration",
    "The file is not valid JSON, or a server entry is not an object, so it was not analysed.",
    Severity.MEDIUM, ATLAS, OWASP,
)
MCP_CONFIG_RULES = (
    UNPINNED_SERVER, CONFIG_SECRET, PLAINTEXT_TRANSPORT,
    SHELL_LAUNCH, UNTRUSTED_LOCATION, MALFORMED_CONFIG,
)

# Runners that resolve a package at launch time instead of running an installed one.
_RUNNERS = {"npx", "bunx", "pnpx", "uvx", "pipx", "dlx"}
_SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "fish", "cmd", "cmd.exe", "powershell", "pwsh"}
_INTERPRETERS = {"python", "python3", "node", "deno", "bun", "ruby", "perl", "php"}
_INLINE_FLAGS = {"-c", "-e", "--eval", "--command", "/c", "/k"}
# What separates code from a wrapper: `bash -c "curl x | sh"` is a program written in
# the config, `cmd /c npx -y pkg` is the documented Windows way to start a package.
_SHELL_CODE = re.compile(r"[|;&><`$]")
# docker flags that take no value, so the first remaining argument is the image.
_DOCKER_NO_VALUE = {
    "-i", "-t", "-it", "-ti", "-d", "--rm", "--init", "--interactive", "--tty", "--detach",
}
# Directories whose contents anything can replace.
_VOLATILE = re.compile(r"(?i)^(?:/tmp/|/var/tmp/|/dev/shm/|.*/downloads?/|.*/temp/|.*\\temp\\)")
_LOOPBACK = re.compile(r"(?i)^https?://(?:localhost|127(?:\.\d+){3}|\[::1\]|0\.0\.0\.0)(?::\d+)?(?:/|$)")

# A reference to a secret rather than the secret itself. This has to match a value that
# only contains a reference, because "Bearer ${MCP_TOKEN}" is how headers are written.
_REFERENCE = re.compile(r"\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|<[^>]+>|\.\.\.")
# Token shapes that are recognisable on sight, whatever the key is called.
_KNOWN_SECRET = re.compile(
    r"^(?:gh[pousr]_[A-Za-z0-9]{16,}|sk-[A-Za-z0-9_\-]{16,}|xox[baprse]-[A-Za-z0-9\-]{10,}|"
    r"AKIA[0-9A-Z]{16}|glpat-[A-Za-z0-9_\-]{16,}|eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.)"
)
# Keys whose value is a secret by definition, if it is a value at all.
_SECRET_KEY = re.compile(r"(?i)(?:token|secret|password|passwd|api[_\-]?key|credential|auth)")
MIN_SECRET_LENGTH = 12


class MCPConfigScanner:
    name = "mcp-config"
    formats = frozenset({Format.MCP_CONFIG})
    rules = MCP_CONFIG_RULES

    def scan(self, path: Path, display: str) -> Iterator[Finding]:
        yield from scan_config(path.read_bytes(), display)


def scan_config(data: bytes, display: str, member: str | None = None) -> Iterator[Finding]:
    where = Location(display, member)
    try:
        document = json.loads(data.decode("utf-8"))
    except (ValueError, RecursionError) as exc:
        yield Finding(MALFORMED_CONFIG, MALFORMED_CONFIG.default_severity,
                      f"cannot parse JSON: {exc}", where)
        return

    servers = extract_servers(document)
    if servers is None:
        yield Finding(MALFORMED_CONFIG, MALFORMED_CONFIG.default_severity,
                      "no mcpServers object in this document", where)
        return

    for name, server in sorted(servers.items()):
        if not isinstance(server, dict):
            yield Finding(MALFORMED_CONFIG, MALFORMED_CONFIG.default_severity,
                          f"server {name!r} is not an object", where)
            continue
        yield from _server(name, server, where)


def extract_servers(document: object) -> dict | None:
    """Every server map in the document, the per-project ones included.

    A client that keeps one file for several working directories nests them: Claude
    Code writes `projects.<absolute path>.mcpServers`, so such a file has no top-level
    map at all. Reading only the top level did not merely miss those servers, it left
    the file unrecognised as a configuration, so the scan reported it as skipped and
    said nothing. Found by pointing the scanner at a real installation.
    """
    if not isinstance(document, dict):
        return None
    top = document.get("mcpServers")
    found: dict = dict(top) if isinstance(top, dict) else {}
    recognised = isinstance(top, dict)

    projects = document.get("projects")
    if isinstance(projects, dict):
        for project, settings in projects.items():
            if not isinstance(settings, dict) or not isinstance(settings.get("mcpServers"), dict):
                continue
            recognised = True
            # Qualified by project: two directories may configure the same name
            # differently, and a finding has to say which one it means.
            found.update({f"{project}: {name}": server
                          for name, server in settings["mcpServers"].items()})
    return found if recognised else None


def _server(name: str, server: dict, where: Location) -> Iterator[Finding]:
    command = server.get("command")
    args = [a for a in server.get("args", []) if isinstance(a, str)]
    if isinstance(command, str) and command:
        yield from _launch(name, command, args, where)

    url = server.get("url")
    if isinstance(url, str) and url.lower().startswith("http://") and not _LOOPBACK.match(url):
        yield Finding(PLAINTEXT_TRANSPORT, PLAINTEXT_TRANSPORT.default_severity,
                      f"server {name!r} is reached at {url}", where, url)

    for field in ("env", "headers"):
        values = server.get(field)
        if isinstance(values, dict):
            yield from _secrets(name, field, values, where)


def _launch(
    name: str, command: str, args: list[str], where: Location, depth: int = 0
) -> Iterator[Finding]:
    program = re.split(r"[/\\]", command)[-1].lower().removesuffix(".exe")
    inline = next((i for i, a in enumerate(args) if a in _INLINE_FLAGS), None)

    if program in _INTERPRETERS and inline is not None:
        # An interpreter given code on the command line: the program is the config.
        yield Finding(SHELL_LAUNCH, SHELL_LAUNCH.default_severity,
                      f"server {name!r} runs {command!r} with code from the config", where, command)
    elif program in _SHELLS and inline is not None:
        rest = args[inline + 1:]
        if len(rest) == 1 and _SHELL_CODE.search(rest[0]):
            yield Finding(SHELL_LAUNCH, SHELL_LAUNCH.default_severity,
                          f"server {name!r} runs a shell command from the config: {rest[0]!r}",
                          where, command)
        elif rest and depth < 2:
            # `cmd /c npx -y pkg`, the documented Windows launch: judge what it starts.
            yield from _launch(name, rest[0], rest[1:], where, depth + 1)

    if _VOLATILE.match(command):
        yield Finding(UNTRUSTED_LOCATION, UNTRUSTED_LOCATION.default_severity,
                      f"server {name!r} runs {command!r}", where, command)

    if program in _RUNNERS:
        package = _package_argument(args)
        if package is not None and not _is_pinned(package):
            yield Finding(UNPINNED_SERVER, UNPINNED_SERVER.default_severity,
                          f"server {name!r} runs {package!r} through {program}, "
                          "which resolves the newest version at launch", where, package)
    elif program == "docker":
        image = _docker_image(args)
        if image is not None and not _image_is_pinned(image):
            yield Finding(UNPINNED_SERVER, UNPINNED_SERVER.default_severity,
                          f"server {name!r} runs the image {image!r}, which has no version tag",
                          where, image)


def _docker_image(args: list[str]) -> str | None:
    if not args or args[0] != "run":
        return None
    skip_next = False
    for arg in args[1:]:
        if skip_next:
            skip_next = False
            continue
        if arg.startswith("-"):
            skip_next = "=" not in arg and arg not in _DOCKER_NO_VALUE
            continue
        return arg
    return None


def _image_is_pinned(image: str) -> bool:
    """`mcp/server:1.2` is pinned; `mcp/server`, `:latest` and `host:5000/img` are not."""
    _, separator, tag = image.rpartition(":")
    if not separator or "/" in tag:
        return False
    return tag != "latest"


def _package_argument(args: list[str]) -> str | None:
    """The first argument that is a package rather than a flag or a flag's value."""
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg.startswith("-"):
            # --package NAME style flags take a value; -y and --yes do not.
            skip_next = "=" not in arg and arg not in ("-y", "--yes", "-q", "--quiet", "-n")
            continue
        return arg
    return None


def _is_pinned(package: str) -> bool:
    """Whether the spec names one version: pkg@1.2.3, @scope/pkg@1.2.3, pkg==1.2.3."""
    if "==" in package:
        return True
    body = package[1:] if package.startswith("@") else package  # keep npm scopes out of it
    _, _, version = body.partition("@")
    return bool(version) and version[0].isdigit()


def _secrets(name: str, field: str, values: dict, where: Location) -> Iterator[Finding]:
    for key, value in sorted(values.items()):
        if not isinstance(value, str) or not value.strip():
            continue
        known = _KNOWN_SECRET.search(value)
        # A recognisable token counts even next to other text ("Bearer ghp_..."), but a
        # value that merely points at a variable is a reference, not a stored secret.
        if not known and _REFERENCE.search(value):
            continue
        by_key = _SECRET_KEY.search(str(key)) and len(value) >= MIN_SECRET_LENGTH
        if not (known or by_key):
            continue
        why = "a recognisable token" if known else "a value in a field named for a secret"
        yield Finding(CONFIG_SECRET, CONFIG_SECRET.default_severity,
                      f"server {name!r}: {field}.{key} holds {why} in plain text", where,
                      f"{field}.{key}")
