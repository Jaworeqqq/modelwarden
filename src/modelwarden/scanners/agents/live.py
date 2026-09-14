"""Asking a running MCP server what it offers, instead of reading a saved answer.

A `tools/list` file is a snapshot somebody kept. What reaches a model comes from a
server that is running now, and a server is free to answer one way while it is being
reviewed and another way afterwards — the rug pull the lockfile exists to catch.
Against a file, a lockfile can only tell you that two files differ. Against a live
server it tells you that the thing your client is about to trust has changed.

Starting a server runs its code, and there is no way around that: a server cannot be
asked what it offers without running. So the command is always named by the user on
the command line, never taken from a configuration file the scanner happened to
read, and never handed to a shell. `modelwarden` will report that a config launches
`npx -y something`; it will not launch it for you.

Transports are the two the specification defines: newline-delimited JSON-RPC over a
child process's stdin and stdout, and JSON-RPC over HTTP POST, whose reply may be a
JSON object or an SSE stream.
"""
from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from modelwarden.core.findings import Finding, Location, Rule, Severity
from modelwarden.scanners.agents.mcp import ATLAS, OWASP, scan_tools

PROTOCOL_VERSION = "2025-06-18"
DEFAULT_TIMEOUT = 30.0
# A tool list larger than this is not a tool list; refuse rather than buffer it.
MAX_MESSAGE = 16 * 1024 * 1024

UNREACHABLE = Rule(
    "MW-MCP-009",
    "MCP server could not be reached",
    "The server did not start, did not answer, or answered in a shape that is not the "
    "protocol. Nothing about its tools was checked. Reported rather than passed over, "
    "because a server that cannot be questioned has not been cleared.",
    Severity.MEDIUM, ATLAS, OWASP,
)
LIVE_RULES: tuple[Rule, ...] = (UNREACHABLE,)


class TransportError(RuntimeError):
    """The server could not be reached, or did not speak the protocol."""


def _client_info() -> dict:
    from modelwarden import __version__

    return {"name": "modelwarden", "version": __version__}


@dataclass
class StdioServer:
    """A server started as a child process, spoken to over its stdin and stdout."""

    command: str
    args: Sequence[str] = ()
    timeout: float = DEFAULT_TIMEOUT
    env: dict[str, str] | None = None
    _process: subprocess.Popen | None = field(default=None, repr=False, compare=False)
    _replies: queue.Queue = field(default_factory=queue.Queue, repr=False, compare=False)

    def describe(self) -> str:
        return " ".join([self.command, *self.args])

    def __enter__(self) -> StdioServer:
        try:
            # shell=False is the whole point: the argument list is what runs, and
            # nothing in it is interpreted by a shell.
            self._process = subprocess.Popen(
                [self.command, *self.args],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=self.env if self.env is not None else os.environ.copy(),
                text=True, bufsize=1,
            )
        except OSError as exc:
            raise TransportError(f"cannot start {self.describe()!r}: {exc}") from None
        threading.Thread(target=self._read_replies, daemon=True).start()
        threading.Thread(target=self._drain_errors, daemon=True).start()
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def close(self) -> None:
        process = self._process
        if process is None:
            return
        self._process = None
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()

    def _read_replies(self) -> None:
        process = self._process
        if process is None or process.stdout is None:
            return
        for line in process.stdout:
            if len(line) > MAX_MESSAGE:
                self._replies.put(TransportError("a message exceeded the size limit"))
                return
            line = line.strip()
            if not line:
                continue
            try:
                self._replies.put(json.loads(line))
            except ValueError:
                # Servers do print things that are not protocol; ignore, and let the
                # request time out if nothing valid ever arrives.
                continue

    def _drain_errors(self) -> None:
        # Nobody reads stderr, and a full pipe would wedge the child mid-answer.
        process = self._process
        if process is not None and process.stderr is not None:
            for _ in process.stderr:
                pass

    def send(self, message: dict) -> None:
        process = self._process
        if process is None or process.stdin is None:
            raise TransportError("the server is not running")
        try:
            process.stdin.write(json.dumps(message) + "\n")
            process.stdin.flush()
        except (OSError, ValueError) as exc:
            raise TransportError(f"cannot write to {self.describe()!r}: {exc}") from None

    def request(self, identifier: int, method: str, params: dict) -> dict:
        self.send({"jsonrpc": "2.0", "id": identifier, "method": method, "params": params})
        return self._await(identifier, method)

    def notify(self, method: str, params: dict) -> None:
        self.send({"jsonrpc": "2.0", "method": method, "params": params})

    def _await(self, identifier: int, method: str) -> dict:
        """Wait for the answer to one request, ignoring whatever else arrives first.

        The timeout covers the whole wait, not each message: a server that chatters
        notifications must not be able to hold the deadline open indefinitely.
        """
        deadline = time.monotonic() + self.timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                message = self._replies.get(timeout=remaining)
            except queue.Empty:
                break
            if isinstance(message, TransportError):
                raise message
            if message.get("id") == identifier:
                return _result(message, method)
        raise TransportError(f"{method}: no answer within {self.timeout:g}s")


@dataclass
class HttpServer:
    """A server reached over HTTP, whose reply may be JSON or an SSE stream."""

    url: str
    headers: dict[str, str] = field(default_factory=dict)
    timeout: float = DEFAULT_TIMEOUT
    session: str | None = field(default=None, repr=False, compare=False)
    _opener: urllib.request.OpenerDirector = field(default=None, repr=False, compare=False)

    def describe(self) -> str:
        return self.url

    def __enter__(self) -> HttpServer:
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def close(self) -> None:
        return None

    def _post(self, message: dict) -> bytes | None:
        body = json.dumps(message).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": "modelwarden",
            **self.headers,
        }
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        request = urllib.request.Request(self.url, data=body, headers=headers, method="POST")
        try:
            opener = self._opener or urllib.request.build_opener()
            with opener.open(request, timeout=self.timeout) as response:
                self.session = response.headers.get("Mcp-Session-Id") or self.session
                raw = response.read(MAX_MESSAGE + 1)
        except urllib.error.HTTPError as exc:
            detail = exc.read()[:200].decode("utf-8", "replace").strip()
            raise TransportError(f"{self.url} answered HTTP {exc.code}: {detail}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise TransportError(f"{self.url} is unreachable: {exc}") from None
        if len(raw) > MAX_MESSAGE:
            raise TransportError("the reply exceeded the size limit")
        return raw

    def request(self, identifier: int, method: str, params: dict) -> dict:
        raw = self._post({"jsonrpc": "2.0", "id": identifier, "method": method,
                          "params": params})
        return _result(_decode(raw, self.url, method), method)

    def notify(self, method: str, params: dict) -> None:
        self._post({"jsonrpc": "2.0", "method": method, "params": params})


def _decode(raw: bytes | None, where: str, method: str) -> dict:
    """One JSON-RPC message, whether it arrived as JSON or inside an SSE stream."""
    text = (raw or b"").decode("utf-8", "replace").strip()
    if not text:
        raise TransportError(f"{method}: {where} returned an empty reply")
    if text.startswith("{"):
        candidates = [text]
    else:
        # text/event-stream: the payload lives in the data: lines of each event.
        candidates = [line[5:].strip() for line in text.splitlines()
                      if line.startswith("data:")]
    for candidate in reversed(candidates):
        try:
            message = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(message, dict) and ("result" in message or "error" in message):
            return message
    raise TransportError(f"{method}: {where} answered in an unexpected shape")


def _result(message: dict, method: str) -> dict:
    if not isinstance(message, dict):
        raise TransportError(f"{method}: the answer is not a JSON-RPC message")
    error = message.get("error")
    if isinstance(error, dict):
        raise TransportError(f"{method} failed: {error.get('message', error)}")
    result = message.get("result")
    if not isinstance(result, dict):
        raise TransportError(f"{method}: the answer carries no result object")
    return result


def fetch_tools(server) -> list:
    """Handshake with a server and return the tools it offers."""
    server.request(1, "initialize", {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": _client_info(),
    })
    server.notify("notifications/initialized", {})
    result = server.request(2, "tools/list", {})
    tools = result.get("tools")
    if not isinstance(tools, list):
        raise TransportError("tools/list did not return a list of tools")
    return tools


def scan_server(server, save_lock: Path | None = None) -> Iterator[Finding]:
    """Question a live server and judge what it answers, or report that it could not be.

    `save_lock` pins what the server offered right now. Pinning a live server is the
    point of the exercise: a lockfile written from a file only records what that file
    said, while one written here records what the server actually served.
    """
    where = Location(server.describe())
    try:
        with server:
            tools = fetch_tools(server)
    except TransportError as exc:
        yield Finding(UNREACHABLE, UNREACHABLE.default_severity, str(exc), where)
        return
    if save_lock is not None:
        from modelwarden.scanners.agents.mcp import build_lock

        save_lock.write_text(json.dumps(build_lock(tools), indent=2, sort_keys=True) + "\n",
                             encoding="utf-8")
    yield from scan_tools(json.dumps({"tools": tools}).encode("utf-8"), server.describe())
