"""An OpenAI-compatible chat endpoint, reached with the standard library only.

Ollama, llama.cpp's server, vLLM and the commercial APIs all answer
POST /v1/chat/completions with the same JSON shape, so one client covers local
and hosted targets alike. urllib is enough for a JSON POST; adding an HTTP
dependency would put a third-party parser between the scanner and the thing it
is meant to be suspicious of.

Nothing here ever logs or returns the API key, and no probe text is sent
anywhere except to the endpoint the user named.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections.abc import Sequence
from dataclasses import dataclass, field

USER_AGENT = "modelwarden"
DEFAULT_TIMEOUT = 120.0


class TargetError(RuntimeError):
    """The endpoint was unreachable, refused the request, or answered in another shape."""


@dataclass(frozen=True)
class Reply:
    """One answer, with what it cost, so slow refusals are distinguishable from fast ones."""

    text: str
    seconds: float
    finish_reason: str | None = None

    def __bool__(self) -> bool:
        return bool(self.text.strip())


@dataclass
class ChatTarget:
    """A chat endpoint under test.

    The defaults are the most reproducible settings the API offers: temperature 0
    and a fixed seed. That is a starting point, not a guarantee. Servers are free
    to ignore both, which is exactly why a probe is repeated and reported as a
    rate rather than as a single verdict.
    """

    url: str
    model: str
    api_key: str | None = None
    system: str | None = None
    temperature: float = 0.0
    seed: int | None = 0
    max_tokens: int = 512
    timeout: float = DEFAULT_TIMEOUT
    _opener: urllib.request.OpenerDirector = field(default=None, repr=False, compare=False)

    @property
    def endpoint(self) -> str:
        base = self.url.rstrip("/")
        if base.endswith("/chat/completions"):
            return base
        if not base.endswith("/v1"):
            base += "/v1"
        return base + "/chat/completions"

    def describe(self) -> str:
        """Identify the target for a report, without ever revealing the key."""
        return f"{self.model} at {self.endpoint}"

    def _opening(self, system: str | None) -> list[dict[str, str]]:
        instructions = system if system is not None else self.system
        return [{"role": "system", "content": instructions}] if instructions else []

    def _payload(self, messages: list[dict[str, str]]) -> dict[str, object]:
        payload: dict[str, object] = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "stream": False,
        }
        if self.seed is not None:
            payload["seed"] = self.seed
        return payload

    def ask(self, prompt: str, system: str | None = None) -> Reply:
        messages = self._opening(system)
        messages.append({"role": "user", "content": prompt})
        return self._post(self._payload(messages))

    def converse(self, turns: Sequence[str], system: str | None = None) -> list[Reply]:
        """Hold a short conversation, feeding each answer back as context.

        Some instructions only fail after a few exchanges, once the model has its own
        earlier replies to reason from and the original rule is further up the window.
        Asking the same questions separately would be a different test entirely.
        """
        messages = self._opening(system)
        replies: list[Reply] = []
        for turn in turns:
            messages.append({"role": "user", "content": turn})
            reply = self._post(self._payload(messages))
            replies.append(reply)
            messages.append({"role": "assistant", "content": reply.text})
        return replies

    def sample(self, prompt: str, times: int, system: str | None = None) -> list[Reply]:
        """Ask the same question repeatedly. A probe that only sometimes works still works."""
        return [self.ask(prompt, system) for _ in range(max(1, times))]

    def _post(self, payload: dict) -> Reply:
        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        request = urllib.request.Request(self.endpoint, data=body, headers=headers, method="POST")

        started = time.monotonic()
        try:
            opener = self._opener or urllib.request.build_opener()
            with opener.open(request, timeout=self.timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read()[:200].decode("utf-8", "replace").strip()
            raise TargetError(f"{self.endpoint} answered HTTP {exc.code}: {detail}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise TargetError(f"{self.endpoint} is unreachable: {exc}") from None
        seconds = time.monotonic() - started

        try:
            document = json.loads(raw.decode("utf-8"))
            choice = document["choices"][0]
            text = choice["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise TargetError(f"{self.endpoint} answered in an unexpected shape: {exc}") from None
        if not isinstance(text, str):
            raise TargetError(f"{self.endpoint} returned a non-text message")
        return Reply(text=text, seconds=seconds, finish_reason=choice.get("finish_reason"))
