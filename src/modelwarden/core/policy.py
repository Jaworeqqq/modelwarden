"""User-supplied additions to the import allowlist.

The allowlist is a setting of one scan, but the code that consults it sits deep
inside the format scanners. A context variable carries it there without threading
a parameter through every scanner; `allowing()` scopes it to a single scan.
"""
from __future__ import annotations

from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

Entry = tuple[str, str]

_ALLOWED: ContextVar[frozenset[Entry]] = ContextVar("modelwarden_allowed", default=frozenset())
_LOCK: ContextVar[dict | None] = ContextVar("modelwarden_lock", default=None)


@contextmanager
def allowing(entries: Iterable[Entry]) -> Iterator[None]:
    token = _ALLOWED.set(frozenset(entries))
    try:
        yield
    finally:
        _ALLOWED.reset(token)


def user_allowed(module: str, name: str) -> bool:
    return (module, name) in _ALLOWED.get()


@contextmanager
def pinning(lock: dict | None) -> Iterator[None]:
    """Scope a lockfile to one scan, the same way `allowing` scopes the allowlist."""
    token = _LOCK.set(lock)
    try:
        yield
    finally:
        _LOCK.reset(token)


def pinned() -> dict | None:
    return _LOCK.get()


def adopt(entries: Iterable[Entry], lock: dict | None) -> None:
    """Take on a scan's context permanently, for a worker process.

    `allowing()` and `pinning()` scope the context to a block, which is right in one
    process and impossible across several: a context manager cannot span a fork. A
    worker exists only for the scan that started it, so it adopts the settings once and
    never resets them.
    """
    _ALLOWED.set(frozenset(entries))
    _LOCK.set(lock)


def read_lock_file(path: Path) -> dict:
    """Load a modelwarden.lock, checking its shape so a broken file is not silently ignored."""
    import json

    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or not isinstance(document.get("tools"), dict):
        raise ValueError(f"{path}: not a modelwarden lockfile (no 'tools' object)")
    return document


def parse_allow_entry(text: str) -> Entry:
    """Parse "module:name", the same form findings use as evidence."""
    module, sep, name = text.strip().partition(":")
    if not sep or not module or not name or ":" in name:
        raise ValueError(f"expected MODULE:NAME, got {text!r}")
    return module, name


def read_allow_file(path: Path) -> set[Entry]:
    """One MODULE:NAME per line; blank lines and '#' comments are ignored."""
    entries: set[Entry] = set()
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            entries.add(parse_allow_entry(line))
        except ValueError as exc:
            raise ValueError(f"{path}:{number}: {exc}") from None
    return entries
