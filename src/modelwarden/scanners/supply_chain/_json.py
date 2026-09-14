"""Strict JSON loading shared by the format scanners."""
from __future__ import annotations

import json
from collections import Counter


def load_strict(data: bytes) -> object:
    """Parse UTF-8 JSON and reject duplicate keys.

    Duplicate keys are a parser differential: Python keeps the last value, other
    parsers keep the first or refuse the file, so a scanner and a loader can end
    up looking at different data. Raises ValueError (UnicodeDecodeError included)
    or RecursionError.
    """
    return json.loads(data.decode("utf-8"), object_pairs_hook=_unique)


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    counts = Counter(key for key, _ in pairs)
    duplicates = sorted(key for key, n in counts.items() if n > 1)
    if duplicates:
        raise ValueError(f"duplicate keys {duplicates}")
    return dict(pairs)
