"""Text patterns shared by the scanners that read prose written for a model.

MCP tool descriptions and RAG corpus documents are different targets, but both are
text a model reads and a person usually does not. The character class below is the
clearest example of why it belongs in one place: a scanner that knows about one
fewer invisible codepoint than its sibling is a silent hole, and two copies drift
the moment somebody extends one of them.

What is *not* shared is the judgement. A tool description may legitimately instruct
the model; a retrieved document may not. Those rules live in their own scanners.
"""
from __future__ import annotations

import re

# Characters that render as nothing, or that reorder what follows, in any normal
# renderer. The model reads them; the reviewer does not see them.
HIDDEN = re.compile(
    "["
    "­"                  # soft hyphen
    "᠎"                  # Mongolian vowel separator
    "​-‏"           # zero-width space, joiners, LRM/RLM
    "‪-‮"           # bidirectional embedding and override
    "⁠-⁤"           # word joiner, invisible operators
    "⁦-⁩"           # bidirectional isolates
    "﻿"                  # zero-width no-break space
    "\U000e0000-\U000e007f"   # tag characters
    "\U000e0100-\U000e01ef"   # variation selectors supplement
    "]"
)

# Concrete credential locations. Generic words like "credentials" are left out on
# purpose: a document about credential management would describe itself with them.
SENSITIVE_PATH = re.compile(
    r"(?i)(~/\.ssh|\bid_rsa\b|\bid_ed25519\b|~/\.aws|\.git-credentials|~/\.npmrc|"
    r"~/\.pypirc|/etc/(?:passwd|shadow)|\bmcp\.json\b|~/\.config/[^\s]*token|"
    r"(?:^|[\s\"'`(/])\.env\b|\bkeychain\b|\bwallet\.dat\b)"
)


# "ignore the previous instructions", "disregard all earlier guidance". Shared
# because both targets carry it: a retrieved document uses it to hijack the turn it
# is read in, and a tool definition uses it to unseat what the operator told the
# model beforehand. Measurement widened it by one word — "guidance" is the ordinary
# term for the thing, and without it "disregard all earlier guidance" passed both
# scanners. Adding it changed nothing across this repository's 110 documents.
OVERRIDE = re.compile(
    r"(?i)\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}?"
    r"\b(?:previous|prior|above|earlier|preceding|all|any)\b[^.\n]{0,30}?"
    r"\b(?:instruction|instructions|prompt|prompts|rule|rules|direction|directions|"
    r"guideline|guidelines|guidance|context|constraint|constraints)\b"
)


def hidden_codepoints(text: str) -> list[str]:
    """Every invisible codepoint in `text`, as sorted U+XXXX labels."""
    return sorted({f"U+{ord(c):04X}" for c in HIDDEN.findall(text)})
