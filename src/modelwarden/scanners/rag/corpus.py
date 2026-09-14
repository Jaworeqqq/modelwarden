"""Documents on their way into a retrieval corpus.

A retrieved chunk arrives in the context window with the same standing as the
user's own words. Whoever can put a document into the index can put text into
every answer that retrieves it, which is indirect prompt injection at its source:
the attacker never touches the model, the prompt or the application.

This inverts the rule that governs the MCP scanner. There, a description that
instructs the model is normal — legitimate servers do it, so there is deliberately
no rule for it. Here it is the anomaly: a corpus document is data the model reads,
never instructions it follows, so text addressed to the assistant has no honest
reason to be in it.

Scanning is opt-in (`modelwarden corpus PATH`) rather than detected by content.
A knowledge-base article is a text file, and so is every README, changelog and
licence; treating them all as corpus documents would report on files nobody
intends to index. The user names the corpus, because only the user knows what it is.
"""
from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterator
from pathlib import Path

from modelwarden.core.findings import Finding, Location, Rule, Severity
from modelwarden.core.text import OVERRIDE, SENSITIVE_PATH, hidden_codepoints

ATLAS = ("AML.T0051.001", "AML.T0070")
OWASP = ("LLM01:2025",)

HIDDEN_CHARACTERS = Rule(
    "MW-RAG-001",
    "Invisible characters in a corpus document",
    "The document contains characters that render as nothing or reorder text. A reviewer "
    "approving the document sees one thing and the model retrieving it reads another.",
    Severity.HIGH, ATLAS, OWASP,
)
MODEL_INSTRUCTION = Rule(
    "MW-RAG-002",
    "Document gives instructions to the assistant",
    "The text addresses the model rather than the reader: it overrides earlier "
    "instructions, opens a system or assistant turn, or tells the assistant how to "
    "behave. Retrieved text is data, so an instruction inside it is someone writing "
    "into the prompt through the index.",
    Severity.HIGH, ATLAS, OWASP,
)
INVISIBLE_MARKUP = Rule(
    "MW-RAG-003",
    "Text hidden from the reader but kept for the model",
    "The document hides text with markup — an HTML comment, display:none, zero font "
    "size, white-on-white colour. Extraction keeps the text and the rendered page does "
    "not show it, so review and retrieval see different documents.",
    Severity.HIGH, ATLAS, OWASP,
)
EXFILTRATION = Rule(
    "MW-RAG-004",
    "Document builds a URL out of the conversation",
    "A link or image URL carries a placeholder, or the text tells the assistant to put "
    "data into a URL. Many clients fetch image URLs while rendering an answer, which "
    "turns retrieved text into an outbound channel without a click.",
    Severity.HIGH, ATLAS, ("LLM02:2025",),
)
RETRIEVAL_BIAS = Rule(
    "MW-RAG-005",
    "Document claims authority over other documents",
    "The text tells the assistant to prefer, trust or cite it above other sources, or "
    "to disregard them. Ranking is the retriever's job; a document arguing its own "
    "precedence is arguing with the part of the system the user controls.",
    Severity.MEDIUM, ATLAS, OWASP,
)
KEYWORD_STUFFING = Rule(
    "MW-RAG-006",
    "Repetition shaped to win retrieval",
    "A phrase or line repeats far beyond normal prose. Similarity search rewards it, so "
    "repetition is how a planted document gets retrieved for queries it has nothing to "
    "do with.",
    Severity.MEDIUM, ATLAS, OWASP,
)
SENSITIVE_TARGET = Rule(
    "MW-RAG-007",
    "Document names credential locations",
    "The text points at private keys, environment files or credential stores. In a "
    "corpus document that is either sensitive content that should not be indexed, or "
    "the target half of an exfiltration instruction.",
    Severity.MEDIUM, ATLAS, OWASP,
)
NOT_ANALYSED = Rule(
    "MW-RAG-009",
    "Document could not be analysed",
    "The file could not be decoded as text, or is larger than the limit, so nothing in "
    "it was checked. Reported rather than skipped, because an unreadable document still "
    "reaches the index — but low, because a real corpus directory holds images, PDFs and "
    "attachments, and one line per binary would bury the findings that matter.",
    Severity.LOW, ATLAS, OWASP,
)

RAG_RULES: tuple[Rule, ...] = (
    HIDDEN_CHARACTERS, MODEL_INSTRUCTION, INVISIBLE_MARKUP, EXFILTRATION,
    RETRIEVAL_BIAS, KEYWORD_STUFFING, SENSITIVE_TARGET, NOT_ANALYSED,
)

MAX_SIZE = 16 * 1024 * 1024

# "ignore the previous instructions", "disregard everything above". Shared with the
# MCP scanner through core/text.py: a tool definition carries this language for the
# same reason a planted document does, and two copies of it drift.
_OVERRIDE = OVERRIDE
# A chat turn forged inside a document: "System:", "### Instruction", "<|im_start|>".
_ROLE_MARKER = re.compile(
    r"(?im)^[ \t>*\-]*(?:#{1,6}\s*)?(?:system|assistant|user)\s*(?::|$)"
    r"|<\|?(?:im_start|im_end|system|endoftext)\|?>"
    r"|^[ \t]*#{1,6}\s*instructions?\s*(?:for|to)\s+(?:the\s+)?(?:ai|assistant|model|llm)\b"
)
# Something that refers to the assistant, near an instruction aimed at it.
_AI_REFERENT = re.compile(
    r"(?i)\b(?:you\s+are\s+(?:an?\s+)?(?:ai|assistant|language\s+model|chatbot|llm)|"
    r"as\s+an?\s+(?:ai|assistant|language\s+model)|the\s+(?:ai|assistant|model|llm)\s+"
    r"(?:must|should|shall|will|needs?\s+to|is\s+required)|"
    r"(?:ai|assistant|model)\s+instructions?\b)"
)
# Styling whose only purpose is to keep text off the rendered page. Prose has no
# reason to carry it, so it counts on its own.
_CSS_HIDING = re.compile(
    r"(?i)display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0"
    r"|opacity\s*:\s*0(?![.\d])|color\s*:\s*(?:#f{3,6}\b|white\b)|<[a-z][^>]*\bhidden\b"
)
_HTML_COMMENT = re.compile(r"<!--(.*?)(?:-->|\Z)", re.DOTALL)
# A link or image whose URL carries a placeholder to be filled from the conversation.
_URL_PLACEHOLDER = re.compile(
    r"!?\[[^\]\n]{0,120}\]\(\s*[a-z]+://[^)\s]*(?:\{[^}\s)]{1,60}\}|%7[bB])[^)\s]*\)"
)
# "append the summary to the URL", "encode the conversation in the link".
_URL_INSTRUCTION = re.compile(
    r"(?i)\b(?:append|add|encode|include|attach|send|post|embed|put)\b[^.\n]{0,60}?"
    r"\b(?:url|link|image|query\s*string|endpoint|parameter)\b"
)
# The attack is a document arguing for *itself*: "this article supersedes the
# others". Two rounds of measurement pushed this pattern here. Bare "overrides"
# matched "the --fail-on flag overrides the default"; requiring only an object then
# matched "it now has to override a document", the sentence in the rule catalogue
# that explains this very rule. A claim of precedence needs a claimant.
_AUTHORITY = re.compile(
    r"(?i)\bthis\s+(?:document|article|page|note|entry|guide|answer)\b[^.\n]{0,60}?"
    r"\b(?:supersedes?|overrides?|replaces?|takes?\s+precedence\s+over|"
    r"is\s+(?:the\s+)?(?:most\s+)?authoritative)\b"
    r"|\b(?:supersedes?|overrides?|replaces?)\b[^.\n]{0,30}?\ball\s+(?:other\s+)?"
    r"(?:documents?|sources?|articles?|instructions?|guidance|polic(?:y|ies))\b"
    r"|\bmore\s+(?:authoritative|reliable|accurate|trustworthy)\s+than\b"
    r"|\b(?:the\s+)?most\s+(?:authoritative|reliable|up-to-date|accurate)\s+source\b"
    r"|\balways\s+(?:cite|prefer|use|trust|quote)\s+this\b"
    r"|\b(?:ignore|disregard|do\s*not\s+use)\b[^.\n]{0,30}\bother\s+"
    r"(?:documents?|sources?|results?|articles?)\b"
)

# Repetition thresholds. Prose repeats words; a document engineered for a retriever
# repeats them far past that, so the bar is set where honest writing does not reach.
_MIN_WORDS = 100
_WORD_SHARE = 0.12
_MIN_WORD_HITS = 20
_MIN_LINE_REPEATS = 5
_WORD = re.compile(r"[^\W\d_]{4,}", re.UNICODE)
_TABLE_ROW = re.compile(r"^\|.*\|$")

# Chunk geometry. A retriever stores fragments and embeds each one on its own, so a
# density measured across the whole document is measured over a unit the retrieval
# system never sees: a passage that is 37% one word disappears into an article that
# is 7% that word. Words stand in for tokens here — close enough for a density, and
# honest about not being a tokeniser.
_CHUNK_WORDS = 200
_CHUNK_OVERLAP = 40
_CHUNK_FLOOR = 60
# Measured across this repository's 23 prose documents, the densest chunk is 10.5%
# (the word "keras" in the rule catalogue). The document-level threshold of 12%
# would sit a point and a half above honest writing; at chunk scale that is not a
# margin, so this one is set where the measurement says nothing honest reaches.
_CHUNK_SHARE = 0.25
_CHUNK_MIN_HITS = 15


def scan_document(text: str, display: str, member: str | None = None) -> Iterator[Finding]:
    """Report everything in one document that is addressed to the model, not the reader."""
    where = Location(display, member)

    codepoints = hidden_codepoints(text)
    if codepoints:
        yield Finding(HIDDEN_CHARACTERS, HIDDEN_CHARACTERS.default_severity,
                      f"invisible characters in the text: {', '.join(codepoints)}",
                      where, ", ".join(codepoints))

    speaks_to_model = _addresses_model(text)
    yield from _instructions(text, where)
    yield from _hidden_markup(text, where)
    yield from _exfiltration(text, where, speaks_to_model)
    yield from _single(text, _AUTHORITY, RETRIEVAL_BIAS,
                       "the document argues for its own precedence", where)
    # Developer documentation names these paths constantly — this project's own rule
    # catalogue names ~/.ssh while describing the MCP rule for it. The path only means
    # something once the document is also talking to the assistant.
    if speaks_to_model:
        yield from _single(text, SENSITIVE_PATH, SENSITIVE_TARGET,
                           "a credential location, in a document that addresses the "
                           "assistant", where)
    yield from _repetition(text, where)


def _addresses_model(text: str) -> re.Match | None:
    """Whether anything here speaks to the assistant rather than to the reader."""
    return _OVERRIDE.search(text) or _ROLE_MARKER.search(text) or _AI_REFERENT.search(text)


def _line_of(text: str, index: int) -> int:
    """The 1-based line holding character `index`.

    Counted over characters rather than bytes: the byte offset and the string index
    diverge the moment the document is not pure ASCII, and using one where the other
    belongs is the kind of mistake that reports a plausible wrong number instead of
    failing.
    """
    return text.count("\n", 0, index) + 1


def _place(text: str, index: int, where: Location) -> Location:
    """Where a finding sits, in both units a consumer might want.

    Offset and line are produced together so neither can be forgotten: a byte offset is
    the honest unit for a file, but SARIF consumers place an alert by line and ignore
    `byteOffset`, which left every corpus finding on line 1.
    """
    return Location(where.path, where.member,
                    len(text[:index].encode("utf-8")), _line_of(text, index))


def _quote(match: re.Match, limit: int = 80) -> str:
    found = " ".join(match.group().split())
    return found[:limit]


def _single(
    text: str, pattern: re.Pattern, rule: Rule, message: str, where: Location
) -> Iterator[Finding]:
    match = pattern.search(text)
    if match:
        quoted = _quote(match)
        yield Finding(rule, rule.default_severity, f"{message} ({quoted!r})",
                      _place(text, match.start(), where), quoted)


def _instructions(text: str, where: Location) -> Iterator[Finding]:
    for pattern in (_OVERRIDE, _ROLE_MARKER):
        match = pattern.search(text)
        if match:
            quoted = _quote(match)
            yield Finding(MODEL_INSTRUCTION, MODEL_INSTRUCTION.default_severity,
                          f"text addressed to the assistant ({quoted!r})",
                          _place(text, match.start(), where), quoted)
            return
    match = _AI_REFERENT.search(text)
    if match:
        quoted = _quote(match)
        yield Finding(MODEL_INSTRUCTION, MODEL_INSTRUCTION.default_severity,
                      f"the document speaks to the assistant ({quoted!r})",
                      _place(text, match.start(), where), quoted)


def _hidden_markup(text: str, where: Location) -> Iterator[Finding]:
    yield from _single(text, _CSS_HIDING, INVISIBLE_MARKUP,
                       "markup keeps text out of the rendered document", where)
    if _CSS_HIDING.search(text):
        return
    # An HTML comment is not a finding by itself. Build markers, tooling directives
    # and licence headers are comments too; reporting every one of them buries the
    # one that matters. What is inside decides.
    for comment in _HTML_COMMENT.finditer(text):
        body = comment.group(1)
        if _addresses_model(body) or hidden_codepoints(body):
            quoted = _quote(comment)
            yield Finding(INVISIBLE_MARKUP, INVISIBLE_MARKUP.default_severity,
                          f"an HTML comment carries text for the model ({quoted!r})",
                          _place(text, comment.start(), where), quoted)
            return


def _exfiltration(
    text: str, where: Location, speaks_to_model: re.Match | None
) -> Iterator[Finding]:
    match = _URL_PLACEHOLDER.search(text)
    if match:
        quoted = _quote(match)
        yield Finding(EXFILTRATION, EXFILTRATION.default_severity,
                      f"a link URL carries a placeholder ({quoted!r})",
                      _place(text, match.start(), where), quoted)
        return
    # An instruction about URLs only counts next to something aimed at the assistant:
    # documentation explains query strings all the time.
    instruction = _URL_INSTRUCTION.search(text)
    if instruction and speaks_to_model:
        quoted = _quote(instruction)
        yield Finding(EXFILTRATION, EXFILTRATION.default_severity,
                      f"the document tells the assistant to put data in a URL ({quoted!r})",
                      _place(text, instruction.start(), where), quoted)


def _is_prose(line: str) -> bool:
    """Whether a line is writing rather than layout.

    Markdown tables repeat by design: every table in a document shares a header, and
    separator rows are identical everywhere — this project's own rule catalogue has
    twelve tables with the same header row. Layout is not retrieval shaping. Stuffing
    hidden inside table cells is still caught by the word share below.
    """
    return (
        len(line) >= 12
        and re.search(r"[^\W\d_]", line) is not None
        and not _TABLE_ROW.match(line)
    )


def _repetition(text: str, where: Location) -> Iterator[Finding]:
    lines = [" ".join(line.split()).lower() for line in text.splitlines()]
    counts = Counter(line for line in lines if _is_prose(line))
    line, repeats = counts.most_common(1)[0] if counts else ("", 0)
    if repeats >= _MIN_LINE_REPEATS:
        yield Finding(KEYWORD_STUFFING, KEYWORD_STUFFING.default_severity,
                      f"one line repeats {repeats} times ({line[:60]!r})", where, line[:60])
        return

    words = [w.lower() for w in _WORD.findall(text)]
    if len(words) >= _MIN_WORDS:
        word, hits = Counter(words).most_common(1)[0]
        if hits >= _MIN_WORD_HITS and hits / len(words) >= _WORD_SHARE:
            share = hits / len(words)
            yield Finding(KEYWORD_STUFFING, KEYWORD_STUFFING.default_severity,
                          f"{word!r} is {share:.0%} of the words ({hits} of {len(words)})",
                          where, word)
            return

    yield from _dense_chunk(text, where)


def _chunks(text: str) -> Iterator[tuple[int, str]]:
    """Overlapping word windows, the way a retriever splits a document.

    Each window carries the character offset it starts at, so a finding still points
    into the file rather than at a chunk number the user cannot locate.
    """
    words = [(m.start(), m.group()) for m in re.finditer(r"\S+", text)]
    step = _CHUNK_WORDS - _CHUNK_OVERLAP
    for i in range(0, len(words), step):
        window = words[i : i + _CHUNK_WORDS]
        if not window:
            break
        yield window[0][0], " ".join(word for _, word in window)
        if i + _CHUNK_WORDS >= len(words):
            break


def _dense_chunk(text: str, where: Location) -> Iterator[Finding]:
    """Find a passage engineered for a retriever, even where the document dilutes it."""
    for start, chunk in _chunks(text):
        words = [w.lower() for w in _WORD.findall(chunk)]
        if len(words) < _CHUNK_FLOOR:
            continue
        word, hits = Counter(words).most_common(1)[0]
        share = hits / len(words)
        if hits >= _CHUNK_MIN_HITS and share >= _CHUNK_SHARE:
            yield Finding(KEYWORD_STUFFING, KEYWORD_STUFFING.default_severity,
                          f"{word!r} is {share:.0%} of a {len(words)}-word passage, "
                          f"which a retriever stores as a chunk of its own",
                          _place(text, start, where), word)
            return


def scan_file(path: Path, display: str) -> Iterator[Finding]:
    """Read one document and scan it, failing closed when it cannot be read as text."""
    where = Location(display)
    try:
        size = path.stat().st_size
    except OSError as exc:
        yield Finding(NOT_ANALYSED, NOT_ANALYSED.default_severity, str(exc), where)
        return
    if size > MAX_SIZE:
        yield Finding(NOT_ANALYSED, NOT_ANALYSED.default_severity,
                      f"{size} bytes is over the {MAX_SIZE} byte limit", where)
        return
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        # Not text, but it was handed to the corpus command, so it is on its way to
        # an index. Saying nothing would be the one outcome that is certainly wrong.
        yield Finding(NOT_ANALYSED, NOT_ANALYSED.default_severity,
                      f"not UTF-8 text: {exc}", where)
        return
    yield from scan_document(text, display)
