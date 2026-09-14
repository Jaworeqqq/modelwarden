"""A dense retriever behind the same interface as the lexical one (ADR 0012).

The lexical index in `retrieval.py` answers "which document shares the most
distinctive words with this query". A production stack almost never asks that: it
embeds text and compares vectors, where a planted document can share *no* vocabulary
with its target and still be retrieved for it. That is semantic mimicry, and it is
invisible to lexical scoring by construction.

This module is the other half of that comparison. It is the only place in the package
that touches something outside the standard library, it is never imported at module
level by a scanner, and the import happens inside the one function that needs it so a
machine without the extra gets a sentence rather than a traceback.

The tokenizer is WordPiece, written here rather than pulled from `tokenizers` or
`transformers`: ADR 0012 authorises exactly one backend, and a second package for
splitting strings would be a dependency nobody recorded. Pooling and normalisation
are done in plain Python on `.tolist()` output, so `numpy` is never imported either
even though onnxruntime brings it along.
"""
from __future__ import annotations

import math
import unicodedata
from collections.abc import Iterable
from pathlib import Path

# Where the model lives. Nothing downloads it: a missing model is an error that says
# what is missing, because a scanner that quietly fetches 90 MB from the internet is
# doing something the user did not ask for.
MODEL_ENV = "MODELWARDEN_EMBEDDING_MODEL"
DEFAULT_MODEL_DIR = Path.home() / ".cache" / "modelwarden" / "all-MiniLM-L6-v2"

MODEL_FILE = "model.onnx"
VOCAB_FILE = "vocab.txt"

# all-MiniLM-L6-v2 accepts 512 positions. Corpus chunks are 200 words, which is well
# inside that, so the cap only guards against a pathological chunk.
MAX_TOKENS = 256
UNK, CLS, SEP, PAD = "[UNK]", "[CLS]", "[SEP]", "[PAD]"
MAX_WORD_CHARS = 100


class EmbeddingUnavailable(RuntimeError):
    """The optional backend, or the model it needs, is not installed."""


def model_dir(explicit: str | Path | None = None) -> Path:
    import os

    if explicit is not None:
        return Path(explicit)
    return Path(os.environ.get(MODEL_ENV) or DEFAULT_MODEL_DIR)


def _strip_accents(text: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFD", text)
                   if unicodedata.category(c) != "Mn")


def _is_punctuation(char: str) -> bool:
    code = ord(char)
    if (33 <= code <= 47) or (58 <= code <= 64) or (91 <= code <= 96) or (123 <= code <= 126):
        return True
    return unicodedata.category(char).startswith("P")


def _is_cjk(char: str) -> bool:
    code = ord(char)
    return any(start <= code <= end for start, end in (
        (0x4E00, 0x9FFF), (0x3400, 0x4DBF), (0x20000, 0x2A6DF), (0x2A700, 0x2B73F),
        (0x2B740, 0x2B81F), (0x2B820, 0x2CEAF), (0xF900, 0xFAFF), (0x2F800, 0x2FA1F),
    ))


def basic_tokens(text: str) -> list[str]:
    """Lowercase, drop accents, split on whitespace, punctuation and CJK characters.

    This is BERT's BasicTokenizer. It matters that it matches: a vocabulary is a map
    from the strings *that* tokenizer produces, so a different split silently turns
    ordinary words into [UNK] and the vectors stop meaning anything.
    """
    cleaned: list[str] = []
    for char in _strip_accents(text.lower()):
        code = ord(char)
        if code == 0 or code == 0xFFFD or unicodedata.category(char) == "Cc":
            continue
        if _is_cjk(char):
            cleaned.append(f" {char} ")
        elif _is_punctuation(char):
            cleaned.append(f" {char} ")
        else:
            cleaned.append(char)
    return "".join(cleaned).split()


def wordpiece(token: str, vocab: dict[str, int]) -> list[str]:
    """Greedy longest-match-first, with '##' marking a continuation piece."""
    if len(token) > MAX_WORD_CHARS:
        return [UNK]
    pieces: list[str] = []
    start = 0
    while start < len(token):
        end = len(token)
        found = None
        while start < end:
            piece = token[start:end]
            if start > 0:
                piece = "##" + piece
            if piece in vocab:
                found = piece
                break
            end -= 1
        if found is None:
            return [UNK]
        pieces.append(found)
        start = end
    return pieces


class Tokenizer:
    """BERT WordPiece over a vocab.txt, which is all the model needs."""

    def __init__(self, vocab: dict[str, int]) -> None:
        self.vocab = vocab
        for required in (UNK, CLS, SEP, PAD):
            if required not in vocab:
                raise EmbeddingUnavailable(f"vocabulary has no {required} entry")

    @classmethod
    def from_file(cls, path: Path) -> Tokenizer:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise EmbeddingUnavailable(f"cannot read the vocabulary at {path}: {exc}") from exc
        return cls({token: index for index, token in enumerate(lines)})

    def encode(self, text: str) -> tuple[list[int], list[int]]:
        """Token ids and attention mask for one passage, with [CLS] and [SEP]."""
        pieces: list[str] = []
        for token in basic_tokens(text):
            pieces.extend(wordpiece(token, self.vocab))
            if len(pieces) >= MAX_TOKENS - 2:
                break
        pieces = [CLS, *pieces[: MAX_TOKENS - 2], SEP]
        ids = [self.vocab.get(piece, self.vocab[UNK]) for piece in pieces]
        return ids, [1] * len(ids)


def _pad(rows: list[list[int]], value: int) -> list[list[int]]:
    width = max((len(row) for row in rows), default=0)
    return [row + [value] * (width - len(row)) for row in rows]


def normalise(vector: list[float]) -> list[float]:
    length = math.sqrt(sum(value * value for value in vector))
    return [value / length for value in vector] if length else vector


def cosine(left: list[float], right: list[float]) -> float:
    """Dot product. Both sides are unit vectors, so this is the cosine."""
    return sum(a * b for a, b in zip(left, right, strict=True))


class Encoder:
    """The model, loaded once. Encoding a passage yields one unit vector."""

    def __init__(self, directory: str | Path | None = None) -> None:
        self.directory = model_dir(directory)
        model = self.directory / MODEL_FILE
        if not model.is_file():
            raise EmbeddingUnavailable(
                f"no embedding model at {model}. Download all-MiniLM-L6-v2 in ONNX form "
                f"into that directory, or set {MODEL_ENV} to where it already is."
            )
        try:
            import onnxruntime
        except ModuleNotFoundError as exc:  # pragma: no cover - depends on the install
            raise EmbeddingUnavailable(
                "semantic retrieval needs the optional backend: pip install 'modelwarden[rag]'"
            ) from exc

        self.tokenizer = Tokenizer.from_file(self.directory / VOCAB_FILE)
        options = onnxruntime.SessionOptions()
        options.log_severity_level = 3
        self.session = onnxruntime.InferenceSession(
            str(model), options, providers=["CPUExecutionProvider"]
        )
        self._inputs = {i.name for i in self.session.get_inputs()}

    def encode(self, passages: Iterable[str]) -> list[list[float]]:
        """One unit vector per passage, mean-pooled over the unmasked positions."""
        passages = list(passages)
        if not passages:
            return []
        encoded = [self.tokenizer.encode(text) for text in passages]
        ids = _pad([row for row, _ in encoded], self.tokenizer.vocab[PAD])
        mask = _pad([row for _, row in encoded], 0)

        feed: dict[str, object] = {"input_ids": ids, "attention_mask": mask}
        if "token_type_ids" in self._inputs:
            feed["token_type_ids"] = [[0] * len(row) for row in ids]
        # tolist() rather than numpy indexing: onnxruntime returns arrays, but importing
        # numpy here would put a second package in front of the boundary test for no gain.
        hidden = self.session.run(None, feed)[0].tolist()

        # strict=True throughout: these pair hidden states with the mask that says which
        # positions are real. A length mismatch would silently pool part of a passage and
        # return a vector that looks perfectly ordinary, so it must raise instead.
        vectors = []
        for rows, row_mask in zip(hidden, mask, strict=True):
            kept = [vector for vector, flag in zip(rows, row_mask, strict=True) if flag]
            if not kept:
                vectors.append([0.0] * len(rows[0]))
                continue
            width = len(kept[0])
            summed = [0.0] * width
            for vector in kept:
                for index, value in enumerate(vector):
                    summed[index] += value
            vectors.append(normalise([value / len(kept) for value in summed]))
        return vectors


class DenseIndex:
    """The dense counterpart of `retrieval.Index`, with the same three methods.

    `subject_of` stays lexical on purpose. "What is this document about" is a question
    about words, and holding the query identical across both backends is what makes a
    comparison mean anything: the retriever is then the only thing that changed. If the
    subject were derived from vectors too, a difference in the result could come from
    either half and would say nothing about retrieval.
    """

    def __init__(self, encoder: Encoder | None = None) -> None:
        from modelwarden.scanners.rag.retrieval import Index

        self.encoder = encoder if encoder is not None else Encoder()
        self.lexical = Index()
        self.documents: list[str] = []
        self.chunks: list[tuple[str, list[float]]] = []

    def add(self, document: str, text: str) -> None:
        """Index one document as the same overlapping windows the lexical side stores."""
        from modelwarden.scanners.rag.corpus import _chunks

        self.lexical.add(document, text)
        self.documents.append(document)
        passages = [chunk for _offset, chunk in _chunks(text)]
        for vector in self.encoder.encode(passages):
            self.chunks.append((document, vector))

    def rank(self, query: list[str]) -> list[tuple[str, float]]:
        """Documents by their best-matching chunk, nearest first."""
        if not query or not self.chunks:
            return []
        [vector] = self.encoder.encode([" ".join(query)])
        best: dict[str, float] = {}
        for document, chunk in self.chunks:
            score = cosine(vector, chunk)
            if score > best.get(document, -1.0):
                best[document] = score
        return sorted(best.items(), key=lambda item: (-item[1], item[0]))

    def subject_of(self, document: str) -> list[str]:
        return self.lexical.subject_of(document)
