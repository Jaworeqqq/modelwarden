"""A lexical retriever, kept as a measuring instrument rather than as a rule.

MW-RAG-006 asks whether a passage *looks* shaped to win retrieval, which is a guess
about a system the scanner does not have. This module builds the cheap half of that
system — a lexical index scored the way BM25 describes, over the same windows a
retriever would store — so the guess can be checked: asked about a subject belonging
to some other document, which document actually comes back first?

**Nothing here emits a finding, and that is the result, not an omission.** The
measurements are in docs/rules.md; the short version is that displacement is real
and easy — eight words drawn from a document's own distinctive terms outrank the
658-word document they were taken from — but an ordinary duplicate displaces its
original just as reliably, in five cases out of five. Versioned pages, a section
copied into two places, an FAQ restating an article: a knowledge base is full of
those, so a rule built on displacement would fire mostly on legitimate content. The
clean "honest corpora displace nothing" baseline measured here held only because
this repository happens to contain no near-duplicates.

The module stays because the measurement is worth being able to repeat, and because
a future dense-retrieval version would start here. What it models is a lexical
retriever and nothing else: a production stack usually embeds text and compares
vectors, where the matching attack is semantic mimicry rather than shared
vocabulary.
"""
from __future__ import annotations

import math
from collections import Counter
from collections.abc import Mapping

from modelwarden.scanners.rag.corpus import _WORD, _chunks

# The usual BM25 constants. They are deliberately not tuned here: tuning them
# against this project's own corpus would be fitting the instrument to the sample.
K1 = 1.2
B = 0.75

# How many of a document's most distinctive terms stand in for "what it is about".
QUERY_TERMS = 8


def terms_of(text: str) -> Counter:
    return Counter(word.lower() for word in _WORD.findall(text))


class Index:
    """Chunks of every document, scored against a query the way BM25 describes."""

    def __init__(self) -> None:
        self.chunks: list[tuple[str, Counter, int]] = []
        self.document_frequency: Counter = Counter()
        self.documents: list[str] = []
        self._total_length = 0

    def add(self, document: str, text: str) -> None:
        """Index one document as the overlapping windows a retriever would store."""
        self.documents.append(document)
        for _offset, chunk in _chunks(text):
            counts = terms_of(chunk)
            if not counts:
                continue
            length = sum(counts.values())
            self.chunks.append((document, counts, length))
            self._total_length += length
            self.document_frequency.update(counts.keys())

    @property
    def average_length(self) -> float:
        return self._total_length / len(self.chunks) if self.chunks else 0.0

    def idf(self, term: str) -> float:
        frequency = self.document_frequency.get(term, 0)
        total = len(self.chunks)
        return math.log(1 + (total - frequency + 0.5) / (frequency + 0.5))

    def rank(self, query: list[str]) -> list[tuple[str, float]]:
        """Documents by their best-scoring chunk, best first."""
        average = self.average_length or 1.0
        best: dict[str, float] = {}
        for document, counts, length in self.chunks:
            score = 0.0
            for term in query:
                frequency = counts.get(term, 0)
                if not frequency:
                    continue
                norm = 1 - B + B * length / average
                score += self.idf(term) * frequency * (K1 + 1) / (frequency + K1 * norm)
            if score > best.get(document, 0.0):
                best[document] = score
        return sorted(best.items(), key=lambda item: (-item[1], item[0]))

    def subject_of(self, document: str) -> list[str]:
        """The terms that make a document itself: frequent in it, rare in the corpus.

        Note that this depends on the whole corpus, so adding a document changes the
        subject of its neighbours — including in ways that work against an attacker
        who copies those terms, since copying them lowers their idf.
        """
        counts: Counter = Counter()
        for name, chunk_counts, _length in self.chunks:
            if name == document:
                counts.update(chunk_counts)
        if not counts:
            return []
        scored = ((count * self.idf(term), term) for term, count in counts.items())
        return [term for _weight, term in sorted(scored, reverse=True)[:QUERY_TERMS]]


def displacements(
    documents: Mapping[str, str], index: object | None = None
) -> dict[str, list[str]]:
    """For each document, the documents it beat on their own subject.

    A document ranking first for its own subject is the ordinary case. Ranking first
    for somebody else's is what an attacker wants — and also what a duplicate does,
    which is why this is a measurement and not a rule.

    `index` accepts any retriever with the same three methods, so the identical
    measurement can be run against the dense backend in `embedding.py`. Keeping one
    function for both is the point: a difference in the result is then a difference
    between retrievers, not between two pieces of measuring code.
    """
    index = Index() if index is None else index
    for name, text in documents.items():
        index.add(name, text)

    displaced: dict[str, list[str]] = {}
    for name in index.documents:
        query = index.subject_of(name)
        if not query:
            continue
        ranked = index.rank(query)
        if not ranked:
            continue
        winner = ranked[0][0]
        if winner != name:
            displaced.setdefault(winner, []).append(name)
    return displaced


def retrieved(
    documents: Mapping[str, str], k: int = 3, index: object | None = None
) -> dict[str, list[str]]:
    """For each document's subject, which *other* documents come back in the top k.

    Displacement asks who wins. That turned out to be the wrong question: a paraphrase
    engineered to share no vocabulary with its target scored 0.398 against the target's
    own 0.688 — comfortably retrieved, never first. Nothing has to win to be injected.
    A retriever hands the model everything in its top k, so entering that list is the
    whole of the attack and rank 1 is a detail.

    The same measurement over a lexical index returns nothing at all for such a
    document, because it shares no terms and scores exactly zero. That gap between the
    two backends is the reason the optional extra exists.
    """
    index = Index() if index is None else index
    for name, text in documents.items():
        index.add(name, text)

    found: dict[str, list[str]] = {}
    for name in index.documents:
        query = index.subject_of(name)
        if not query:
            continue
        neighbours = [other for other, _score in index.rank(query)[:k] if other != name]
        if neighbours:
            found[name] = neighbours
    return found
