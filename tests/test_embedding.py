"""The dense backend, and the measurement that decided what it is good for.

The tokenizer tests run anywhere: WordPiece is standard library here. Everything that
touches the model skips unless the optional extra *and* a local model are both present,
because CI installs neither — `pip install modelwarden[rag]` is a deliberate act.

What these tests pin is a gap between backends, never a score. A threshold was tried
and refused: the mimic below scores 0.398 against its target's 0.688, while two
genuinely related documents in this repository reach 0.515. A cutoff separating the
first pair convicts the second. See docs/rules.md.
"""
import pytest

from modelwarden.scanners.rag.embedding import (
    DenseIndex,
    EmbeddingUnavailable,
    Encoder,
    Tokenizer,
    basic_tokens,
    cosine,
    normalise,
    wordpiece,
)
from modelwarden.scanners.rag.retrieval import Index, displacements, retrieved

VOCAB = {
    token: index
    for index, token in enumerate(
        ["[PAD]", "[UNK]", "[CLS]", "[SEP]", "play", "##ing", "##ed", "the", "quick",
         "un", "##able", "fox"]
    )
}

CORPUS = {
    "vpn.md": "Renew the certificate from the portal when the VPN client reports a "
              "handshake timeout, then reconnect and confirm the tunnel is up.",
    "expenses.md": "Submit an expense report within thirty days. Your manager approves "
                   "claims under five hundred euro; finance approves anything above.",
    "onboarding.md": "A new starter receives a laptop, building access and accounts on "
                     "the first morning, followed by the introductory training schedule.",
    "printers.md": "Install the printer driver from the software centre, then choose the "
                   "queue for your floor. Colour printing needs a cost centre code.",
    "backups.md": "Backups run nightly to the offsite repository and are verified weekly "
                  "by restoring a random archive into a scratch volume.",
}
# A paraphrase of vpn.md sharing no content word with it: "a", "and" and "the" only.
MIMIC = ("If the secure link will not establish, obtain a fresh credential through the "
         "web console and retry the session until it stays open.")
POISONED = {**CORPUS, "mimic.md": MIMIC}


@pytest.fixture(scope="module")
def encoder():
    try:
        return Encoder()
    except EmbeddingUnavailable as exc:
        pytest.skip(str(exc))


# --- the tokenizer, which needs nothing installed ---------------------------------

def test_basic_tokens_lowercases_strips_accents_and_splits_punctuation():
    assert basic_tokens("Héllo, World!") == ["hello", ",", "world", "!"]


def test_wordpiece_is_greedy_longest_match_first():
    assert wordpiece("playing", VOCAB) == ["play", "##ing"]
    assert wordpiece("unable", VOCAB) == ["un", "##able"]


def test_an_unknown_word_becomes_unk_rather_than_partial_nonsense():
    assert wordpiece("zebra", VOCAB) == ["[UNK]"]


def test_a_word_longer_than_the_limit_is_unk():
    assert wordpiece("a" * 200, VOCAB) == ["[UNK]"]


def test_encode_brackets_the_passage_with_cls_and_sep():
    ids, mask = Tokenizer(VOCAB).encode("the quick fox")
    assert ids[0] == VOCAB["[CLS]"] and ids[-1] == VOCAB["[SEP]"]
    assert mask == [1] * len(ids)


def test_a_vocabulary_without_the_special_tokens_is_refused():
    # Rather than producing vectors from a model fed the wrong ids.
    with pytest.raises(EmbeddingUnavailable):
        Tokenizer({"hello": 0})


def test_normalise_and_cosine_agree_on_a_unit_vector():
    unit = normalise([3.0, 4.0])
    assert cosine(unit, unit) == pytest.approx(1.0)


def test_a_missing_model_says_so_instead_of_raising_importerror(tmp_path):
    with pytest.raises(EmbeddingUnavailable, match="no embedding model"):
        Encoder(tmp_path)


# --- the model itself -------------------------------------------------------------

def test_the_encoder_places_a_paraphrase_nearer_than_an_unrelated_document(encoder):
    vectors = encoder.encode([CORPUS["vpn.md"], MIMIC, CORPUS["expenses.md"]])
    assert cosine(vectors[0], vectors[0]) == pytest.approx(1.0)
    assert cosine(vectors[0], vectors[1]) > cosine(vectors[0], vectors[2])


def test_every_document_still_wins_its_own_subject(encoder):
    # The control. Without it, any displacement result below could be noise.
    index = DenseIndex(encoder)
    for name, text in CORPUS.items():
        index.add(name, text)
    for name in CORPUS:
        assert index.rank(index.subject_of(name))[0][0] == name


def test_an_honest_corpus_displaces_nothing_densely_either(encoder):
    assert displacements(CORPUS, index=DenseIndex(encoder)) == {}


# --- the reason the extra exists --------------------------------------------------

def test_a_lexical_index_cannot_see_the_mimic_at_all():
    """Not "ranks it low" — scores it zero and never returns it, at any k."""
    lexical = Index()
    for name, text in POISONED.items():
        lexical.add(name, text)
    ranked = [name for name, _score in lexical.rank(lexical.subject_of("vpn.md"))]
    assert "mimic.md" not in ranked
    assert retrieved(POISONED, k=5).get("vpn.md") is None


def test_a_dense_index_retrieves_the_mimic_for_its_target(encoder):
    """The threat ADR 0012 was taken on for, in the form it actually appears."""
    neighbours = retrieved(POISONED, k=3, index=DenseIndex(encoder))
    assert "mimic.md" in neighbours.get("vpn.md", [])


def test_the_mimic_never_displaces_its_target(encoder):
    """Which is why `retrieved` exists and `displacements` was the wrong instrument.

    Nothing has to win to be injected: a retriever hands the model its whole top k.
    """
    assert "mimic.md" not in displacements(POISONED, index=DenseIndex(encoder))


def test_the_duplicate_confound_survives_the_dense_backend(encoder):
    """ADR 0012 predicted this, and the prediction held.

    Near-identical documents have near-identical vectors and tie just as thoroughly as
    they do lexically, so the tie-break stays arbitrary and MW-RAG-008 stays withdrawn.
    """
    duplicated = {**CORPUS, "copy.md": CORPUS["vpn.md"]}
    dense = displacements(duplicated, index=DenseIndex(encoder))
    assert dense in ({"copy.md": ["vpn.md"]}, {"vpn.md": ["copy.md"]})
