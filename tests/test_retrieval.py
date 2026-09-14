"""What measuring retrieval showed, pinned so the conclusion can be re-checked.

No rule ships from this module. These tests hold the measurements that decided that:
a document wins its own subject, a duplicate displaces its original, and the query a
document yields depends on the corpus around it — so copying a document's terms
lowers their weight and an attacker who looks only once defeats themselves.
"""
import pytest

from modelwarden.scanners.rag.retrieval import Index, displacements

# Short, ordinary articles about unrelated things: the honest case.
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


def indexed(corpus):
    index = Index()
    for name, text in corpus.items():
        index.add(name, text)
    return index


def subject_in(corpus, document):
    return indexed(corpus).subject_of(document)


def test_a_document_wins_its_own_subject():
    # The control. If this fails, subject terms are not identifying documents and
    # nothing measured with them means anything.
    index = indexed(CORPUS)
    for name in CORPUS:
        assert index.rank(index.subject_of(name))[0][0] == name


def test_an_honest_corpus_displaces_nothing():
    # True of this corpus, and of the 27 documents in this repository. It is not a
    # general fact about corpora — see the duplicate below.
    assert displacements(CORPUS) == {}


@pytest.mark.parametrize("victim", sorted(CORPUS))
def test_a_duplicate_ties_with_its_original(victim):
    # The measurement that stopped this from becoming a rule. A copy scores exactly
    # what the original scores, so one of the two displaces the other and which one it
    # is carries no meaning. A knowledge base holds versioned pages, sections repeated
    # in two places and FAQ entries restating an article; all of them look like this.
    poisoned = {**CORPUS, "copy.md": CORPUS[victim]}
    assert displacements(poisoned) in ({"copy.md": [victim]}, {victim: ["copy.md"]})


def test_the_duplicate_tie_is_broken_by_name():
    # The same duplicate under two names. The winner follows the alphabet, not the
    # text, which is the clearest possible statement that the signal is empty here.
    early = displacements({**CORPUS, "aaa.md": CORPUS["vpn.md"]})
    late = displacements({**CORPUS, "zzz.md": CORPUS["vpn.md"]})
    assert early.get("aaa.md") == ["vpn.md"]
    assert late.get("vpn.md") == ["zzz.md"]


def test_copying_a_subject_lowers_the_weight_of_those_terms():
    # Adding a document raises the document frequency of every term it carries, which
    # lowers their idf. The victim's subject then moves to terms the copy does not
    # have, so an attacker who reads the corpus once works against themselves.
    before = subject_in(CORPUS, "expenses.md")
    naive = {**CORPUS, "notes.md": " ".join(before)}
    assert subject_in(naive, "expenses.md") != before
    assert displacements(naive) == {}


def test_subject_derivation_oscillates_rather_than_settling():
    # Recomputing the subject after each attempt does not converge: it alternates.
    # An "adaptive attacker" built on a fixed point has nothing to stand on.
    seen = []
    text = "Notes."
    for _ in range(4):
        subject = subject_in({**CORPUS, "notes.md": text}, "expenses.md")
        seen.append(tuple(subject))
        text = "Notes. " + " ".join(subject)
    assert seen[0] == seen[2] and seen[1] == seen[3] and seen[0] != seen[1]


def test_an_empty_corpus_is_harmless():
    assert displacements({}) == {}
    assert indexed({}).average_length == 0.0
