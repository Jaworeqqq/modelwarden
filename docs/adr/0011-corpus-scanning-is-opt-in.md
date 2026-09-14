# ADR 0011: Corpus scanning is opt-in, and an instruction to the assistant is a finding there

- **Date:** 2026-09-13
- **Status:** accepted
- **Language:** English, as an exception to the repository convention (see [ADR 0008](0008-own-ai-security-framework.md))

## Context

Phase 4 scans documents on their way into a retrieval index. A retrieved chunk
arrives in the context window with the same standing as the user's own words, so
whoever can add a document to the index can write into every answer that retrieves
it — indirect prompt injection at its source, with the attacker never touching the
model, the prompt, or the application.

Two design questions had no obvious answer.

**How does the scanner know a file is a corpus document?** Everywhere else in
`modelwarden`, format detection is by content and never by extension, because
`torch.load` picks a format by content and a scanner that trusts names is bypassed
by renaming. That principle does not transfer here. A knowledge-base article is a
text file, and so is every README, changelog, licence and ADR beside it. Nothing in
the bytes distinguishes a document someone intends to index from one they do not.

**Is a text instructing the assistant a finding?** The MCP scanner deliberately has
no rule for it, and that absence is documented: legitimate servers do instruct the
model — the official reference `fetch` server tells it to stop refusing internet
access — so such a rule would fire on honest servers.

## Decision

1. **`modelwarden corpus PATH` is a separate command**, not a format the engine
   detects. `modelwarden scan` never treats a text file as a corpus document. The
   user names the corpus, because only the user knows what is going into an index.
2. **MW-RAG-002 reports text addressed to the assistant** — an override of earlier
   instructions, a forged system or assistant turn, an imperative aimed at the
   model — at high severity. This is the exact inverse of the MCP decision above,
   taken on purpose.
3. **Shared detectors, separate judgement.** The invisible-character class and the
   credential-path pattern live in `core/text.py` and are used by both scanners.
   What differs is what each concludes from a match.

## Consequences

**The inversion is the point, and it has to be defensible.** A tool description is
addressed to the model by design; a retrieved document is data the model reads and
must never be instructions it follows. The same observation therefore produces no
rule in one scanner and a high-severity rule in the other. The target differs, not
the text. Anyone reading both catalogues will notice the contradiction, which is
why it is written down here rather than left to look like an oversight.

**Opt-in means it can be forgotten.** A scanner nobody runs finds nothing. There is
no automatic coverage: a corpus is checked only when someone points the command at
it, and nothing in a CI pipeline will notice a poisoned document unless the
pipeline was told where the corpus lives. The alternative was worse — measured
against this repository, treating every markdown file as a corpus document would
have reported six findings, all false positives, on documentation nobody intends to
index.

**The tool reports its own documentation, and that stays.** Running the corpus
command across this repository reports the rule catalogue itself, which quotes
`this article supersedes` as an example of what MW-RAG-005 detects. The rule is
right: the file does contain the shape. Weakening a correct rule so that
documentation about the rule stops matching it would make the rule worse everywhere
it matters. The finding is kept and explained instead.

**What is still not modelled.** The scanner reads whole documents while a retriever
stores fragments, so density is measured over both the document and 200-word
windows. It says "this passage is shaped to be retrieved", never "this passage will
be retrieved for that query". Answering the second needs an embedding model and the
index itself — the one place this design would have to take a dependency, which is
why it has not been built.
