# ADR 0013: Semantic mimicry is measured by retrieval, not displacement, and carries no threshold

- **Date:** 2026-09-13
- **Status:** accepted
- **Language:** English, as an exception to the repository convention (see [ADR 0008](0008-own-ai-security-framework.md))
- **Amends:** [ADR 0012](0012-optional-embedding-extra-for-rag.md), on three points: the model chosen, the instrument, and how the import guard is satisfied

## Context

ADR 0012 authorised an optional `onnxruntime` backend so that **semantic mimicry** —
a planted document sharing no vocabulary with its target and retrieved for it anyway —
would become observable. It named a backend and an architecture. It did not say how
the threat would be measured, and the obvious inherited instrument, `displacements()`,
turned out to be the wrong one.

Three things were measured once the backend existed.

**The mimic never wins.** A paraphrase of a VPN article sharing only "a", "and" and
"the" with it scores 0.398 against the target's own 0.688. It is retrieved second,
never first. Every displacement measurement returns nothing, on both backends.

**It is still in the context window.** The same document scores *exactly zero*
lexically and never enters the lexical ranking at any k, while sitting at rank 2
densely. A retriever hands the model its whole top k; nothing has to win to be
injected. The attack is retrieval, and rank 1 is a detail.

**No threshold separates it from honest writing.** Against a corpus of five short,
deliberately unrelated documents the mimic's 0.398 sat well above an honest ceiling of
0.186, which looked like a rule. Recomputed over this repository's real prose — 5
documents, 13,513 words, 84 chunks — the honest ceiling is **0.515**: two genuinely
related documents reach further than the mimic does. The 0.186 was an artifact of a
toy corpus whose documents were about maximally unrelated things. A cutoff that
convicts the mimic convicts a README for resembling the rule catalogue it describes.

## Decision

1. **`retrieved(documents, k, index)` is the instrument**, added beside
   `displacements()` rather than replacing it. Displacement keeps its own result — it
   is how the duplicate confound was found — but the threat this extra exists for is
   measured as membership of the top k.
2. **No rule ships from semantic similarity.** This is the second retrieval rule to be
   refused on measurement, after MW-RAG-008, and for a sharper reason: not a confound
   that might be engineered around, but the absence of any separating score. What
   ships is an instrument and its measurements.
3. **The fp32 model, not the quantised one.** 90,387,606 bytes rather than 22,972,370,
   chosen by the user for fidelity. ADR 0012's "about 50 MB" therefore becomes: 23.6 MB
   for the `onnxruntime` wheel, ~0.25 MB of transitive dependencies not already
   present, and 90 MB of model — about 114 MB, still two orders below torch's 2 GB, and
   the model stays outside the repository in a cache directory.
4. **The import guard records the exception instead of being evaded.** ADR 0012 assumed
   a lazy import inside a function would satisfy the allowlist test. It does not: that
   test walks the AST with `ast.walk`, which reaches inside function bodies, so a lazy
   import is caught exactly like a top-level one. The exception is therefore written
   down, scoped to the single file allowed to hold it, and guarded by a second test
   that fails if any other module imports the backend or if a scanner imports the
   backend module at import time. `numpy` is never imported at all: onnxruntime returns
   arrays, and `.tolist()` needs no import.

## Consequences

**What we gain.** A measured, threshold-free statement: a paraphrase that a lexical
retriever cannot see at all is retrieved at rank 2 by a dense one. That is the gap the
extra was taken on for, and it is now a test rather than an argument.

**What we lose.** The hope that Phase 4 ends in a rule. It does not. A corpus scanner
can say a passage is *shaped* to be retrieved; it still cannot say a passage *will* be
retrieved, and now it also cannot say a passage is suspiciously similar, because
similarity does not separate. The RAG area ships eight rules and two instruments.

**What this does not authorise.** Anything beyond the one backend in the one module.
The core install keeps `dependencies = []`, every other area stays
standard-library-only, and both guards fail the build if that stops being true.

**Honest limit of the measurement.** The 0.515 ceiling comes from five documents that
all describe the same project, so they are related by construction — a fair test of
"does a threshold exist", a poor estimate of what unrelated prose scores. The
conclusion drawn is only the negative one: no defensible cutoff was found. A larger,
genuinely heterogeneous corpus could sharpen that, and would not rescue it.
