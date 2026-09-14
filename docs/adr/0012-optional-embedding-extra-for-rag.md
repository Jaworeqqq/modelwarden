# ADR 0012: An optional embedding extra for RAG, and the end of "no dependencies at all"

- **Date:** 2026-09-13
- **Status:** accepted
- **Language:** English, as an exception to the repository convention (see [ADR 0008](0008-own-ai-security-framework.md))
- **Amends:** [ADR 0008](0008-own-ai-security-framework.md), which made the standard library the whole of the dependency budget

## Context

Phase 4 ships a lexical retriever and no rule built on it. The reasoning is recorded
in `docs/rules.md`: displacement is real and easy — eight words drawn from a
document's distinctive terms outrank the 658-word document they came from — but an
uncrafted copy scores exactly what the original scores, so the winner is decided by
the filename. Near-duplicates are the normal condition of a knowledge base, so the
rule would have fired on them constantly.

That is a limit of the *metric*, not of the retriever, and it is worth being precise
about what an embedding model would and would not change. It would not fix the
duplicate confound: two near-identical documents have near-identical vectors and tie
just as thoroughly. What it would add is a threat this project currently cannot see
at all — **semantic mimicry**, a planted document that shares no vocabulary with its
target and still retrieves for it. Lexical scoring is blind to that by construction.

Against this sits the constraint from ADR 0008, now enforced by a test: every import
under `src/` must come from `sys.stdlib_module_names`, and `pyproject.toml` must
declare no runtime dependency. That test was added deliberately, one commit before
this decision, because the claim appears in the README and the changelog and was
protected only by a denylist of six deserialisers.

## Decision

1. **Semantic retrieval becomes an optional extra, `modelwarden[rag]`.** The core
   install keeps `dependencies = []` and stays standard-library-only. Nothing in
   `scanners/` imports the extra at module level; the import happens inside the code
   path that needs it, and its absence is a clear error rather than a traceback.
2. **The backend is `onnxruntime` with a small sentence model in ONNX form**, not
   `sentence-transformers`. The latter is the field's default and has better models,
   but it pulls `torch`: roughly 2 GB on a machine with no GPU, which would make the
   optional extra forty times heavier than the tool it extends. The ONNX route is
   about 50 MB, runs on CPU, and matches the hardware this project is developed on.
3. **The retriever stays an interface.** `scanners/rag/retrieval.py` already models a
   lexical retriever behind `Index`/`rank`/`subject_of`; a dense backend implements
   the same shape. Nothing in the corpus rules learns which one is in use.
4. **The manifest test is amended, not deleted.** It continues to assert
   `dependencies == []` and now permits exactly `{"dev", "rag"}` as extras. An extra
   nobody recorded here still fails the build.

## Consequences

**What we lose, stated plainly.** "No dependency outside the standard library" stops
being true without qualification, and that sentence appears in four places. It
becomes "the core has no dependencies; one optional extra does", which is weaker and
longer and has to be repeated every time the claim is made. A reader who installs
`modelwarden[rag]` no longer gets the property that made the tool easy to trust in a
CI image.

**What we gain.** Semantic mimicry becomes observable. Every measurement in
`docs/rules.md` about retrieval — displacement, the duplicate tie, the oscillating
subject derivation — was made against a lexical index, and each carries the caveat
that a production stack embeds text instead. The extra is what makes those caveats
testable rather than permanent.

**What this does not fix.** The duplicate confound that withdrew MW-RAG-008 survives
the change. A dense retriever ties near-identical documents exactly as a lexical one
does, and the tie-break remains arbitrary. Anyone hoping the extra revives that rule
should read the measurement first.

**Scope discipline.** This ADR authorises the architecture and names the backend. It
does not authorise a dependency in any other area: supply-chain scanning, MCP and
LLM probing remain standard-library-only, and the test enforces that by allowing one
named extra rather than relaxing the rule.
