# Contributing

## The gate

Both must pass before anything is committed:

```bash
pytest -q
ruff check .
```

No flags needed — `pyproject.toml` carries the test paths and the lint
configuration. The CI workflow runs exactly these two commands and installs
nothing but `pytest` and `ruff`.

## Rules that are not negotiable

**No dependency outside the standard library in the core.** This is the loudest
claim the project makes, so it is enforced rather than trusted:
`tests/test_boundary.py` walks every import in `src/` against
`sys.stdlib_module_names`. The single authorised exception is `onnxruntime`, in
`scanners/rag/embedding.py` only, behind the `[rag]` extra
([ADR 0012](docs/adr/0012-optional-embedding-extra-for-rag.md)). CI deliberately
does not install the project, so an import of anything third-party fails there on
the commit that added it.

**Nothing is ever deserialised.** The package imports neither `pickle`, `torch`,
`numpy` nor `keras`. For the whole test run, `pickle.load`, `pickle.loads` and
`pickle.Unpickler` are replaced by tripwires.

**No malicious binary in the repository.** Fixtures that carry a payload are
built from raw opcodes at test time by `tests/builders.py`. Committed binaries
would trip antivirus and GitHub scanning, and nobody can review them by reading.

**Prompts may not extract harmful content.** The guardrail probe measures the
strength of an instruction against a harmless word (`pumpernickel`) reappearing.
That is the design, not a placeholder: a probe suite has to be runnable by anyone
against any endpoint without producing something they did not want to generate.

## Adding a rule

A rule needs a measurement, not an opinion. The pattern this project follows:

1. Build the case that should fire, and the closest case that should not.
2. Run both. Record the numbers, including the false-positive side — that is the
   half that decides whether a rule ships.
3. Write it down in `docs/rules.md` with its denominators.
   `tests/test_rules.py` fails if a rule exists with no catalogue entry.
4. Map it to MITRE ATLAS and OWASP LLM Top 10.

Rules have been withdrawn here for failing step 2. A finding that fires on most
honest files is not a rule, it is noise.

## Probes

Probe results are **rates, never verdicts**
([ADR 0010](docs/adr/0010-canary-detectors-and-rates-for-llm-probes.md)).
Detection is a deterministic canary test; no model judges another model's output.

`tools/probe_bench.py` measures one attempt at a time so a new technique can be
compared with the one before it. Two things it learned the hard way, both now
enforced: it draws a **fresh canary per sample** (the canary value itself changes
whether a model repeats it), and an attempt whose endpoint failed is recorded as
`NOT MEASURED`, never as a zero.

## Commits

One reviewable change per commit, with a message that says what was measured and
what the change costs. The catalogue and the changelog are part of the change,
not follow-up work.
