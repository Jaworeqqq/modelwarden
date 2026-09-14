# ADR 0010: Canary detectors and reported rates, not a judge model and not verdicts

- **Date:** 2026-09-13
- **Status:** accepted

## Context

Phase 3 of `modelwarden` probes a live OpenAI-compatible endpoint: system-prompt
leakage, direct and indirect injection, guardrail bypass, context leakage across
turns. Every probe needs an answer to one question — did it work? — and there are
two ways to get one.

The common approach in this field is **LLM-as-judge**: a second model reads the
reply and decides. garak and PyRIT both support it, and it covers attacks whose
success is a matter of degree.

The hardware rules it out here. None of the machines available has a GPU, so any
judge would be a small quantised model on CPU — the same class as the targets,
often the same model. A judge no stronger than its target does not turn a
doubtful answer into a reliable one; it adds a second doubtful answer and hides
the first.

The alternative is a **canary token**: the probe plants a string that has no
reason to appear in a reply unless the probe worked, and the detector is a
substring test.

There is a second question underneath: what a finding should claim. A probe that
works once and fails twice has still found something, and a probe that works once
out of one has not proven much.

## Decision

1. **Canary-token detectors only.** A probe is scored by a deterministic test —
   the canary came back, or a named forbidden word appeared. No model is asked for
   an opinion about another model's output. Probe definitions loaded from a file
   may choose `canary` or `literal`; there is no `judge` option to choose.
2. **Every probe is repeated**, `-n` times, default 2, and a conversation counts
   as one attempt no matter how many turns it holds.
3. **A finding reports a rate, never a verdict**: "worked in 2 of 8 attempts
   (25%)", with the attempt labels that succeeded. There is no pass/fail wording
   anywhere in the probe output.
4. **The defaults are the most reproducible settings the API offers** —
   temperature 0, a fixed seed — while assuming the server ignores them.
5. **An unreachable endpoint is a finding** (MW-LLM-009), not a silent zero.

## Consequences

**What this buys.** The probe suite runs in CI against a stub endpoint with no
model at all, deterministically. Results are comparable between runs and between
targets, because the detector cannot drift. Nothing in the tool needs a GPU, an
API budget, or a second model, which keeps the zero-dependency rule intact.

**What we lose, and it is real.** Canaries only detect what can be expressed as a
token appearing. Attacks whose success is a matter of degree — a model that
becomes gradually more compliant, that leaks a paraphrase rather than the string,
that adopts a persona without quoting anything — are invisible to this design. A
judge model would catch some of them. Anyone needing that coverage should reach
for garak, and this ADR is the reason they will not find it here.

**The rate is not a stylistic preference, and that was measured.** Five identical
runs against `qwen2.5:0.5b` at temperature 0 with a fixed seed returned
2/4, 1/4, 1/4, 3/4, 1/4 for system-prompt leakage and 3/3, 2/3, 3/3, 3/3, 2/3 for
direct injection, while three other probes were silent every time. A single sample
would have described the same endpoint as anywhere between 25% and 75%.

A later measurement found a second source of that variation, and it is recorded
in `docs/rules.md`: the canary value itself decides whether a model repeats it, so
runs that drew different canaries were not comparable. The conclusion here holds
and holds harder — report a rate — but the harness now draws a fresh canary per
sample rather than per run.

**Cost.** Running each probe `n` times multiplies latency by `n`. Against a hosted
API it also multiplies the bill, which is why the default is 2 rather than
something statistically comfortable.

**A quiet probe is evidence too.** Because the detector cannot drift, a probe that
reports nothing means the model did not do the thing — not that the judge was
lenient. That is what makes the loud results readable, and it only holds as long
as detection stays deterministic.
