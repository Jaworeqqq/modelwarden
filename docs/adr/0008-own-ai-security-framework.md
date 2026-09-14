# ADR 0008: Our own AI security framework (modelwarden) instead of extending existing tools

- **Date:** 2026-09-10
- **Status:** accepted

## Context

We want open-source tooling for validating the security of AI models, covering
the model supply chain, agents and MCP, LLM applications, and RAG pipelines.
Mature tools exist for parts of this: garak and PyRIT for LLM red-teaming,
promptfoo for evaluations in CI, and modelscan, picklescan and fickling for
model files.

The hardware sets the order of work. None of the machines this is developed on
has a GPU, so anything that needs inference is limited to small quantized models
on CPU.

## Decision

1. **Build our own framework, `modelwarden`**, rather than plugins for garak or
   PyRIT. It has one data model (target, scanner/probe, finding, reporter) shared
   by all four areas.
2. **Deliver the areas in order of infrastructure needed:** model files (no
   inference), then MCP (static manifests first), then LLM red-teaming, then RAG.
3. **Core and phase 1 use the standard library only.** The package never imports
   a deserialiser; a test enforces this.
4. **MIT licence, and the project is entirely in English**: code, README, docs,
   these ADRs and the write-up. The project is developed inside a larger private
   repository whose documentation is in another language; this is a deliberate
   exception there, because the tool is meant for a public audience.
5. **It is published with `git subtree split`** from that repository. Nothing in
   it may reference the surrounding infrastructure — inventories, secrets,
   host addresses or sibling projects — and `tests/test_boundary.py` enforces it
   by walking every shipped file.

## Rationale

- One data model is what makes cross-area features cheap. SARIF output, the CI
  gate, and ATLAS/OWASP mappings are written once and apply to model files,
  MCP servers and LLM endpoints alike.
- The known failures of existing file scanners (denylists, trusting file
  extensions, skipping unparseable members) are design decisions, not missing
  rules. They are easier to avoid from scratch than to retrofit.
- Starting with static file analysis gives a usable tool with no inference, no
  API keys and no vulnerable workloads. That fits both the hardware and the rule
  against keeping long-lived secrets on a host that runs untrusted workloads.

## Consequences

- **We lose garak's and PyRIT's probe libraries.** Hundreds of maintained
  prompt-injection and jailbreak probes, and community detectors, will have to be
  rewritten or imported in phase 3. This is the largest cost of the decision.
- **Real risk of building a weaker clone.** Each phase has to be judged against
  the existing tool for that area. If the only difference is "ours", the phase
  should end as a contribution upstream instead.
- **All maintenance is ours:** format quirks, new torch serialisation versions,
  new safetensors dtypes, and a false-positive tail from real-world models.
- **Two documentation conventions coexist** in the repository where this is
  developed. The exception is written down there so it is not "fixed" by accident.
- **Phase 3 is limited by hardware.** 1-3B models on CPU are good enough as
  targets, but too weak to act as a judge, so detectors start with deterministic
  canary tokens ([ADR 0010](0010-canary-detectors-and-rates-for-llm-probes.md)).
  Phase 2 needs deliberately vulnerable MCP servers, which must not share a host
  with anything holding personal data, so they run on a workstation for now.
