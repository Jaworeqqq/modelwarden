# ADR 0009: modelwarden judges imports with an allowlist, not a denylist

- **Date:** 2026-09-10
- **Status:** accepted
- **Language:** English (modelwarden exception, see ADR 0008)

## Context

modelwarden reads every import a pickle performs (`GLOBAL`, `STACK_GLOBAL`,
`INST`) and every `module` + `class_name` reference in a Keras config. For each
one, `classify_global` has to decide whether it is a finding and how severe.

There are two established answers:

- **Denylist** (picklescan): flag known-dangerous imports, pass the rest. It has
  been bypassed repeatedly by gadgets nobody listed: `pip.main`,
  `runpy._run_code`, `numpy.testing._private.utils.runstring`, `torch.hub.load`
  reached through a protocol 4 dotted name.
- **Allowlist:** pass only what checkpoints are known to need and flag the rest.
  Every custom class in a legitimate model (scikit-learn estimators, a whole
  model saved with `torch.save(model)`, custom Keras layers) is then flagged.

## Decision

An allowlist, in four tiers:

1. The built-in allowlist of exact `(module, name)` pairs gets no finding.
2. Known dangerous imports are CRITICAL. The list is picklescan's maintained
   `_unsafe_globals` (MIT), copied verbatim and cross-checked against
   modelscan, plus a few documented additions of our own. Entries match on
   dotted-path boundaries of the full path. The user cannot allow these.
3. Imports the user allowed with `--allow MODULE:NAME` or `--allow-file` are
   INFO, so they stay visible in reports.
4. Everything else is HIGH, which fails the default CI gate (`--fail-on high`).

## Rationale

- The scanner is a gate. A gadget missing from a list should stop the pipeline,
  not pass it silently, because silent passes are exactly how the denylist
  scanners failed.
- A false positive costs one `--allow` line, versioned next to the model. A
  false negative costs code execution on whatever machine loads the model.
- Allowed imports are downgraded, not removed. A reviewer still sees what a model
  imports, and an allow entry left behind after the class changed stays visible.
- The user cannot silence known-dangerous imports, so a careless
  `--allow os:system` cannot turn the gate off.

## Consequences

- **Real models with custom classes fail by default.** This covers
  scikit-learn, full-model `torch.save`, and Keras models whose custom classes
  live in the user's own modules. Adoption requires writing an allow file. This
  is the main cost, and it will be the most common complaint.
- **The built-in allowlist becomes maintenance work.** New torch or numpy
  releases that pickle new internals (numpy 2 already moved `numpy.core` to
  `numpy._core`) produce HIGH findings until the list is updated.
- **Exact matching is strict on purpose.** `("collections",
  "OrderedDict.__init__")` is not the allowed `("collections", "OrderedDict")`.
  Walking attributes from a safe global is treated as unknown.
- **The dangerous list is a snapshot of someone else's research.** New gadgets
  picklescan adds do not reach us until the snapshot is updated. The allowlist
  softens this, because an unlisted gadget is still HIGH, just not CRITICAL and
  not immune to `--allow`.
- **One policy covers pickle and Keras.** Tuning it for one format affects the
  other. That is intended, since both mean "import this and call it".
