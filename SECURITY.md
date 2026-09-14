# Security policy

## Status

modelwarden is pre-alpha. It is a scanner, not a sandbox: it reduces the chance
that a malicious model file reaches a loader unnoticed. It does not make loading
one safe.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository
(**Security → Report a vulnerability**). That keeps the report private until a
fix exists. Please do not open a public issue for a security problem.

Expect a first reply within a week. This is a spare-time project with no bounty.

## What is worth reporting

The highest-value report against a scanner is **a bypass**: a file that a loader
would treat as dangerous and that modelwarden reports as clean. The project's own
catalogue (`docs/rules.md`) records several of these found during development —
a padded MCP file that slipped past a size limit, an ONNX model whose classifier
gave up early, one flipped bit that erased a finding while leaving the file valid.
Each was a real gap and each is now a test.

Concretely, please report:

- a payload reaching `REDUCE`, `INST`, `OBJ` or `BUILD` that is not reported;
- a container (zip, npz, HDF5, safetensors) whose member a loader reads and the
  scanner skips;
- any input where the scanner reports **nothing at all** rather than reporting
  that it could not parse something — silence is the failure mode this project
  is built against;
- a crash or hang on a crafted file, including unbounded memory or time.

## What is not a vulnerability

- **False positives.** Unknown imports are HIGH by design; `--allow`,
  `--allow-file` and `--baseline` exist for that. Report them as ordinary issues.
- **The scanner not executing anything.** It never deserialises, never imports
  the model's code, and never resolves external data. That is the design.
- **Findings about your model being accurate.** A reported custom operator or
  external tensor path is information, not a bug.

## Handling proof of concept

Do not attach a working malicious model file. Describe the structure, or supply
a script that generates it — that is how this repository's own fixtures work, and
it is why no malicious binary is committed here.
