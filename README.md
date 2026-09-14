# modelwarden

> Security validation for AI models, starting with static analysis of model files
> that never loads what it scans.

[![CI](https://github.com/Jaworeqqq/modelwarden/actions/workflows/ci.yml/badge.svg)](https://github.com/Jaworeqqq/modelwarden/actions/workflows/ci.yml)

## Problem

Downloading a model is downloading code. A PyTorch checkpoint is a zip with a
pickle inside, and unpickling runs whatever the pickle imports. Existing scanners
have been bypassed repeatedly, in the same few ways:

- **Denylists.** They miss any gadget nobody thought of.
- **Trusting extensions.** `torch.load` and `pickle.load` choose a format by content.
- **Skipping what they cannot parse.** A loader is often more lenient than the scanner.

## Solution

modelwarden is a framework with four planned areas, built in order of how much
infrastructure they need:

1. **Model supply chain.** Static analysis of model files (this release).
2. **Agent / MCP security.** Tool poisoning, rug pulls and hidden instructions in tool descriptions.
3. **LLM red-teaming.** Prompt injection, system-prompt leakage and jailbreaks against OpenAI-compatible endpoints.
4. **RAG poisoning.** Poisoned retrieval and cross-tenant leakage.

Phase 1 design choices:

- **Never deserialise.** Pickles are read as an opcode stream with an emulated
  stack and memo. The package does not import `pickle`, `torch` or `numpy`, and
  a test enforces it.
- **Content over names.** Formats are detected by magic bytes.
- **Fail closed.** Unparseable members, scanner crashes and unknown model-like
  files are findings, not silent passes.
- **Zero dependencies in the core.** Python 3.12 standard library only, enforced by a
  test rather than by intention. Semantic retrieval is the single optional extra,
  `modelwarden[rag]`; every other area stays standard-library-only.

## Architecture

```
paths ─▶ engine ─▶ detect (magic bytes) ─▶ registry ─▶ scanner ─▶ findings ─▶ reporter
                                                        │                     ├─ console
                         pickle ◀── zip members ────────┤                     ├─ json
                         pickle ◀── npy object arrays ──┤                     └─ sarif (GitHub code scanning)
                         pickle ◀── safetensors gaps ───┘
```

| Format | What is checked |
|---|---|
| pickle (protocol 0-5), legacy torch | imports, unresolvable imports, malformed streams, back-to-back pickles |
| zip: torch.save, `.npz`, TorchScript | every member by content, bad CRC members, embedded source |
| NumPy `.npy` | object arrays and the pickle inside them, header limits |
| safetensors | header size, duplicate keys, offsets, overlaps, unclaimed bytes, hidden pickles |
| GGUF (v2/v3, both endiannesses) | size fields against the file, tensor descriptors, Jinja chat-template injection |
| Keras v3 `.keras` | foreign modules in config.json, Lambda, TorchModuleWrapper (blob scanned as a checkpoint), TFSMLayer, loader APIs, name traversal |
| HDF5 (`.h5`, legacy Keras, `model.weights.h5`) | external links, external storage, virtual datasets, size bombs, Lambda in legacy `model_config` |
| ONNX (protobuf) | external-data path traversal, custom operator domains |
| MCP `tools/list` (JSON) | hidden instructions, invisible characters, tool shadowing, contradictory trust hints |
| MCP client config (JSON) | unpinned servers, stored secrets, plain HTTP, shell launches |
| Live LLM endpoint (probed) | system-prompt leakage, direct and indirect injection, guardrail bypass |
| RAG corpus documents (opt-in) | instructions aimed at the assistant, text hidden from the reader, URL exfiltration, retrieval shaping |
| Live MCP server (stdio or HTTP) | the same tool checks against what a server serves now, and against a lockfile |

Rules and their MITRE ATLAS / OWASP LLM mappings: [docs/rules.md](docs/rules.md).
Releases and what is in them: [CHANGELOG.md](CHANGELOG.md).
Why the project is shaped this way, and what each choice costs:
[docs/adr/](docs/adr/). Reporting a vulnerability: [SECURITY.md](SECURITY.md).
Running the gate and adding a rule: [CONTRIBUTING.md](CONTRIBUTING.md).

## Usage

```bash
pip install -e .            # or, without installing: PYTHONPATH=src python -m modelwarden
modelwarden scan ./models
modelwarden scan model.pt --format sarif --output modelwarden.sarif
modelwarden scan ./models --fail-on medium   # exit 1 at or above this severity
modelwarden scan ./models --allow mylib.layers:CustomBlock   # expected custom class: info, not high
modelwarden scan ./models --allow-file .modelwarden-allow    # one MODULE:NAME per line
modelwarden scan ./models --jobs 4           # spread files over processes; same report, in the same order
modelwarden scan ./models --save-baseline .modelwarden-baseline   # accept what is there today
modelwarden scan ./models --baseline .modelwarden-baseline        # report only what is new since
modelwarden scan ./models --lock server.lock   # tool definitions changed since the lock was written
modelwarden rules
modelwarden probe http://localhost:11434 --model qwen2.5:0.5b -n 10   # live endpoint
modelwarden probe https://api.example.com --model m --api-key-env MY_API_KEY
modelwarden corpus ./knowledge-base   # documents on their way into a RAG index
modelwarden server -- npx -y @scope/server        # question a live MCP server
modelwarden server --url https://mcp.example.com/mcp --save-lock server.lock
```

Exit codes: `0` nothing at or above the threshold (default `high`), `1` findings
at or above it, `2` usage error.

## Verification

```bash
pytest -q
```

The suite builds malicious samples from raw opcodes at test time, so no
malicious binary is ever committed. It runs with `pickle.load`, `pickle.loads`
and `pickle.Unpickler` replaced by tripwires. What it covers:

- **Detection matrix.** GLOBAL, protocol 0, STACK_GLOBAL, STACK_GLOBAL through
  the memo, computed module names, EXT opcodes, a payload after a benign pickle,
  and truncated streams.
- **False-positive guards.** `pickle.dumps` output for protocols 0-5 must parse
  cleanly, and torch storages that look like pickle headers must not be flagged.
- **Container edge cases.** Bad CRC members, spoofed extensions, safetensors
  overlaps and hidden payloads, and a sparse-file header bomb.
- **Probes against a stub endpoint.** A stub speaking the OpenAI chat shape can
  be told to leak, refuse or fail, which keeps the probe tests deterministic and
  runnable without a model. To try them against a real one:

  ```bash
  ollama serve &
  ollama pull qwen2.5:0.5b
  modelwarden probe http://127.0.0.1:11434 --model qwen2.5:0.5b -n 5
  ```

## Roadmap

- [x] Import policy for pickle globals and Keras references: an allowlist, extendable with `--allow`
- [x] GGUF: header bounds and Jinja chat templates (template injection in llama-cpp-python, CVE-2024-34359)
- [x] Keras `.keras`: config.json object references (safe_mode bypass CVEs 2025-2026)
- [x] HDF5 (`model.weights.h5`, legacy `.h5`): external storage, virtual datasets, external links, shape bombs, legacy Lambda in `model_config`
- [x] HDF5 user blocks: find the superblock at 512, 1024, ... instead of only at offset 0
- [x] HDF5 dense link storage (fractal heap with a direct root block), where an external link could hide
- [x] HDF5 dense attributes, the doubling table of indirect blocks, and B-tree internal nodes
- [x] HDF5 name indexes at any depth, with the child-pointer geometry derived and checked against h5py
- [ ] HDF5 fractal heaps that are filtered (h5py cannot write one, so the branch stays untested)
- [x] ONNX: `external_data` path traversal and custom operators (own protobuf reader, no dependency)
- [x] Phase 2: MCP `tools/list` scanning — hidden instructions, invisible characters, tool shadowing, trust hints
- [x] Phase 2: `modelwarden.lock` pinning tool definitions, to catch a server changing them after approval (rug pull)
- [x] Phase 2: MCP client configuration files (`.mcp.json`, desktop configs)
- [x] Phase 3: probes against a live OpenAI-compatible endpoint, reported as a rate over N samples
- [x] Phase 3: multi-turn conversations, so a rule that holds for one question can be tested three questions later
- [x] Phase 4: RAG corpus documents — indirect injection caught at ingestion (`modelwarden corpus`)
- [x] Phase 4: chunk-aware density, so a passage engineered for a retriever is not diluted by the article around it
- [ ] Phase 4: probes against a live retrieval pipeline, which needs an embedding model and the index
- [x] Live MCP servers over stdio and HTTP, so a lockfile can be compared against what a server serves now
