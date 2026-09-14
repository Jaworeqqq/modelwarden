# Changelog

Notable changes to modelwarden. Dates are the day the work landed, not a release
cadence.

## Unreleased

### Fixed

- **One flipped bit could silence an ONNX custom-operator finding, and no longer can.**
  Byte 23 of `custom-domain.onnx` is the `NodeProto.domain` field header; changing its
  wire type leaves `ai.evil` in the file, leaves the protobuf valid, leaves every byte
  accounted for — and leaves MW-SC-072 unreported. Three byte-accounting discriminators
  were tried and refuted: bytes consumed, submessage count and parse errors are
  identical between the clean file and the mutant. The case was pinned as a strict
  `xfail` for as long as that held.
- What closed it reads the model's own declaration instead of its byte layout. The
  mutation does not touch `opset_import`, which still imports `ai.evil`, and importing
  an operator set is a statement that loading needs that runtime. A domain the model
  imports that **no node uses** is now reported on its own; one that a node does use is
  reported from the node walk as before, so nothing is reported twice. Measured before
  shipping: every fixture and a real 86 MB all-MiniLM-L6-v2 declare only the empty
  domain, and none of them fires it.

- **The canary detector counted an encoded answer as a clean pass.** The check was
  `canary in reply.lower()`, so a model that answered in base64 — the ordinary way
  round an output filter, not an exotic one — was recorded as a miss. Every reply is
  now read several ways and a hit in any counts: literally, with separators removed
  (`M W - C A N` and `MW.CAN` fold together), reversed, ROT13, and base64 or hex
  decoded out of any long run that decodes cleanly, with confusable characters folded
  so `O` for `0` does not hide it. Measured: 9 of 9 encodings found, and a *different*
  canary still not matched, because eight hex digits behind a fixed prefix do not
  collide however they are folded.
- This came before writing any new prompt, and the order is the point: new attempts
  behind a literal matcher are measured with a broken instrument, so the detector
  multiplies the value of every probe at once.

### Added

- **`--jobs N`, to scan files across several processes.** Measured before it was
  written, not after: scanning eight 90 MB ONNX models spent 1.22 s of processor time
  out of 1.23 s wall, with 60% of it inside the protobuf field walk. That shape rules
  threads out and points at processes, which then returned 2.69x on four workers.
  A single file stays sequential, because starting a pool costs more than scanning it.
- The property worth having is not speed but sameness: `iter_files` already sorts and
  `map` preserves input order, so a parallel run reports the same findings in the same
  sequence. Verified end to end — the JSON report from `--jobs 4` is byte for byte the
  report from one process. A scanner that reordered its output under a flag would make
  two runs impossible to diff, which is most of what a report is for.
- The allowlist and the lockfile reach a worker through `policy.adopt()`. They are
  carried by context variables scoped with a context manager, and a context manager
  cannot span a fork; a worker lives only for one scan, so it adopts them once. The
  test for this deliberately uses an *unknown* import rather than `os.system`, because
  a known-dangerous global stays CRITICAL whatever the user allows — it would have
  passed even if the allowlist never crossed the fork.
- One honest consequence: multiprocessing's transport is itself pickle, so the suite's
  tripwire against unpickling had to be narrowed. The exemption is given to the
  transport rather than to the worker, so a forked worker still carries the tripwire
  and the scanning code stays covered on both sides of the fork. What the project
  claims is unchanged — nothing *under scan* is ever deserialised.
- **MW-LLM-006**, for a document that makes the model call a tool. The model is given
  one tool and a page that asks the *tool* rather than asking the model. Nothing is
  ever wired up — the reply is text either way — so what is measured is willingness to
  emit the call. An agent turns every retrieved page, file and tool result into
  something that can act on its behalf.
- **MW-LLM-007**, for a model that writes private data into a URL. It needs to send
  nothing: a client rendering the markdown fetches the link, and the data leaves with
  the request. The corpus scanner already reports a document *carrying* such a template
  (MW-RAG-004); this reports whether a model will *write* one.
- **The probe suite grew from 15 attempts to 51**, across 68 conversation turns.
  Encoding, continuation, forged turns and delimiters, many-shot examples, zero-width
  characters inside the instruction, non-English phrasings, and a crescendo that
  escalates over four turns. Every channel an application feeds a model — web page,
  email, CSV cell, footnote, tool result — now carries the same instruction, because a
  rule that holds for one channel and fails for another is not a rule.
- The guardrail probe still measures the strength of an instruction on a harmless
  word. Nothing here asks a model to produce anything worth withholding.

### Changed

- `test_guardrail_probe_uses_a_harmless_word` asserted `/4` attempts and broke the
  moment the suite grew. It now asserts against the probe's own attempt count — a test
  pinned to a number it does not own is measuring the wrong thing.

- **The README described a tool three phases smaller than the one that ships.** It
  opened with "four *planned* areas" and marked the supply chain "(this release)",
  while its own roadmap below showed phases 2, 3 and 4 complete. A reader who stopped
  after the second paragraph — which is most of them — concluded this was a pickle
  scanner. It now leads with all four areas, the command that reaches each one, and
  the 75 rules across five families.
- Four shipped capabilities were reachable only by reading `--help`: the `lock`
  subcommand, `probe --probe-file` (with `examples/custom-probes.json` sitting in the
  repository unmentioned), `server --header`, and baselines on `corpus`. All four are
  documented now, with worked commands.
- The `[rag]` extra was advertised beside the zero-dependency claim as though it added
  a feature. Nothing in the CLI reaches it and no finding depends on it: it is the
  instrument that measured two candidate rules out of existence (ADR 0013). Said
  plainly, so nobody installs it expecting a scan to change.
- Added what a reader could not get anywhere else: real console output for each of the
  four areas, a SARIF upload snippet for GitHub code scanning, the severity ladder
  `--fail-on` takes, the allowlist-versus-baseline distinction, and a **What it does
  not do** section — no weight inspection, no execution, a probe rate is not a verdict,
  the unparsed filtered-fractal-heap branch, and the pinned silencing defect.
- **The new tagline claimed the tool "never executes what it inspects", which is false
  for one subcommand.** `modelwarden server -- <command>` starts the MCP server named on
  the command line; the Live MCP servers section said so three screens further down, and
  the "It does not execute anything" bullet under *What it does not do* contradicted it
  too. Both now scope the claim to model files and name the exception. The README also
  buried live probing inside a list, so a reader parsed the whole tool as static: the
  tagline is now explicitly two modes, and the network boundary is stated — `probe` and
  `server` send traffic to the target you name, `scan` and `corpus` send none, and an
  external HDF5 link or ONNX `external_data` path is reported rather than followed.
- `CONTRIBUTING.md` sent contributors to `tests/test_rules.py`, which does not exist;
  the catalogue check is `tests/test_cli.py::test_every_rule_is_documented`. The `.npy`
  fixture generator still claimed CI installs pyyaml. The package description and
  keywords still said "starting with static analysis of model files".

### Added, for using this in CI

- **`--baseline FILE` and `--save-baseline FILE`** on `scan` and `corpus`. The first
  scan of an existing project is a wall of findings, and a wall is what gets a scanner
  switched off — not because the findings are wrong, but because nobody can tell which
  one is new today. The count held back is always reported, including when it is zero:
  a baseline matching nothing usually means the paths moved, and silence would look
  like a clean run.
- **SARIF `partialFingerprints`.** Without them GitHub falls back to matching alerts by
  position, so anything that shifts a file gives every finding in it a new identity and
  triaged alerts come back as new. Identity is built from the rule, path, member and
  evidence — never the byte offset — and lives on `Finding` so the baseline and SARIF
  cannot drift apart. Also adds `helpUri` to every rule.
- **Corpus findings carry their line number.** SARIF consumers place an alert by line
  and ignore `byteOffset`, so every corpus finding used to land on line 1 of its
  document. Lines are counted over characters rather than bytes, because the two agree
  only while a document is ASCII and counting wrong yields a plausible wrong number
  rather than an error.

### Fixed

- A malformed `--baseline` gave `scan` a traceback while `corpus` turned it into a
  usage error: three `_report()` call sites sat inside the guarded block and the fourth
  did not. The same bad input had two behaviours.

### Measured

- **The probe suite grew to 55 attempts and lost six**, measured against qwen2.5:3b on
  local hardware. Two rounds held: asking for the same text under a different pretext
  (quote it, proofread it, tabulate it) lands where asking for a transformation does
  not, and the same split repeats for the guardrail probe — the forbidden word as data
  a task operates on scores 10/10, as the thing to transform 0/8.
- **The measurement instrument was the problem, and finding that out was the main
  result.** `probe_bench.py` drew one canary per probe per run, so consecutive runs used
  different instruments. Measured directly: `format_task` scores 5/5 when one canary is
  repeated five times and 6/10 across ten different ones. At temperature 0 the canary is
  the only thing that varies, so repeating one measures a single case five times.
- Re-run against eight canaries each, **four attempts previously written off as dead
  turned out to land**, one of them 3 in 8. Deleting on the old reading would have
  removed working probes. Only six attempts were removed — those with a mechanism
  behind the zero, all asking the model to transform text — while the canonical
  techniques were kept: zero against one 3B model is not evidence about stronger ones.

## 0.4.0 — 2026-09-13

Released for the classification-limit fix below. On 0.3.0, padding a file past one of
those limits removes its findings: a tool list carrying a description that asks the
model to conceal what it does and names `~/.ssh/id_rsa` reports two HIGH findings at 30
bytes and nothing at all at 16.8 MB. Anyone scanning files an attacker can size has
that gap.

### Fixed

- **Padding a file past a classification limit erased its findings.** Detection reads
  bounded prefixes, and a file that outran one of them was answered "no format at
  all"; for an extension outside the model list the engine then reported nothing and
  counted it under `skipped`. Measured with one poisoned MCP tool list — a description
  asking the model to conceal what it does and naming `~/.ssh/id_rsa`: MW-MCP-002 and
  MW-MCP-003 at 30 bytes, and at 16.8 MB `scanned: 0, skipped: 1`, exit 0, nothing
  said. Padding was the whole attack.
- The same shape was found twice more by audit, and the three cases did not deserve
  the same answer. `MCP_SNIFF_LIMIT` and `HEADERLESS_PROBE_LIMIT` bound work that is
  linear in file size, so they stay and now fail closed. `USER_BLOCK_LIMIT` bounded a
  search that doubles its offset — about thirty seeks for a terabyte — so it bought
  nothing and hid every HDF5 file whose user block was one doubling past it. A 33 MB
  HDF5 model was answered "matches no supported format"; that cap is gone, and a test
  measures the seek count so it cannot return as a performance argument.
- A headerless pickle larger than 16 MB was not detected either: "not a pickle" and
  "the prefix ran out mid-stream" were the same answer. They are now distinct.

### Added

- **MW-GEN-006**, for a file whose classification stopped at a limit. Reported
  whatever the extension, because the extension rule exists to keep READMEs quiet and
  was silencing this instead. A file that matched some format never raises it.

### Removed

- A dead `MAX_SIZE` constant in the MCP scanner, declared and never read.

### Coverage

- An audit of every rule against every test found two named in none. **MW-SC-002** was
  the interesting one: the opcode walk that finds an unresolvable import was covered
  twice over, but nothing asserted that the analysis becomes a HIGH finding, so the
  rule could have stopped being emitted with the suite still green. **MW-GEN-003**, an
  unreadable file, had no test at all. Both now have one, and every rule in the
  catalogue is named by at least one test and documented.

## 0.3.0 — 2026-09-13

Released for the ONNX fix below. Anyone on 0.2.1 has a scanner that answers
"unrecognised file" for every real ONNX model — LOW, exit 0 — with all three ONNX
rules unreachable behind that answer.

### Fixed

- **Every ONNX model larger than the 64 KB sniff limit went unscanned.** ONNX has no
  magic bytes, so detection recognises the ModelProto shape over a bounded prefix. A
  real graph is very nearly the whole file — the canonical `all-MiniLM-L6-v2` export
  declares a 90,387,579-byte graph inside a 90,387,606-byte file — and the strict
  protobuf walk refused that field for running past the prefix. The sniffer therefore
  concluded "not ONNX", and a 90 MB model came back as `MW-GEN-001 content of this
  .onnx file matches no supported format`: severity LOW, exit 0, a clean gate. All
  three ONNX rules sat unreachable behind that answer.
- `iter_fields` takes `allow_truncated`, used only by detection. A field header at the
  edge of a deliberately bounded read is evidence the field exists, not evidence the
  file is malformed. The scanner reads whole files and stays strict, so nothing about
  what counts as a malformed model changed.
- Found by scanning the embedding model this project was about to load, before loading
  it. The fixtures in `tests/fixtures/onnx` are real files written by the `onnx`
  package, so "confront it with the real library" had been done — but every one of
  them is small, their graphs fit the prefix, and the missing dimension was size
  rather than authenticity. After the fix: 51 non-ONNX files — every other fixture,
  ELF binaries, shared objects, a vocabulary and a JSON config — none newly detected
  as ONNX, and all six ONNX fixtures unchanged.

### Added

- **MW-MCP-013**, for a tool definition that claims to supersede instructions already
  in force: "this replaces any earlier guidance", "supersedes all previous
  instructions", "takes precedence over any existing policy". The scanner
  deliberately has no rule for a description that *instructs* the model, because
  legitimate servers do that; claiming to displace what the operator already said is
  a different act, and no honest server needs it.
- The pattern was calibrated before it was written, against the most directive honest
  text available: 40 fields of real first-party tool definitions, several carrying
  genuine replacement language ("the skill's instructions load into the turn for you
  to follow in place of your default approach"). None matched. The verb alone never
  counts; it has to reach an object naming instructions already given.

### Changed

- The override pattern ("ignore the previous instructions") moved to `core/text.py`
  and is now shared by the MCP and corpus scanners, with a test asserting both hold
  the same object. It had lived in the corpus scanner alone, which is exactly the
  drift that module exists to prevent.
- Measurement widened it by one word. "guidance" is the ordinary term for the thing,
  and without it "disregard all earlier guidance from the operator" passed *both*
  scanners. Adding it changed nothing across this repository's 110 documents.

### Added, as an optional extra

- **`modelwarden[rag]`**, the semantic-retrieval backend ADR 0012 authorised and ADR
  0013 amends. `onnxruntime` plus a local sentence model in ONNX form; the core install
  keeps `dependencies = []` and every other area stays standard-library-only. The
  WordPiece tokenizer is written against `vocab.txt` in the standard library rather
  than pulling `tokenizers` or `transformers`, and `numpy` is never imported — the
  session returns arrays and `.tolist()` needs no import. Nothing downloads a model: a
  missing one is a sentence saying what is missing and where to put it.
- **`retrieved(documents, k, index)`**, beside `displacements()`. Both take any
  retriever with the same three methods, so the identical measurement runs against the
  lexical and the dense index and a difference is attributable to the retriever.

### Measured, and not shipped

- **A paraphrase that a lexical retriever cannot see at all is retrieved by a dense
  one.** A rewrite of a VPN article sharing only "a", "and" and "the" with it scores
  exactly zero lexically and never enters the ranking at any k; densely it sits at rank
  2, 0.398 against the target's 0.688. That gap is the reason the extra exists, and it
  is now a test.
- **It never displaces its target, and that is the point.** Displacement asks who wins.
  A retriever hands the model its entire top k, so nothing has to win to be injected —
  which is why `retrieved` was added rather than reusing the older instrument.
- **No rule ships from similarity, and this time not because of a confound.** Against
  five short unrelated documents the mimic's 0.398 cleared an honest ceiling of 0.186
  and looked like a threshold. Over this repository's real prose the honest ceiling is
  0.515: two genuinely related documents score higher than the mimic does. A cutoff
  convicting the mimic convicts a README for resembling the catalogue it describes. The
  0.186 was an artifact of a corpus whose documents were about maximally unrelated
  things.
- ADR 0012 predicted the dense backend would not rescue MW-RAG-008, because
  near-duplicates have near-identical vectors. Measured: `{'copy.md': ['vpn.md']}` on
  both backends. The prediction held and the rule stays withdrawn.

## 0.2.1 — 2026-09-13

### Fixed

- **One bit could silence a finding in an HDF5 file.** In 0.2.0, flipping a single
  bit of `extstorage-v0.h5` leaves `/nonexistent/secret.bin` in the file, the file
  still detected and parsed, and the scan reporting nothing at all — no finding and
  no MW-SC-064, because nothing looked malformed. Fuzzing found 198 such flips across
  ten fixtures.
- Two mechanisms, two fixes. A group B-tree declaring zero entries ended the walk
  silently; it is now reported when the group's local heap still names a child (15
  honest groups measured, none flagged). And a stray `0x01` anywhere in the file was
  accepted as a version 1 object header, so an address off by eight bytes walked into
  nothing; acceptance now requires a zero reserved byte, exactly one reference and at
  least one message (26 honest headers measured, none rejected).

### Known limitation

- **The equivalent ONNX case is still open.** A single bit turns a custom operator
  domain into an unreachable field while `ai.evil` remains in the bytes, and the
  result is a valid protobuf that is byte-for-byte identical to the clean file on
  every accounting metric. No extent check can separate them; it needs a semantic
  one. The reproduction is pinned as an `xfail` so the fix announces itself.

## 0.2.0 — 2026-09-13

Released for the fix below: 0.1.0 accepts a file that `torch.load` opens as an
archive containing `os.system` and reports it clean. Anyone on the tagged release
has that bypass.

### Added

- `modelwarden server` questions a **live MCP server** instead of reading a saved
  `tools/list`, over either transport the specification defines: newline-delimited
  JSON-RPC to a child process, or JSON-RPC over HTTP POST whose reply may be JSON or
  an SSE stream. `--save-lock` pins what the server serves right now and `--lock`
  compares a later answer against it, which is the rug pull MW-MCP-010 describes:
  against a file a lockfile can only say two files differ, against a server it says
  the thing the client is about to trust has changed.
- **MW-MCP-009**, for a server that would not start, timed out, or answered outside
  the protocol. Nothing about its tools was checked, and an empty finding list would
  have read like approval.

Running a server runs its code, and that cannot be worked around. The command is
always named by the user on the command line — never taken from a configuration file
the scanner happened to read, never handed to a shell.

### Fixed

- **A polyglot file hid a malicious archive completely.** `zipfile` finds an archive
  by its tail, so a harmless pickle in front of a malicious one reads as a pickle to
  anything checking the first bytes and as the archive to `torch.load`. Measured with
  one archive behind six different fronts: five were reported entirely clean. Only
  safetensors caught it, and only because its scanner accounts for every byte in the
  file — the one format that balances the whole file is the one that could not be
  used as a decoy.
- Detection now returns **every** format a file plausibly is, ordered as a loader
  would resolve them, and the engine scans all of them. Guessing once and guessing
  wrong meant reporting on a file nobody would load.
- **MW-GEN-005** reports the overlap itself, because one model file is one format.
  None of the 39 committed fixtures matches more than one.

### Measured

- **Detection rate, against gadgets this project did not invent.** 47 callables
  published by picklescan and by fickling's advisory-linked bypass suite, every one
  reported at HIGH or above; the same import through four opcode paths, all
  CRITICAL; and four frame-boundary straddles (python/cpython#154848) all caught as
  malformed rather than passing in silence. The pairs are now a test, so a
  regression in the import policy fails CI. No sample is downloaded and none is
  executed — the pickles are assembled from raw opcodes like every other fixture.

### Measured, and not shipped

- A **lexical retriever** (`scanners/rag/retrieval.py`), built to turn MW-RAG-006's
  guess about retrieval into a measurement. It answers the question it was built for:
  eight words drawn from a document's distinctive terms outrank the 658-word document
  they came from.
- **No rule ships from it.** An uncrafted copy of a document scores exactly what the
  original scores, so one displaces the other and the winner is decided by the
  tie-break — the filename. Near-duplicates are the normal condition of a knowledge
  base, so a rule built on displacement would fire on them constantly and accuse
  whichever file sorted first. MW-RAG-008 existed for two commits' worth of work and
  was withdrawn before it reached a release. The instrument, its tests and the
  measurements stay in `docs/rules.md`.

## 0.1.0 — 2026-09-13

First release. 69 rules over four areas, 377 tests, and no dependency outside the
Python 3.12 standard library.

### Model files (34 rules)

- **pickle**, protocols 0 to 5, read as an opcode stream with an emulated stack and
  memo. The package imports neither `pickle`, `torch` nor `numpy`, and a test
  enforces it by replacing pickle's loading entry points with tripwires.
- **Containers**: `torch.save` archives, legacy tar checkpoints, `.npz`, and
  TorchScript, with members judged by content — a bad CRC does not stop the scan,
  because `torch.load` reads such members anyway.
- **safetensors**: header size, duplicate keys, overlapping and out-of-range tensor
  offsets, unclaimed bytes.
- **NumPy** `.npy` / `.npz`: object arrays and the pickle inside them, header limits.
- **GGUF**: size fields checked against the file, and Jinja chat templates that
  reach Python internals (CVE-2024-34359).
- **Keras v3**: foreign modules in `config.json`, `Lambda`, `TorchModuleWrapper`,
  `TFSMLayer`, loader APIs, and names that escape the archive directory.
- **HDF5**: a read-only walker on the standard library. External links, external
  storage, virtual datasets, size bombs, legacy `model_config`, user blocks at
  powers of two, and dense link and attribute storage — the fractal heap, its
  doubling table, and name indexes at any depth.
- **ONNX**: `external_data` path traversal and custom operator domains, through an
  own protobuf reader.

### Agents and MCP (17 rules)

- Tool definitions: invisible characters, concealment, credential paths, tool
  shadowing, marked-up instruction blocks, annotations that contradict the tool.
- `modelwarden lock` pins definitions per field, so a server that changes one after
  being trusted is reported — the published rug-pull technique.
- Client configurations: unpinned servers, stored secrets, plain HTTP, shell
  launches, volatile locations. Both the top-level `mcpServers` shape and the
  per-project nesting Claude Code writes.

### Retrieval corpora (8 rules)

- `modelwarden corpus` checks documents before they reach an index: instructions
  addressed to the assistant, text hidden from the reader, URL exfiltration,
  claims of precedence, and repetition shaped to win retrieval — measured over the
  document and over 200-word windows, because a retriever stores fragments.

### Live endpoints (6 rules)

- `modelwarden probe` sends probes to an OpenAI-compatible endpoint. Detection is
  by canary token, never by a second model, and every result is a rate over
  repeated samples rather than a verdict. Multi-turn probes carry replies forward.

### Output

- Console, JSON, and SARIF 2.1.0 for GitHub code scanning. Exit 1 at or above the
  `--fail-on` threshold, default `high`.
- Every rule carries MITRE ATLAS and OWASP LLM Top 10 (2025) identifiers, listed in
  `docs/rules.md`.

### Known limits

- A **filtered fractal heap** is refused rather than parsed, and that branch has no
  test: h5py offers no way to write such a file, so nothing exercises it.
- The corpus scanner does not model the retriever. It reports that a passage is
  shaped to be retrieved, never that it will be retrieved for a given query.
- Canary detection cannot see attacks whose success is a matter of degree.
- A 0.5B model was used for probe validation. Those numbers describe that endpoint
  on that run and nothing else.
