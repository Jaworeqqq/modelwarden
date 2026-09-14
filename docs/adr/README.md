# Decision records

Why the project is shaped the way it is, including what each decision costs.
Every record has a **Consequences** section naming what was given up, because a
decision with only upsides was not a decision.

| ADR | Decision |
|---|---|
| [0008](0008-own-ai-security-framework.md) | Our own framework rather than plugins for garak or PyRIT, and the order the four areas are delivered in |
| [0009](0009-modelwarden-allowlist-import-policy.md) | Pickle imports are judged by an allowlist with severity tiers, not a denylist — unknown means HIGH |
| [0010](0010-canary-detectors-and-rates-for-llm-probes.md) | Deterministic canary detectors and reported rates, never a judge model and never a verdict |
| [0011](0011-corpus-scanning-is-opt-in.md) | Corpus scanning is a separate command, not part of `scan` |
| [0012](0012-optional-embedding-extra-for-rag.md) | The one authorised dependency outside the standard library, and where it may be imported |
| [0013](0013-semantic-mimicry-is-retrieval-not-displacement.md) | Semantic mimicry is reported as retrieval, not displacement, because displacement could not be measured |

Numbering starts at 0008 because the first seven records predate this project.
