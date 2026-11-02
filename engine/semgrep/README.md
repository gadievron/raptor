# Sanitizer-recognition maintenance

Across Semgrep and CodeQL, the current recognition contract handles
multi-step sanitizer chains within one expression, not across statements.
Misses in that class remain findings for downstream validation.

A statement-chain upgrade is per-engine dataflow work: a CodeQL local-flow
join; Semgrep cannot express it outside `by-side-effect`. The documented
rationale was that no observed false-positive burden justified that upgrade.
Reassess that evidence when extending recognition rather than broadening
suppression without proof.

Recognitions with suppression authority must be single-call sanitizers
(one call is complete) or proof-gated. Preserve this boundary when editing
rules and their precision tests. The user-facing contract remains in
[static analysis](../../docs/static-analysis.md#sanitizer-recognition-contract).
