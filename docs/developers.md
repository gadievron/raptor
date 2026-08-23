# Developer Guide

**This page is developer-facing by design.** It is the one sanctioned
home for developer documentation under `docs/` — everything else in
this directory documents the operator surface (flags, outputs,
behaviour). It carries the durable orientation a new contributor
needs and nothing deeper: the tree, docstrings, and `--help` output
are the reference for anything this page does not cover, and if a
section here grows past orientation size it is restoring cut material,
not curating. Contribution *process* — setup, tests, style, review,
security conventions — lives in [CONTRIBUTING.md](../CONTRIBUTING.md).

## The two-layer split

RAPTOR is a Python **execution layer** (scanning, subprocess
management, SARIF parsing, LLM dispatch, cost tracking — no judgement
calls) driven by a Claude Code **decision layer** (`.claude/`,
`tiers/`, `CLAUDE.md`) that prioritises findings, interprets results,
and decides what to do next. The split is deliberate: the Python layer
runs standalone in CI, the decision layer drives it interactively.
When you add a capability, the mechanical part goes in Python and the
judgement part goes in a skill or command file — never the other way
round.

## Layering rules

- **`core/`** is shared infrastructure. Dependencies point one way:
  everything may import `core/`, `core/` does not import `packages/`
  at module level (the few exceptions are lazy, function-level imports
  for feature probes such as `doctor`).
- **`packages/`** holds independent security capabilities. Each
  package owns its CLI, tests, and domain logic. Cross-package imports
  stay minimal; where capabilities genuinely compose, one package may
  drive a sibling (e.g. `static-analysis` runs the `semgrep` and
  `coccinelle` stages).
- **`libexec/`** scripts are thin dispatch shims for the decision
  layer; they delegate to `core/` or `packages/` and hold no logic
  worth testing on its own.
- **`engine/`** separates detection rules from the packages that run
  them, so rule updates never touch package code.
- Structural facts vs reasoning: `core/inventory/` captures what the
  code *is* (file enumeration, function extraction, call graph);
  `core/analysis/` reasons about it (reachability, taint summaries,
  the binary oracle). Keep new code on the right side of that line.
- `core/llm/` is the only place provider APIs are touched. It gives
  every caller cost tracking, retries, caching, and the per-model
  reliability scorecard for free.

## Package map

One line of purpose per real capability (run `ls packages/` for the
authoritative list; each package's README or module docstring is the
detail):

- **`static-analysis`** — Semgrep policy-group scanning plus the
  Coccinelle stage; normalises everything to SARIF (`scanner.py`).
- **`semgrep`** / **`coccinelle`** — rule-pack management and the
  `.cocci` runner behind the scan stage, consumed by
  `static-analysis` and the audit tool chain.
- **`codeql`** — CodeQL database creation, suite execution, and
  dataflow validation (SMT path feasibility plus LLM review).
- **`llm_analysis`** — LLM exploitability analysis of findings; the
  orchestrator dispatches `claude -p` sub-agents and correlates
  multi-model verdicts.
- **`exploitability_validation`** — the staged `/validate` pipeline
  proving findings real, reachable, and exploitable.
- **`fuzzing`** — AFL++ campaign orchestration, corpus management,
  crash collection and ranking.
- **`binary_analysis`** — GDB-driven crash triage and context
  extraction for externally- or fuzzer-discovered crashes.
- **`exploit_feasibility`** — binary mitigation analysis; produces the
  `exploitation_paths` verdicts the exploit workflow is gated on.
- **`sca`** — dependency scanning against OSV/KEV/EPSS advisory data,
  SBOM generation, CI gating.
- **`web`** — crawler, fuzzer, and OWASP-style scanner for web
  applications (alpha).
- **`code_understanding`** — the `/understand` modes (map, trace,
  hunt, teach, study).
- **`checker_synthesis`** — turns one confirmed bug into a Semgrep or
  Coccinelle rule and sweeps the codebase for variants.
- **`frida`** — dynamic instrumentation runs (attach/spawn, JS hooks,
  event capture).
- **`joern`** — Joern CPG server lifecycle and queries for the audit
  tool chain.

The hypothesis-driven audit itself lives in `core/audit/`
(orchestrator, strategies, gates) because several packages and the
decision layer share it.

## engine/: authoring detection rules

Where rules live:

- `engine/semgrep/rules/<category>/*.yaml` — in-repo Semgrep rules.
- `engine/coccinelle/rules/*.cocci` — Coccinelle semantic patches;
  `prereqs/` holds inventory patches, `source_intel/` the
  source-intel rules.
- `engine/codeql/queries/` and `engine/codeql/suites/` — custom CodeQL
  queries and suite configs. Defaults are the official per-language
  `security-and-quality` suites; see `engine/codeql/suites/README.md`.

Conventions a new rule must follow:

- **Fixture gate.** Every in-repo Semgrep rule ships a positive
  fixture (must fire) and a negative fixture (must stay silent) under
  `engine/semgrep/tests/fixtures/`; the real semgrep binary
  adjudicates in `engine/semgrep/tests/test_rule_fixtures.py`.
- **Negative controls.** `engine/negative_controls/` holds known-safe
  code that superficially resembles each bug family (e.g. a
  parameterised query whose SQL text still contains `SELECT` and a
  `LIKE '%'`). Synthesized per-hypothesis rules are run against the
  matching control at sweep time (`core/audit/sweep.py`); a rule that
  fires on it is a presence detector and its verdict is capped at
  inconclusive. A new bug-family keyword needs a control fixture.
- **Data packs over hardcoding.** Identifier vocabularies live in
  JSON packs, not in rule or Python logic:
  `engine/coccinelle/source_intel/crypto/packs/` (schema and growth
  rules in its README — a new library is a new pack file, no `.cocci`
  edit; invalid entries are dropped with a warning, a structurally
  broken pack is skipped, never fatal),
  `core/audit/data/vocab_packs/`, and
  `core/function_taxonomy/data/packs/`. The vocab-lists CI gate
  (below) enforces this.

## CLI help-text standard

Every CLI entry point (package agents, `libexec/` scripts) ships a
`--help` with:

1. a one-paragraph description of what it does;
2. required arguments;
3. optional arguments with their defaults;
4. at least two usage examples.

`--help` is authoritative. End-user docs describe the operator
surface and defer to it — do not add flag inventories to `docs/`
pages when you add a flag; update the help text.

## Sandbox: what code may assume

[sandbox.md](sandbox.md) is the operator surface; the `sandbox()` /
`run()` docstrings in `core/sandbox/` are the kwarg reference. The
model in ten lines:

- Isolation composes up to six layers — user, network, PID, IPC, and
  mount namespaces plus Landlock/seccomp/rlimits. Each layer falls
  back gracefully with a one-time warning; nothing silently downgrades
  to "no isolation", and the untrusted entry points fail closed
  rather than degrade silently.
- Egress-proxy enforcement is tiered, strongest available first:
  empty network namespace bridged to the proxy; Landlock pin to the
  proxy port plus a UDP block; environment variables alone as the
  last resort.
- New code picks a **trust level**, not kwargs: `run_untrusted()` /
  `run_untrusted_networked()` for anything attacker-derived,
  `run_trusted()` only when the full command line is RAPTOR-owned.

What code must **never** assume: that a specific layer engaged on a
given host — the run's `sandbox_info` stamps (`proxy_enforcement`,
`mount_ns_degraded`, `degraded_net_deny`, `audit_engaged`) are the
truth, so read them instead of assuming; that `$HOME`, `/tmp`, or the
network inside a sandbox are the host's; or that it may bypass
`core.sandbox` for subprocess work touching untrusted input.

## Mechanical gates you will hit

The full control inventory, triggers, and reproduce-locally commands
are in [ci-controls.md](ci-controls.md). The ones that bite
contributors, one line each:

- **ruff** (PR-blocking) — `F401`/`F811`/`F821`/`F841` over changed
  Python files; config in `pyproject.toml`.
- **command-metadata** (PR-blocking,
  `.github/scripts/check_command_metadata.py`) — every
  `.claude/commands/*.md` needs a parseable `dispatch:` field whose
  target exists on disk.
- **env-docs** (daily, `.github/scripts/check_env_docs.py`) — extracts
  every environment variable the tree reads or writes; an undocumented
  operator-facing variable fails, and so does a stale entry in
  [environment.md](environment.md).
- **vocab-lists** (daily, `.github/scripts/check_vocab_lists.py`) —
  literal function-name lists longer than nine names outside the
  data-pack seams fail; route the names through a pack.
- **miswiring** (daily, `.github/scripts/check_miswiring.py`) — dead
  definitions, kwarg/signature mismatches, swallowed exceptions,
  parsed-but-never-read flags. Note it counts textual mentions in
  `docs/`, `.claude/`, `bin/`, `tiers/`, and `.github/` as
  references — a doc line can keep a symbol "alive".
- **optional-dep-imports** (daily) — test files importing optional
  packages need an import guard, or they pass on developer hosts and
  fail on bare CI.
- **canonical-json** (daily, `.github/scripts/check_canonical_json.py`)
  — canonical JSON byte forms are frozen: inside the MAC/hash module
  list every raw `json.dumps` must be `core.json.dumps_canonical` or
  baselined with a note, and a `json.dumps` result flowing into
  `hashlib`/`hmac` anywhere is a new canonical site that must be
  routed through `dumps_canonical` or baselined.
- **ci-controls doc guard** (PR,
  `.github/tests/test_ci_controls_docs.py`) — every path named in
  [ci-controls.md](ci-controls.md) must exist on disk.
- **preflight hazards** (PR, `.github/workflows/preflight.yml`) —
  re-runs the PR's changed tests under CI-reality hazards (hidden
  optional deps, shuffle legs, duration guard).

Each baseline file under `.github/scripts/*_baseline.json` is an
exception list whose target size is zero: fix the finding, or baseline
it deliberately with a note.
