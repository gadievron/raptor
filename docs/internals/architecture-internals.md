# Architecture Internals

Contributor-facing reference: the file-by-file inventory of the RAPTOR tree and
the internals of the `calibrated_aggregation` output. For the conceptual "how it
works" tour (modes, design principles, model reasoning), read
[`../concepts.md`](../concepts.md) first.

> Inventory current as of 2026-07-18 (verified against every `packages/*` and
> `core/*` directory in the working tree). Regenerate from the working tree
> (`ls -d packages/*/ core/*/`) if directories are added, removed, or renamed —
> treat this as a snapshot, not a contract.

---

## Directory inventory

```
raptor/
│
├── core/                           # Shared utilities layer (45 subpackages)
│   ├── __init__.py
│   ├── analysis/                   # Taint approx, reachability, binary-oracle verdicts, CFG, dataflow
│   ├── annotations/                # Per-function prose annotations (markdown mirroring source tree)
│   ├── archive/                    # Archive facade — multi-format detection + safe extraction
│   ├── ast/                        # Structured per-function views over the inventory substrate
│   ├── atomic_fs/                  # Atomic file-write primitive (tempfile + rename)
│   ├── binary/                     # Binary substrate: fingerprinting + capability diff
│   ├── build/                      # Build-system detection + toolchain probes
│   ├── config/                     # RaptorConfig (paths, settings)
│   ├── coverage/                   # Read-coverage tracking + summary
│   ├── cve/                        # Per-CVE signal layer: EPSS, KEV, vulnrichment
│   ├── dataflow/                   # Producer-neutral dataflow finding schema + adapters
│   ├── dockerfile/                 # Dockerfile parsing helpers (FROM/ENV)
│   ├── function_taxonomy/          # Shared taxonomy of function-name categories with security significance
│   ├── git/                        # Sandbox-routed clone + URL allowlist
│   ├── hash/                       # SHA-256 helpers (tree/file/bytes/string)
│   ├── http/                       # EgressClient + per-host allowlists
│   ├── inventory/                  # Shared source inventory
│   │   ├── builder.py              # build_inventory() — file enumeration + checksums
│   │   ├── extractors.py           # Language-aware function extraction
│   │   ├── languages.py            # LANGUAGE_MAP, detect_language
│   │   ├── exclusions.py           # File exclusion + generated-file detection
│   │   ├── lookup.py               # lookup_function() — file:line → function
│   │   ├── diff.py                 # compare_inventories() — SHA-256 diffing
│   │   ├── reachability.py         # Function-call reachability (substrate)
│   │   └── coverage.py             # checked_by tracking + coverage stats
│   ├── json/                       # BOM-tolerant JSON utils + cache helpers
│   ├── labeled_attempts/           # Finding-keyed append-only corpus of oracle-verified attempts
│   ├── license/                    # Target license detection + classification (SPDX)
│   ├── llm/                        # LLM substrate (clients, providers, scorecard, tool-use loop)
│   ├── logging/                    # Structured logging with JSONL audit trail
│   ├── oci/                        # OCI image-ref parsing + canonicalisation
│   ├── orchestration/              # Pipeline orchestration helpers (understand_bridge, agentic_passes)
│   ├── progress/                   # Progress tracking utilities
│   ├── project/                    # Project workspace mgmt (CLI, merge, clean, export, diff)
│   ├── reporting/                  # Findings/report formatting (markdown, summary lines)
│   ├── run/                        # Per-run lifecycle (output dir, suffixes)
│   ├── sage/                       # SAGE inception client + hooks (memory layer)
│   ├── sandbox/                    # subprocess isolation (Landlock + seccomp + namespaces)
│   ├── sarif/
│   │   └── parser.py               # SARIF 2.1.0 parsing utilities
│   ├── schema_constants/           # Shared schema field-name constants
│   ├── security/                   # Prompt envelope, secret redaction, env sanitisation, cc_trust
│   ├── sentinels/                  # Reload-stable sentinel objects
│   ├── smt_solver/                 # Z3-based path-feasibility (rejection, witness, csem)
│   ├── startup/                    # CLI startup banner + env validation
│   ├── status/                     # Status/verdict string normalisation (single source of truth)
│   ├── tar/                        # Tar primitives for attacker-influenced archives
│   ├── threat_model/               # Project-level threat model artefact (assets, trust boundaries, scope)
│   ├── trajectories/                # Trajectory persistence — per-iteration tool-call traces
│   ├── tuning/                     # Hardware-aware resource tuning
│   ├── upstream_latest/            # Look up latest stable version of an upstream package/release
│   ├── url_patterns/               # Canonical URL regex patterns for commit-URL extraction
│   ├── witness/                    # Canonical "input bytes that triggered a bug" artefact
│   └── zip/                        # Zip primitives for attacker-influenced archives (mirrors core/tar)
│
├── packages/                       # Security capabilities layer (27 subpackages)
│   ├── __init__.py
│   │
│   ├── autonomous/                 # Autonomous agent capabilities
│   │   ├── __init__.py
│   │   ├── corpus_generator.py     # Fuzzing corpus generation
│   │   ├── dialogue.py             # Agent dialogue management
│   │   ├── exploit_validator.py    # Exploit code validation
│   │   ├── goal_planner.py         # Goal-oriented planning
│   │   ├── memory.py               # Agent memory and context
│   │   └── planner.py              # Task planning and decomposition
│   │
│   ├── binary_analysis/            # Binary crash analysis
│   │   ├── __init__.py
│   │   ├── crash_analyser.py       # Main: GDB crash analysis
│   │   └── debugger.py             # GDB wrapper and automation
│   │
│   ├── checker_synthesis/          # KNighter-style checker synthesis: bug → Semgrep/Coccinelle rule → variant hunt
│   │
│   ├── coccinelle/                 # Coccinelle integration: semantic patching + inconsistency detection for C/C++
│   │
│   ├── codeql/                     # CodeQL deep analysis
│   │   ├── __init__.py
│   │   ├── agent.py                # Main: CodeQL workflow orchestration
│   │   ├── autonomous_analyzer.py  # Autonomous CodeQL analysis
│   │   ├── build_detector.py       # Build system detection
│   │   ├── database_manager.py     # CodeQL database creation/management
│   │   ├── dataflow_validator.py   # Dataflow path validation
│   │   ├── dataflow_visualizer.py  # Dataflow visualization
│   │   ├── language_detector.py    # Programming language detection
│   │   └── query_runner.py         # CodeQL query execution
│   │
│   ├── code_understanding/         # Code-understanding multi-model consumers (--hunt / --trace orchestration)
│   │
│   ├── cve_diff/                   # CVE patch discovery: find, acquire, diff the fix commit for a CVE
│   │
│   ├── cvss/                       # CVSS v3.1 base score calculator
│   │
│   ├── describe/                   # Target description: language mix, build system, catalog match, cost estimate
│   │
│   ├── diagram/                    # Mermaid diagram generation from /understand and /validate outputs
│   │
│   ├── exploitability_validation/  # Multi-stage pipeline validating findings are real/reachable/exploitable
│   │
│   ├── exploitation/               # Exploit-development workflow support (bootstrap, reporting)
│   │
│   ├── exploit_feasibility/        # Mitigation + exploitation-factor analysis (run before exploit dev)
│   │
│   ├── frida/                      # Frida dynamic-instrumentation substrate (runner, CLI, hook templates)
│   │
│   ├── fuzzing/                    # Binary fuzzing
│   │   ├── __init__.py
│   │   ├── afl_runner.py           # AFL++ orchestration
│   │   ├── crash_collector.py      # Crash triage and ranking
│   │   └── corpus_manager.py       # Seed corpus generation
│   │
│   ├── hypothesis_validation/      # Hypothesis-driven, tool-grounded vulnerability validation
│   │
│   ├── llm_analysis/               # LLM-powered analysis
│   │   ├── __init__.py
│   │   ├── agent.py                # Main: Source code analysis
│   │   ├── crash_agent.py          # Main: Binary crash analysis
│   │   ├── orchestrator.py         # Multi-agent coordination (requires Claude Code)
│   │   └── llm/
│   │       ├── __init__.py
│   │       ├── client.py           # LLM client abstraction
│   │       ├── config.py           # LLM configuration
│   │       ├── detection.py        # LLM availability detection
│   │       ├── model_data.py       # Model costs, limits, provider endpoints
│   │       └── providers.py        # Provider implementations (Anthropic, OpenAI, etc.)
│   │
│   ├── nvd/                        # NVD API v2.0 shared client + parser
│   │
│   ├── osv/                        # OSV.dev shared client, parser, oracle verdict types
│   │
│   ├── recon/                      # Reconnaissance
│   │   ├── __init__.py
│   │   └── agent.py                # Main: Tech stack enumeration
│   │
│   ├── sca/                        # Software Composition Analysis
│   │   ├── __init__.py
│   │   └── cli.py                  # Main: Dependency vulnerability scanning
│   │
│   ├── semgrep/                    # Semgrep integration: pattern-matching static analysis
│   │
│   ├── source_intel/               # Cocci-based structural evidence for memory-corruption CWEs
│   │
│   ├── static-analysis/            # Static code scanning
│   │   ├── __init__.py
│   │   ├── scanner.py              # Main: Semgrep orchestrator
│   │   └── codeql/
│   │       └── env.py              # CodeQL environment setup
│   │
│   ├── strategy_eval/              # Evaluation harness for cwe_strategies bug-class lenses
│   │
│   ├── web/                        # Web application testing
│   │   ├── __init__.py
│   │   ├── client.py               # HTTP client wrapper
│   │   ├── crawler.py              # Web crawler
│   │   ├── fuzzer.py               # Input fuzzing
│   │   └── scanner.py              # Web vulnerability scanner
│   │
│   └── zkpox/                      # Zero-Knowledge Proof of Exploit (tiered proving)
│
├── engine/                         # Analysis engines
│   ├── codeql/
│   │   └── suites/                 # CodeQL query suites
│   └── semgrep/
│       ├── rules/                  # Semgrep custom rules
│       ├── semgrep.yaml            # Semgrep configuration
│       └── tools/                  # Semgrep utilities
│
├── tiers/                          # Tiered expertise system
│   ├── analysis-guidance.md        # Adversarial analysis guidance
│   ├── recovery.md                 # Error recovery protocols
│   ├── personas/                   # Expert personas
│   │   ├── binary_exploitation_specialist.md
│   │   ├── codeql_analyst.md
│   │   ├── codeql_finding_analyst.md
│   │   ├── crash_analyst.md
│   │   ├── exploit_developer.md
│   │   ├── fuzzing_strategist.md
│   │   ├── patch_engineer.md
│   │   ├── penetration_tester.md
│   │   └── security_researcher.md
│   └── specialists/
│       └── README.md               # Specialist documentation
│
├── docs/                           # Documentation
│
├── out/                            # Output directory (all artifacts)
│   ├── logs/                       # JSONL structured logs
│   │   └── raptor_<timestamp>.jsonl
│   └── scan_<repo>_<timestamp>/    # Scan outputs
│       ├── semgrep_*.sarif         # SARIF findings
│       ├── scan_metrics.json       # Scan statistics
│       └── verification.json       # Verification results
│
├── raptor.py                       # Main launcher (Claude Code integration)
├── raptor_agentic.py               # Source code analysis workflow
├── raptor_codeql.py                # CodeQL workflow orchestrator
├── raptor_fuzzing.py               # Binary fuzzing workflow
├── requirements.txt                # Python dependencies
├── CLAUDE.md                       # Claude Code instructions
├── LICENSE                         # License file
└── README.md                       # Main README
```

---

## Core layer notes

### `core/config/` — RaptorConfig

Centralised configuration; the single source of truth for all paths. Environment
variable support (`RAPTOR_DIR`, `RAPTOR_OUT_DIR`) with graceful fallback to
auto-detection. Exposes the `REPO_ROOT`/`LOG_DIR` class attributes and
`get_out_dir()`.

> **Import contract:** packages reach `core/` via the interpreter's normal
> package resolution. Per the repo's `CLAUDE.md`, the only permitted `sys.path`
> entry is `os.environ["RAPTOR_DIR"]` (hard lookup, no fallbacks). Do not add
> ad-hoc `sys.path` manipulation in package modules.

### `core/logging/` — Structured logging

Unified logging with a JSONL audit trail (machine-readable), console output for
humans, timestamped log files (`raptor_<timestamp>.jsonl`), and automatic log
directory creation. Entry point: `get_logger(name="raptor")`.

### `core/sarif/parser.py` — SARIF utilities

Parses SARIF 2.1.0 findings. Shared by `scanner`, `llm_analysis`, and
`reporting`, so it is centralised to prevent duplication.

---

## Package internals

Each package owns one capability and imports only from `core/`. Selected
per-package detail:

### `codeql`
`agent.py` (workflow orchestration) plus `autonomous_analyzer.py`,
`build_detector.py`, `database_manager.py`, `dataflow_validator.py`,
`dataflow_visualizer.py`, `language_detector.py`, `query_runner.py`. Emits
`codeql_*.sarif`, `dataflow_*.json`, `dataflow_*.svg`, `codeql_analysis.json`.
Also driven end-to-end by `raptor_codeql.py`.

### `llm_analysis`
`agent.py` (standalone source-code analysis, OpenAI/Anthropic-compatible),
`crash_agent.py` (binary crash analysis), and `orchestrator.py` (Phase-4
orchestration: dispatches `claude -p` sub-agents for parallel analysis; requires
Claude Code). The `llm/` subpackage abstracts providers (`client.py`,
`config.py`, `detection.py`, `model_data.py`, `providers.py`) so Anthropic,
OpenAI, and local backends are interchangeable. See
[calibrated aggregation](#calibrated-aggregation) below for the orchestrator's
additive output.

### `sca`
Entry point is `packages/sca/cli.py`, invoked via the `libexec/raptor-sca-run`
shim or `python3 -m packages.sca.cli` (also `python3 raptor.py sca`).
Sub-commands (`fix`, `check`, `upgrade`, `diff`, `verify`, `health`, `purl`,
`render`, `clean-cache`) are documented in `.claude/commands/raptor-sca.md`.
Threshold CI gating: `--fail-on-severity` / `--fail-on-kev` /
`--fail-on-supply-chain` / `--fail-on-hygiene`. Outputs `findings.json` (canonical
schema), `report.md`, and `sbom.cdx.json` (CycloneDX 1.5 with VEX).

### `binary_analysis`
`crash_analyser.py` extracts crash context under GDB; `debugger.py` wraps GDB
automation. Process: run under GDB with the crash input → capture signal +
address → extract stack trace and register dump → disassemble the crash location
→ classify the crash type. Classification feeds the LLM assessment. (The crash
taxonomy is listed in [`../concepts.md`](../concepts.md#crash-analysis-what-binary-mode-detects).)

---

## Workflow orchestrators

The three top-level workflow scripts are the mechanical drivers behind the
[three modes](../concepts.md#the-three-analysis-modes).

### `raptor_agentic.py` — full source workflow
1. Scan with Semgrep/CodeQL (`packages/static-analysis/scanner.py`)
2. Exploitability validation (`packages/exploitability_validation/`)
3. Autonomous analysis (`packages/llm_analysis/agent.py`) — full with an external
   LLM, or prep-only when Phase 4 will orchestrate
4. Orchestration (`packages/llm_analysis/orchestrator.py`) — dispatches
   `claude -p` sub-agents when no external LLM is configured

### `raptor_codeql.py` — CodeQL workflow
Phases: language/build detection → database creation → query execution → dataflow
validation → dataflow-diagram generation → optional LLM exploitability analysis.
Key flags: `--repo` (required), `--language`, `--validate-dataflow`,
`--visualize`, `--analyze`, `--output`.

### `raptor_fuzzing.py` — binary fuzzing workflow
Phases: AFL++ fuzz (`afl_runner.py`) → collect/rank crashes (`crash_collector.py`)
→ GDB crash analysis (`crash_analyser.py`) → LLM exploitability assessment
(`crash_agent.py`) → C exploit generation. Key flags: `--binary` (required),
`--corpus`, `--duration`, `--parallel`, `--max-crashes`, `--timeout`.

---

## Calibrated aggregation

**Phase 3 of the calibrated-aggregation arc — see
[`aggregation-dominators.md`](aggregation-dominators.md).**

Each finding in `orchestrated_report.json` gains an additive
`calibrated_aggregation` field carrying a Dawid–Skene calibrated posterior over
the panel verdict. Shape:

```json
"calibrated_aggregation": {
  "posterior_true_positive": 0.87,
  "credible_interval": [0.42, 0.97],
  "n_models": 3,
  "decision_class": "agentic:py/sql-injection",
  "aggregation_method": "dawid_skene",        // or "vote"
  "aggregation_fallback_reason": null,         // string when vote fallback
  "converged": true,
  "model_reliabilities": [
    {"model": "haiku", "alpha": 0.91, "beta": 0.88},
    {"model": "sonnet", "alpha": 0.94, "beta": 0.95}
  ]
}
```

- `aggregation_method = "dawid_skene"` when the finding had ≥2 valid panel
  members; the EM estimator (`core/llm/multi_model/dawid_skene.py`) infers
  per-model `(α, β)` confusion matrices and a per-finding latent-label posterior.
- `aggregation_method = "vote"` when there's no panel (single-model run, all-error
  panel). `aggregation_fallback_reason` is populated (`"no_panel"`,
  `"insufficient_panel_size_1"`, etc.) and `posterior_true_positive` degenerates
  to `1.0` / `0.0` matching the legacy `is_exploitable` boolean.
- `model_reliabilities` is per-decision-class — the same model can have different
  `(α, β)` on `py/sql-injection` vs `cpp/uncontrolled-format`. The deferred Phase
  4 (below) will read this for posterior-weighted scorecard updates.

The existing `is_exploitable`, `multi_model_analyses`, and `ruling` fields are
untouched; downstream consumers that don't read `calibrated_aggregation` keep
working.

The step is unconditional: it is purely additive (only ever adds the
`calibrated_aggregation` field), so there is no opt-out to maintain. The block at
`orchestrator.py:~830` is wrapped in a `try / except` — if D–S fails for any
reason, the field is dropped, a `WARNING` is logged, and the failure is recorded
under `orchestration.calibrated_aggregation.failed` in `orchestrated_report.json`.

**Phase 4 (deferred, follow-up PR):** the posterior-weighted scorecard update is
*not* in this PR. `core/llm/scorecard/consensus.py` still grades dissenters
against the majority vote via `record_event` on the single
`multi_model_consensus` slot. The follow-up — gated on replay-harness validation
because the Phase-1a audit returned no-data — will collapse to one consensus mode
that always records *soft* credits (the legacy discrete update being the
`correct=1.0, incorrect=0.0` special case), grade against the Dawid–Skene
posterior (`correct_credit = p if verdict else (1-p)`), and draw its priors from
`/validate` ground truth rather than the scorecard. See
[`aggregation-dominators.md`](aggregation-dominators.md)
Phase 4.
