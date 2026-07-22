# RAPTOR Modular Architecture

**Version**: 3.1
**Date**: 2026-07-22

See also: [README](README.md), [security](security.md), [sandbox](sandbox.md).



## Table of Contents

1. [Overview](#overview)
2. [Architecture Principles](#architecture-principles)
3. [Directory Structure](#directory-structure)
4. [Core Layer](#core-layer)
5. [Packages Layer](#packages-layer)
6. [Analysis Engines](#analysis-engines)
7. [Tiered Expertise System](#tiered-expertise-system)
8. [Entry Points](#entry-points)
9. [Import Patterns](#import-patterns)
10. [Output Structure](#output-structure)
11. [CLI Interfaces](#cli-interfaces)
12. [Comparison with Original](#comparison-with-original)
13. [Dependencies](#dependencies)
14. [LLM Quality Considerations](#llm-quality-considerations)


## Overview

RAPTOR (Recursive Autonomous Penetration Testing and Observation Robot) is a security testing framework that uses LLMs to autonomously analyse code for vulnerabilities, generate exploits, and create patches. The framework operates in three distinct modes:

1. **Source Code Analysis Mode**: Static analysis of source code using Semgrep (`raptor_agentic.py`)
2. **Deep CodeQL Analysis Mode**: Advanced static analysis with dataflow validation (`raptor_codeql.py`)
3. **Binary Fuzzing Mode**: Coverage-guided fuzzing of compiled binaries using AFL++ (`raptor_fuzzing.py`)
4. **Software Composition Analysis**: Dependency scanning, advisory matching, SBOM generation (`packages/sca/`)
5. **Exploitability Validation**: Multi-stage pipeline proving findings are real, reachable, and exploitable
6. **Code Understanding**: Adversarial code comprehension -- attack surface mapping, data flow tracing

All modes are accessible via the unified `raptor.py` launcher or via Claude Code slash commands (`/scan`, `/agentic`, `/codeql`, `/fuzz`, `/web`, `/sca`, `/validate`, `/understand`, etc.).

The modular architecture refactors the original monolithic structure into a clean, hierarchical design:

```
raptor/
├── bin/                   # User-facing launcher scripts
│   └── raptor             # Main entry point (launches Claude Code)
├── libexec/               # Internal helper scripts (not user-facing)
│   ├── raptor-agentic     # Agentic workflow wrapper
│   ├── raptor-annotate    # Annotation management
│   ├── raptor-ast         # AST enrichment
│   ├── raptor-binary      # Binary investigation
│   ├── raptor-binary-graph-query  # Binary call-graph queries
│   ├── raptor-binary-oracle-e2e   # Binary oracle end-to-end audit
│   ├── raptor-binary-oracle-precision  # Binary oracle precision measurement
│   ├── raptor-build-checklist     # Build checklist generation
│   ├── raptor-cc-trust-check      # C compiler trust check
│   ├── raptor-coverage-summary    # Coverage summary reporting
│   ├── raptor-cve-diff            # CVE patch diffing
│   ├── raptor-describe            # Pre-flight target inspection
│   ├── raptor-enrich-context-map-*  # Context map enrichment passes
│   ├── raptor-enrich-flow-trace-*   # Flow trace enrichment passes
│   ├── raptor-frida               # Frida instrumentation
│   ├── raptor-lifecycle-hook      # Run lifecycle hook
│   ├── raptor-llm-scorecard       # LLM scorecard queries
│   ├── raptor-normalize-context-map  # Context map normalisation
│   ├── raptor-pick-strategies     # Strategy selection
│   ├── raptor-pid1-shim           # PID 1 shim for sandboxed processes
│   ├── raptor-project-manager     # Project workspace management
│   ├── raptor-r2-sandboxed        # Sandboxed radare2 wrapper
│   ├── raptor-render-diagrams     # Mermaid diagram generation
│   ├── raptor-run-feasibility     # Run feasibility check
│   ├── raptor-run-lifecycle       # Run lifecycle management
│   ├── raptor-run-sandboxed       # Sandboxed subprocess runner
│   ├── raptor-sage-setup          # SAGE memory layer setup
│   ├── raptor-sandbox-*           # Sandbox calibration and observation
│   ├── raptor-sca-*               # SCA helpers
│   ├── raptor-seatbelt-shim       # macOS Seatbelt shim
│   ├── raptor-session-init        # Session initialisation
│   ├── raptor-smt-*               # SMT constraint checkers
│   ├── raptor-startup-check       # Startup environment validation
│   ├── raptor-strategy-eval       # Strategy evaluation
│   ├── raptor-threat-model        # Threat model management
│   ├── raptor-tune                # LLM tuning helpers
│   ├── raptor-understand          # Code understanding workflow
│   ├── raptor-understand-annotate # Understanding annotation synthesis
│   ├── raptor-understand-sage     # Understanding SAGE integration
│   ├── raptor-validate-schema     # Schema validation
│   ├── raptor-validation-helper   # Validation pipeline helper
│   ├── raptor-verified-outcomes   # Verified outcome tracking
│   └── raptor-zkpox               # Zero-knowledge proof of exploitation
├── core/                  # Shared infrastructure
│   ├── analysis/          # Reasoning about code (reachability, CFG, taint, binary oracle)
│   ├── annotations/       # Per-function prose annotations (manual + LLM-emitted)
│   ├── archive/           # Archive extraction and handling
│   ├── ast/               # AST enrichment helpers
│   ├── atomic_fs/         # Atomic filesystem operations (tempfile + rename)
│   ├── binary/            # Binary analysis primitives (ELF parsing, symbol lookup)
│   ├── build/             # Build-system detection + toolchain probes
│   ├── config/            # RaptorConfig (paths, settings)
│   ├── coverage/          # Read-coverage tracking + summary
│   ├── cve/               # CVE data structures and lookups
│   ├── dataflow/          # Dataflow analysis primitives
│   ├── dockerfile/        # Dockerfile parsing helpers
│   ├── dynamic/           # Dynamic analysis support (Frida integration)
│   ├── evidence/          # Evidence collection and management
│   ├── function_taxonomy/ # Function classification (source, sink, sanitiser)
│   ├── git/               # Sandbox-routed clone + URL allowlist
│   ├── hash/              # SHA-256 helpers
│   ├── http/              # EgressClient + per-host allowlists
│   ├── inventory/         # Source inventory (file enumeration, extractors, call graph)
│   ├── json/              # BOM-tolerant JSON utils + cache helpers
│   ├── labeled_attempts/  # Labeled attempt tracking for iterative workflows
│   ├── license/           # Licence detection and analysis
│   ├── llm/               # LLM substrate (clients, providers, scorecard, tool-use loop)
│   ├── logging/           # Structured logging with JSONL audit trail
│   ├── oci/               # OCI image-ref parsing + canonicalisation
│   ├── orchestration/     # Pipeline orchestration helpers
│   ├── progress/          # Progress bar and status tracking
│   ├── project/           # Project workspace management
│   ├── reporting/         # Report generation and formatting
│   ├── run/               # Per-run lifecycle (output dir, metadata)
│   ├── sage/              # SAGE inception client + hooks (memory layer)
│   ├── sandbox/           # Subprocess isolation (Landlock + seccomp + namespaces)
│   ├── sarif/             # SARIF 2.1.0 parsing
│   ├── schema_constants/  # Shared schema constants and enums
│   ├── security/          # Prompt envelope, secret redaction, env sanitisation
│   ├── sentinels/         # Sentinel values and markers
│   ├── smt_solver/        # Z3-based path feasibility
│   ├── source/            # Source file reading and normalisation
│   ├── staleness/         # Staleness detection (hash-based drift)
│   ├── startup/           # CLI startup banner + env validation
│   ├── status/            # Run status tracking and reporting
│   ├── tar/               # Tar archive handling
│   ├── threat_model/      # Threat model data structures
│   ├── trajectories/      # LLM trajectory recording and replay
│   ├── tuning/            # LLM tuning parameters and configuration
│   ├── upstream_latest/   # Upstream version resolution
│   ├── url_patterns/      # URL pattern matching and validation
│   ├── verified_outcome/  # Verified outcome tracking
│   ├── witness/           # Witness collection + sandbox outcome tracking
│   └── zip/               # Zip archive handling
├── packages/              # Independent security capabilities
│   ├── static-analysis/   # Semgrep scanning
│   ├── codeql/            # CodeQL deep analysis and dataflow validation
│   ├── coccinelle/        # Coccinelle semantic patch analysis
│   ├── llm_analysis/      # LLM-powered vulnerability analysis
│   ├── autonomous/        # Autonomous planning, memory, and dialogue
│   ├── fuzzing/           # AFL++ fuzzing orchestration
│   ├── binary_analysis/   # GDB crash analysis and triage
│   ├── checker_synthesis/  # Automated checker synthesis
│   ├── code_understanding/# Code comprehension (/understand)
│   ├── cve_diff/          # CVE patch diffing
│   ├── cve_env/           # CVE reproduction environments
│   ├── cvss/              # CVSS scoring utilities
│   ├── describe/          # Pre-flight target inspection (/describe)
│   ├── diagram/           # Mermaid diagram generation (/diagram)
│   ├── exploit_feasibility/# Binary exploit feasibility analysis
│   ├── exploitability_validation/# Multi-stage exploitability validation
│   ├── exploitation/      # Exploit generation engine
│   ├── frida/             # Frida dynamic instrumentation
│   ├── hypothesis_validation/# Hypothesis-driven validation
│   ├── nvd/               # NVD (National Vulnerability Database) queries
│   ├── osv/               # OSV (Open Source Vulnerabilities) queries
│   ├── recon/             # Reconnaissance and enumeration
│   ├── sca/               # Software Composition Analysis
│   ├── semgrep/           # Semgrep rule management
│   ├── source_intel/      # Source-level intelligence gathering
│   ├── strategy_eval/     # Strategy evaluation and comparison
│   ├── web/               # Web application testing
│   └── zkpox/             # Zero-knowledge proof of exploitation
├── plugins/               # Hook-based extensions
│   └── coverage/          # Coverage tracking plugin (PostToolUse hook)
├── engine/                # Analysis engines (CodeQL suites, Semgrep rules)
├── tiers/                 # Expert personas and recovery protocols
├── test/                  # Integration and end-to-end tests
├── eval/                  # Evaluation harnesses and corpora
├── docs/                  # Documentation
├── out/                   # All outputs (scans, logs, reports)
├── raptor.py              # Main launcher (unified CLI)
├── raptor_agentic.py      # Source code analysis workflow
├── raptor_codeql.py       # CodeQL workflow
└── raptor_fuzzing.py      # Binary fuzzing workflow
```



## Architecture Principles

Key structural notes:

- **`core/inventory/`** captures structural facts: file enumeration, function extraction,
  call-graph building, language detection, exclusions.
- **`core/analysis/`** reasons about code properties: reachability, CFG construction,
  taint summaries, dataflow, dominators, binary oracle, sanitiser identification.
  Split from `core/inventory/` in the analysis refactor (#880).
- **`core/llm/`** is the LLM substrate -- client abstraction, provider implementations,
  scorecard (per-model reliability tracking), tool-use loop.
- **`packages/`** contains independent security capabilities. Each package owns its
  CLI, tests, and domain logic. Run `ls packages/` for the full list.



## Core Layer

### Purpose
Provide minimal shared utilities that all packages need.

### Components

#### `core/config/` - RaptorConfig
**Responsibility**: Centralised configuration management

```python
class RaptorConfig:
    @staticmethod
    def get_raptor_root() -> Path:
        """Get RAPTOR installation root"""

    @staticmethod
    def get_out_dir() -> Path:
        """Get output directory (raptor/out/)"""

    @staticmethod
    def get_logs_dir() -> Path:
        """Get logs directory (out/logs/)"""
```

**Key Decisions**:
- Single source of truth for all paths
- Environment variable support (RAPTOR_ROOT)
- Graceful fallback to auto-detection

#### `core/logging/` - Structured Logging
**Responsibility**: Unified logging with audit trail

```python
def get_logger(name: str = "raptor") -> logging.Logger:
    """Get configured logger with JSONL audit trail"""
```

**Features**:
- JSONL format for structured logs (machine-readable)
- Console output for human readability
- Timestamped log files (raptor_<timestamp>.jsonl)
- Automatic log directory creation

**Example Log Entry**:
```json
{
  "timestamp": "2025-11-09 05:22:00,081",
  "level": "INFO",
  "logger": "raptor",
  "module": "logging",
  "function": "info",
  "line": 111,
  "message": "RAPTOR logging initialized - audit trail: /path/to/raptor_1762658520.jsonl"
}
```

#### `core/progress/` - Progress Tracking
**Responsibility**: Progress bar and status tracking utilities

**Features**:
- Visual progress indicators for long-running operations
- Status updates during scans and analysis
- Integration with logging system

#### `core/sarif/parser.py` - SARIF Utilities
**Responsibility**: Parse and extract data from SARIF 2.1.0 files

**Functions**:
- `parse_sarif(sarif_path)`: Load and validate SARIF file
- `get_findings(sarif)`: Extract finding list
- `get_severity(result)`: Map SARIF levels to severity
- (Additional utilities as needed)

**Why Separate Module**: SARIF parsing is shared by scanner, llm_analysis, and reporting. Centralisation prevents duplication.


## Packages Layer

### Design Principles
1. **One responsibility per package**
2. **No cross-package imports** (only import from core)
3. **Standalone executability** (each agent.py can run independently)
4. **Clear CLI interface** (argparse, help text, examples)


### Package: `static-analysis`

**Purpose**: Static code analysis using Semgrep and CodeQL

**Main Entry Point**: `scanner.py`

**CLI Interface**:
```bash
python3 packages/static-analysis/scanner.py \
  --repo /path/to/code \
  --policy_groups secrets,owasp \
  --output /path/to/output
```

**Responsibilities**:
- Run Semgrep scans with configured policy groups
- Parse and normalise SARIF outputs
- Generate scan metrics (files scanned, findings count, severities)
- (Future: CodeQL integration)

**Outputs**:
- `semgrep_<policy>.sarif` - SARIF 2.1.0 findings per policy group
- `scan_metrics.json` - Scan statistics
- `verification.json` - Verification results

**Dependencies**:
- `core.config` (output paths)
- `core.logging` (structured logging)
- External: `semgrep` CLI (must be installed)

**Import Pattern**:
```python
# Add parent to path for core access
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.config import RaptorConfig
from core.logging import get_logger
```


### Package: `codeql`

**Purpose**: Deep CodeQL analysis with autonomous dataflow validation

**Main Entry Point**: `agent.py`

**CLI Interface**:
```bash
python3 packages/codeql/agent.py \
  --repo /path/to/code \
  --language python \
  --output /path/to/output
```

**Components**:
- `agent.py` - Main CodeQL workflow orchestrator
- `autonomous_analyzer.py` - LLM-powered CodeQL analysis
- `build_detector.py` - Automatic build system detection
- `database_manager.py` - CodeQL database creation and management
- `dataflow_validator.py` - Validates dataflow paths from CodeQL results
- `dataflow_visualizer.py` - Generates visual dataflow diagrams
- `language_detector.py` - Programming language detection
- `query_runner.py` - CodeQL query execution

**Responsibilities**:
- Automatic language and build system detection
- CodeQL database creation
- Query execution with custom suites
- Dataflow path validation and visualisation
- LLM-powered exploitability analysis of CodeQL findings

**Outputs**:
- `codeql_*.sarif` - CodeQL findings in SARIF format
- `dataflow_*.json` - Validated dataflow paths
- `dataflow_*.svg` - Visual dataflow diagrams
- `codeql_analysis.json` - Analysis summary

**Key Features**:
- Automatic build command detection
- Multi-language support (Python, Java, C/C++, JavaScript, Go, etc.)
- Dataflow path validation to reduce false positives
- Integration with LLM for exploitability assessment
- Visual dataflow diagrams for complex taint flows

**Dependencies**:
- `core.config` (paths)
- `core.logging` (logging)
- `core.sarif.parser` (SARIF parsing)
- External: `codeql` CLI (must be installed)

**Entry Point**: Also accessible via `raptor_codeql.py` for full workflow


### Package: `llm_analysis`

**Purpose**: LLM-powered autonomous vulnerability analysis

**Main Entry Points**:
- `agent.py` - Standalone analysis (OpenAI/Anthropic compatible)
- `orchestrator.py` - Phase 4 orchestration: dispatches claude -p sub-agents for parallel analysis (requires Claude Code)

**CLI Interface (agent.py)**:
```bash
python3 packages/llm_analysis/agent.py \
  --repo /path/to/code \
  --sarif findings1.sarif findings2.sarif \
  --max-findings 10 \
  --out /path/to/output
```

**Responsibilities**:
- Parse SARIF findings
- Read vulnerable code files
- Analyse exploitability with LLM reasoning
- Generate working exploit PoCs (optional)
- Create secure patches (optional)
- Produce analysis reports

**Outputs**:
- `autonomous_analysis_report.json` - Summary statistics
- `exploits/` - Generated exploit code (if requested)
- `patches/` - Proposed secure fixes (if requested)

**Calibrated Aggregation Output** (Phase 3 of the calibrated-aggregation arc -- see `docs/design-aggregation-dominators-wp.md`):

Each finding in `orchestrated_report.json` gains an additive `calibrated_aggregation` field carrying a Dawid--Skene calibrated posterior over the panel verdict. Shape:

```json
"calibrated_aggregation": {
  "posterior_true_positive": 0.87,
  "credible_interval": [0.42, 0.97],
  "n_models": 3,
  "decision_class": "agentic:py/sql-injection",
  "aggregation_method": "dawid_skene",
  "aggregation_fallback_reason": null,
  "converged": true,
  "model_reliabilities": [
    {"model": "haiku", "alpha": 0.91, "beta": 0.88},
    {"model": "sonnet", "alpha": 0.94, "beta": 0.95}
  ]
}
```

- `aggregation_method = "dawid_skene"` when the finding had >=2 valid panel members; the EM estimator (`core/llm/multi_model/dawid_skene.py`) infers per-model `(alpha, beta)` confusion matrices and a per-finding latent-label posterior.
- `aggregation_method = "vote"` when there's no panel (single-model run, all-error panel). `aggregation_fallback_reason` is populated (`"no_panel"`, `"insufficient_panel_size_1"`, etc.) and `posterior_true_positive` degenerates to `1.0` / `0.0` matching the legacy `is_exploitable` boolean.
- `model_reliabilities` is per-decision-class -- the same model can have different `(alpha, beta)` on `py/sql-injection` vs `cpp/uncontrolled-format`. The deferred Phase 4 (below) will read this for posterior-weighted scorecard updates.

The existing `is_exploitable`, `multi_model_analyses`, and `ruling` fields are untouched; downstream consumers that don't read `calibrated_aggregation` keep working.

The step is unconditional: it is purely additive (only ever adds the `calibrated_aggregation` field), so there is no opt-out to maintain. The block at `orchestrator.py:~830` is wrapped in a `try / except` -- if D--S fails for any reason, the field is dropped, a `WARNING` is logged, and the failure is recorded under `orchestration.calibrated_aggregation.failed` in `orchestrated_report.json`.

**Phase 4 (deferred, follow-up PR)**: the posterior-weighted scorecard update is *not* in this PR. `core/llm/scorecard/consensus.py` still grades dissenters against the majority vote via `record_event` on the single `multi_model_consensus` slot. The follow-up -- gated on replay-harness validation because the Phase-1a audit returned no-data -- will collapse to one consensus mode that always records *soft* credits (the legacy discrete update being the `correct=1.0, incorrect=0.0` special case), grade against the Dawid--Skene posterior (`correct_credit = p if verdict else (1-p)`), and draw its priors from `/validate` ground truth rather than the scorecard. See `docs/design-aggregation-dominators-wp.md` Phase 4.

**LLM Abstraction**:
```
llm/
├── client.py       # Unified client interface
├── config.py       # API keys, model selection
└── providers.py    # Provider implementations (Anthropic, OpenAI, local)
```

**Benefits**:
- Provider-agnostic (swap OpenAI <-> Anthropic easily)
- Configurable via environment variables
- Rate limiting and error handling

**Dependencies**:
- `core.config` (paths)
- `core.logging` (logging)
- `core.sarif.parser` (SARIF parsing)
- External: `anthropic` or `openai` SDK


### Package: `autonomous`

**Purpose**: Autonomous agent capabilities for planning, memory, and validation

**Components**:
- `corpus_generator.py` - Intelligent fuzzing corpus generation
- `dialogue.py` - Agent dialogue and interaction management
- `exploit_validator.py` - Automated exploit code validation
- `goal_planner.py` - Goal-oriented task planning
- `memory.py` - Agent memory and context management
- `planner.py` - Task decomposition and planning

**Responsibilities**:
- Autonomous task planning and decomposition
- Exploit code validation and testing
- Fuzzing corpus generation based on code analysis
- Agent memory management for long-running tasks
- Dialogue management for multi-turn interactions

**Key Features**:
- Goal-oriented planning with LLM reasoning
- Automatic exploit compilation and execution testing
- Context-aware corpus generation for targeted fuzzing
- Persistent memory across agent interactions
- Task decomposition for complex security testing workflows

**Dependencies**:
- `core.config` (paths)
- `core.logging` (logging)
- `core.llm` (LLM client)

**Design Rationale**: Provides higher-level autonomous capabilities that can be composed across different security testing workflows (fuzzing, exploitation, analysis).


### Package: `recon`

**Purpose**: Reconnaissance and technology enumeration

**Main Entry Point**: `agent.py`

**CLI Interface**:
```bash
python3 packages/recon/agent.py \
  --target /path/to/code \
  --out /path/to/output
```

**Responsibilities**:
- Detect programming languages
- Identify frameworks and libraries
- Enumerate dependencies
- Map attack surface
- Generate reconnaissance report

**Outputs**:
- `recon_report.json` - Technology stack enumeration

**Dependencies**:
- `core.config` (paths)
- `core.logging` (logging)


### Package: `sca`

**Purpose**: Software Composition Analysis (dependency vulnerabilities)

**Main Entry Point**: `cli.py` (invoked via the `libexec/raptor-sca-run`
shim or `python3 raptor.py sca`)

**CLI Interface**:
```bash
# Recommended -- wraps the run-lifecycle helpers + project resolution.
libexec/raptor-sca-run /path/to/code --out /path/to/output

# Equivalent direct invocation:
python3 -m packages.sca.cli /path/to/code --out /path/to/output

# Or via the unified launcher:
python3 raptor.py sca --repo /path/to/code --out /path/to/output
```

Sub-commands (`fix`, `check`, `upgrade`, `diff`, `verify`, `health`,
`purl`, `render`, `clean-cache`) are documented in
`.claude/commands/raptor-sca.md`. Threshold-based CI gating is exposed
via `--fail-on-severity` / `--fail-on-kev` / `--fail-on-supply-chain` /
`--fail-on-hygiene` flags on the main scan and on `render`.

**Responsibilities**:
- Detect dependency files (requirements.txt, package.json, pom.xml, etc.)
- Query vulnerability databases (OSV, NVD, etc.)
- Generate dependency vulnerability reports
- Suggest remediation (version upgrades)

**Outputs**:
- `findings.json` - Dependency vulnerabilities (canonical schema)
- `report.md` - Human-readable summary
- `sbom.cdx.json` - CycloneDX 1.5 SBOM with VEX

**Dependencies**:
- `core.config` (paths)
- `core.logging` (logging)
- External: `safety`, `npm audit`, or equivalent


### Package: `web`

**Purpose**: Web application security testing

**Components**:
- `client.py` - HTTP client wrapper (session management, headers)
- `crawler.py` - Web crawler (enumerate endpoints)
- `fuzzer.py` - Input fuzzing (injection testing)
- `scanner.py` - Main orchestrator (OWASP Top 10 checks)

**CLI Interface**:
```bash
python3 packages/web/scanner.py \
  --url https://example.com \
  --out /path/to/output
```

**Responsibilities**:
- Crawl web application
- Test for OWASP Top 10 vulnerabilities
- Fuzz inputs for injections
- Generate web security report

**Outputs**:
- `web_report.json` - Web vulnerabilities
- `endpoints.json` - Discovered endpoints
- `payloads.json` - Tested payloads

**Dependencies**:
- `core.config` (paths)
- `core.logging` (logging)
- External: `requests`, `beautifulsoup4`


### Package: `fuzzing`

**Purpose**: Binary fuzzing orchestration using AFL++

**Main Entry Point**: `afl_runner.py`

**Components**:
- `afl_runner.py` - AFL++ process management and monitoring
- `crash_collector.py` - Crash triage, deduplication, and ranking
- `corpus_manager.py` - Seed corpus generation and management

**Responsibilities**:
- Launch AFL++ fuzzing campaigns (single or parallel instances)
- Monitor fuzzing progress and collect crashes
- Rank crashes by exploitability heuristics
- Manage seed corpus (auto-generation or custom)
- Handle AFL-instrumented and non-instrumented binaries (QEMU mode)

**Outputs**:
- `afl_output/` - AFL++ fuzzing results (crashes, queue, stats)
- Crash inputs ranked by exploitability

**Dependencies**:
- `core.config` (paths)
- `core.logging` (logging)
- External: `afl-fuzz` (must be installed)

**Key Features**:
- Parallel fuzzing support (multiple AFL instances)
- Automatic crash deduplication by signal
- Early termination on crash threshold
- Support for AFL-instrumented binaries (faster) and QEMU mode (slower but works)

**Design Rationale**: Separated from binary analysis to maintain clean boundaries. Fuzzing orchestration is independent of crash analysis.


### Package: `binary_analysis`

**Purpose**: Binary crash analysis and debugging using GDB

**Main Entry Point**: `crash_analyser.py`

**Components**:
- `crash_analyser.py` - Main: Crash context extraction and classification
- `debugger.py` - GDB automation wrapper

**Responsibilities**:
- Analyse crash inputs using GDB
- Extract stack traces, register states, disassembly
- Classify crash types (stack overflow, heap corruption, use-after-free, etc.)
- Provide context for LLM analysis

**Outputs**:
- `CrashContext` objects with full debugging information
- Crash classification and heuristics

**Dependencies**:
- `core.config` (paths)
- `core.logging` (logging)
- External: `gdb` (must be installed)

**GDB Analysis Process**:
1. Run binary under GDB with crash input
2. Capture crash signal and address
3. Extract stack trace and register dump
4. Disassemble crash location
5. Classify crash type based on signal and context

**Crash Types Detected**:
- Stack buffer overflows (SIGSEGV with stack address)
- Heap corruption (SIGSEGV with heap address, malloc errors)
- Use-after-free (SIGSEGV on freed memory)
- Integer overflows (SIGFPE, wraparound detection)
- Format string vulnerabilities (SIGSEGV in printf family)
- NULL pointer dereference (SIGSEGV at low addresses)

**Design Rationale**: Independent from fuzzing package to allow standalone crash analysis of externally discovered crashes.


## Analysis Engines

### `engine/codeql/`

**Purpose**: CodeQL query suites and configurations

**Contents**:
- `suites/` - Custom CodeQL query suites for different languages and vulnerability categories
- Query configurations for taint tracking, security patterns, and dataflow analysis

**Usage**: Consumed by `packages/codeql/` for automated CodeQL scanning


### `engine/semgrep/`

**Purpose**: Semgrep rules and configurations

**Contents**:
- `rules/` - Custom Semgrep rules for security patterns
- `semgrep.yaml` - Semgrep configuration file
- `tools/` - Utilities for rule development and testing

**Usage**: Consumed by `packages/static-analysis/scanner.py` for Semgrep scanning

**Design Rationale**: Separating analysis engines from packages allows for centralised rule management and easier rule updates without modifying package code.


## Tiered Expertise System

### `tiers/`

**Purpose**: Progressive loading of expert personas and guidance for specialised tasks

**Components**:

#### `tiers/analysis-guidance.md`
- Adversarial security analysis guidelines
- Exploitation thinking frameworks
- Loaded when scan completes to provide analysis context

#### `tiers/recovery.md`
- Error recovery protocols
- Debugging strategies
- Loaded when errors occur during analysis

#### `tiers/personas/`
Expert persona specifications for specialised analysis:
- `binary_exploitation_specialist.md` - Binary exploitation expertise
- `codeql_analyst.md` - CodeQL query development
- `codeql_finding_analyst.md` - CodeQL finding analysis
- `crash_analyst.md` - Crash analysis and triage
- `exploit_developer.md` - Exploit development
- `fuzzing_strategist.md` - Fuzzing strategy development
- `patch_engineer.md` - Secure patch development
- `penetration_tester.md` - Penetration testing methodology
- `security_researcher.md` - General security research

#### `tiers/specialists/`
- Additional specialist knowledge bases
- Domain-specific security expertise

**Usage**:
- Loaded on-demand by `raptor.py` (Claude Code integration)
- Provides specialised context for different security testing phases
- Enables persona-based LLM prompting for improved analysis quality

**Design Rationale**: Progressive loading reduces initial context size while providing deep expertise when needed. Persona-based approach allows for specialised prompting tailored to specific security tasks.


## Entry Points

### `raptor.py` - Main Launcher (Claude Code Integration)

**Purpose**: Interactive launcher with Claude Code integration for conversational security testing

**Usage**:
```bash
# Run with Claude Code
claude-code raptor.py

# Interactive session with progressive loading
```

**Features**:
- Claude Code integration for interactive analysis
- Progressive loading of expert personas from `tiers/`
- Slash command support (/scan, /fuzz, /web, /agentic, /codeql, /analyze, /exploit, /patch)
- On-demand loading of specialised guidance
- ASCII art and inspirational security quotes on startup
- Session-based workflow management

**Workflow**:
1. Display banner and available commands
2. Load appropriate persona based on user request
3. Execute requested command (scan, fuzz, analyse, etc.)
4. Load analysis guidance or recovery protocols as needed
5. Provide interactive follow-up and recommendations

**Key Features**:
- Conversational interface via Claude Code
- Context-aware persona loading (e.g., load `fuzzing_strategist.md` for /fuzz)
- Progressive expertise loading to manage context window
- Integration with all RAPTOR packages
- Safe operations execute immediately, dangerous operations require confirmation

**Design Rationale**: Provides a conversational, user-friendly interface for security testing workflows while leveraging Claude Code's capabilities for interactive analysis and multi-turn reasoning.


### `raptor_codeql.py` - CodeQL Workflow Orchestrator

**Purpose**: End-to-end CodeQL analysis with dataflow validation

**Usage**:
```bash
python3 raptor_codeql.py \
  --repo /path/to/code \
  --language python \
  --validate-dataflow \
  --visualize
```

**Workflow**:
1. **Phase 1**: Language and build detection
2. **Phase 2**: CodeQL database creation
3. **Phase 3**: Query execution with custom suites
4. **Phase 4**: Dataflow path validation
5. **Phase 5**: Visual dataflow diagram generation
6. **Phase 6**: LLM exploitability analysis (optional)

**Parameters**:
- `--repo`: Path to repository (required)
- `--language`: Target language (auto-detected if not specified)
- `--validate-dataflow`: Enable dataflow path validation
- `--visualize`: Generate visual dataflow diagrams
- `--analyze`: Enable LLM exploitability analysis
- `--output`: Output directory (default: auto-generated)

**Outputs**:
```
out/codeql_<repo>_<timestamp>/
├── database/              # CodeQL database
├── codeql_*.sarif         # CodeQL findings
├── dataflow_*.json        # Validated dataflow paths
├── dataflow_*.svg         # Visual diagrams
└── codeql_report.json     # Summary report
```

**Key Features**:
- Automatic language and build system detection
- Multi-language support
- Dataflow path validation to reduce false positives
- Visual dataflow diagrams for complex vulnerabilities
- Integration with LLM for exploitability assessment

**Design Rationale**: Provides a complete CodeQL workflow with advanced features like dataflow validation that go beyond basic CodeQL scanning.


### `raptor_agentic.py` - Full Workflow Orchestrator

**Purpose**: End-to-end autonomous security testing workflow

**Usage**:
```bash
python3 raptor_agentic.py \
  --repo /path/to/code \
  --policy-groups all \
  --max-findings 10 \
  --mode thorough
```

**Workflow**:
1. **Phase 1**: Scan code with Semgrep/CodeQL (`packages/static-analysis/scanner.py`)
2. **Phase 2**: Exploitability validation (`packages/exploitability_validation/`)
3. **Phase 3**: Autonomous analysis (`packages/llm_analysis/agent.py`) -- full with external LLM, or prep-only when Phase 4 will orchestrate
4. **Phase 4**: Orchestration (`packages/llm_analysis/orchestrator.py`) -- dispatches claude -p sub-agents when no external LLM configured

**Outputs**:
- `raptor_agentic_report.json` - End-to-end summary
- `scan_<repo>_<timestamp>/` - All scan artifacts
- Exploits, patches, analysis reports

**Key Features**:
- Handles git initialisation (Semgrep requires git repos)
- Orchestrates multiple components sequentially
- Aggregates results into unified report


### `raptor_fuzzing.py` - Binary Fuzzing Workflow

**Purpose**: Autonomous binary fuzzing with LLM-powered crash analysis

**Usage**:
```bash
python3 raptor_fuzzing.py \
  --binary /path/to/binary \
  --duration 3600 \
  --max-crashes 10 \
  --parallel 4
```

**Workflow**:
1. **Phase 1**: Fuzz binary with AFL++ (`packages/fuzzing/afl_runner.py`)
2. **Phase 2**: Collect and rank crashes (`packages/fuzzing/crash_collector.py`)
3. **Phase 3**: Analyse crashes with GDB (`packages/binary_analysis/crash_analyser.py`)
4. **Phase 4**: LLM exploitability assessment (`packages/llm_analysis/crash_agent.py`)
5. **Phase 5**: Generate exploit PoC code (C exploits)

**Outputs**:
```
out/fuzz_<binary>_<timestamp>/
├── afl_output/              # AFL fuzzing results
│   ├── main/crashes/        # Crash-inducing inputs
│   ├── main/queue/          # Interesting test cases
│   └── main/fuzzer_stats    # Coverage statistics
├── analysis/
│   ├── analysis/            # LLM crash analysis (JSON)
│   │   └── crash_*.json
│   └── exploits/            # Generated exploits (C code)
│       └── crash_*_exploit.c
└── fuzzing_report.json      # Summary with LLM statistics
```

**Parameters**:
- `--binary`: Path to target binary (required)
- `--corpus`: Seed corpus directory (optional, auto-generated if not provided)
- `--duration`: Fuzzing duration in seconds (default: 3600)
- `--parallel`: Number of parallel AFL instances (default: 1)
- `--max-crashes`: Maximum crashes to analyse (default: 10)
- `--timeout`: Timeout per execution in milliseconds (default: 1000)

**Key Features**:
- AFL++ orchestration with parallel fuzzing support
- Automatic crash deduplication and ranking
- GDB-powered crash context extraction
- LLM exploitability assessment (CVSS scoring, attack scenarios)
- Automatic C exploit generation
- Comprehensive fuzzing report with costs and statistics

**Mode Selection**:
RAPTOR operates in two mutually exclusive modes:
- **Source Code Mode** (`--repo`): Static analysis with Semgrep/CodeQL
- **Binary Fuzzing Mode** (`--binary`): AFL++ fuzzing with crash analysis

These modes cannot be combined in a single run. Use source mode for design flaws and logic bugs; use binary mode for memory corruption and runtime behaviour.



## CLI Interfaces

All package agents follow a consistent CLI pattern:

### Common Arguments
- `--repo` / `--target`: Path to code/target
- `--out`: Output directory (default: auto-generated in out/)
- `--help`: Usage information with examples

### Package-Specific Arguments

**static-analysis/scanner.py**:
- `--policy_groups`: Comma-separated policy groups (e.g., `secrets,owasp`)

**llm_analysis/agent.py**:
- `--sarif`: SARIF file(s) to analyse (can specify multiple)
- `--max-findings`: Limit number of findings to process
- `--no-exploits`: Skip exploit generation
- `--no-patches`: Skip patch generation

**raptor.py** (interactive):
- Slash commands: `/scan`, `/fuzz`, `/web`, `/agentic`, `/codeql`, `/analyze`, `/exploit`, `/patch`
- Progressive loading of expert personas
- Claude Code integration for conversational interface

**raptor_codeql.py**:
- `--repo`: Path to repository (required)
- `--language`: Target language (auto-detected if not specified)
- `--validate-dataflow`: Enable dataflow validation
- `--visualize`: Generate visual dataflow diagrams
- `--analyze`: Enable LLM exploitability analysis

**raptor_agentic.py**:
- `--policy-groups`: Policy groups for scanning
- `--max-findings`: Limit findings processed
- `--no-exploits`, `--no-patches`: Control LLM analysis behaviour
- `--mode`: `fast` or `thorough`

**raptor_fuzzing.py**:
- `--binary`: Path to target binary (required)
- `--duration`: Fuzzing duration in seconds
- `--parallel`: Number of parallel AFL instances
- `--max-crashes`: Maximum crashes to analyse

### Help Text Standard

Every agent includes:
1. Description of what it does
2. Required arguments
3. Optional arguments with defaults
4. Usage examples (at least 2)

**Example**:
```bash
$ python3 packages/static-analysis/scanner.py --help

RAPTOR Static Analysis Scanner

Scans code using Semgrep with configurable policy groups.

Required Arguments:
  --repo PATH          Path to repository to scan

Optional Arguments:
  --policy_groups STR  Comma-separated policy groups (default: all)
  --output PATH        Output directory (default: auto-generated)

Examples:
  # Scan with all policy groups
  python3 scanner.py --repo /path/to/code

  # Scan specific policy groups
  python3 scanner.py --repo /path/to/code --policy_groups secrets,owasp
```


## LLM Quality Considerations

### Exploit Generation Requirements

RAPTOR's exploit generation capabilities vary significantly based on the LLM provider used. Understanding these differences is critical for production deployments.

### Provider Comparison

| Provider | Analysis | Patching | Exploit Generation | Cost per Crash |
|----------|----------|----------|-------------------|----------------|
| **Anthropic Claude** | Excellent | Excellent | Compilable C code | ~£0.01 |
| **OpenAI GPT-4** | Excellent | Excellent | Compilable C code | ~£0.01 |
| **Ollama (local)** | Good | Good | Often non-compilable | Free |

### Technical Requirements for Exploit Code

Generating working exploit code requires capabilities that distinguish frontier models from local models:

**Memory Layout Understanding**:
- Precise knowledge of x86-64/ARM stack structures
- Correct register usage and calling conventions
- Understanding of heap allocator internals (glibc malloc, tcache)

**Shellcode Generation**:
- Valid x86-64/ARM assembly encoding
- Correct escape sequences (e.g., `\x90\x31\xc0` not `\T`)
- NULL-byte avoidance for string-based exploits
- System call number correctness

**Exploitation Primitives**:
- ROP chain construction with valid gadget addresses
- Stack pivot techniques for limited buffer sizes
- ASLR leak construction and information disclosure
- Heap feng shui for use-after-free exploitation

**Code Correctness**:
- Syntactically valid C code that compiles without errors
- Proper handling of pointers and memory addresses
- Correct usage of system APIs (socket, exec, mmap)

### Observed Limitations of Local Models

Testing with Ollama models (including deepseek-r1:7b, llama3, codellama) revealed consistent issues:

**Common Failures**:
- Chinese characters in C preprocessor directives (e.g., `#ifdef "__看清地址信息__"`)
- Invalid escape sequences in shellcode strings
- Incorrect pointer arithmetic and type casts
- Non-existent libc function calls
- Malformed assembly syntax in inline asm blocks

**Root Cause**: Local models often generate syntactically plausible but semantically incorrect code. Exploit development requires not just code generation, but deep understanding of low-level system behaviour that smaller models lack.

### Recommendations

**For Production Exploit Generation**:
```bash
# Use Anthropic Claude (recommended)
export ANTHROPIC_API_KEY=your_key_here

# OR OpenAI GPT-4
export OPENAI_API_KEY=your_key_here
```

**For Testing and Analysis**:
```bash
# Ollama works well for:
# - Crash triage and classification
# - Exploitability assessment
# - Vulnerability analysis
# - Patch generation

# But not for:
# - C exploit generation
# - Shellcode creation
# - ROP chain construction
```


### Cost Considerations

We think it useful to include such costings, just so people understand how much it might cost to generate code. It will vary


**Frontier Models**:
- Cost: ~£0.01 per crash analysed with exploit generation
- Typical fuzzing run (10 crashes): ~£0.10
- Value: Compilable, working exploit code

**Local Models**:
- Cost: Free (runs locally)
- Typical fuzzing run: £0.00
- Value: Good analysis, unreliable exploit code

**Recommendation**: For security research and penetration testing where working exploits are required, the nominal cost of frontier models (£0.10-1.00 per binary) is justified by the quality of output.


## Dependencies

### Core Dependencies (Required by All)
- Python 3.10+ (PEP 604 union syntax used at function-definition time)
- Standard library: pathlib, logging, json, subprocess, argparse

See [dependencies](dependencies.md) for the full tool and package reference.

### Package-Specific Dependencies

**static-analysis**:
- External: `semgrep` (must be installed)

**codeql**:
- External: `codeql` CLI (must be installed - see https://codeql.github.com/)
- Supports multiple languages (Python, Java, C/C++, JavaScript, Go, Ruby, etc.)

**llm_analysis**:
- `anthropic` SDK (if using Claude)
- `openai` SDK (if using GPT-4)
- OR local model server

**autonomous**:
- `anthropic` or `openai` SDK (for LLM-powered planning)
- Standard library for validation and corpus generation

**fuzzing**:
- External: `afl-fuzz` (AFL++ must be installed)
- External: `afl-gcc` or `afl-clang` for instrumentation (optional)

**binary_analysis**:
- External: `gdb` (must be installed)

**recon**:
- Standard library only (file detection)
- Future: Language-specific tools (pip, npm, maven)

**sca**:
- `safety` (Python dependency checking)
- `npm audit` (Node.js, if installed)
- Future: Additional scanners (Snyk, etc.)

**web**:
- `requests` (HTTP client)
- `beautifulsoup4` (HTML parsing)
- Future: `playwright` (browser automation)

### Installation

**Core Setup**:
```bash
# Clone repository
git clone <repo-url>
cd raptor

# Install Python dependencies
pip install -r requirements.txt

# Or install manually:
pip install semgrep anthropic openai instructor requests beautifulsoup4
```

**Verify Installation**:
```bash
# Test main launcher
python3 raptor.py

# Test static analysis
python3 packages/static-analysis/scanner.py --help

# Test CodeQL
python3 raptor_codeql.py --help

# Test LLM analysis
python3 packages/llm_analysis/agent.py --help

# Test full workflows
python3 raptor_agentic.py --help
python3 raptor_fuzzing.py --help
```
