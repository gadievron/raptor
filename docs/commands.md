# Command Reference

RAPTOR exposes its capabilities through slash commands in the Claude Code
session.  Run `/commands` at any time for the live list.  Commands dispatch to
either a Python entry point (`raptor.py`), a shell script under `libexec/`, or
a multi-step skill.  The [Python CLI](python-cli.md) documents the `raptor.py`
modes directly; this page covers the slash-command surface.

All path arguments respect the [default target resolution
order](commands.md): active project target, then `$RAPTOR_CALLER_DIR`,
then prompt.  Output directories are managed by the [run
lifecycle](architecture.md) unless noted otherwise.

---

## Security Testing

### /scan

Static analysis scan using Semgrep (and optionally CodeQL and Coccinelle).

```
/scan [<target_path>]
```

| Flag | Description |
|------|-------------|
| `--repo <path>` | Target repository path |
| `--policy-version <ver>` | Semgrep policy version to use |
| `--policy-groups <groups>` | Semgrep policy groups to enable |
| `--codeql` / `--no-codeql` | Enable or disable CodeQL analysis |
| `--no-cocci` | Disable Coccinelle (spatch) analysis |
| `--languages <langs>` | Restrict to specific languages |
| `--build-command <cmd>` | Build command for compiled languages (CodeQL) |
| `--keep` | Keep intermediate scan artefacts |
| `--sequential` | Run scanners sequentially instead of in parallel |
| `--out <dir>` | Output directory override |
| `--exclude-dir <glob>` | Exclude directories matching glob (repeatable) |
| `--extra-config <path>` | Additional Semgrep config file (repeatable) |
| `--show-suppressed` | Include suppressed findings in output |
| `--sandbox` / `--no-sandbox` | Enable or disable [sandbox](sandbox.md) isolation |
| `--audit` | Enable the systematic review layer |
| `--audit-verbose` | Verbose audit output |
| `--audit-budget <n>` | Maximum audit budget (finding count) |

See [architecture](architecture.md) for scanner configuration and rule-set
details.

---

### /agentic

Full autonomous security workflow: scan, deduplicate, prepare context, analyse
findings with LLM, then optionally validate, generate exploits, and emit
patches.

```
/agentic [<target_path>]
```

**Core flags**

| Flag | Description |
|------|-------------|
| `--repo <path>` | Target repository path |
| `--sarif <file>` | Ingest existing SARIF file (repeatable) |
| `--also-scan` | Run a fresh scan even when `--sarif` is provided |
| `--sarif-out <file>` | Write merged SARIF output to file |
| `--reanalyze <dir>` | Re-analyse a previous run directory |
| `--out <dir>` | Output directory override |
| `--mode {fast,thorough}` | Analysis depth |
| `--sequential` | Bypass parallel orchestration |
| `--verbose` | Verbose output |
| `--log-level <level>` | Logging level |

**Finding selection**

| Flag | Description |
|------|-------------|
| `--max-findings <n>` | Maximum findings to analyse (default 10) |
| `--prefer <glob>` | Prioritise findings matching glob (repeatable) |
| `--exclude-dir <glob>` | Exclude directories matching glob (repeatable) |
| `--policy-groups <groups>` | Semgrep policy groups |
| `--vuln-type <type>` | Restrict to a specific vulnerability class |
| `--skip-dedup` | Skip the deduplication pass |
| `--max-parallel <n>` | Maximum parallel analysis workers |
| `--phase-timeout <secs>` | Per-phase timeout in seconds (default 1800) |

**Scanner selection**

| Flag | Description |
|------|-------------|
| `--codeql` | Enable CodeQL alongside Semgrep |
| `--codeql-only` | Run CodeQL only (skip Semgrep) |
| `--no-codeql` | Disable CodeQL |
| `--languages <langs>` | Restrict to specific languages |
| `--build-command <cmd>` | Build command for compiled languages |
| `--extended` | Enable extended CodeQL query suites |
| `--codeql-cli <path>` | Path to CodeQL CLI binary |

**Output control**

| Flag | Description |
|------|-------------|
| `--no-exploits` | Skip exploit generation |
| `--no-patches` | Skip patch generation |
| `--no-annotations` | Skip per-function [annotation](#annotate) emission |
| `--no-visualizations` | Skip diagram generation |

**Binary oracle** (see [binary analysis](binary-analysis.md))

| Flag | Description |
|------|-------------|
| `--binary <path>` | Explicit debug binary for reachability filtering (repeatable) |
| `--binary-auto` | Auto-detect locally-built binaries |
| `--binary-edges` | Extract call edges and vtable resolution via r2 |
| `--no-binary-oracle` | Disable binary-oracle filtering entirely |
| `--target-kind {auto,library,hybrid,application}` | Target kind for binary oracle |
| `--allow-unreachable` | Do not suppress unreachable findings |
| `--check-mitigations` | Run binary mitigation checks |
| `--skip-mitigation-checks` | Skip binary mitigation checks |

**Sanitiser cut**

| Flag | Description |
|------|-------------|
| `--sanitizer-cut {off\|on\|strict\|shadow}` | Sanitiser-cut mode |
| `--sanitizer-cut-parity-log <path>` | Write parity log to path |

**Dataflow validation**

| Flag | Description |
|------|-------------|
| `--no-validate-dataflow` | Skip dataflow validation |
| `--deep-validate` / `--no-deep-validate` | Enable or disable deep validation |
| `--deep-validate-budget <fraction>` | Fraction of budget allocated to deep validation |

**Multi-model** (see [scorecard](#scorecard))

| Flag | Description |
|------|-------------|
| `--model <model>` | LLM model for analysis (repeatable -- each independently analyses every finding) |
| `--consensus <model>` | Consensus review model |
| `--judge <model>` | Judge model for final adjudication |
| `--aggregate <model>` | Aggregation/synthesis model |

**Pipeline extensions**

| Flag | Description |
|------|-------------|
| `--understand` | Pre-map the codebase with [/understand](#understand) before scanning |
| `--threat-model` | Generate a [threat model](#threat-model) before analysis |
| `--threat-model-only` | Generate threat model and stop |
| `--threat-model-refresh` | Force-refresh an existing threat model |
| `--threat-model-use-stale` | Accept a stale threat model without refresh |
| `--validate` | Run the full [validation pipeline](#validate) on exploitable findings |
| `--fuzz` | Run [fuzzing](#fuzz) on applicable targets |
| `--fuzz-duration <secs>` | Fuzz duration in seconds |
| `--fuzz-corpus <path>` | Fuzz seed corpus directory |
| `--fuzz-dict <path>` | Fuzz dictionary file |
| `--fuzz-plan-only` | Generate fuzz plan without executing |
| `--sca` | Run [SCA](#sca) alongside static analysis |
| `--skip-sca-review` | Skip SCA LLM review |
| `--skip-sca-triage` | Skip SCA triage |
| `--accept-weakened-defenses` | Accept findings in weakened-defence categories |
| `--trust-repo` | Trust the repository (skip untrusted-repo sanitisation) |

**Sandbox** (see [sandbox](sandbox.md))

| Flag | Description |
|------|-------------|
| `--sandbox <mode>` | Sandbox mode: `debug`, `frida`, `full`, `network-only`, `none`, `strict`, `target_run` |
| `--no-sandbox` | Disable sandbox entirely |

**Audit layer**

| Flag | Description |
|------|-------------|
| `--audit` | Enable systematic code review layer |
| `--audit-verbose` | Verbose audit output |
| `--audit-budget <n>` | Maximum audit budget |

---

### /codeql

Deep static analysis with CodeQL dataflow validation.

```
/codeql [<target_path>]
```

| Flag | Description |
|------|-------------|
| `--repo <path>` | Target repository path |
| `--languages <langs>` | Languages to analyse |
| `--build-command <cmd>` | Build command for compiled languages |
| `--out <dir>` | Output directory override |
| `--force` | Force database rebuild even if one exists |
| `--extended` | Enable extended query suites |
| `--min-files <n>` | Minimum source files required to proceed |
| `--codeql-cli <path>` | Path to CodeQL CLI binary |
| `--scan-only` | Run scan only, skip LLM analysis (default) |
| `--analyze` | Run LLM analysis on findings |
| `--allow-unreachable` | Do not suppress unreachable findings |
| `--target-kind {auto,library,hybrid,application}` | Target kind for binary oracle |
| `--binary <path>` | Debug binary for reachability (repeatable) |
| `--binary-auto` | Auto-detect locally-built binaries |
| `--binary-edges` | Extract call edges via r2 |
| `--no-binary-oracle` | Disable binary-oracle filtering |
| `--sanitizer-cut {off\|on\|strict\|shadow}` | Sanitiser-cut mode |
| `--sanitizer-cut-parity-log <path>` | Write parity log to path |
| `--max-findings <n>` | Maximum findings to process |
| `--no-visualizations` | Skip diagram generation |
| `--trust-repo` | Trust the repository |
| `--phase-timeout <secs>` | Per-phase timeout in seconds |
| `--sandbox` / `--no-sandbox` | Enable or disable [sandbox](sandbox.md) |
| `--audit` | Enable audit layer |
| `--audit-verbose` | Verbose audit output |
| `--audit-budget <n>` | Audit budget |

See [CodeQL dataflow validation](codeql.md) for details
on dataflow validation and SMT path feasibility.

---

### /fuzz

Coverage-guided fuzzing with automatic harness generation.

```
/fuzz [<target_path>]
```

**Target and corpus**

| Flag | Description |
|------|-------------|
| `--binary <path>` | Binary to fuzz |
| `--corpus <path>` | Seed corpus directory |
| `--seed-profile <profile>` | Seed profile for corpus generation |
| `--export-seed-corpus <dir>` | Export generated seed corpus to directory |
| `--prepare-corpus <project_dir>` | Prepare corpus from project directory |
| `--seed-out <path>` | Seed output directory |
| `--seed-max-size <bytes>` | Maximum seed file size |
| `--seed-include-lockfiles` | Include lockfiles in seed corpus |
| `--dict <path>` | Fuzzer dictionary file |
| `--input-mode {stdin,file}` | How to feed input to the target |

**Execution**

| Flag | Description |
|------|-------------|
| `--duration <secs>` | Fuzz duration in seconds (default 3600) |
| `--parallel <n>` | Number of parallel fuzzing jobs |
| `--max-crashes <n>` | Stop after N unique crashes (default 10) |
| `--timeout <secs>` | Per-execution timeout |
| `--out <dir>` | Output directory override |
| `--check-sanitizers` | Verify sanitiser availability |
| `--recompile-guide` | Emit recompilation guidance for instrumentation |
| `--use-showmap` | Use afl-showmap for coverage |
| `--memory-file <path>` | Memory file for persistent state |
| `--goal <text>` | High-level fuzzing goal description |

**Orchestration**

| Flag | Description |
|------|-------------|
| `--autonomous` | Fully autonomous fuzzing mode |
| `--orchestrator` / `--legacy` | Use orchestrator or legacy mode |
| `--plan-only` | Generate fuzz plan without executing |

**Exploit verification**

| Flag | Description |
|------|-------------|
| `--no-verify-exploits` | Skip exploit verification |
| `--no-judge-intent` | Skip intent judgement |
| `--no-record-witnesses` | Skip witness recording |
| `--execute-exploits` | Execute generated exploits |
| `--execute-timeout <secs>` | Execution timeout for exploits |
| `--execute-sanitizers` | Run exploits with sanitisers |

**Sandbox and audit**

| Flag | Description |
|------|-------------|
| `--sandbox` / `--no-sandbox` | Enable or disable [sandbox](sandbox.md) |
| `--audit` | Enable audit layer |
| `--audit-verbose` | Verbose audit output |
| `--audit-budget <n>` | Audit budget |

See [fuzzing quickstart](fuzzing.md) for getting started.

---

### /web

Web application security scanner (alpha).

```
/web --url <url>
```

| Flag | Description |
|------|-------------|
| `--url <url>` | Target URL (required) |
| `--out <dir>` | Output directory override |
| `--max-depth <n>` | Maximum crawl depth (default 3) |
| `--max-pages <n>` | Maximum pages to crawl (default 100) |
| `--insecure` | Accept invalid TLS certificates |
| `--reveal-secrets` | Include discovered secrets in output |

**ffuf integration**

| Flag | Description |
|------|-------------|
| `--ffuf-wordlist <path>` | Wordlist for directory brute-forcing |
| `--ffuf-path <path>` | Path pattern for ffuf |
| `--ffuf-bin <path>` | Path to ffuf binary |
| `--ffuf-threads <n>` | ffuf thread count |
| `--ffuf-rate <n>` | ffuf request rate limit |
| `--ffuf-timeout <secs>` | ffuf per-request timeout |
| `--ffuf-report-limit <n>` | Maximum ffuf results to report |
| `--ffuf-max-runtime <secs>` | Maximum ffuf runtime |
| `--ffuf-no-auto-calibration` | Disable ffuf auto-calibration |
| `--ffuf-match-status <codes>` | HTTP status codes to match |
| `--ffuf-filter-status <codes>` | HTTP status codes to filter |
| `--ffuf-filter-size <sizes>` | Response sizes to filter |
| `--ffuf-header <header>` | Custom HTTP header (repeatable) |
| `--ffuf-cookie <cookie>` | Cookie to include in requests |

---

### /analyze

Analyse existing SARIF findings with LLM without re-scanning.

```
/analyze [<target_path>]
```

| Flag | Description |
|------|-------------|
| `--repo <path>` | Target repository path |
| `--sarif <file> [...]` | SARIF file(s) to analyse |
| `--findings <file>` | Pre-filtered findings file |
| `--out <dir>` | Output directory override |
| `--max-findings <n>` | Maximum findings to analyse |
| `--prefer <glob>` | Prioritise findings matching glob (repeatable) |
| `--exclude-dir <glob>` | Exclude directories matching glob (repeatable) |
| `--checklist` | Generate a review checklist |
| `--no-annotations` | Skip annotation emission |
| `--no-checker-synthesis` | Skip checker synthesis |
| `--no-verify-exploits` | Skip exploit verification |
| `--no-judge-intent` | Skip intent judgement |
| `--no-record-witnesses` | Skip witness recording |
| `--no-verified-exemplars` | Skip verified exemplar generation |
| `--sage-precall <path>` | SAGE pre-call context file |
| `--prep-only` | Prepare context only, do not analyse |
| `--max-parallel <n>` | Maximum parallel analysis workers |
| `--model <model>` | LLM model (repeatable) |
| `--consensus <model>` | Consensus model |
| `--judge <model>` | Judge model |
| `--aggregate <model>` | Aggregation model |
| `--deep-validate` / `--no-deep-validate` | Enable or disable deep validation |

---

## Exploitability & Validation

### /validate

Multi-stage pipeline to validate that findings are real, reachable, and
exploitable.  Stages run in order: 0 (inventory) through A--F (LLM stages) to
1 (mechanical output).

```
/validate <target_path> [--findings <file>]
```

| Flag | Description |
|------|-------------|
| `--vuln-type <type>` | Restrict to a specific vulnerability class |
| `--findings <file>` | Findings file to validate |
| `--binary <path>` | Debug binary for feasibility analysis |
| `--skip-feasibility` | Skip binary feasibility stage |
| `--out <dir>` | Output directory (shared with [/understand](#understand) for pipeline handoff) |

See [validation pipeline](validation.md) for stage
descriptions, gates, and methodology.

---

### /exploit (beta)

Generate exploit proof-of-concepts for confirmed vulnerabilities.  Dispatches
through the agentic pipeline with `--no-patches`.

```
/exploit [<target_path>]
```

Accepts the same flags as [/agentic](#agentic) minus `--no-exploits`.  The
exploit engine uses CWE-specific composers, a GDB sub-loop for info-leak
eligibility, and the REPLicator substrate for multi-round format-string and
similar chains.

See [exploit feasibility](binary-analysis.md) for constraint analysis and
the mandatory `exploitation_paths` check.

---

### /patch (beta)

Generate patches for confirmed vulnerabilities.  Dispatches through the
agentic pipeline with `--no-exploits`.

```
/patch [<target_path>]
```

Accepts the same flags as [/agentic](#agentic) minus `--no-patches`.

---

## Code Understanding & Forensics

### /understand

Deep, adversarial code comprehension for security research.  Four mutually
exclusive modes.

```
/understand <target> --map
/understand <target> --trace <entry>
/understand <target> --hunt <pattern>
/understand <target> --teach <subject>
```

**Mode flags** (exactly one required)

| Flag | Description |
|------|-------------|
| `--map` | Build context map: entry points, trust boundaries, sinks |
| `--trace <entry>` | Follow one data-flow path source to sink |
| `--hunt <pattern>` | Find all variants of a vulnerability pattern |
| `--teach <subject>` | Explain a framework, library, or pattern |

**Common flags**

| Flag | Description |
|------|-------------|
| `--out <dir>` | Output directory |
| `--model <name>` | LLM model (repeatable) |
| `--target <path>` | Target path |
| `--runtime-dir <dir>` | Runtime data directory |
| `--fuzz-dir <dir>` | Fuzz data directory |
| `--constraint-file <path>` | Constraint conditions JSON |
| `--compare <binary>` | Compare against an older binary |
| `--slice-arch <arch>` | Architecture slice for fat binaries |
| `--max-decompile <n>` | Maximum functions to decompile |

**Outputs:**
- `--map` produces `context-map.json`
- `--trace` produces `flow-trace-<id>.json`
- `--hunt` produces `variants.json`
- `--teach` is inline (no file output)

Pipeline integration: [/validate](#validate) Stage 0 automatically imports
`/understand` output via the bridge.  See [architecture](architecture.md) for
details.

---

### /crash-analysis

Autonomous root-cause analysis for C/C++ crashes.  Skill-dispatched
multi-agent orchestration using rr recordings, function traces, and gcov
coverage data.

```
/crash-analysis <bug-tracker-url> <git-repo-url>
```

No flags.  The orchestrator spawns specialised agents (crash-analyser,
function-trace-generator, coverage-analysis-generator) and a checker agent
for validation.

Requirements: rr, gcc/clang (with ASAN), gdb, gcov.

See [crash analysis](crash-analysis.md) for the full guide.

---

### /oss-forensics

Evidence-backed forensic investigation for public GitHub repositories.
Skill-dispatched multi-agent orchestration.

```
/oss-forensics <prompt> [--max-followups 3] [--max-retries 3]
```

| Flag | Description |
|------|-------------|
| `--max-followups <n>` | Maximum follow-up investigation rounds (default 3) |
| `--max-retries <n>` | Maximum retries on transient failures (default 3) |

Agents query GH Archive (BigQuery), live GitHub API, Wayback Machine, and
local git history.  Requires `GOOGLE_APPLICATION_CREDENTIALS` for BigQuery.

Output: `.out/oss-forensics-<timestamp>/forensic-report.md`

---

## Software Composition Analysis

### /sca

Find vulnerable dependencies, gate CI, fix and pin.  Alias: `/raptor-sca`.

```
/sca <path>
/sca fix <path>
/sca check <ecosystem> <name> <version>
/sca upgrade <ecosystem> <name> <from> <to>
/sca diff <old.json> <new.json>
/sca verify <path> --proposed <dir>
/sca health
/sca purl <ecosystem> <name> <version>
/sca render <findings.json>
/sca clean-cache --max-age <days>
```

**Scan flags** (default subcommand)

| Flag | Description |
|------|-------------|
| `--skip-review` | Skip LLM review of findings |
| `--skip-triage` | Skip LLM triage |
| `--fail-on-severity {critical,high,medium,low}` | Fail if any finding meets or exceeds severity |
| `--fail-on-kev` | Fail if any finding is in the Known Exploited Vulnerabilities catalogue |
| `--offline` | Offline mode (use cached data only) |

**Fix flags**

| Flag | Description |
|------|-------------|
| `--apply` | Apply fixes directly |
| `--cve-only` | Fix only CVE-tracked vulnerabilities |
| `--harden` | Apply hardening measures |
| `--allow-major` | Allow major version bumps |
| `--no-llm` | Skip LLM-assisted fix generation |

**Upgrade flags**

| Flag | Description |
|------|-------------|
| `--candidate <version>` | Candidate version to evaluate (repeatable) |

See [SCA](sca.md) for the full SCA guide.

---

## Binary Analysis

### /binary

Black-box binary investigation: decompilation, mapping, runtime tracing,
harness generation, and fuzzing.

```
/binary investigate <binary>
/binary map <binary>
/binary runtime <binary>
/binary trace-parser <run-dir>
/binary harness <run-dir>
/binary fuzz <binary>
/binary graph <run-dir>
/binary report <run-dir>
/binary handoff <run-dir>
/binary diagram <run-dir>
/binary help
```

**Map flags**

| Flag | Description |
|------|-------------|
| `--quick` | Quick mode (fewer decompilation passes) |
| `--slice-arch {arm64\|x86_64}` | Architecture slice for fat binaries |
| `--constraint-file <path>` | Constraint conditions JSON |
| `--compare <binary>` | Compare against an older binary |
| `--runtime-dir <dir>` | Runtime trace data directory |
| `--fuzz-dir <dir>` | Fuzz data directory |
| `--max-decompile <n>` | Maximum functions to decompile |

**Investigate flags**

| Flag | Description |
|------|-------------|
| `--runtime` | Include runtime analysis |
| `--fuzz` | Include fuzz testing |
| `--active` | Active probing mode |

**Harness flags**

| Flag | Description |
|------|-------------|
| `--ingress <point>` | Ingress point for harness |
| `--abi {buffer-size\|cstring}` | ABI convention for input |
| `--device <dev>` | Device target |
| `--ioctl-code <code>` | IOCTL code for device harnesses |

**Graph flags**

| Flag | Description |
|------|-------------|
| `--edges` | Include edges in graph |
| `--kind <type>` | Graph kind |
| `--evidence` | Include evidence annotations |
| `--tier <tier>` | Filter by confidence tier |
| `--json` | Output as JSON |

See [binary analysis](binary-analysis.md) for the full binary
investigation guide.

---

## Dynamic Instrumentation

### /frida

Dynamic instrumentation via Frida.  Skill-dispatched.

```
/frida --target <pid|name|bundle-id|binary>
```

| Flag | Description |
|------|-------------|
| `--target <target>` | Process ID, name, bundle ID, or binary path |
| `--template <name>` | Use a bundled template |
| `--script <path>` | Use a custom Frida script |
| `--host <host[:port]>` | Remote Frida server |
| `--usb` | Connect via USB |
| `--duration <secs>` | Instrumentation duration |
| `--spawn` | Spawn the target (rather than attach) |
| `--unsafe-attach` | Attach without safety checks |
| `--list-templates` | List available bundled templates |

**Bundled templates:** `api-trace`, `ssl-unpin`, `binary-flow-trace`,
`bb-coverage`.

See [Frida quickstart](frida/QUICKSTART.md) for installation and
platform-specific setup ([Linux](frida/SETUP_LINUX.md),
[macOS](frida/SETUP_MACOS.md)).

---

## Project Management

### /project

Named workspaces that corral analysis runs into a shared directory.

```
/project create <name> --target <path> [-d <description>]
/project list
/project status [<name>]
/project use [<name>]
/project none
/project delete <name> [--purge] [--yes]
/project rename <old> <new>
/project notes <name> [<text>] [--file <path>]
/project description <name> [<text>]
/project add <name> <dir> [--target <path>]
/project remove <name> <run> --to <path>
/project report [<name>]
/project diff <name> <run1> <run2>
/project merge [<name>] [--type <type>] [--yes]
/project findings [<name>] [--detailed]
/project coverage [<name>] [--detailed]
/project annotations [<name>]
/project annotations-diff <run-a> <run-b>
/project clean [<name>] [--keep <n>] [--dry-run] [--yes]
/project export <name> <path> [--force]
/project import <path> [--force] [--sha256 <hash>]
/project binary add <path>
/project binary list
/project binary remove <path>
/project binary clear
/project help
```

**Subcommand summary**

| Subcommand | Description |
|------------|-------------|
| `create` | Create a new project with a target path and optional `-d` description |
| `list` | List all projects |
| `status` | Show project status and run history |
| `use` | Set the active project |
| `none` | Clear the active project |
| `delete` | Delete a project (`--purge` removes output directory, `--yes` skips confirmation) |
| `rename` | Rename a project |
| `notes` | View or set project notes (inline text or `--file`) |
| `description` | View or set project description |
| `add` | Add a run directory to the project |
| `remove` | Remove a run, moving it to `--to <path>` |
| `report` | Generate a merged report across all runs |
| `diff` | Diff two runs within a project |
| `merge` | Merge findings across runs (`--type` selects merge strategy) |
| `findings` | Show merged findings (`--detailed` for per-finding breakdown) |
| `coverage` | Show tool coverage summary (`--detailed` for per-file table) |
| `annotations` | Show annotations across runs |
| `annotations-diff` | Diff annotations between two runs |
| `clean` | Delete old runs (`--keep <n>` retains the N most recent, `--dry-run` previews) |
| `export` | Export project to a portable archive (`--force` overwrites) |
| `import` | Import a project archive (`--force` overwrites, `--sha256` verifies integrity) |
| `binary add` | Persist a debug binary path for the active project |
| `binary list` | List persisted binaries |
| `binary remove` | Remove a persisted binary |
| `binary clear` | Clear all persisted binaries |

Persisted binaries are auto-loaded by `/agentic`, `/codeql`, and `/validate`
runs.  See [architecture](architecture.md) for run lifecycle and output
directory conventions.

---

## Utilities

### /describe

Generate a concise description of a target repository or directory.

```
/describe [--target <path>] [--json]
```

| Flag | Description |
|------|-------------|
| `--target <path>` | Target path to describe |
| `--json` | Output as JSON |

---

### /diagram

Generate Mermaid visual maps from `/understand` and `/validate` JSON outputs.

```
/diagram <out-dir> [--target <name>]
```

| Flag | Description |
|------|-------------|
| `--target <name>` | Filter to a specific target |
| `--stdout` | Print diagrams to stdout instead of writing `diagrams.md` |
| `--force` | Overwrite existing `diagrams.md` |

**Rendered artefacts:**
- `context-map.json` and `attack-surface.json` become flowchart LR diagrams
  (entry points, trust boundaries, sinks)
- `flow-trace-*.json` become per-trace flowchart TD diagrams (call chain hops,
  tainted variables, branches)
- `attack-tree.json` becomes a styled flowchart (confirmed/disproven/exploring
  nodes)
- `attack-paths.json` become per-path flowchart TD diagrams (proximity scores,
  blocker annotations)

Diagrams are auto-generated at the end of `/validate` and `/understand --map`
/ `--trace`.

---

### /annotate

Attach free-form prose to individual functions.  Annotations are stored as
Markdown files mirroring the source tree, with `## function_name` sections.

```
/annotate add <file> <function> [--status <status>] [-m <body>]
/annotate ls [--file <path>] [--status <status>]
/annotate show <file> <function>
/annotate edit <file> <function>
/annotate rm <file> <function>
/annotate stale [--target <repo_root>]
```

**Common flags**

| Flag | Description |
|------|-------------|
| `--base <path>` | Base directory for annotation storage |

**Add flags**

| Flag | Description |
|------|-------------|
| `--status {clean,suspicious,finding,error}` | Annotation status |
| `--cwe <CWE-XX>` | Associated CWE identifier |
| `-m` / `--body <text>` | Annotation body text |
| `--body-file <path>` | Read annotation body from file |
| `--lines <N-M>` | Source line range |
| `--target <repo_root>` | Repository root for hash computation |
| `--meta <KEY=VALUE>` | Metadata key-value pair (repeatable) |
| `--source <value>` | Attribution source (`human` or `llm`) |
| `--overwrite {all,respect-manual}` | Overwrite policy |

**Ls flags**

| Flag | Description |
|------|-------------|
| `--file <path>` | Filter by source file |
| `--status <value>` | Filter by status |
| `--source <value>` | Filter by source attribution |
| `--cwe <CWE-XX>` | Filter by CWE |
| `--rule-id <pattern>` | Filter by rule ID pattern |
| `--grep <text>` | Full-text search in annotation bodies |
| `--since <interval>` | Filter by age (`Nd`, `Nh`, `Nm`, `Ns`, `Nw`) |

**Stale flags**

| Flag | Description |
|------|-------------|
| `--target <repo_root>` | Repository root for re-hashing |

Status values: `clean` (reviewed, no concern), `suspicious` (real bug, not
exploitable), `finding` (exploitable), `entry_point`, `sink`,
`trust_boundary`, `flow_step`, `unchecked_flow`, `error`.

Annotations are emitted automatically by `/agentic` and `/understand`.

---

### /scorecard

Inspect per-model reliability across decision classes.  Answers
natural-language questions about model competence.

```
/scorecard [list]
/scorecard compare <model-a> <model-b>
/scorecard samples <decision_class>
/scorecard pin <decision_class> --model <model> --as <mode>
/scorecard unpin <decision_class> --model <model>
/scorecard reset [<decision_class>] [--model <model>]
```

**List flags** (default subcommand)

| Flag | Description |
|------|-------------|
| `--by-savings` | Sort by cost savings |
| `--by-miss-rate` | Sort by miss rate |
| `--untrusted` | Show untrusted-only decisions |
| `--learning` | Show learning-phase decisions |
| `--prefix <prefix>` | Filter decision classes by prefix |
| `--since <interval>` | Filter by recency (`Nd`, `Nh`) |
| `--recency <days>` | Recency window in days |

**Pin flags**

| Flag | Description |
|------|-------------|
| `--model <model>` | Model to pin |
| `--as {short-circuit,fall-through,auto}` | Pin mode |

**Unpin flags**

| Flag | Description |
|------|-------------|
| `--model <model>` | Model to unpin |

**Reset flags**

| Flag | Description |
|------|-------------|
| `--model <model>` | Reset specific model |
| `--older-than-days <n>` | Reset data older than N days |
| `--all` | Reset all data |

---

### /threat-model

Generate, maintain, and export threat models for a target.

```
/threat-model show
/threat-model init
/threat-model export
/threat-model sync
/threat-model lint
/threat-model diff --context-map <path>
/threat-model report [--context-map <path>]
/threat-model add --field <field> --value <text>
/threat-model remove --field <field> --value <text>
/threat-model build
/threat-model refresh
/threat-model use-stale
/threat-model help
```

| Subcommand | Description |
|------------|-------------|
| `show` | Display the current threat model |
| `init` | Initialise a new threat model |
| `export` | Export threat model to a portable format |
| `sync` | Synchronise threat model with current codebase state |
| `lint` | Validate threat model for consistency |
| `diff` | Diff threat model against a context map |
| `report` | Generate a threat model report |
| `add` | Add a value to a threat model field |
| `remove` | Remove a value from a threat model field |
| `build` | Build threat model from scratch |
| `refresh` | Force-refresh the threat model |
| `use-stale` | Accept the existing model without refresh |

See [threat model](threat-model.md) for methodology and field definitions.

---

### /cve-diff

Discover, acquire, and diff the fix commit for a CVE.

```
/cve-diff run <CVE-ID> [--output-dir <dir>]
/cve-diff health
```

| Flag | Description |
|------|-------------|
| `--output-dir <dir>` | Directory for diff output |
| `--budget-multiplier <n>` | Budget multiplier for search depth |
| `--with-root-cause` | Include root-cause analysis in output |

---

### /version

Print the running RAPTOR framework version.

```
/version
```

No flags.  Version is derived at render time via `git describe`.

---

## Python CLI (raptor.py)

The `raptor.py` entry point supports 11 modes directly: `scan`, `sca`,
`binary`, `fuzz`, `web`, `agentic`, `codeql`, `analyze`, `doctor`, `describe`,
and `frida`.  Most slash commands dispatch to either `raptor.py` or a
`libexec/` script.

See [Python CLI](python-cli.md) for the full `raptor.py` reference including
all mode-specific arguments and environment variables.
