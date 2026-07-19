# RAPTOR Python CLI Reference

For direct command-line usage, scripting, or CI/CD integration — this is the
**only** RAPTOR doc that covers running the framework without Claude Code.
Every mode below is invoked as `python3 raptor.py <mode> [options]`; nothing
here requires the `claude` CLI to be installed. RAPTOR's own LLM analysis
talks directly to a provider SDK when you set one of the API-key env vars
below — the `claude` binary on PATH is only ever used as a last-resort
fallback (no API key configured). If you're driving RAPTOR interactively
inside Claude Code instead, see the main README and `docs/commands.md`.

---

## Quick Reference

```bash
# Full autonomous workflow
python3 raptor.py agentic --repo /path/to/code

# Static analysis only
python3 raptor.py scan --repo /path/to/code --policy-groups secrets,injection

# Software Composition Analysis (vulnerable dependencies)
python3 raptor.py sca --repo /path/to/code

# Black-box binary investigation
python3 raptor.py binary investigate /path/to/binary

# Binary fuzzing
python3 raptor.py fuzz --binary /path/to/binary --duration 3600

# Web testing
python3 raptor.py web --url https://example.com

# CodeQL only
python3 raptor.py codeql --repo /path/to/code --languages java

# Analyze existing SARIF
python3 raptor.py analyze --repo /path/to/code --sarif findings.sarif

# Pre-flight inspection (no LLM cost, no side effects)
python3 raptor.py describe --target /path/to/code

# Local setup status report (no LLM required)
python3 raptor.py doctor

# Dynamic instrumentation via Frida (alpha)
python3 raptor.py frida --target 1234 --template api-trace --duration 30

# Get help
python3 raptor.py --help
python3 raptor.py help scan
```

---

## Prerequisites

- Python 3.10+ (3.12 is the tested/CI version)
- `pip install -r requirements.txt`
- `pip install semgrep`
- One LLM provider SDK + its API key — `pip install anthropic` (or `openai` /
  `google-genai`), then set one of: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`,
  `GEMINI_API_KEY`, `MISTRAL_API_KEY` (a longer list of aggregator/alternate
  provider keys is also recognised — see `core/config/__init__.py`
  `LLM_API_KEY_VARS`).

**Optional tools (only needed for the corresponding mode):**
- AFL++ (`apt install afl++` / `brew install afl++`) — `/fuzz`
- CodeQL CLI (https://github.com/github/codeql-cli-binaries) — `/codeql`, deep `/scan`
- GDB/LLDB, binutils (`nm`, `objdump`, `addr2line`) — `/binary`, crash triage
- Frida (`pip install frida frida-tools`) — `/frida`

See `docs/install.md` for the full baseline/optional tool matrix and
`docs/configuration.md` for per-provider model selection.

---

## Mode Details

Full mode list (`raptor.py --help` / `_HELP_EPILOG` is the source of truth):

| Mode | Purpose |
|------|---------|
| `scan` | Static analysis with Semgrep (fast, focused) |
| `sca` | Software Composition Analysis — deps, advisories, SBOM |
| `binary` | Black-box binary investigation and evidence collection |
| `fuzz` | Binary fuzzing with AFL++ |
| `web` | Web application security testing (alpha) |
| `agentic` | Full autonomous workflow (Semgrep + CodeQL + LLM analysis + exploits/patches) |
| `codeql` | CodeQL-only deep dataflow analysis |
| `analyze` | LLM-powered analysis of existing SARIF files |
| `describe` | Pre-flight inspection: target type, tool readiness, cost estimate — no LLM cost |
| `doctor` | Status report for local setup — no LLM required |
| `frida` | Dynamic instrumentation via Frida (alpha) |

### 1. scan - Static Analysis

```bash
python3 raptor.py scan --repo /path/to/code --policy-groups secrets,injection
```

Runs Semgrep only. See [Policy Groups](#policy-groups) below for the valid
`--policy-groups` values.

### 2. sca - Software Composition Analysis

```bash
python3 raptor.py sca --repo /path/to/full/source --no-llm --no-progress
```

Finds vulnerable dependencies (OSV/KEV/EPSS), runs reachability + supply-chain
checks, emits `findings.json`, `report.md`, and a CycloneDX SBOM. Subcommands
(`fix`, `check`, `upgrade`, `diff`, `health`, ...) follow the target path —
see `docs/sca.md` for the full surface, including the `diff --fail-on-severity`
exit-code gate used for PR checks.

### 3. binary - Black-Box Binary Investigation

```bash
python3 raptor.py binary investigate /path/to/binary
```

Autonomous evidence-first investigation of a binary with no source available:
`map`, `runtime`, `trace-parser`, `harness`, `fuzz`, `graph`, `report`,
`handoff`, and `diagram` subcommands build on top of `investigate`.

### 4. agentic - Full Autonomous

```bash
python3 raptor.py agentic --repo /path/to/code --max-findings 10
```

Runs Semgrep + CodeQL (CodeQL is on by default; pass `--no-codeql` to skip
it) + LLM analysis + exploit generation + patches.

**Optional enrichment flags:**

```bash
# Pre-map architecture before scanning AND validate exploitable findings after
python3 raptor.py agentic --repo /path/to/code --understand --validate

# Same, via the libexec wrapper (avoids per-invocation Bash permission prompt)
libexec/raptor-agentic --repo /path/to/code --understand --validate
```

- `--understand` runs `/understand --map` as a sibling lifecycle-managed run
  before scanning. Produces `context-map.json` and enriches the agentic
  checklist with priority markers so per-finding analysis prompts know which
  functions sit on entry points or sinks.
- `--validate` runs `/validate` as a sibling lifecycle-managed run after
  scanning. Selects findings flagged `is_exploitable=true` or
  `confidence="high"` (capped at 50, sorted by signal strength) and runs the
  full multi-stage pipeline against them.

Both flags degrade gracefully: if `claude` isn't on PATH or the target
fails the `cc_trust` check, the flag is skipped with a logged warning and
the base pipeline still runs.

**Binary-oracle flags** (DWARF-joined reachability filtering; suppresses
dead-code findings — see CLAUDE.md "BINARY-ORACLE REACHABILITY" for the
full contract):

```bash
python3 raptor.py agentic --repo /path/to/code --binary build/app --binary-auto
python3 raptor.py agentic --repo /path/to/code --no-binary-oracle
```

- `--binary <path>` — explicit debug binary for inventory enrichment.
  Repeatable for hybrid targets (a function is `absent` only when EVERY
  declared binary lacks it).
- `--binary-auto` — auto-detect debug binaries under common build dirs
  (`build/`, `target/release/`, `cmake-build-*/`, `bazel-bin/`, `builddir/`,
  `Debug/`, `Release/`, `out/`, `dist/`, `bin/`, ...).
- `--binary-edges` — extract call edges via r2 (slow, cached); required for
  the `binary_call_edge` reachability-rescue verdict.
- `--no-binary-oracle` — disable binary-oracle filtering entirely for this run.

**Multi-model analysis flags:**

```bash
python3 raptor.py agentic --repo /path/to/code \
  --model claude-opus-4-6 --model gpt-5.4 --aggregate claude-sonnet-4-6
```

- `--model MODEL` (repeatable) — each model independently analyses every
  finding; with 2+, results are correlated.
- `--consensus MODEL` — blind second opinion (majority vote).
- `--judge MODEL` — non-blind review of the primary model's reasoning.
- `--aggregate MODEL` — synthesises multi-model output for downstream triage.

### 5. codeql - Deep Analysis

```bash
python3 raptor.py codeql --repo /path/to/code --languages java
```

CodeQL-only for deep dataflow analysis (slower, finds complex vulnerabilities).
Accepts the same `--binary` / `--binary-auto` / `--binary-edges` /
`--no-binary-oracle` flags as `agentic`.

### 6. fuzz - Binary Fuzzing

```bash
python3 raptor.py fuzz --binary /path/to/binary --duration 3600 --parallel 4
```

AFL++ fuzzing with crash analysis and exploit generation. If no `--corpus` is
provided, RAPTOR uses autonomous corpus generation when available and otherwise
falls back to its built-in starter corpus.

```bash
python3 raptor.py fuzz --export-seed-corpus /tmp/raptor-fuzz-seeds
python3 raptor.py fuzz --binary /path/to/binary --corpus /tmp/raptor-fuzz-seeds
```

### 7. web - Web Testing

```bash
python3 raptor.py web --url https://example.com
```

OWASP Top 10 scanning for web applications. Alpha — expect false positives
and incomplete coverage.

### 8. analyze - LLM Analysis Only

```bash
python3 raptor.py analyze --repo /path/to/code --sarif findings.sarif --max-findings 10
```

Analyze existing SARIF files (from previous scans or other tools). Accepts
the same `--model` / `--consensus` / `--judge` multi-model flags as `agentic`.

### 9. describe - Pre-Flight Inspection

```bash
python3 raptor.py describe --target /path/to/code
```

Target-shape inference + tool readiness + recommended pipeline + cost
estimate. No LLM cost, no side effects. `--json` for machine-readable output.

### 10. doctor - Setup Status Report

```bash
python3 raptor.py doctor
```

Status report for the local install (API keys detected, optional tools
present, sandbox capability). No LLM call required — the one mode you can
run with nothing configured.

### 11. frida - Dynamic Instrumentation

```bash
python3 raptor.py frida --target 1234 --template api-trace --duration 30
python3 raptor.py frida --target ./victim --spawn --script ./my-hook.js --duration 60
```

Attach to or spawn a process, load a JS hook (built-in `--template` or custom
`--script`), capture emitted events into a lifecycle-managed run directory.
Alpha. `--list-templates` shows the built-in hook scripts.

---

## Output Structure

All results save to `out/` (or the active project's directory, if you've
created one with `/project` — see `docs/commands.md`):

```
out/scan_<repo>_<timestamp>/
├── semgrep_*.sarif
├── codeql_*.sarif (if CodeQL enabled)
├── scan_metrics.json
├── autonomous_analysis_report.json (agentic runs)
├── agentic-report.md
├── exploits/
└── patches/
```

The exact path is printed at the start of the run as `OUTPUT_DIR=<path>`.

---

## CI/CD Integration

```bash
# Fast mode for pipelines
python3 raptor.py agentic \
  --repo . \
  --policy-groups secrets,injection \
  --max-findings 5 \
  --mode fast \
  --no-exploits
```

- `--mode fast` trades thoroughness for speed (default is `thorough`).
- `--max-findings N` caps how many findings get the full LLM analysis pass.
- `--no-exploits` skips PoC generation (there's also `--no-patches`).

**Exit code reflects run execution, not finding severity:** `0` means the
pipeline ran to completion (even if it found critical vulnerabilities); a
non-zero code (`1`, or `4` for scan mode's "every Semgrep pack failed") means
the run itself broke — a crashed subprocess, a pre-flight cost-gate refusal,
or a sandbox-engagement failure. `agentic`/`scan`/`codeql` do **not** gate the
process exit code on finding severity. To fail a build on severity, parse
`findings.json` / `agentic-report.md` / `scan_metrics.json` yourself, or use
`sca diff --fail-on-severity <level>`, which does have a real severity-based
exit code (`0` = no regression, `1` = regression found, `2` = invalid input) —
see `docs/sca.md`.

---

## Environment Variables

```bash
# LLM provider — set exactly one (see LLM_API_KEY_VARS in core/config/__init__.py
# for the full recognised list, including aggregator keys)
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
export GEMINI_API_KEY="..."
export MISTRAL_API_KEY="..."

# Optional
export RAPTOR_OUT_DIR="/custom/output/path"   # override the output directory
export RAPTOR_DIR="/path/to/raptor"           # installation root (libexec scripts derive paths from it)
```

Beyond the two vars above and the API-key vars, RAPTOR also reads `RAPTOR_CONFIG`
(path to a `models.json` that explicitly selects the provider/model), `OLLAMA_HOST`,
and a couple of resolution helpers (`RAPTOR_TARGET_KIND`, `RAPTOR_CALLER_DIR`). With
no `models.json`, provider selection is inferred from which API-key env var / SDK is
present (see `core/llm/detection.py`); the installation root is `RAPTOR_DIR` itself.

---

## Policy Groups

`--policy-groups` (comma-separated, default `all`) selects among the groups
in `RaptorConfig.POLICY_GROUP_TO_SEMGREP_PACK` (`core/config/__init__.py`):

- `secrets` - hardcoded credentials, API keys
- `injection` - command/SQL/etc. injection
- `auth` - authentication/authorization weaknesses (JWT, ...)
- `flows` - dataflow-pack rules
- `sinks` - dangerous sinks (XSS, ...)
- `best-practices` - general secure-coding practices

Three baseline Semgrep packs (`security-audit`, `owasp-top-ten`, `secrets`)
always run regardless of `--policy-groups`. Custom groups can be added in
`packages/static-analysis/scanner.py`.

---

## Discovering flags

Every mode's full flag list comes from its own argparse — don't guess:

```bash
python3 raptor.py help scan
python3 raptor.py scan --help
```

Sandbox flags (`--sandbox`, `--no-sandbox`, `--audit`, `--audit-verbose`) are
added by `core.sandbox.add_cli_args` after the mode name and only show up in
the mode's own `--help`, not the top-level one.
