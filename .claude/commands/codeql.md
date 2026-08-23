---
description: CodeQL deep static analysis with dataflow validation
dispatch: python3 raptor.py codeql
---

# /codeql - RAPTOR CodeQL Analysis

**`--help` / `-h`:** If the user passes only `--help` or `-h`, run `python3 raptor.py codeql --help` and present its output. That command is side-effect-free (no run, lifecycle, output directory, or LLM dispatcher) and is the complete, authoritative flag list — do NOT start a scan or hand-summarise flags from this doc.

Runs CodeQL deep static analysis with dataflow validation. Slower but finds complex vulnerabilities that Semgrep misses (tainted flows, use-after-free, injection chains).

## Usage

```
python3 raptor.py codeql --repo <path> [options]
```

## Options

| Option | Description |
|--------|-------------|
| `--repo <path>` | Repository path (required) |
| `--languages <list>` | Comma-separated languages (auto-detected if omitted) |
| `--scan-only` | Scan only — produce SARIF, skip LLM analysis (default) |
| `--analyze` | Enable LLM-powered autonomous analysis + exploit generation |
| `--build-command <cmd>` | Custom build command for database creation |
| `--extended` | Use extended security suites (more rules, slower) |
| `--force` | Force database recreation |
| `--max-findings <n>` | Max findings to analyse (with `--analyze`) |

## SMT Dataflow Pre-Check

When `--analyze` is enabled, dataflow findings are routed through an SMT
pre-check before the full LLM analysis (`core/smt_solver/path_feasibility.py`,
driven from `packages/codeql/dataflow_validator.py`):

1. The LLM extracts branch conditions from each path step as structured predicates
   (`"size > 0"`, `"offset + length <= buffer_size"`, etc.)
2. Z3 checks whether those conditions are **jointly satisfiable**
3. **unsat** → path is provably unreachable; finding marked non-exploitable without
   the full analysis LLM call (confidence capped at 0.7)
4. **sat** → concrete satisfying values returned; fed as candidate inputs into the
   LLM prompt and `prerequisites` field of `DataflowValidation`
5. **None** → Z3 unavailable or conditions unparseable; full LLM analysis runs

Requires `z3-solver` (`pip install z3-solver`). Degrades gracefully when absent.

**Best coverage:** CWE-190 (integer overflow, **including 32-bit wraparound** —
the extraction LLM emits per-path width/signedness hints so Z3 models the right
C type semantics), CWE-120/122 (buffer size checks), CWE-193 (off-by-one),
CWE-476 (null deref). String-based findings (CWE-89) fall through to LLM analysis.

## Trust escalation on degraded builds (interactive sessions only)

Two run-output hints mark places where a trust decision — not a retry — is what
unblocks better results. After the run completes (never mid-pipeline), offer the
decision as a structured choice (see CLAUDE.md § INTERACTIVE PROMPTS). Run
`libexec/raptor-may-ask` first; only if it prints `interactive` AND the
AskUserQuestion tool is available, ask. Quote the actual hint text from the run
output in the question.

**Trigger A — buildless extraction hit unresolved includes** (output contains
"build-generated headers are invisible without a traced build (opt in via
--traced-build)"):

1. **Keep buildless (Recommended)** — accept the results as-is; TUs needing
   build-generated headers stay partially analysed. No repo code is executed.
2. **Re-run with `--traced-build`** — grants for that one run: CodeQL executes the
   repo's build system (attacker-controlled build scripts from the scanned repo) to
   extract with full build context.
3. **Persist `/project trust build`** — grants: every future `/codeql` and `/agentic`
   run on this project does traced-build extraction (per-run `--no-traced-build`
   still overrides). `build` does NOT imply `config`.

**Trigger B — strict trust checks skipped an LLM-assisted step** (output warns the
target repo has dangerous Claude Code config and says "Pass --trust-repo to
override"):

1. **Keep strict (Recommended)** — the run stands; repo-provided Claude Code /
   CodeQL configuration stays quarantined.
2. **Re-run with `--trust-repo`** — grants for that one run: lifts the cc_trust +
   codeql_trust strict checks, so repo-provided Claude Code config and CodeQL
   packs/configs are honoured.
3. **Persist `/project trust config`** — grants: the `--trust-repo` umbrella
   (cc_trust + codeql_trust) on every future run of this project (per-run
   `--no-trust-repo` still overrides).

**Non-interactive fallback (both triggers):** current behavior — proceed with the
degraded results and surface the hint text plus the flag / trust-marker escape
hatches in the run summary. Never set a trust marker or add a trust flag without an
explicit operator selection.

## Examples

```bash
# Scan only (default) — produces SARIF
/codeql --repo /tmp/vulns

# Full autonomous analysis (includes SMT dataflow pre-check if z3 installed)
/codeql --repo /tmp/vulns --analyze

# Specific language with custom build
/codeql --repo /tmp/vulns --languages cpp --build-command "make"
```

---
