---
description: "Systematic hypothesis-driven security review of coverage gaps"
dispatch: skill
user-invocable: true
---

# /audit — Systematic Code Review

## What this is

A hypothesis-driven, tool-grounded security review. The LLM reasons about assumptions and violations; deterministic tools (Semgrep, Coccinelle, CodeQL, SMT) validate. The LLM never directly classifies code as vulnerable — it generates hypotheses and mechanical tests; tool output IS the verdict.

## Execution model

Two-phase: Claude runs `/understand --map` (LLM-driven, produces context-map.json), then `libexec/raptor-audit run` drives the orchestrator (LLM review via API + mechanical tool validation, lifecycle management, and report generation).

## Usage

```
/audit <target_path> [--strategy <name>] [--budget <N>] [--scope <dir>] [--out <dir>]
       [--codeql-db <path>] [--max-cost <USD>] [--deepen-reserve <fraction>] [--max-time <seconds>]
       [--review-passes <N>] [--subsystem-depth <N>] [--batch-sloc-threshold <N>]
       [--include-kinds <list>] [--max-propagation-depth <N>] [--adversarial]
       [--no-verdict-reuse] [--schedule {cost,priority}] [--dynamic | --no-dynamic]
       [--binary <path> ...] [--binary-auto] [--no-binary-oracle]
       [--annotations-dir <path>] [--no-validate] [--model <name> ...]
```

- `<target_path>` — path to codebase to review (required on first run; resolved per DEFAULT TARGET DIRECTORY if omitted)
- `--strategy <name>` — filter to one strategy: general, input_handling, concurrency, memory, auth, crypto, aliasing
- `--budget <N>` — max functions to review (default: all gaps)
- `--scope <dir>` — restrict to a subdirectory (e.g. `ipc/`, `net/ipv4/`). Annotations and coverage still write to the project-level output dir, so successive scoped runs accumulate
- `--out <dir>` — output directory (default: resolved by lifecycle)
- `--codeql-db <path>` — path to a CodeQL database for query dispatch and pre-sweep
- `--max-cost <USD>` — stop after spending this many dollars on LLM calls
- `--deepen-reserve <fraction>` — slice of `--max-cost` held back for the deepen phase so announced re-reviews can execute (default 0.15; 0 disables)
- `--max-time <seconds>` — stop after this many wall-clock seconds
- `--review-passes <N>` — independent review passes per function for self-consistency (default: 1)
- `--subsystem-depth <N>` — directory grouping depth for subsystem-ordered review (default: 0)
- `--batch-sloc-threshold <N>` — functions at or under N SLOC are batched per file into combined reviews (default: 15; 0 disables). Raise on codebases dense with tiny accessors/wrappers to cut per-call overhead
- `--include-kinds <list>` — comma-separated item kinds beyond functions/methods (default: `top_level`, `macro`, `global`); positive list overrides the defaults, `-kind` opts one out, `none` restricts to functions/methods only
- `--no-verdict-reuse` — disable cross-run verdict reuse (importing prior-run journal verdicts for functions whose source is unchanged)
- `--schedule {cost,priority}` — parallel review ordering: `cost` packs predicted-longest reviews first (shortest wall time), `priority` reviews the most promising functions first (fastest first finding)
- `--dynamic` / `--no-dynamic` — enable/disable dynamic validation (Frida observation / target execution) for confirmed findings; `--no-dynamic` also overrides the project's `dynamic` trust marker
- `--binary <path>` — debug binary for binary-oracle enrichment (repeatable); `--binary-auto` auto-detects under common build dirs; `--no-binary-oracle` disables the oracle for this run
- `--annotations-dir <path>` — annotations directory for team workflows or cross-run review (default: project-level `annotations/` for lifecycle runs, else `$OUTPUT_DIR/annotations`)
- `--no-validate` — skip the /validate post-pass (not recommended)
- `--model <name>` — model ID (repeatable for multi-model consensus; first model used for lifecycle)
- `--adversarial` — enable adversarial reviewer that challenges positive verdicts (requires `--model` x2+)
- `--max-propagation-depth <N>` — override adaptive constraint propagation depth (default: auto-calibrated p90+2, floor 5, cap 15)

## Instructions

### Step 0: Choose execution mode

Run mode detection, passing through any `--local` or `--model` flags from the operator:

```bash
libexec/raptor-resolve-mode [--local] [--model <name>]
```

Output is one line:
- `orchestrator <model>` → follow Steps 1–4 below (`libexec/raptor-audit run` with the external LLM)
- `in-session` → load and follow `.claude/skills/audit/SKILL.md` (Claude Code is the LLM; covers study, map, review loop, cross-session resume, scoping). Skip Steps 1–4.

### Step 1: Resolve output directory

If the operator passed `--out`, use that directory. Otherwise, start a lifecycle run to get one:

```bash
libexec/raptor-run-lifecycle start audit --target "$TARGET_PATH"
```

Parse `OUTPUT_DIR=<path>` from the last line.

### Step 2: Context map

Check whether `context-map.json` exists in `$OUTPUT_DIR`. If missing, run `/understand --map` to build it — the orchestrator depends on it for sink/entry-point priority boosting.

```
/understand --map "$TARGET_PATH" --out "$OUTPUT_DIR"
```

Note: for a source-tree target this is the **in-session** `/understand` workflow (you perform the map following `.claude/skills/code-understanding/map.md`) — `libexec/raptor-understand --map` only accepts compiled artefacts. Since `--out` is already resolved, skip the understand lifecycle start and write into `$OUTPUT_DIR` directly.

If the operator passed `--scope`, still map the full target (the map covers the whole codebase; the scope only filters gap selection).

### Step 3: Run the orchestrator

**IMPORTANT:** `target` is a **positional** argument, NOT `--target`. The lifecycle uses `--target` but `raptor-audit run` does not.

```bash
libexec/raptor-audit run "$TARGET_PATH" --out "$OUTPUT_DIR"
```

Pass through any operator flags (`--strategy`, `--budget`, `--scope`, `--annotations-dir`, `--no-validate`, `--model`, `--adversarial`, `--max-propagation-depth`, `--codeql-db`, `--max-cost`, `--deepen-reserve`, `--max-time`, `--review-passes`, `--subsystem-depth`, `--batch-sloc-threshold`, `--include-kinds`, `--no-verdict-reuse`, `--schedule`, `--dynamic`, `--no-dynamic`, `--binary`, `--binary-auto`, `--no-binary-oracle`).

The orchestrator handles everything from here: gap computation, context assembly, LLM review, tool chain dispatch, Joern background build, sweep validation, constraint propagation, Mode 2 checker synthesis, /validate post-pass, report generation, and lifecycle completion.

### Step 4: Surface results

When the orchestrator completes, read and print the summary from `$OUTPUT_DIR/audit-report.json`.

---

## Pipeline (reference)

```
0. context-map.json (from /understand --map, done by the .md shim above)
1. Lifecycle start, build inventory → checklist.json
2. Compute gaps → gaps.json (functions with no coverage)
2a. Consistency census pre-pass → return-census.json (registry-grade contract deviations become LLM-free findings)
2b. Pre-loop LLM summary pass: callee-context summaries for connected but unsummarised functions (booked as the `summary` phase in cost-breakdown.json)
3. For each gap batch (by directory):
   a. Assemble context slice (source + callers + callees + metadata + strategy exemplars + flow traces)
   b. LLM review: form hypotheses about assumptions and violations
   c. Generate mechanical tests (Semgrep/Coccinelle/CodeQL/SMT)
   d. Run tests via tool chain dispatch → evaluate results
   e. Record journal entry (what was tested, tool evidence)
   f. Record status (clean/suspicious/finding/error/dormant)
   g. If pattern has variants: generate codebase-wide checker (Mode 2)
4. Joern CPG builds in background, drains when ready for dataflow re-review
5. Constraint propagation across related functions
6. Sweep validation to confirm tool-backed evidence
7. Tool-grounded critique: identifies gaps, generates additional tool invocations
8. Report: review-journal.jsonl + findings.json + summary
9. /validate post-pass on findings (unless --no-validate)
```

## Tool menu (reference)

These tools are available for hypothesis validation. The orchestrator invokes them via `raptor-audit sweep` to ensure results are logged to the audit trail:

| Tool | Sweep invocation | When |
|------|-----------------|------|
| **Semgrep** | `raptor-audit sweep --tool semgrep --rule-file rule.yaml --file F --function FN --out $DIR --target $T` | Pattern matching, missing checks |
| **Coccinelle** | `raptor-audit sweep --tool coccinelle --rule-file rule.cocci --file F --function FN --out $DIR --target $T` | Inconsistency detection, variant sweep |
| **CodeQL** | `raptor-audit sweep --tool codeql --rule-file query.ql --file F --function FN --out $DIR --target $T [--codeql-db $DB]` | Dataflow validation |
| **SMT** | `raptor-audit sweep --tool smt --smt-verb check-overflow --smt-args '{"var":"len","type":"int32","op":"len*size","bound":"4294967295"}' --file F --function FN --out $DIR` | Arithmetic/bounds/path feasibility |
| **Joern** | CPG-based dataflow queries (background build, drain on ready; guard-dominance and flow-reachability channels; not a `sweep --tool` choice) | Complex dataflow reachability |
| **Compiler analyzers** | Orchestrator channel: gcc `-fanalyzer` / clang `--analyze` verification sweep over hypothesis TUs | Mechanical corroboration of memory/null-deref hypotheses |
| **Expanded-view Semgrep** | Orchestrator channel: rules re-run over fidelity-3 preprocessor-expanded C/C++ views | Macro-hidden sinks |
| **Git history** | Orchestrator channel: prior security fixes touching the function (corroboration only, never a verdict) | Bug-class recurrence |

**SMT verbs:** `check-overflow`, `check-oob`, `check-null-deref`, `check-overflow-to-oob`, `check-negative-bypass`, `validate-path`

**Orchestrator-only channels** (not `sweep --tool` choices): fail-open (`fail_open:*`), consistency (`consistency:*`, peer census + contract witnesses), API-boundary caller contracts (`api_boundary:caller-contract`), SMT invariant preservation (`smt:invariant-preservation`). See `docs/audit.md` for semantics.

**Manual sweep logging** (for tools not yet auto-executed):
```bash
raptor-audit sweep --tool compilation --file F --function FN --outcome confirmed --result-file output.txt --out $DIR
```

## Record statuses (reference)

```bash
# For clean/error:
libexec/raptor-audit record --out "$OUTPUT_DIR" --file <file> --function <name> --status clean --body "what was tested"

# For suspicious/dormant (requires --hypothesis):
libexec/raptor-audit record --out "$OUTPUT_DIR" --file <file> --function <name> --status suspicious --hypothesis "testable claim" --body "what was tested and found"

# For finding (requires --hypothesis, --evidence-tool, --vuln-type):
libexec/raptor-audit record --out "$OUTPUT_DIR" --file <file> --function <name> --status finding --hypothesis "testable claim" --evidence-tool semgrep --vuln-type buffer_overflow --body "what was tested and tool output"
```

Line numbers auto-resolve from the checklist. `--evidence-tool`: semgrep|coccinelle|codeql|smt|compilation|compiler|joern|dark_verify:confirmed|dark_verify:refuted|dynamic:crash|dynamic:sanitizer|frida:runtime. `--vuln-type`: sql_injection|buffer_overflow|path_traversal|xss|command_injection|use_after_free|etc.

## Automatic /validate post-pass

After the review loop completes, `/validate` runs automatically on all findings (including sweep-promoted suspicious items). The audit is a cheap wide net; `/validate` is the expensive filter that kills false positives by tracing reachability through the full Stage A-F pipeline.

To skip: pass `--no-validate` to the orchestrator.

## Post-run workflows

### Feedback loop (after /validate)

Import validation results to close the Reflexion loop:

```bash
libexec/raptor-audit feedback --validation-report <validate-out>/findings.json --annotations-dir "$OUTPUT_DIR/annotations" --audit-out "$OUTPUT_DIR"
```

Corrections append fresh review-journal entries (carrying the prior verdict and lesson) — nothing is rewritten in place:

- **Disproven findings** → correction entry downgrading to `clean` with reason
- **Missed vulnerabilities** → correction entry upgrading to `finding`
- **Corroborated findings** → confirmation entry, no status change
- Human annotations are never modified — human-grade ones (`source=human` plus an interactive-TTY provenance stamp, or legacy pre-stamp notes) veto feedback for their function entirely; non-human-grade notes only serve as the prior claim when no journal entry exists

### Staleness check

After source code changes, check which annotations have drifted:

```bash
libexec/raptor-audit stale --annotations-dir "$OUTPUT_DIR/annotations" --target "$TARGET_PATH"
```

Stale annotations should be re-reviewed with fresh context.

### Critique

Run the critique to identify gaps in tool coverage:

```bash
libexec/raptor-audit critique --out "$OUTPUT_DIR"
```

Reports:
- Functions with few tool sweeps (low sweep:record ratio)
- Confirmed findings without codebase-wide rules (Mode 2 gaps)
- Suspicious functions with untried tools (e.g. tried Semgrep but not SMT)

## Environment variable warning

**NEVER prefix commands with environment variable assignments.** `OUTPUT_DIR=/path libexec/raptor-audit gaps` is WRONG — it breaks permission patterns. Instead, pass values via flags:
```bash
# CORRECT
libexec/raptor-audit gaps --out "$OUTPUT_DIR"

# WRONG
OUTPUT_DIR=/path/to/out libexec/raptor-audit gaps --out /path/to/out
```

## Output

- `$OUTPUT_DIR/review-journal.jsonl` — per-function review decisions (status, hypotheses, tools, cost)
- `$OUTPUT_DIR/findings.json` — findings in standard format (→ `/validate`)
- `$OUTPUT_DIR/gaps.json` — gap list used for this run
- `$OUTPUT_DIR/.audit-log.jsonl` — full audit trail (context/sweep/record/feedback actions)
- `$OUTPUT_DIR/return-census.json` — return-usage census from the consistency pre-pass
- `$OUTPUT_DIR/prefilter-kills.jsonl` — one record per prefilter/triage kill, with spot-audit corroboration
- `$OUTPUT_DIR/fuzz-dict.json` + `fuzz.dict` — fuzz handoff (AFL dictionary; auto-discovered by `/fuzz`)
- `$OUTPUT_DIR/cost-breakdown.json` — per-phase cost ledger reconciliation
- `$OUTPUT_DIR/llm-telemetry.jsonl` — per-call LLM telemetry
- `annotations/<source_path>.md` — human-written per-function notes (project-level; never written by the LLM)
