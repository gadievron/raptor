# Systematic Code Review

[Documentation index](README.md)

`/audit` is RAPTOR's hypothesis-driven, tool-grounded security review.  It
works through coverage gaps systematically: for each unreviewed function, the
LLM forms hypotheses about assumption violations; deterministic tools
(Semgrep, Coccinelle, CodeQL, SMT, Joern) validate or refute them.  The LLM
never directly classifies code as vulnerable -- tool output is the verdict.

The output is a per-function audit trail with tool evidence, coverage
records that accumulate across runs, and a findings file compatible with
`/validate`.

**Related documentation:**
[commands](commands.md#audit) |
[validation](validation.md) |
[understand](commands.md#understand) |
[annotations](commands.md#annotate) |
[coverage](commands.md#review)


**On this page:**

- [Usage](#usage)
- [Pipeline](#pipeline)
- [Execution Model](#execution-model)
- [Strategies](#strategies)
- [Tool Menu](#tool-menu)
- [Gates](#gates)
- [Statuses](#statuses)
- [Open Discovery](#open-discovery)
- [Checker Synthesis (Mode 2)](#checker-synthesis-mode-2)
- [Vocabulary Packs](#vocabulary-packs)
- [Cost forecasting](#cost-forecasting)
- [Running long audits](#running-long-audits)
- [Post-run Workflows](#post-run-workflows)
- [Output](#output)
- [Integration](#integration)

## Usage

```
/audit <target_path> [flags]
```

The command maps the target with `/understand --map` before starting review.
Use the examples below to choose a scope and budget.

```text
/audit /path/to/code                       # review all gaps
/audit /path/to/code --strategy memory     # focus on memory safety
/audit /path/to/code --scope net/ipv4/     # restrict to a subsystem
/audit /path/to/code --budget 50           # cap at 50 functions
/audit /path/to/code --model claude-opus-4-7 --model gpt-5 --adversarial
```

### Flags

Use the command help for the complete flag reference and current defaults:

```bash
libexec/raptor-audit run --help
libexec/raptor-audit resume --help
```

Set `--budget` to limit reviewed functions, `--max-cost` to limit LLM spend,
and `--max-time` to bound a run. Use `--scope` to focus on a subsystem and
`--model` to select the review model. See [Running long audits](#running-long-audits)
for checkpoints and resume behavior.

## Pipeline

1. Map the target and identify functions that still need review.
2. Review source and calling context to form testable hypotheses.
3. Use available tools to check those hypotheses and record their evidence.
4. Search for related issues and review additional candidates within budget.
5. Save findings, unresolved concerns, coverage, and costs.
6. Run `/validate` on findings unless `--no-validate` is set.


## Execution Model

Each concern starts as a testable claim about the source or binary. Available
analysis tools check the claim, and the journal records the evidence and the
result. A pattern match or mathematical model is useful only within its stated
scope; inspect assumptions before treating it as proof of an application bug.

A tool returning no matches is not automatically a refutation. Failed,
incomplete, unsupported, or inconclusive checks leave the claim unresolved.
A `clean` result records the outcome of that review, not a guarantee that the
function is safe. Changes and newly available evidence can require re-review.

Some checks execute test witnesses and require explicit repository trust.
See the [project trust controls](commands.md#project) before enabling execution
of target code. Binary reviews also compare relevant decompiler claims with
machine-code evidence where supported. Unsupported architectures or incomplete
binary evidence remain limitations rather than evidence of safety.


## Strategies

Strategies are selected per-function based on file paths, parameter types,
and return types.  Multiple strategies can apply to the same function.

| Strategy | When | Key questions |
|----------|------|---------------|
| **General** | Default | What does it trust?  What happens when assumptions are violated? |
| **Input handling** | Parsers, decoders, protocol handlers | Input format/size assumptions?  Length fields trusted before use? |
| **Concurrency** | Lock APIs, mutexes, atomics | Lock windows?  Concurrent interleavings?  Memory barriers? |
| **Memory** | Allocators, refcounts, pools | Ownership model?  Symmetric refcounting?  Cleanup on failure? |
| **Auth/privilege** | Permission checks, ACLs, credentials | Check bypass?  Error path security?  Unvalidated transitions? |
| **Crypto** | Crypto APIs, key material, RNG | Correct algorithm usage?  Timing side channels?  Key lifecycle? |
| **Aliasing** | splice, zero-copy, scatterlist, sk_buff | Alias assumptions?  Who owns backing pages?  Concurrent writes? |
| **Integer** | Arithmetic feeding sizes, indices, or allocations | Overflow?  Truncation?  Sign confusion before a bounds check? |

Each strategy includes CVE-backed exemplars showing the hypothesis →
tool → verdict chain that found the bug, injected into the LLM context
alongside the target code.


## Tool Menu

Tool availability depends on the target language, installed dependencies, and
build information. Missing tools reduce coverage; they do not clear a concern.

| Tool | What it checks |
|------|----------------|
| Semgrep | Source patterns, missing checks, and supported taint flows |
| Coccinelle | C/C++ structural patterns and related variants |
| CodeQL | Dataflow and reachability through supported languages |
| SMT | Supported arithmetic, bounds, and path constraints under recorded assumptions |
| Compiler analyzers | Compiler-detected memory, resource, and control-flow problems |
| Joern | Dataflow and call relationships |
| Test witnesses | Observed behavior of a specific test, when execution is authorized |
| Binary analysis | Machine-code corroboration and supported binary checks |

Additional checks look for inconsistent caller contracts, lifecycle errors,
lock misuse, resource bounds, and protocol-state violations. Historical fixes
can supply context, but do not establish a new finding on their own.


## Gates

Findings require a testable hypothesis, recorded tool evidence, and relevant
source or binary context. Reachability is checked before an issue is reported
as an active finding. Issues identified as unreachable are recorded separately
as `dormant`.

Mechanical detections need appropriate evidence to be dismissed. Model wording
alone does not establish that a reported issue is safe. Unresolved concerns
remain visible in the journal and status reports.

## Statuses

Each reviewed function gets exactly one status:

| Status | Meaning |
|--------|---------|
| `clean` | Reviewed, no concern found |
| `suspicious` | Concern identified but not tool-confirmed |
| `finding` | Tool-confirmed, reachable vulnerability |
| `dark` | Suspicious claim with no tool coverage — the hypothesis is plausible but no available tool could verify or refute it.  Exported for `/validate` |
| `dormant` | Real bug but currently unreachable (dead code, no callers) |
| `error` | Review blocked (e.g. parse failure, tool error) |

A `dormant` bug becomes a `finding` when reachability changes.  `dormant`
is not `clean` -- the bug is real, it just can't be triggered today.

`dark` is distinct from `suspicious`: a `suspicious` item has tool
evidence that was inconclusive; a `dark` item has none at all because
the claim fell outside the tool menu's coverage.  Open-discovery items
without tool evidence resolve to `dormant` instead — see [Open
Discovery](#open-discovery).


## Open Discovery

Open discovery (default on; disable with `--no-open-discovery`) extends
the audit beyond the static checklist.  The baseline pipeline reviews
only functions in the gap inventory; open discovery adds three
LLM-driven perspectives that generate hypotheses the checklist cannot:

1. **Cross-scope contracts** — boundary mismatches, caller/callee
   contract violations, cross-module assumptions.
2. **Architectural negative space** — controls, checks, or invariants
   that *should* exist but don't.
3. **Unconstrained sweep** — a free-form pass with no CWE or strategy
   constraint, looking for anything the structured strategies miss.

Hypotheses feed a composition engine that walks call-graph edges to
pair individual weaknesses into composite vulnerabilities.  Verifiable
compositions go through the same tool-grounded verification as
checklist items; non-verifiable ones are exported as
`composition-leads.json`.

Discovery-generated hypotheses that lack tool evidence resolve to
`dormant` (below the reporting threshold) rather than `dark`.
Checklist hypotheses without tool evidence still resolve to `dark`
(exported for `/validate`).

With multi-model consensus (`--model` x2+), disagreements where one
model calls suspicious and the other clean — with no mechanical
evidence — resolve to the lower status rather than the higher.


## Checker Synthesis (Mode 2)

When a confirmed finding suggests a repeatable pattern, the orchestrator
generates a codebase-wide checker:

1. Abstract the pattern from the specific finding
2. Generate a Semgrep or Coccinelle rule
3. Validate the rule with dual control: a positive fixture it must match
   and a negative control it must not (over-broad rules are refuted and
   refined iteratively)
4. Run it across the entire codebase
5. Each match is a new candidate to review

This is the KNighter pattern: one hypothesis → sweep the whole codebase.
Rules are stored in the project's rule library and can be replayed across
runs.

The same synthesis channel also runs on demand for chain-less suspicious
hypotheses during a run, and post-run against the witness backlog's dark
rows (see "Witness-backlog drain" under Post-run Workflows).


## Vocabulary Packs

RAPTOR uses vocabulary packs and concepts learned during study to recognize
project-specific APIs. Malformed packs produce warnings and reduce recognition;
they do not establish that an API is safe.

For extending detection rules and vocabulary, see the
[rule-authoring guidance](developers.md#engine-authoring-detection-rules).

## Cost forecasting

`--forecast` prints a low/central/high cost estimate and exits without LLM
calls. Uncapped runs also show a forecast before review starts.

```bash
libexec/raptor-audit run /path/to/code --out out/myrun --forecast
```

The estimate includes first-pass reviews, follow-up investigation, and support
work such as study and checker generation. Prior project results can improve
the estimate; unfamiliar projects have wider uncertainty. Follow-up work can
cost more than the initial reviews.

A forecast does not cap spending. Set `--max-cost` to enforce a budget. At run
completion, the report compares the forecast with recorded spend; detailed
costs are saved in `cost-breakdown.json`.


## Running long audits

Launch long audits from the main session or a terminal that can remain alive.
Claude Code subagent background shells have a time cap, commonly one hour.
Raise `CLAUDE_SUBAGENT_BG_SHELL_MAX_MS` before launching the harness if needed.

When RAPTOR detects that cap and no explicit `--max-time` is set, it reserves
time to save results before the shell is stopped. `--no-supervisor-bound`
disables that automatic time limit. A completed bounded run may still have
coverage gaps; start a new run to continue those gaps.

A first SIGTERM requests a graceful interruption and saves resumable state.
A second requests immediate exit after a best-effort save. Allow cleanup to
finish before restarting.

Watch progress without interrupting the run:

```bash
libexec/raptor-run-status <run-dir>
```

The status view shows heartbeat age, spend, and recent activity. Use
`--project [name]` to view a project's runs together.

### Resuming an interrupted run

Resume an interrupted run from its output directory:

```bash
libexec/raptor-audit resume "$OUTPUT_DIR"
```

Previously recorded decisions are checked against the target, remaining gaps
are recomputed, and the report combines all resumed segments. Booked spend
still counts against the original cost cap. Use `resume --help` for per-segment
budget overrides.

Changed source blocks resume by default. `--allow-drift` permits continuation
and re-reviews affected functions. Completed runs require a new audit rather
than resume; prior eligible verdicts can be reused there.

Only one audit may write a run directory at a time. If another worker is still
active, wait for it to finish. Unverifiable or invalid lock state is reported
with recovery guidance; do not remove a live run's lock.

## Post-run Workflows

### Feedback loop

After `/validate` completes, import its results:

```bash
libexec/raptor-audit feedback --validation-report <dir>/findings.json \
    --annotations-dir "$OUTPUT_DIR/annotations" --audit-out "$OUTPUT_DIR"
```

Feedback appends corrections to the review journal while preserving earlier
entries. Supported human review notes can prevent automated feedback from
overriding a function's assessment.

A model-only disagreement cannot fully dismiss a tool-evidenced finding.
Without an appropriate mechanical disproof, the issue stays unresolved and is
flagged for re-review. Inspect the updated journal and supporting evidence.

### Witness-backlog drain

Hypotheses that available tools could not adjudicate can remain in
`witness-backlog.json`. The backlog commands attempt static checker generation
for those concerns without executing target witnesses.

```bash
libexec/raptor-audit backlog list --out "$OUTPUT_DIR"
libexec/raptor-audit backlog drain --out "$OUTPUT_DIR" \
    --target "$TARGET_PATH" --budget 5.00
```

`list` shows the ranked queue without LLM spend. `drain` requires a positive
USD budget and runs after the audit worker has stopped. Unanswered study
questions can delay attempts until the relevant contract is better understood.

A checker must pass its controls and produce a recorded tool result before a
row leaves the backlog. That result supplies evidence for review rather than
automatically confirming a vulnerability or completing function coverage.
Failed or refused attempts remain visible in `drain-report.json`; repeated
failures eventually stay parked. Use command help for sampling and study-ledger
options.

### Staleness check

After source code changes:

```bash
libexec/raptor-audit stale --annotations-dir "$OUTPUT_DIR/annotations" \
    --target "$TARGET_PATH"
```

### Critique

Identify tool coverage gaps:

```bash
libexec/raptor-audit critique --out "$OUTPUT_DIR"
```

Reports functions with low sweep coverage, confirmed findings without
codebase-wide rules, and suspicious functions with untried tool types.

### Review

Query audit state across all four layers:

```text
/review <file> [function]      # unified per-function view
/review findings               # all findings across runs
/review gaps                   # what needs review
/review coverage               # tool coverage
/review stats                  # entry counts, costs, coverage %
```


## Output

The output directory contains the reports below. Use `/review` for a
per-function view and the post-run commands above to investigate unresolved
concerns or incomplete coverage.

| File | Contents |
|------|----------|
| `audit-report.json` | Run summary, coverage, and costs |
| `findings.json` | Findings for review and `/validate` |
| `review-journal.jsonl` | Per-function decisions, hypotheses, tools, and costs |
| `gaps.json` | Functions selected for review in this run |
| `.audit-log.jsonl` | Detailed event trail; large logs may have numbered sibling files |
| `suppressions.jsonl` | Recorded suppression and skip decisions |
| `annotations/<source_path>.md` | Human-written review notes |
| `cost-breakdown.json` | Recorded spend by phase |
| `forecast.json` | Estimated cost band |
| `llm-telemetry.jsonl` | Per-call LLM usage and costs |
| `prep-profile.json` | Preparation timings and errors |


## Integration

### /understand → /audit

`/audit` requires `context-map.json` from `/understand --map`.  If
missing, it runs the map automatically.  The context map provides
entry points, sinks, and trust boundaries that drive priority ordering.

### Hypothesis seeds

Use `--hypothesis-seeds <file>` to provide candidate claims from another
analysis. The flag is repeatable, and a `sibling-hypotheses.json` file in the
output directory is picked up automatically. Seeds direct attention; every
claim still needs review and appropriate verification.

By default, seeds apply to functions with remaining coverage gaps. Add
`--seed-rereview` to request fresh reviews of already-covered functions. Those
reviews consume the normal budget and can displace never-reviewed functions
from a bounded run. Each seed requests at most one fresh review per audit,
including resumed segments. Seeds for unknown functions are reported as misses.

Binary audits automatically use available sibling-consistency analysis for the
same binary build. If compatible analysis is unavailable or the pass fails,
the report records why it was skipped. Use `--no-auto-siblings` to opt out.


### Token-enforcement map

For supported PHP targets, study can map entry points to known CSRF or nonce
checks. The map distinguishes direct or indirect calls, missing checks, and
unknown coverage. A recorded call does not prove that every path enforces the
check; review the source before relying on it.

```bash
libexec/raptor-audit token-map project --out <run-dir> --target <src>
libexec/raptor-audit token-map drift --prior <run-A> --current <run-B>
libexec/raptor-audit token-map sweep --out <run-dir> [--finding-id F-7]
```

`drift` compares runs. `sweep` produces hypothesis seeds for related entry
points after a token-related finding; the seeds still require review.


### /agentic → /audit

`/agentic --gap-audit` reviews functions left uncovered after scan-result
analysis. Analyzing an individual scanner finding does not count as reviewing
the whole function; earlier claims become context for a fresh audit review.

The post-pass uses the parent's checklist, CodeQL databases, and selected
models. `--gap-audit-share` reserves part of the parent budget for the audit
(default: 0.35). Results appear in the parent report's **Gap Audit Post-Pass**
section.

When the parent runs validation, audit findings join that selection. If a gap
audit is interrupted and resumed separately, follow the deferred validation
and feedback steps printed at completion; see
[Resuming an interrupted run](#resuming-an-interrupted-run).

### /audit → /validate

Findings are written in standard format.  `/validate` runs automatically
as a post-pass (unless `--no-validate`), filtering out false positives
by tracing reachability through the full Stage A--F pipeline.

### /audit → /review

`/review` reads the review journal, coverage store, context map, and
annotations to present a unified per-function view.

### Coverage accumulation

Coverage records persist across runs.  Each run reviews only the
remaining gaps, so successive runs progressively cover the codebase.
Scoped runs (`--scope <dir>`) write to the same project-level output
directory, so they accumulate into one audit trail.  In project mode,
`libexec/raptor-coverage-summary` shows the accumulation as a
`Progress:` trend line (reviewed counts per completed run).

### Target integer ABI

Source-directory integer checks default to the analysis host's C integer
layout. This is an assumption about the target's platform. Override it when
the deployment layout is known:

```bash
libexec/raptor-audit run /path/to/code --integer-abi lp64
```

Use `--integer-abi unknown` to leave layout-dependent checks inconclusive.
Supported binary-file targets derive their standard integer layout from the
binary platform instead of the analysis host. Unsupported or ambiguous binary
platforms remain unknown. Binary headers do not establish arbitrary
compiler-specific settings.

Logs and saved run configuration identify the selected layout and its origin.
Resume retains that selection, including when moved to a different host.

### Verification limits

A solver witness establishes a result only for the model it checked. Source
checks must also bind that model to the relevant declarations, access, guards,
and integer layout. Supplied or inferred arithmetic models alone do not prove
an application bug or refute a source claim.

Source-bound checks support a limited set of builtin integer and local-array
operations. Unsupported types, conversions, mutation, or control flow remain
inconclusive. A function-entry witness does not by itself establish application
reachability or satisfy a caller's contract. Inspect the recorded assumptions
and use independent verification where necessary.
