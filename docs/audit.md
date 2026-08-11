# Systematic Code Review

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
[understand](concepts.md#understand) |
[annotations](commands.md#annotate) |
[coverage](commands.md#review)


## Usage

```
/audit <target_path> [flags]
```

Dispatches as a skill (two-phase: `/understand --map` then
`libexec/raptor-audit run`).  See [commands.md](commands.md#audit) for the
full flag table.

```bash
/audit /path/to/code                       # review all gaps
/audit /path/to/code --strategy memory     # focus on memory safety
/audit /path/to/code --scope net/ipv4/     # restrict to a subsystem
/audit /path/to/code --budget 50           # cap at 50 functions
/audit /path/to/code --model claude-opus-4-7 --model gpt-5 --adversarial
```

### Flags

| Flag | Description |
|------|-------------|
| `--strategy <name>` | Filter to one strategy: general, input_handling, concurrency, memory, auth, crypto, aliasing |
| `--budget <N>` | Maximum functions to review (default: all gaps) |
| `--scope <dir>` | Restrict to a subdirectory (successive scoped runs accumulate) |
| `--out <dir>` | Output directory |
| `--codeql-db <path>` | CodeQL database for query dispatch and pre-sweep |
| `--max-cost <USD>` | Stop after spending this many dollars on LLM calls |
| `--max-time <seconds>` | Wall-clock time limit |
| `--review-passes <N>` | Independent review passes per function for self-consistency (default: 1) |
| `--subsystem-depth <N>` | Directory grouping depth for subsystem-ordered review (default: 0) |
| `--max-propagation-depth <N>` | Override adaptive constraint propagation depth (default: auto-calibrated p90+2, floor 5, cap 15) |
| `--model <name>` | Model ID (repeatable for multi-model consensus) |
| `--adversarial` | Adversarial reviewer that challenges positive verdicts (requires `--model` x2+) |
| `--no-validate` | Skip the /validate post-pass |


## Pipeline

```
0. /understand --map  →  context-map.json (entry points, sinks, trust boundaries)
1. Build inventory    →  checklist.json (SHA-256 per file)
2. Compute gaps       →  gaps.json (functions with no coverage)
3. For each gap batch (grouped by directory):
   a. Assemble context slice (source + callers + callees + strategy exemplars)
   b. LLM review: form hypotheses about assumptions and violations
   c. Generate mechanical tests (Semgrep/Coccinelle/CodeQL/SMT rules)
   d. Run tests via tool chain dispatch → evaluate results
   e. Write annotation (what was tested, tool evidence)
   f. Record status (clean / suspicious / finding / error / dormant)
   g. If pattern has variants: generate codebase-wide checker (Mode 2)
4. Joern CPG builds in background, drains when ready for dataflow re-review
5. Constraint propagation across related functions
6. Sweep validation to confirm tool-backed evidence
7. Tool-grounded critique: identifies gaps, generates additional tool invocations
8. Report: coverage-audit.json + findings.json + summary
9. /validate post-pass on findings (unless --no-validate)
```


## Execution Model

The LLM does not directly classify code.  Every suspicious pattern must
go through:

1. **Hypothesis** -- a testable claim.  "If input Y reaches sink Z without
   check W, CWE-N applies."  Not "this looks dangerous."
2. **Mechanical test** -- a Semgrep rule, CodeQL query, Coccinelle patch,
   SMT check, or compilation test.
3. **Verdict** -- tool output confirms or refutes.  If refuted, the
   hypothesis is discarded with no "but I still think..."

This achieves substantially higher precision than self-critique loops.
The IEEE-ISTAS 2025 result: 37.6% MORE false positives after 5 iterations
of LLM self-refinement without tool feedback.  Tool grounding eliminates
the regression.


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

Each strategy includes CVE-backed exemplars showing the hypothesis →
tool → verdict chain that found the bug, injected into the LLM context
alongside the target code.


## Tool Menu

All tool invocations run through `libexec/raptor-audit sweep` so results
are logged to the audit trail automatically.

| Tool | What it validates | Example use |
|------|-------------------|-------------|
| **Semgrep** | Pattern matching, missing checks | "Return value of `read()` is used without checking for -1" |
| **Coccinelle** | Inconsistency detection, variant sweep | "Other call sites check error, this one doesn't" |
| **CodeQL** | Dataflow reachability | "Tainted input reaches `execv()` without sanitisation" |
| **SMT** | Arithmetic/bounds/path feasibility | "Integer overflow when `len * size > UINT32_MAX`" |
| **Joern** | Complex dataflow, indirect calls | "Callback registered at A reaches sink at B" |

### SMT verbs

| Verb | CWE | What it checks |
|------|-----|----------------|
| `check-overflow` | CWE-190 | Integer overflow in arithmetic expressions |
| `check-oob` | CWE-119/122 | Out-of-bounds access given buffer size and index |
| `check-null-deref` | CWE-476 | Null dereference reachability |
| `check-overflow-to-oob` | CWE-190→122 | Overflow feeding a buffer index |
| `check-negative-bypass` | CWE-839 | Signed comparison bypass with negative values |
| `validate-path` | Various | Branch condition satisfiability along a dataflow path |


## Gates

Every finding must pass these gates before it can be emitted:

| Gate | Rule |
|------|------|
| **G1 Hypothesis-first** | Every suspicion framed as a testable hypothesis before any finding is emitted |
| **G2 Tool-grounded** | At least one mechanical validation (Semgrep, CodeQL, Coccinelle, SMT, compilation) |
| **G3 No self-critique loop** | Iteration without tool feedback is prohibited |
| **G4 Evidence in annotation** | Annotation body includes tool names and results |
| **G5 Read-first** | Code read with the Read tool before any hypothesis is formed |
| **G6 Assumption-trust** | For every function, identify what it trusts and what happens when violated |
| **G7 Reachability** | Findings must be reachable -- zero callers AND binary oracle `absent` forces `dormant` |


## Statuses

Each reviewed function gets exactly one status:

| Status | Meaning |
|--------|---------|
| `clean` | Reviewed, no concern found |
| `suspicious` | Concern identified but not tool-confirmed |
| `finding` | Tool-confirmed, reachable vulnerability |
| `dormant` | Real bug but currently unreachable (dead code, no callers) |
| `error` | Review blocked (e.g. parse failure, tool error) |

A `dormant` bug becomes a `finding` when reachability changes.  `dormant`
is not `clean` -- the bug is real, it just can't be triggered today.


## Checker Synthesis (Mode 2)

When a confirmed finding suggests a repeatable pattern, the orchestrator
generates a codebase-wide checker:

1. Abstract the pattern from the specific finding
2. Generate a Semgrep or Coccinelle rule
3. Run it across the entire codebase
4. Each match is a new candidate to review

This is the KNighter pattern: one hypothesis → sweep the whole codebase.
Rules are stored in the project's rule library and can be replayed across
runs.


## Post-run Workflows

### Feedback loop

After `/validate` completes, import results to close the Reflexion loop:

```bash
libexec/raptor-audit feedback --validation-report <dir>/findings.json \
    --annotations-dir "$OUTPUT_DIR/annotations" --audit-out "$OUTPUT_DIR"
```

Disproven findings are downgraded to `clean`; missed vulnerabilities are
upgraded to `finding`; corroborated findings get confirmation appended.
Human annotations (`source=human`) are never modified.

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

```bash
/review <file> [function]      # unified per-function view
/review findings               # all findings across runs
/review gaps                   # what needs review
/review coverage               # tool coverage
/review stats                  # entry counts, costs, coverage %
```


## Output

| File | Contents |
|------|----------|
| `annotations/<source_path>.md` | Per-function review prose with tool evidence |
| `coverage-audit.json` | Per-function status and source hash |
| `findings.json` | Findings in standard format (fed to `/validate`) |
| `gaps.json` | Gap list used for this run |
| `.audit-log.jsonl` | Full audit trail |
| `review-journal.jsonl` | Per-function review decisions (strategies, hypotheses, tools, cost) |
| `audit-report.json` | Summary report |


## Integration

### /understand → /audit

`/audit` requires `context-map.json` from `/understand --map`.  If
missing, it runs the map automatically.  The context map provides
entry points, sinks, and trust boundaries that drive priority ordering.

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
directory, so they accumulate into one audit trail.
