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
| `--scope <dir>` | Restrict to a subdirectory (repeatable; successive scoped runs accumulate) |
| `--out <dir>` | Output directory |
| `--codeql-db <path>` | CodeQL database for query dispatch and pre-sweep |
| `--max-cost <USD>` | Stop after spending this many dollars on LLM calls |
| `--deepen-reserve <fraction>` | Slice of `--max-cost` held back for the deepen phase so announced re-reviews can execute (default 0.15; 0 disables) |
| `--max-time <seconds>` | Wall-clock time limit |
| `--no-supervisor-bound` | Do not default a wall budget under a capped Claude subagent shell (see [long-runs.md](long-runs.md)) |
| `--review-passes <N>` | Independent review passes per function for self-consistency (default: 1) |
| `--subsystem-depth <N>` | Directory grouping depth for subsystem-ordered review (default: 0) |
| `--max-propagation-depth <N>` | Override adaptive constraint propagation depth (default: auto-calibrated p90+2, floor 5, cap 15) |
| `--model <name>` | Model ID (repeatable for multi-model consensus) |
| `--adversarial` | Adversarial reviewer that challenges positive verdicts (requires `--model` x2+) |
| `--no-validate` | Skip the /validate post-pass |
| `--include-kinds <list>` | Item kinds beyond functions/methods (default: `top_level`, `macro`, `global`). Positive list overrides the defaults; `-kind` opts one out; `none` restricts to functions/methods |
| `--batch-sloc-threshold <N>` | Batch functions at or under this SLOC per file into combined reviews (default: 15; 0 disables) |
| `--no-verdict-reuse` | Disable cross-run verdict reuse (importing prior-run journal verdicts for unchanged functions) |
| `--schedule {cost,priority}` | Parallel review ordering: `cost` packs predicted-longest reviews first, `priority` reviews most promising first |
| `--dynamic` / `--no-dynamic` | Enable/disable dynamic validation (Frida observation / target execution) for confirmed findings |
| `--binary <path>` / `--binary-auto` / `--no-binary-oracle` | Binary-oracle reachability enrichment of the inventory |
| `--annotations-dir <dir>` | Annotations directory (default: project-level `annotations/`, falling back to `<out>/annotations`) |


## Pipeline

```
0. /understand --map  →  context-map.json (entry points, sinks, trust boundaries)
1. Build inventory    →  checklist.json (SHA-256 per file)
2. Compute gaps       →  gaps.json (functions with no coverage)
3. Consistency census pre-pass (once per run)  →  return-census.json;
   registry-grade contract deviations become LLM-free findings
4. Pre-loop LLM summary pass: callee-context summaries for connected but
   unsummarised functions (booked as the `summary` phase in the cost ledger;
   skipped when the run has no LLM budget client)
5. For each gap batch (grouped by directory):
   a. Assemble context slice (source + callers + callees + strategy exemplars)
   b. LLM review: form hypotheses about assumptions and violations
   c. Generate mechanical tests (Semgrep/Coccinelle/CodeQL/SMT rules)
   d. Run tests via tool chain dispatch → evaluate results
   e. Record journal entry (what was tested, tool evidence)
   f. Record status (clean / suspicious / finding / error / dormant)
   g. If pattern has variants: generate codebase-wide checker (Mode 2)
6. Joern CPG builds in background, drains when ready for dataflow re-review
7. Constraint propagation across related functions
8. Sweep validation to confirm tool-backed evidence
9. Tool-grounded critique: identifies gaps, generates additional tool invocations
10. Report: review-journal.jsonl + findings.json + summary
11. /validate post-pass on findings (unless --no-validate)
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

Semgrep, Coccinelle, CodeQL, SMT, and compilation invocations run through
`libexec/raptor-audit sweep` so results are logged to the audit trail
automatically.  Joern, the compiler analyzers, the expanded-view Semgrep
pass, the fail-open channel, the consistency channel, the API-boundary
channel, the SMT invariant channel, the ptr-lifecycle and lock-region
channels, the resource-bounds channel, the release-order channel, the
protocol-state channel, and the git-history oracle run as orchestrator
channels.

| Tool | What it validates | Example use |
|------|-------------------|-------------|
| **Semgrep** | Pattern matching, missing checks | "Return value of `read()` is used without checking for -1" |
| **Coccinelle** | Inconsistency detection, variant sweep; flow-sensitive per-hypothesis rules | "Other call sites check error, this one doesn't" |
| **CodeQL** | Dataflow reachability | "Tainted input reaches `execv()` without sanitisation" |
| **SMT** | Arithmetic/bounds/path feasibility | "Integer overflow when `len * size > UINT32_MAX`" |
| **Joern** | Complex dataflow, indirect calls; guard-dominance and flow-reachability channels | "Callback registered at A reaches sink at B" |
| **Compiler analyzers** | Mechanical verification sweep (gcc `-fanalyzer` / clang `--analyze`) over hypothesis TUs | "Analyzer confirms the null-deref path the hypothesis names" |
| **Expanded-view Semgrep** | Re-runs rules over fidelity-3 preprocessor-expanded views of macro-heavy C/C++ | "Sink hidden behind a macro expansion" |
| **Git history** | Corroboration only -- prior security fixes touching the function (never a verdict by itself) | "This function was patched for the same bug class before" |
| **Fail-open channel** | Swallowed-error hypotheses (CWE-703/636/391/390/252/345, plus CWE-248 routed but never confirmed): security role x permissive handler outcome x fallibility, all mechanical with receipts. Handler shapes: Python broad handlers and suppress blocks; C ignored-return + tri-state; Java catch clauses (empty catch, swallowed checked exceptions via declared-throws or the compilability witness, quiet-log-only); Go discarded errors (blank discard, err never checked, bare calls) and recover-and-continue; JS/TS unawaited promises are phase 3. A prep-phase census seeds `fail_open_leads` onto gaps (hypothesize-or-discharge prompts; undischarged leads journaled), and a confirmed Joern flow from a hypothesis-named parameter to the fallible callee escalates the receipt to `tainted`/`joern:flow` | "The broad `except` around token verification swallows signature errors and the request proceeds" |
| **Consistency channel** | Peer-majority deviations with PeerEvidence receipts: the return-usage census (six-value enum, `return-census.json`), contract witnesses (warn_unused_result, learned contracts, the shared Tier-A registry), flag/mode and error-path-cleanup comparators. Registry-grade contract witness = promote-capable LLM-free finding, stamped `consistency:<dimension>`; majority-only = detection grade, stamped `consistency:<dimension>-majority` and never promotable alone (one shared namespace -- two consistency statistics never self-corroborate to promotion) | "9/10 call sites check `do_auth()`'s return and it is declared `warn_unused_result`; this site discards it" |
| **API-boundary channel** | Caller-contract hypotheses about exported functions, adjudicated mechanically (`api_boundary:caller-contract`): every in-repo call site guarded = refuted; a concrete unguarded call site = confirmed; external-only callers or environment contracts = inconclusive.  Only literal violations confirm | "Every caller of `resolve_path()` must reject `..` first; `handle_upload()` doesn't" |
| **SMT invariant channel** | Invariant-preservation checks (`smt:invariant-preservation`): per mutation site, is `invariant(pre) AND transition AND NOT invariant(post)` satisfiable?  All-unsat = preserved; sat = violable.  Linear integer arithmetic, inductive step only; degrades gracefully without z3 | "`buf_len <= buf_cap` survives every append path except the realloc-failure branch" |
| **Ptr-lifecycle channel** | Stale-alias adjudication on the field-access census (`field-census.json`, CWE-825/672/416): alias edge + lifecycle event + live-alias invalidation search + post-event read, all four receipts (`ptr_lifecycle:stale-alias`; naming-stem event vocabulary or a degraded census = `-naming` detection variant).  The field-assignment-parity leg is a majority statistic and deliberately emits under the consistency namespace (`consistency:field-parity-majority`) so the single-namespace firewall applies to it | "`c->cached` aliases `b->pool`; the error path frees `b` without invalidating the alias and the accessor still returns it" |
| **Lock-region channel** | Callback invoked while a lock is held (CWE-833/667): learned/pack/seed lock pairs x indirect-call or registered-name invocation, with the exported-setter registrability witness (`lock_region:callback-under-lock`; naming-stem pair or internal-only setter = `-naming`).  Confirmations cap at `suspicious` unless entry-reachable AND setter-exported (both escalators); a parametric Coccinelle rule (`callback_under_lock.cocci`, `-D lock -D unlock`) corroborates as an independent namespace | "`ctx->remove_cb(...)` fires inside the `CRYPTO_THREAD_write_lock` region and the setter is exported API" |
| **Resource-bounds channel** | Unbounded-accumulation hypotheses (CWE-770/400/772): insert/alloc-in-loop site with no dominating bound witness (guard comparing a count against a constant/named limit/min-clamp), locally or in a depth-3 caller walk -- the receipt names how far the search went.  Registry vocabulary (learned `collection` pair / pack) AND entry-reachability = promote-capable `resource_bounds:unbounded-accumulation`; seed-only or unknown reachability = `-naming` detection variant | "Each accepted connection is appended to `incoming_channel_list`; no cap in the function or its callers" |
| **Release-order channel** | Release-before-verify hypotheses (CWE-354/347, joining the CWE-345 chain; the EFAIL class): every release site handing data to an escaping destination (out-param/stream/callback) must be dominated by a condition consuming the integrity finalizer's status.  Fresh-call destinations refute as buffered-then-flush; unresolved aliases are `sink-alias-unresolved`; no finalizer vocabulary is `finalizer-unresolved` (unauthenticated pipelines are not claimed).  Optional Joern cross-check: agreement = `engine: cfg+joern`, disagreement = `engines-disagree`.  Learned `verify_release` pair = registry grade; seed-only = `-naming` | "The loop `BIO_write`s each decrypted chunk to `out`; `BIO_get_cipher_status` is consulted only at end-of-stream" |
| **Protocol-state channel** | Protocol-invariant hypotheses (CWE-372; state-field invariants take precedence over the single-function SMT invariant channel and run census-driven multi-site with dominating guards encoded).  Promote-capable `protocol_state:invariant-violated` ONLY when the invariant premise is study-receipted (provenance != `llm_prior` + receipt) AND SMT finds a model at a peer-writable site -- the machine checks consequences, never the premise.  LLM-stated premises confirm under `-unreceipted`; the two lead legs (`dead-state-field`, `unvalidated-peer-write`) are permanently detection-grade and share the channel's single namespace (two of them never self-corroborate to promotion) | "`largest_acked_pkt` is set from the decoded ACK with no guard referencing `highest_sent` -- which is written twice and read never" |

### SMT verbs

| Verb | CWE | What it checks |
|------|-----|----------------|
| `check-overflow` | CWE-190 | Integer overflow in arithmetic expressions |
| `check-oob` | CWE-125/787 | Out-of-bounds access given buffer size and index |
| `check-null-deref` | CWE-476 | Null dereference reachability |
| `check-overflow-to-oob` | CWE-680 | Overflow feeding a buffer index |
| `check-negative-bypass` | CWE-839 | Signed comparison bypass with negative values |
| `validate-path` | Various | Branch condition satisfiability along a dataflow path |


## Gates

Every finding must pass these gates before it can be emitted:

| Gate | Rule |
|------|------|
| **G1 Hypothesis-first** | Every suspicion framed as a testable hypothesis before any finding is emitted |
| **G2 Tool-grounded** | At least one mechanical validation (Semgrep, CodeQL, Coccinelle, SMT, compilation, compiler analyzers, Joern, dark-verify, dynamic, or a mechanical channel receipt: fail-open, registry-grade consistency).  Detection-grade stamps (`consistency:*-majority`) never qualify alone |
| **G3 No self-critique loop** | Iteration without tool feedback is prohibited |
| **G4 Evidence recorded** | Journal entry includes tool names and results |
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
3. Validate the rule with dual control: a positive fixture it must match
   and a negative control it must not (over-broad rules are refuted and
   refined iteratively)
4. Run it across the entire codebase
5. Each match is a new candidate to review

This is the KNighter pattern: one hypothesis → sweep the whole codebase.
Rules are stored in the project's rule library and can be replayed across
runs.


## Vocabulary Packs

The mechanical checkers, the prefilter, and strategy selection draw their
API-name vocabulary from three sources, always unioned additively:
hardcoded seeds < data pack < study-learned domain model.  A pack never
suppresses anything -- it only adds names.  Seed sets are deliberately
tiny (a CI guardrail rejects new literal name lists over nine entries);
growing a vocabulary means teaching the study loop or editing pack data,
never the code.

| Pack family | Location | Consumed by |
|-------------|----------|-------------|
| Checker vocab packs | `core/audit/data/vocab_packs/` (today: `linux_kernel.json` -- allocators, deallocators, lock pairs, callback register/cancel pairs, nullable returns, auth predicates, ...) | SMT condition vocabulary, prefilter, callback-lifetime checker.  Applied when the target is detected as a kernel tree |
| Strategy signal packs | `core/audit/data/strategy_packs/` (today: `linux_kernel.json` -- per-strategy path and source tokens) | Per-function strategy inference |
| Parser-API pack | `core/function_taxonomy/data/packs/parser_apis.json` (seed set + CVE-harvested names; refresh with `libexec/raptor-parser-pack-harvest`) | Function taxonomy (`PARSER_FUNCS`), binary-analysis surface classification, Frida hooks |
| Crypto API packs | `engine/coccinelle/source_intel/crypto/packs/` (`openssl.json`, `kernel-crypto.json`, `libsodium.json`) | The `crypto_calls` Coccinelle rule and `/understand --map`'s crypto inventory |

Adding a library is a data change: drop a new JSON pack in the family's
directory (crypto packs are picked up automatically; a new checker-vocab
target kind additionally needs a `pack_for_target()` branch).  The parser
and crypto pack directories carry a `README.md` documenting their schema;
the audit pack schemas are documented in `core/audit/vocab_packs.py` and
`core/audit/strategy.py`.  Malformed packs are skipped with a warning --
checkers then run on seeds + learned vocabulary alone.


## Post-run Workflows

### Resuming an interrupted run

An audit stopped by an external supervisor (harness shell cap, SIGTERM,
SIGKILL, OOM) leaves coherent artifacts and can be re-entered **as the
same run**:

```bash
libexec/raptor-audit resume "$OUTPUT_DIR" [--allow-drift]
```

Prior verdicts are re-imported at $0 (hash-verified), the remaining
gaps are recomputed against the original checklist/scope/pins, the
remaining budget is the original cap minus booked spend, and one final
report covers all segments. Completed runs are refused — continue those
in a new run (cross-run verdict reuse imports the verdicts at $0). See
[long-runs.md](long-runs.md) for the supervisor caps, self-bounding,
and SIGTERM semantics.

### Feedback loop

After `/validate` completes, import results to close the Reflexion loop:

```bash
libexec/raptor-audit feedback --validation-report <dir>/findings.json \
    --annotations-dir "$OUTPUT_DIR/annotations" --audit-out "$OUTPUT_DIR"
```

Corrections are appended as fresh review-journal entries (with the prior
verdict and lesson recorded): disproven findings are downgraded to `clean`,
missed vulnerabilities are upgraded to `finding`, corroborated findings get
a confirmation entry.  Nothing is rewritten in place, and human-grade
annotations (`source=human` with an interactive-TTY provenance stamp, or
legacy pre-stamp notes) veto feedback for their function entirely; agent
notes and human claims stamped non-interactive only serve as the prior
claim when no journal entry exists.

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
| `annotations/<source_path>.md` | Human-written per-function notes (read as review context; never written by the LLM) |
| `findings.json` | Findings in standard format (fed to `/validate`) |
| `gaps.json` | Gap list used for this run |
| `.audit-log.jsonl` | Full audit trail |
| `review-journal.jsonl` | Per-function review decisions (strategies, hypotheses, tools, cost) |
| `return-census.json` | Return-usage census from the consistency pre-pass (six-value usage enum per call site) |
| `field-census.json` | Field-access census from the lifecycle channel pre-pass (per-field write sites with rhs provenance, read sites with use context) |
| `prefilter-kills.jsonl` | One record per prefilter/triage kill (summary row first, then `file`, `function`, `gate`, `reason`, plus spot-audit corroboration fields on sampled rows) |
| `suppressions.jsonl` | Oracle-earned triage-skip audit trail (same record shape as `/agentic`/`/codeql`) |
| `tier-diagnostics.json` | Per-channel outcome counters (prefilter, semgrep, smt, fail_open, consistency, ...) |
| `fuzz-dict.json` / `fuzz.dict` | Fuzz handoff: dictionary tokens mined from constants, parse-shape literals, and dispatch keys; `fuzz.dict` is AFL format and is auto-discovered by [/fuzz](fuzzing.md#dictionary-auto-discovery) |
| `cost-breakdown.json` | Per-phase cost ledger reconciliation (completed + failed-attempt + unattributed spend always sum to the authoritative total; the pre-loop summary pass books as the `summary` phase) |
| `llm-telemetry.jsonl` | Per-call LLM telemetry |
| `promotion-alarms.jsonl` | Promotion-without-tool-evidence alarms — a `finding` that reached the journal or export without qualifying tool evidence. Empty on every legitimate run; any record means the mechanical-verdict gate was bypassed (possible injection or policy bug). Alarm-only, never blocks |
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
