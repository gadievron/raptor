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
[understand](commands.md#understand) |
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
| `--strategy <name>` | Filter to one strategy: general, input_handling, concurrency, memory, auth, crypto, aliasing, integer |
| `--budget <N>` | Maximum functions to review (default: all gaps) |
| `--scope <dir>` | Restrict to a subdirectory (repeatable; successive scoped runs accumulate) |
| `--pin <file:function>` | Guarantee a review slot for this function ahead of the `--budget` cut (repeatable) |
| `--scope-floor` / `--no-scope-floor` | Every in-scope file keeps at least one review slot under `--budget` (default: on) |
| `--pre-scan` | Bounded Semgrep baseline when the run has no scan SARIF (feeds the SARIF-corroboration channels) |
| `--out <dir>` | Output directory |
| `--codeql-db <path>` | CodeQL database for query dispatch and pre-sweep (repeatable — one per language; dispatch routes by file language) |
| `--max-cost <USD>` | Stop after spending this many dollars on LLM calls. Also accepted by `resume` for a single segment (overrides the original cap; booked spend from prior segments still counts against it; `0` removes the cap) |
| `--deepen-reserve <fraction>` | Slice of `--max-cost` held back for the deepen phase so announced re-reviews can execute (default 0.15; 0 disables) |
| `--max-time <seconds>` | Wall-clock time limit |
| `--no-supervisor-bound` | Do not default a wall budget under a capped Claude subagent shell (see [Running long audits](#running-long-audits)) |
| `--review-passes <N>` | Independent review passes per function for self-consistency (default: 1) |
| `--max-workers <N>` | Concurrent review workers (1-32; values above the cap are clamped). Overrides the transport-derived default — the operator owns the rate-limit consequences (the adaptive throttle still backs off on 429s). Also accepted by `resume` for a single segment. Without the flag, the auto default is account-posture-aware: `tuning.json`'s `llm_account_posture` selects the fair-share (`shared`, default) or solo ceiling, and startup prints the posture plus a sibling-run observation (live LLM-consuming runs seen in the session run ledger) — a banner heuristic, never a gate |
| `--subsystem-depth <N>` | Directory grouping depth for subsystem-ordered review (default: 0) |
| `--max-propagation-depth <N>` | Override adaptive constraint propagation depth (default: auto-calibrated p90+2, floor 5, cap 15) |
| `--model <name>` | Model ID (repeatable for multi-model consensus) |
| `--adversarial` | Adversarial reviewer that challenges positive verdicts (requires `--model` x2+) |
| `--rank-gaps` | LLM re-rank of the gap-queue head, strictly within priority tiers, before pins and the budget cut. Ordering only — never drops a gap; spend lands on the `--max-cost` ledger; the order is deterministic across resume segments |
| `--edges` | Cross-function edge obligations (beta): tier-1 boundary edges reviewed as dedicated contract units before the function loop; tier-2 on-path edges folded into caller reviews as `edge_verdicts` — contract review of aliasing/ownership classes needs a populated domain model (study pass or seeded concepts); its absence is stated as a degradation in the report |
| `--no-validate` | Skip the /validate post-pass |
| `--include-kinds <list>` | Item kinds beyond functions/methods (default: `top_level`, `macro`, `global`). Positive list overrides the defaults; `-kind` opts one out; `none` restricts to functions/methods |
| `--batch-sloc-threshold <N>` | Batch functions at or under this SLOC per file into combined reviews (default: 15; 0 disables) |
| `--no-verdict-reuse` | Disable cross-run verdict reuse (importing prior-run journal verdicts for unchanged functions) |
| `--schedule {cost,priority}` | Parallel review ordering: `cost` packs predicted-longest reviews first, `priority` reviews most promising first |
| `--prior-journal <run-dir>` | Run dir whose review journal feeds prior finding-grade claims into review context (repeatable; used by `/agentic --gap-audit`) |
| `--prior-claims <N>` | Max prior finding-grade claims injected per function (default 3; 0 disables) |
| `--hypothesis-seeds <file>` | `sibling-hypotheses.json` seed file (repeatable); a co-located file in the output dir is picked up automatically — see [Hypothesis seeds](#hypothesis-seeds) |
| `--seed-rereview` | Schedule a fresh review for seeds resolving to already-covered checklist functions (default off: such seeds record as `no_matching_gap` misses) — see [Hypothesis seeds](#hypothesis-seeds) |
| `--dynamic` / `--no-dynamic` | Enable/disable dynamic validation (Frida observation / target execution) for confirmed findings |
| `--binary <path>` / `--binary-auto` / `--no-binary-oracle` | Binary-oracle reachability enrichment of the inventory |
| `--no-vendored-triage` | Disable the vendored/generated-code triage tier (corroborated generated files → skip tier, uncorroborated banners / vendored paths / generated-shape structure → glance tier; every decision leaves a `suppressions.jsonl` record and the run summary counts them) |
| `--no-auto-siblings` | Binary targets only: skip the automatic sibling-consistency pass (default: on for binary targets; source targets never run it) — see [Hypothesis seeds](#hypothesis-seeds). Also accepted by `resume` for a single segment |
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

This achieves substantially higher precision than self-critique loops:
LLM self-refinement without tool feedback is known to *increase* false
positives, which is why gate G3 below prohibits it.

The refutation direction is guarded the same way.  A reviewer cannot
talk a mechanical detection away: when a detector receipt (for example
an uninitialised-return or scatterlist-undersize receipt) stands
against an unverified dismissal, the dismissal is floored back to
`suspicious` unless the refuting fact itself carries proof grade --
verdicts record whether the refuter was a proof or a heuristic, and a
proof-grade override is only accepted once its record lands in
`suppressions.jsonl`.  The same fence holds across ensemble merges: a
standing receipt survives a merge-level demotion to clean (Phase 2)
unless a recorded proof-grade dominance row lifts it.

Some dismissals can be discharged mechanically instead: trust-gated
witnesses (Go internal-concurrency, C caller-held-lock, C lifetime,
and the definite-assignment prover) corroborate a reviewer's dismissal
of race/lifetime/uninitialised-value claims.  These witnesses only arm
when the operator has asserted repo trust -- the project's `config`
trust marker, the `--trust-repo` umbrella (see the trust-marker table
in [commands.md](commands.md#project)).  There is no per-run audit
flag for this: the marker is the control, and the usual trust banner
prints when it affects a run.  Every witness discharge is
accept-with-record -- the row must land in `suppressions.jsonl`
(`dropped: false`) or the discharge is refused and the floor stands.
Binary checklist items additionally journal which refutation gates
could not run on them, so "no refutation" is distinguishable from
"gate never ran".

Binary items get one refutation gate of their own: the disassembly
cross-check (`disasm_xcheck`).  Decompilation can silently drop a
call argument or misrender register liveness, and a review grounded
in that pseudo-C then asserts a mechanism the machine code
contradicts.  When a binary item's suspicious/finding-tier claim
cites an argument-count, register-liveness, sibling-differential
("no count argument, unlike sibling calls that pass one"), or
operand-width fact (a bounded keyword+structure match, never free
LLM classification — the claim is read from the hypothesis, the
hypothesis list, or the verdict body), the gate disassembles a
bounded window around the relevant call site(s) — sandboxed, like
every other parser of target-derived bytes — and runs mechanical
predicates against the decoded instructions.  Checklist and
re-database addresses are corrected for the RE tool's load bias
(Ghidra rebases position-independent ELFs), so the decoded window is
the claimed function, never a lookalike at the wrong address.

Demotion requires refute-grade evidence at every examined call site:
an unconditional 32/64-bit register write that provably reaches the
call within the window (branch-free, or dominating from the
function's straight-line entry region — and only when the call is
itself reachable from the entry; an entry region that returns or
jumps past the call dominates nothing).  Conditional moves, 8/16-bit
alias writes, and writes a jump can bypass never demote — they only
withhold corroboration.  Sibling-differential demotion additionally
requires the callee's FULL attributable caller population sampled
cleanly (a partial sample is decoy-steerable) and a shared register
set with signal beyond the near-universal first two argument
registers.  A load bias guessed from the tool's naming convention
(rather than measured from the re-database's segment table) can
corroborate but never demote.  Operand-width claims never demote at all: a
wide compare beside a narrow one is the classic
truncated-length-check TRUE-finding shape, so width evidence only
corroborates or stays inconclusive.  Consistent evidence attaches a
corroboration receipt without changing anything; an unresolvable
window, an unmatched claimed callee, or a below-grade write records
an honest inconclusive with its reason.  The gate never promotes,
and its per-outcome tallies appear in the run's mechanical tier
effectiveness table under `disasm_xcheck`.  Receipts land in the
audit log (`action: disasm_xcheck`) with the excerpt escaped and
bounded.  Only x86-64 ELF binaries are decoded today; other
architectures record `arch-unsupported`.

Binary targets get two decompiler Semgrep passes.  Per hypothesis,
the tool chain runs curated decompiler-tolerant rules
(`core/audit/rules/decompiler/`) over the reviewed function's
decompilation.  Post-loop, the same corpus -- plus any curated rule
opted in with a `# raptor: decomp-safe` header marker -- runs over
the WHOLE decomp-tree (built from the run's RE database when absent;
a binary run that cannot sweep records a loud skip in
`decomp-sweep.json`, never a silent no-sweep).  Decomp-trees are
attacker-shaped pseudo-C regardless of living in the run directory,
so these scans run sandboxed like every other parser of
target-derived bytes.  Matches map back through the tree's
`decomp-map.json` sidecar to `function @ address` (+ normalized fid)
and land in the journal as `[mechanical]` rows at `suspicious` --
detection-tier leads capped at the decompiled-evidence confidence
ceiling (`traced`), never promotions.  The report's sweep-coverage
line cites the tree's parse-conformance metric
(`decomp-tree-conformance.json`) as its denominator; unmapped
matches are counted and recorded.


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
| **SMT** | Arithmetic/bounds/path feasibility.  A solver or detector model-miss reads as inconclusive, never a refutation | "Integer overflow when `len * size > UINT32_MAX`" |
| **Dark verify** | Witness execution for tool-blind findings: the LLM supplies a structured witness (function, args, expected result), the harness generates and runs the test mechanically -- the LLM cannot fake a pass.  Eligible CWE classes: 287/862/863/134/190/416/457.  Verdicts land as `dark_verify:confirmed` / `dark_verify:refuted` evidence | "Calling `check_token('')` returns True -- the witness confirms the auth bypass" |
| **Joern** | Complex dataflow, indirect calls; guard-dominance and flow-reachability channels | "Callback registered at A reaches sink at B" |
| **Compiler analyzers** | Mechanical verification sweep (gcc `-fanalyzer` / clang `--analyze`) over hypothesis TUs | "Analyzer confirms the null-deref path the hypothesis names" |
| **Expanded-view Semgrep** | Re-runs rules over fidelity-3 preprocessor-expanded views of macro-heavy C/C++ | "Sink hidden behind a macro expansion" |
| **Git history** | Corroboration only -- prior security fixes touching the function (never a verdict by itself) | "This function was patched for the same bug class before" |
| **Fail-open channel** | Swallowed-error hypotheses (CWE-703/636/391/390/252/345): does a permissive error handler let a security decision proceed?  Language legs for Python, C, Java, Go, JS/TS, and Rust handler shapes (Rust `unwrap`/`expect`/`?` count as fail-closed).  A prep-phase census seeds leads the reviewer must discharge; legs without a parser report `language-unsupported` rather than guess | "The broad `except` around token verification swallows signature errors and the request proceeds" |
| **Consistency channel** | Peer-majority deviations: how do this function's peers treat the same return value, flag, or error path?  Registry-grade contract witnesses (e.g. `warn_unused_result`) are promote-capable LLM-free findings (`consistency:<dimension>`); majority-only statistics are detection-grade (`consistency:<dimension>-majority`) and never promote alone | "9/10 call sites check `do_auth()`'s return and it is declared `warn_unused_result`; this site discards it" |
| **API-boundary channel** | Caller-contract hypotheses about exported functions (`api_boundary:caller-contract`): every in-repo call site guarded = refuted; a concrete unguarded call site = confirmed; external-only callers = inconclusive | "Every caller of `resolve_path()` must reject `..` first; `handle_upload()` doesn't" |
| **SMT invariant channel** | Invariant-preservation checks (`smt:invariant-preservation`): can any mutation path leave the stated invariant false?  Degrades gracefully without z3 | "`buf_len <= buf_cap` survives every append path except the realloc-failure branch" |
| **Symbolic channel (binary targets)** | angr witness synthesis (`symbolic-pc-hijack` / `symbolic-reach`): solves for a concrete stdin input reaching the reviewed function — memory-corruption CWEs get the control-flow-hijack solve; the witness is stored and, when dynamic validation is authorised, replayed in a sandbox. No witness within budget is `inconclusive`, never a refutation. Degrades gracefully without angr | "256-byte stdin witness reaches the parser at `0x4011a1`; replay crashed with SIGSEGV" |
| **Ptr-lifecycle channel** | Stale-alias hypotheses (CWE-825/672/416) adjudicated on the field-access census (`ptr_lifecycle:stale-alias`; naming-only vocabulary downgrades to a `-naming` detection variant) | "`c->cached` aliases `b->pool`; the error path frees `b` without invalidating the alias and the accessor still returns it" |
| **Lock-region channel** | Callback invoked while a lock is held (CWE-833/667) (`lock_region:callback-under-lock`).  Confirmations cap at `suspicious` unless the region is entry-reachable and the callback setter is exported API | "`ctx->remove_cb(...)` fires inside the `CRYPTO_THREAD_write_lock` region and the setter is exported API" |
| **Resource-bounds channel** | Unbounded-accumulation hypotheses (CWE-770/400/772): insert/alloc in a loop with no bound check locally or in nearby callers (`resource_bounds:unbounded-accumulation`; seed-only vocabulary = `-naming` detection variant) | "Each accepted connection is appended to `incoming_channel_list`; no cap in the function or its callers" |
| **Release-order channel** | Release-before-verify hypotheses (CWE-354/347, the EFAIL class): data handed to an escaping destination before the integrity finalizer's status is consulted (`release_order:*`) | "The loop `BIO_write`s each decrypted chunk to `out`; `BIO_get_cipher_status` is consulted only at end-of-stream" |
| **Protocol-state channel** | Protocol-invariant hypotheses (CWE-372): promote-capable (`protocol_state:invariant-violated`) only when the invariant premise is study-receipted and SMT finds a violating write site; LLM-stated premises stay detection-grade | "`largest_acked_pkt` is set from the decoded ACK with no guard referencing `highest_sent`" |
| **Sanitizer witness (sanwit, PHP)** | Sanitizer-sufficiency hypotheses (CWE-78/77/88/79/116 with a named sanitizer): the EXACT sanitizer chain is extracted from the function (refusing whenever a pure straight-line chain cannot be isolated), executed in a sandboxed PHP interpreter against the sink context's breakout-payload corpus, and adjudicated by the context's mechanical predicate.  `sanwit:insufficient:<context>` carries the payload + observed output and is detection-grade (aggregates, never convicts alone); `sanwit:sufficient:<context>` is corpus-bounded and context-scoped — it steers, never resolves clean | "`escapeshellcmd` does not quote argument boundaries — the executed chain passes `x --flag` through as two argv words" |

### SMT verbs

| Verb | CWE | What it checks |
|------|-----|----------------|
| `check-overflow` | CWE-190 | Integer overflow in arithmetic expressions |
| `check-oob` | CWE-125/787 | Out-of-bounds access given buffer size and index |
| `check-null-deref` | CWE-476 | Null dereference reachability |
| `check-overflow-to-oob` | CWE-680 | Overflow feeding a buffer index |
| `check-negative-bypass` | CWE-839 | Signed comparison bypass with negative values |
| `check-encoding-residual` | CWE-116 | Encoder completeness: can a target-grammar forbidden byte survive the emitter's supplied transfer semantics unescaped |
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
| Parser-API pack | `core/function_taxonomy/data/packs/parser_apis.json` (seed set + CVE-harvested names; refresh with `core/dataflow/scripts/parser-pack-harvest`) | Function taxonomy (`PARSER_FUNCS`), binary-analysis surface classification, Frida hooks |
| Crypto API packs | `engine/coccinelle/source_intel/crypto/packs/` (`openssl.json`, `kernel-crypto.json`, `libsodium.json`) | The `crypto_calls` Coccinelle rule and `/understand --map`'s crypto inventory |

Adding a library is a data change: drop a new JSON pack in the family's
directory.  Each pack directory carries (or points at) its schema
documentation.  Malformed packs are skipped with a warning -- checkers
then run on seeds + learned vocabulary alone.


## Running long audits

Long audit runs can outlive the environment that launched them.  The
one supervisor RAPTOR detects and defends against automatically is the
Claude Code **subagent** background-shell cap
(`CLAUDE_SUBAGENT_BG_SHELL_MAX_MS`, harness default 1 hour): a shell
backgrounded inside a subagent is killed at the cap regardless of what
it is doing, with a `[killed]` marker in the task output.  Main-thread
background shells are uncapped.

In order of preference when a run may exceed an hour:

1. **Launch from the main thread**, not from a subagent.
2. **Raise the cap**: export a larger `CLAUDE_SUBAGENT_BG_SHELL_MAX_MS`
   before launching the harness.
3. **Let self-bounding handle it** (the default): when the run detects
   it is under a capped subagent shell and no explicit `--max-time` is
   set, it defaults its wall budget to the cap minus a 300 s drain
   margin and concludes **gracefully** inside it — in-flight reviews
   harvested, journal and report written, lifecycle `completed` with a
   note stating how many gaps remain.  Continue in a new run: cross-run
   verdict reuse imports the completed verdicts at $0 and reviews only
   the remainder.  `--no-supervisor-bound` opts out; misdetection is
   safe in both directions (a false positive self-bounds gracefully; a
   false negative dies at the cap and `resume` recovers it).

When a supervisor stops the run with SIGTERM, the first TERM concludes
the run in bounded time (in-flight completions harvested, everything
flushed, report written, lifecycle `interrupted` with a resume hint,
exit 130); a second TERM exits immediately after a best-effort flush.

**Watching a run:** `libexec/raptor-run-status <run-dir>` is the
read-only live view — status, heartbeat age, booked spend vs the
run's cap, LLM call / failed-attempt / breaker counts, and the newest
call class as a phase hint.  `--project [name]` shows every run of a
project at once.  It only reads existing artifacts, so it is safe
against an in-flight run.

### Resuming an interrupted run

An audit stopped by an external supervisor (harness shell cap, SIGTERM,
SIGKILL, OOM) leaves coherent artifacts and can be re-entered **as the
same run**:

```bash
libexec/raptor-audit resume "$OUTPUT_DIR" [--allow-drift] [--max-time <s>] [--max-cost <usd>] [--no-supervisor-bound]
```

Prior verdicts are re-imported at $0 (hash-verified), the remaining
gaps are recomputed against the original checklist/scope/pins, the
remaining budget is the original cap minus booked spend (or a
per-segment `--max-cost` override minus booked spend; `0` removes
the cap for that segment), and one final
report covers all segments (segment provenance noted in the report and
run metadata).

Guards: a **completed** run is refused — continue those in a new run
(cross-run verdict reuse imports the verdicts at $0); a run whose
recorded worker is still alive is refused (it is actually in flight);
and the **staleness gate** re-verifies every hashed journal verdict
against the target tree — any drift refuses the resume with the drifted
functions named, or `--allow-drift` proceeds and re-reviews those
functions instead of reusing them.

Mutual exclusion: `run` and `resume` take an exclusive,
orchestrator-lifetime lock on the run directory (`.audit-run.lock`) at
startup. A second `run`/`resume` against a directory whose orchestrator
is still alive — including one draining after SIGTERM, which keeps the
lock through salvage until the process actually exits — refuses with a
non-zero exit, naming the holder pid and start time. If verification
shows the named pid is not an audit orchestrator working that directory
(a forged or wrong stamp), delete the lock file and retry — but only
after verifying: removing the file under a genuinely live holder splits
lockers across two inodes. A crashed holder's
stale lock is reclaimed automatically when its stamped identity is
provably dead (pid gone, recycled pid, or a prior boot of this
machine); a holder whose liveness cannot be verified fails closed with
the manual remedy named; a lock path occupied by a symlink, directory,
or other non-regular artifact refuses outright until the planted
artifact is removed. Read-only consumers (`report`, `/review`,
coverage readers) and the lifecycle stubs never take the lock.

## Post-run Workflows

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
annotations (`source=human` with a corroborated interactive-TTY provenance
stamp, or legacy pre-stamp notes) veto feedback for their function
entirely; agent notes and human claims stamped non-interactive — or
interactive but uncorroborated (a pty wrapper makes `isatty` true by
design, so readers also check the recorded session-leader shape,
environment markers, and parent chain) — only serve as the prior claim
when no journal entry exists.

Downgrades are refereed: a `ruled_out` may take a **tool-evidenced**
finding to `clean` only when the ruling carries a mechanical
disqualifier — dark-verify witness refutation (`witness_refuted`), an
IRIS Tier-1 CodeQL refutation (`disproven.json`), the Stage-B SMT sweep
proving every linked attack path infeasible, or a Stage-C sanity failure
corroborated by a structural fact (Coccinelle `function_exists=False` /
checklist miss).  An LLM-only ruling demotes a tool-evidenced `finding`
to `suspicious` (evidence preserved, flagged for re-review) and leaves a
tool-evidenced `suspicious` unchanged; findings whose prior verdict had
no tool receipt keep the historical clean downgrade.  The audit-log
`feedback` event records the referee outcome (`referee: <disqualifier>`
or `referee: llm_only_ruling`), and referee-blocked disprovals are
excluded from the model scorecard (an LLM-vs-LLM disagreement is not
ground truth).  This mirrors G2 in the demotion direction: tool output
is the verdict; LLM-only signals neither promote nor fully demote.

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
| `suppressions.jsonl` | Decision audit trail: oracle-earned skips, vendored/generated skip/glance routings, plus the refutation lattice's record-or-refuse rows — witness discharges, proof-grade receipt-floor overrides, and merge-fence holds, all `dropped: false` (same record shape as `/agentic`/`/codeql`) |
| `tier-diagnostics.json` | Per-channel outcome counters (prefilter, semgrep, smt, fail_open, consistency, ...) |
| `decomp-sweep.json` | Binary targets: tree-wide decompiler Semgrep sweep record — rules run/errored, per-finding records (fid + address join, `traced`-capped, `decompiled-evidence`-tagged), unmapped matches, or the loud-skip reason |
| `decomp-tree/decomp-tree-conformance.json` | Binary targets: per-tool parse conformance of the decomp-tree (sandboxed tree-sitter + semgrep probe legs, conservative `parsed_rate`, quarantine list) — the sweep-coverage denominator |
| `fuzz-dict.json` / `fuzz.dict` | Fuzz handoff: dictionary tokens mined from constants, parse-shape literals, and dispatch keys; `fuzz.dict` is AFL format and is auto-discovered by [/fuzz](fuzzing.md#dictionary-auto-discovery) |
| `cost-breakdown.json` | Per-phase cost ledger reconciliation (completed + failed-attempt + unattributed spend always sum to the authoritative total; the pre-loop summary pass books as the `summary` phase) |
| `llm-telemetry.jsonl` | Per-call LLM telemetry |
| `promotion-alarms.jsonl` | Promotion-without-tool-evidence alarms — a `finding` that reached the journal or export without qualifying tool evidence. Empty on every legitimate run; any record means the mechanical-verdict gate was bypassed (possible injection or policy bug). The gate also enforces: a violating `finding` is demoted to `suspicious` before it ships, and the record is the alarm trail |
| `audit-report.json` | Summary report |


## Integration

### /understand → /audit

`/audit` requires `context-map.json` from `/understand --map`.  If
missing, it runs the map automatically.  The context map provides
entry points, sinks, and trust boundaries that drive priority ordering.

### Hypothesis seeds

External producers (sibling-consistency analysis, contract checkers)
can hand the audit hypothesis seeds: a `sibling-hypotheses.json` file
of per-function records — `file` (source path, or the `binary:<stem>`
sentinel plus `address` for binary functions), optional `fid`, a
`claim`, evidence references (`{artifact, pointer}`), an
`evidence_tier` (a `core.evidence` value spelling), a `disproof`
recipe, and `derived_from_target` flags on the text fields.  A
co-located file in the run's output directory is discovered
automatically; `--hypothesis-seeds <file>` (repeatable) names others,
and the flag is persisted so `resume` segments see the same seeds.

**Auto-siblings (binary targets).** For a binary target the pipeline
runs the sibling-consistency pass itself — no hand-ferrying: when a
mapped sibling run for the same binary exists (discovered through
the shared sibling-run search with a recorded-target gate and a
FAIL-CLOSED build-identity gate — the map manifest's `binary_sha256`
must be present and match the audit target's content hash, so
another binary's, another build's, or an identity-unverifiable map
never seeds the audit), its `sibling-hypotheses.json` is captured
co-located into the audit run dir, where the normal intake ingests
it.  A map run that already holds the artifact (a prior hand-run,
possibly operator-adjudicated) is captured verbatim — the engine is
not re-run over it (receipt provenance `captured_existing`); only a
map with no artifact runs the landed `raptor-binary siblings --auto`
engine (provenance `computed`), inside a bounded worker that
degrades to `engine_timeout` instead of stalling audit start.
Operator `--hypothesis-seeds` files merge through the intake's usual
multi-source path (shared record cap, per-seed source provenance in
the receipt).  A co-located seed file that already exists in the
audit run dir (operator-ferried, or captured by an earlier segment)
is reused — nothing runs.  Every other non-captured outcome degrades
loudly to today's unseeded audit: one warning names the reason, the
`auto-siblings.json` receipt persists it, and the run report carries
an "Auto-siblings pass skipped" section with the manual escape
hatch.  `--no-auto-siblings` (on `run` and `resume`) opts out;
source targets never enter the pass.

Seeds are an attention channel riding two existing seams: matched
gap-queue entries get one bounded priority boost — applied after the
sort that fixes the `--budget` cut, so it moves a matched function
earlier in the review order (and across the folded spec-inference
gate) without displacing any other function out of the run — and the
matched function's review context gains a hint-tier block with the
claim and its disproof recipe, enveloped as untrusted content.
Binary seeds join on the checklist's own address space (the
`binary:<stem>` sentinel plus the address the audit's RE database
recorded) — a producer emitting another tool's base gets loud misses,
not silent wrong-function joins.  The journal entry records which
seeds the reviewer saw (`seed_provenance`), and the intake receipt
(`hypothesis-seed-intake.json`) carries per-source resolved paths and
file hashes plus loaded/matched/missed/conflict/skip counts; seeds
naming unknown functions are recorded misses in `fid-misses.json`
(reason-differentiated: placeholder names and address/name conflicts
are called out as producer errors), never run errors.

Against a fully-covered target the boost has nothing to land on: a
seed naming a function every prior run already reviewed records as a
`no_matching_gap` miss and the audit reviews nothing.  `--seed-rereview`
(on `run` and `resume`; default off — the flag is the operator's
consent to re-open spend on covered code) changes exactly that case:
a seed that resolves to a checklist function which is covered rather
than absent is scheduled for a fresh review — hoisted through the
same mechanism `--pin` uses, ahead of the `--budget` cut, with the
seed's claim and disproof recipe injected at the same review-context
seam as matched-gap seeds.  Note the consented displacement this
implies on a partially-covered target: scheduled re-reviews claim
budget slots first, so never-reviewed gaps can be displaced from a
bounded run (recorded in `not-attempted.json`, like any `--pin`);
the displacement is flag-gated and bounded by the intake's 200-seed
record cap, and excess scheduled items beyond the budget are
themselves cut and recorded.  Verdict reuse never satisfies a
scheduled function (the prior verdicts stay in the journal history;
the fresh verdict appends, its row marked `seed_rereview`), and the
marker also bounds the consent: each seed forces at most ONE fresh
review per run — resume segments count an already-reviewed seed as
`rereview_already_satisfied` instead of re-scheduling it.  The
ledger rows for scheduled seeds carry reason `rereview_scheduled`
with the resolved address, and the intake line reports the extra
buckets.  A seed for a function absent from the checklist entirely
remains a miss, flag or no flag.

What seeds NEVER do: they mint no findings (the Ghidra bookmarks
bridge remains the only pre-identified-finding lane), carry no
verdict weight, and suppress nothing — the LLM still forms and
validates every hypothesis, and tool output is still the verdict.
A junk or hostile seed file degrades to counted skips, never a
failed run.  `--seed-rereview` does not change any of this: seeds
still never mint findings or change verdicts, and scheduled
re-reviews spend inside `--max-cost`/`--budget` like every other
review.

### /agentic → /audit

`/agentic --gap-audit` runs the audit orchestrator over the coverage
residual after the analysis phase, as a sibling audit run.  The
composition is kind-aware: journal entries record their producer, and
only function-grade entries (audit reviews) suppress gaps or qualify
for verdict reuse.  A finding-grade entry (/agentic's analysis of one
scanner finding) never counts as a function review — instead it
reaches the audit reviewer as a prior claim in the context slice
(`--prior-journal`, or the project index for prior runs), framed as a
claim to verify, never a verdict to inherit.  The same semantics apply
whether the audit runs standalone after an agentic run or via the
post-pass flag.

The post-pass inherits the agentic run's checklist, every CodeQL
database the scan phase built (dispatch routes per file language),
binary-oracle inputs, and analysis models (two or more enable
`--adversarial`; `--gap-audit-no-adversarial` suppresses the
auto-enable, and the decision is recorded in the report's phase
block).  With `--validate`, audit findings join the agentic validate
selection and the verdicts feed back through `raptor-audit feedback`.
`--gap-audit-share` reserves a slice of `--max-cost-usd` for the
audit up front (default 0.35).

The agentic report inlines the outcome: its **Gap Audit Post-Pass**
section renders the sibling run's journal-verdict-corrected findings
(severity roll-up plus a capped table with tool evidence and, when
the merged validate pass ran, per-finding validation outcomes).

Because the parent validates the merged findings, the sibling audit
runs with `--no-validate` and stages a `pipeline-tail.json` marker;
`raptor-audit resume` on an interrupted gap audit prints the deferred
`/validate` + `feedback` steps when a resumed segment completes with
findings (see [Resuming an interrupted run](#resuming-an-interrupted-run)).

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
