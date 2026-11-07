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

Dispatches as a skill (two-phase: `/understand --map` then
`libexec/raptor-audit run`).  See [commands.md](commands.md#audit) for the
full flag table.

```text
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
| `--forecast` | Print the deepen-aware pre-spend cost forecast band and exit at $0 LLM spend — see [Cost forecasting](#cost-forecasting) |
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
| `--cross-entry {off,index,shadow,context,study}` | C/C++ shared-state analysis (default: `context`): `index` builds a retrieval catalogue; `shadow` writes artifacts only; `context` adds structural evidence to reviews; `study` adds semantic analysis and refutation |
| `--cross-entry-max-files <N>` | Source files per typed context view (default: 200); additional candidate files remain queued |
| `--cross-entry-max-calls <N>` | Study, retrieval, and refutation calls per continuation (default: 8); spend counts against `--max-cost` |
| `--cross-entry-index-batch-files <N>` / `--cross-entry-drain-index` | Indexing quantum (default: 200 files); drain continues indexing until finished or stopped |
| `--cross-entry-max-slices <N>` | Context slices per continuation (default: 40) |
| `--cross-entry-source-chars <N>` / `--cross-entry-input-tokens <N>` | Source and total input limits per study prompt (defaults: 24000 / 12000) |
| `--cross-entry-root <path>` | Larger source root containing the target for shared-state context; report scope stays unchanged |
| `--cross-entry-include-dir <path>` | Header search directory (repeatable; overrides auto-detection). When omitted, ancestor `include/` directories are auto-detected via the same heuristic the compiler sweep uses. Follows referenced headers within the source budget without expanding report scope or walking the header tree |
| `--edges` | Cross-function edge obligations (beta): tier-1 boundary edges reviewed as dedicated contract units before the function loop; tier-2 on-path edges folded into caller reviews as `edge_verdicts` — contract review of aliasing/ownership classes needs a populated domain model (study pass or seeded concepts); its absence is stated as a degradation in the report |
| `--no-validate` | Skip the /validate post-pass |
| `--include-kinds <list>` | Item kinds beyond functions/methods (default: `top_level`, `macro`, `global`). Positive list overrides the defaults; `-kind` opts one out; `none` restricts to functions/methods |
| `--batch-sloc-threshold <N>` | Batch functions at or under this SLOC per file into combined reviews (default: 15; 0 disables) |
| `--no-verdict-reuse` | Disable cross-run verdict reuse (importing prior-run journal verdicts for unchanged functions; cleans inferred from tool silence are re-reviewed, not imported; see Execution Model) |
| `--schedule {cost,priority}` | Parallel review ordering: `cost` packs predicted-longest reviews first, `priority` reviews most promising first |
| `--prior-journal <run-dir>` | Run dir whose review journal feeds prior finding-grade claims into review context (repeatable; used by `/agentic --gap-audit`) |
| `--prior-claims <N>` | Max prior finding-grade claims injected per function (default 3; 0 disables) |
| `--hypothesis-seeds <file>` | `sibling-hypotheses.json` seed file (repeatable); a co-located file in the output dir is picked up automatically — see [Hypothesis seeds](#hypothesis-seeds) |
| `--seed-rereview` | Schedule a fresh review for seeds resolving to already-covered checklist functions (default off: such seeds record as `no_matching_gap` misses) — see [Hypothesis seeds](#hypothesis-seeds) |
| `--dynamic` / `--no-dynamic` | Enable/disable dynamic validation (Frida observation / target execution) for confirmed findings |
| `--binary <path>` / `--binary-auto` / `--no-binary-oracle` | Binary-oracle reachability enrichment of the inventory |
| `--no-immediate-verify` | Disable inline hypothesis verification (IHV) and use the legacy post-loop sweep pipeline instead (for corpus A/B comparison) |
| `--no-open-discovery` | Disable open discovery (LLM-driven hypothesis generation beyond the checklist — see [Open Discovery](#open-discovery)) |
| `--no-vendored-triage` | Disable the vendored/generated-code triage tier (corroborated generated files → skip tier, uncorroborated banners / vendored paths / generated-shape structure → glance tier; every decision leaves a `suppressions.jsonl` record and the run summary counts them) |
| `--no-auto-siblings` | Binary targets only: skip the automatic sibling-consistency pass (default: on for binary targets; source targets never run it) — see [Hypothesis seeds](#hypothesis-seeds). Also accepted by `resume` for a single segment |
| `--annotations-dir <dir>` | Annotations directory (default: project-level `annotations/`, falling back to `<out>/annotations`) |


Cross-entry analysis supplies context about state established or changed by
other calls, including helpers and repeated calls. Its hypotheses remain
conditional and pass through the existing review and verification gates.
Missing source and budget truncation are recorded in `cross-entry-*.json`
artifacts in the run directory. Detection quality is still being evaluated.
Indexing, candidate studies, retrieval, and refutation resume from durable
checkpoints. `cross-entry-progress.json` distinguishes unfinished indexing,
queued or blocked studies, and results awaiting delivery to review. Prompt
limits can still block oversized evidence; increasing a work quantum alone
does not resolve those blocks. An exhausted queue is not a safety proof.


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
   f. Record status (clean / suspicious / finding / error / dormant / dark)
   g. If pattern has variants: generate codebase-wide checker (Mode 2)
6. Joern CPG builds in background, drains when ready for dataflow re-review
7. Constraint propagation across related functions
8. Cross-outcome promotion passes (preconditions, clean-refuted, hypothesis
   consistency, self-contradiction demotion)
9. Dark verification (witness execution for auth/logic CWEs)
10. Sweep validation to confirm tool-backed evidence
11. Report: review-journal.jsonl + findings.json + summary
12. /validate post-pass on findings (unless --no-validate)
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

A tool's **silence** refutes only when it is admissible: the run
completed probatively (an `inconclusive` outcome — vacuous SAT, a
capped match, an unwitnessed scan, an undecidable invariant, a
hypothesis-keyword rule's zero-match, a curated rule marked
`# raptor: confirm-only` — stays in the dispatch record but is booked
in `tools_inconclusive` and never refutes), the rule can adjudicate the
claim, and the silence covered the function (file-level SARIF presence
and a SARIF result with no placeable line never do).  An evidence-free
claim with no admissible refutation resolves `dark` (exported for
/validate), not `clean`.  A clean inferred from silence (gate
resolution, confidence propagation, the sarif-clean gate) is journaled
with `clean_basis`, is never graded tool-backed, and is re-reviewed
rather than imported by cross-run verdict reuse; a clean journaled
before `clean_basis` existed is re-reviewed when its row shows any
sign of silence derivation or a hidden basis, and otherwise imported at
most once per completed run (it re-journals with basis `unknown`,
which the next run re-reviews).  Known limitation: "once" holds only
after the importing run merges into the project index — a run
interrupted before the merge, a resume of it, or concurrent runs can
each import the same pre-field clean again; every such import still
re-journals `unknown`, so the basis is never laundered.  A clean
minted by the retired review-time rationale-consistency gate (body
`[rationale-consistency demotion:`, journaled `verdict`) is re-reviewed
once in every era; a long body slimmed out of the project index is
read back from its origin run (hash-checked), so the screen misses
such a row when that run's journal is gone, rewritten or compacted
(the read-back no longer matches the index stub), or unreadable.
Cleans minted by the retired race-gate protection step carry no marker
and cannot be told from a model clean, so they are not screened.

The refutation direction is guarded the same way.  A reviewer cannot
talk a mechanical detection away: when a detector receipt (for example
an uninitialised-return or scatterlist-undersize receipt) stands
against an unverified dismissal, the dismissal is floored back to
`suspicious` unless the refuting fact itself carries proof grade --
verdicts record whether the refuter was a proof or a heuristic, and a
proof-grade override is only accepted once its record lands in
`suppressions.jsonl`.

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
| `check-array-bounds` | CWE-125 | Source-bound read from a local fixed-size builtin array, with typed function-entry witness |
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

Neither the rationale-consistency check nor the speculative race gate
moves a verdict toward `clean` on prose. The check only annotates: a
rationale that reads clean under a `finding` (`"properly
validated"`, `"no vulnerability"`, ...) leaves the finding as emitted;
the only trace is a `rationale_consistency_note` in the in-memory
review result and an INFO log line (it is not journaled).
The row meets G2 exactly as it would without the phrase. A phrase match
cannot tell an asserted claim from a negated, contrasted, conceded or
attributed one, so it decides nothing. The speculative race gate never
records `clean` off protection wording ("protected by", "serialized
by"). Its remaining step is keyword-triggered: a `finding` whose
hypothesis text contains a race keyword (`race condition`, `toctou`,
`concurrent`, `data race`, `deadlock`, ...) is held at `suspicious`
unless its evidence carries a concurrency-relevant receipt (`smt:`,
`coccinelle:`, `semgrep:`, `codeql:`, `joern:`, `lock_region:`,
`compiler:`, `dynamic:`, ...); a non-concurrency receipt
(`consistency:`, `fail_open:`) does not exempt it. The trigger is the
hypothesis wording, so it can fire on a negated mention and miss a
paraphrased race; it only ever moves toward `suspicious`. Known
pre-existing exceptions, where model wording still decides a verdict
and which this rule does not cover: the all-refuted demotion grounds a
refutation unless its counter matches a delegation phrase ("validated
upstream" is withheld and stays `suspicious`, a paraphrase demotes to
`clean`), and an evidence-free claim with an empty `cwe` takes its bug
class from the hypothesis / mechanism text for coverage resolution
(a class named in words can resolve `clean`, the same claim
paraphrased resolves `dark`).

Model-authored text never carries a machine marker: provenance checks
read bracketed markers in bodies and prompt text, some at the start
(`[gate violation:`, `[counter-hypothesis escalation:`, `[reused:`, ...)
and some anywhere (`[caller-contract:`, `[gadget-absence:`,
`[self-contradiction:`, `[tool-refuted]` ...). Model text is tainted at
its source: every string field of a parsed model / agent response is
defanged once at the parse boundary (review, batch glance, edge
review, chain detector, adversarial refuter, the /validate findings
and machine-tier annotation import, the /agentic journal body, and
the agent's `raptor-audit record --body/--hypothesis`), so a
field later spliced into a machine marker's reason (the escalation's
counter snippet, a rescue reason, an observation) is safe by
construction. Defanging rewrites each registered marker to
`[llm-claimed:<marker>` wherever it occurs; a body that still starts
with `[` also gets a `[llm-claimed] ` lead (this also tags a body that
opens with a markdown link, checkbox or footnote -- cosmetic). The
registry (`evidence_grade.MACHINE_BODY_MARKERS`) is checked against the
tree's consumer sites by a test that re-enumerates them (AST: `in`,
`==`, `startswith`/`find`/..., anchored regexes, constants, loops and
`any(...)`, extensionless libexec entry points) and rejects any
case-normalised marker test. The review and edge-review boundaries
also DROP every pipeline-owned key from a model's parsed review
(`evidence_grade.PIPELINE_OWNED_REVIEW_KEYS`: machine flags such as
`counter_escalated` / `all_refuted_demotion`, receipts, stage records,
and the panel's identity / accounting keys `file` / `function` /
`model` / `cost_usd`), so a model cannot mint a machine signal by
emitting its key either; a batch-glance element carrying any key
outside its closed element schema is rejected and the function gets a
full individual review. A test enumerates every `review_result` key
read or written (through `.review_result`, `getattr(..., "review_result")`,
any `review_result=` keyword, and -- under `core/audit/` and
`core/llm/multi_model/` -- locals or parameters named `review_result` /
`rr` / `_rr` / `primary`) and fails until each is classified
model-authored or pipeline-owned; a write it reaches but cannot resolve
to keys fails until it is pinned by content with a justification.


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


## Cost forecasting

`--forecast` prints a deepen-aware pre-spend cost band and exits at
$0 LLM spend — no review, no model calls, not a run.  The same band
prints informationally at the start of every uncapped run (no
`--max-cost`) before the review loop commits.  Informational only:
nothing about the forecast gates or caps anything — `--max-cost` is
the enforcement surface.

```bash
libexec/raptor-audit run /path/to/code --out out/myrun --forecast
```

The forecast is a **band** (low/central/high), never a point, built
from three phases:

- **review** — first-pass reviews, per-item from the gap queue's SLOC
  census (narrow band);
- **deepen** — the follow-up machinery (`re_review` + `refinement`
  ledger phases): a first-pass `suspicious` verdict spawns refinement
  rounds, the deepen pass, and iterative caller re-review, so this
  phase rides the queue's **predicted suspicious density**.  With
  journal priors (a prior run on the project), the density comes from
  per-function and per-file prior verdict rates; cold runs use a
  measured corpus default with a wide band.  Prior suspicious/finding
  functions outside the queue count as seeded re-review mass.  This
  phase can be several times the first-pass cost on a
  suspicious-dense queue — pricing first-pass economics only is the
  miss the forecast exists to close;
- **support** — triage, study, IRIS, checker synthesis, glances,
  summaries, as a stable fraction of the subtotal.

Each printed band names its drivers (density source and coverage,
deepen-depth spread, seeded mass, model overrides).  At run
completion the forecast is paired with the actual `cost-breakdown.json`
ledger: the comparison lands in `audit-report.json`
(`forecast_vs_actual`), on the console, and as an appended record in
`forecast-calibration.jsonl` (run dir, plus the project dir for
project runs) — the re-fit food for the seeded coefficients in
`core/audit/forecast.py`.

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
   verdict reuse imports the completed reviewed verdicts at $0 (cleans
   inferred from tool silence re-review; see Execution Model) and
   reviews only the remainder.  `--no-supervisor-bound` opts out; misdetection is
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
(cross-run verdict reuse imports the reviewed verdicts at $0;
silence-derived cleans re-review, see Execution Model); a run whose
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

### Witness-backlog drain

`/validate`'s findings import routes dark rows (hypotheses no tool could
adjudicate either way) into `witness-backlog.json` instead of spending
validation budget on them.  The backlog consumer works that queue with
non-executing witnesses: the Mode 2 on-demand checker synthesis is
retargeted at each dark row's stated hypothesis.

```bash
libexec/raptor-audit backlog list --out "$OUTPUT_DIR"
libexec/raptor-audit backlog drain --out "$OUTPUT_DIR" \
    --target "$TARGET_PATH" --budget 5.00
```

`list` ranks the queue by cheapest-available-witness without spending
anything: rows whose hypothesis names a pattern synthesis can target (a
concrete cluster CWE, or a mechanism the keyword dispatch recognises)
rank first, and rows with PENDING study questions on the same
function/file rank behind their questions (study-first ordering — a row
that is dark because a domain contract is unknown is cheaper to drain
after the study loop answers the question).  Rows the on-demand policy
refuses (not-tool-verifiable classes, no stated harm) are recorded and
never attempted.

`drain` works the ranked queue under the mandatory `--budget` USD cap
(a positive, finite amount — synthesis calls cost; mechanical engine
runs are free).  It is a post-run pass: a run directory whose recorded
worker is still alive is refused — wait for the run to finish (or kill
it) first.  The consumer never mints verdicts:

- A row leaves the backlog only on a landed tool verdict — a
  synthesized rule that passed both mechanical controls (positive
  control at the row's site, dual control on fixtures) AND whose
  journal entry actually landed.  Witnessed rows are journaled
  `suspicious` through the orchestrator's own write path with the
  `<engine>:synth-<rule_id>` receipt recorded; the receipt is
  self-matched (distilled from the row's own site), so it corroborates
  without promoting — promotion stays with the review lanes.
- Failed or refused synthesis leaves the row dark, with a per-row
  attempt record in `drain-report.json` and a persisted attempt counter
  on the backlog row (sites past 3 attempts stay parked).  The counter
  is keyed on the site, not the listing: exact duplicates collapse at
  load and share one counter, and one drain dispatches at most one
  synthesis per `file:function` site — duplicate listings never buy
  extra attempts or extra journal rows.

Drain entries carry the finding-grade `backlog-drain` journal producer:
they never suppress audit gaps, fold into coverage, or serve as reused
verdicts.  `--sample N` (with `--sample-seed`) drains a seeded random
calibration sample of the attemptable rows instead of the whole ranked
queue.  `--study-answers <path>` points at an explicit
`study-answers.json` ledger when the run dir (or its newest project
sibling) does not carry one.

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

| File | Contents |
|------|----------|
| `annotations/<source_path>.md` | Human-written per-function notes (read as review context; never written by the LLM) |
| `findings.json` | Findings in standard format (fed to `/validate`) |
| `gaps.json` | Gap list used for this run |
| `.audit-log.jsonl` | Full audit trail (event log; rolls to numbered sibling shards — `.audit-log.002.jsonl`, … — below the per-shard read budget; readers load the contiguous set. `raptor-audit audit-log rotate <out-dir>` re-splits a pre-rotation oversized trail verbatim, backing up originals as `<name>.pre-rotate`; live runs are refused) |
| `review-journal.jsonl` | Per-function review decisions (strategies, hypotheses, tools, cost) |
| `return-census.json` | Return-usage census from the consistency pre-pass (six-value usage enum per call site) |
| `field-census.json` | Field-access census from the lifecycle channel pre-pass (per-field write sites with rhs provenance, read sites with use context) |
| `prefilter-kills.jsonl` | One record per prefilter/triage kill (summary row first, then `file`, `function`, `gate`, `reason`, plus spot-audit corroboration fields on sampled rows) |
| `suppressions.jsonl` | Decision audit trail: oracle-earned skips, vendored/generated skip/glance routings, binary toolchain glance screens (`audit:toolchain-screen` — glance verdict kept, full-review escalation withheld by design), plus the refutation lattice's record-or-refuse rows — witness discharges, proof-grade receipt-floor overrides, and merge-fence holds, all `dropped: false` (same record shape as `/agentic`/`/codeql`) |
| `tier-diagnostics.json` | Per-channel outcome counters (prefilter, semgrep, smt, fail_open, consistency, ...) |
| `decomp-sweep.json` | Binary targets: tree-wide decompiler Semgrep sweep record — rules run/errored, per-finding records (fid + address join, `traced`-capped, `decompiled-evidence`-tagged), unmapped matches, or the loud-skip reason |
| `decomp-tree/decomp-tree-conformance.json` | Binary targets: per-tool parse conformance of the decomp-tree (sandboxed tree-sitter + semgrep probe legs, conservative `parsed_rate`, quarantine list) — the sweep-coverage denominator |
| `fuzz-dict.json` / `fuzz.dict` | Fuzz handoff: dictionary tokens mined from constants, parse-shape literals, and dispatch keys; `fuzz.dict` is AFL format and is auto-discovered by [/fuzz](fuzzing.md#dictionary-auto-discovery) |
| `cost-breakdown.json` | Per-phase cost ledger reconciliation (completed + failed-attempt + unattributed spend always sum to the authoritative total; the pre-loop summary pass books as the `summary` phase) |
| `llm-telemetry.jsonl` | Per-call LLM telemetry, including a bounded application `caller_chain` when available; attribution never changes budget call classes |
| `prep-profile.json` | Diagnostic sub-step timings, errors and cache hit/miss counts for peer-group and mechanical-detector preparation; written at finalisation, replaced on resume. Inclusive/nested/parallel timings must not be summed as elapsed run time |
| `forecast.json` | Pre-spend cost forecast band (`pre_run` for uncapped runs, `forecast_only` for `--forecast` exits) — see [Cost forecasting](#cost-forecasting) |
| `forecast-calibration.jsonl` | Forecast-vs-actual record appended at run completion (also appended at the project level for project runs) |
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
are called out as producer errors), never run errors.  Resumed runs
re-run the intake each segment against that segment's residual
queue: a seed whose target this run already reviewed counts in the
receipt's `already_covered` bucket (no new miss rows accumulate per
resume), and a seed the checklist recognises but the segment's queue
does not carry records the precise reason `not_in_gap_queue` instead
of a guess derived from the seed's name shape.

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

### Token-enforcement map

`/understand --study` can learn WHICH function(s) implement the
target's anti-request-forgery (CSRF/nonce) check idiom — the
`token_checks` vocabulary channel, name-verified against the study
items like every other channel (generic name shapes like
*token*/*csrf*/*nonce* are candidate discovery hints only; the
classification comes from the enforcement behaviour in the studied
code, so a validator without those words in its name still
qualifies).  At save time a mechanical projection maps every entry
point (context-map entry points plus checklist script-handler files;
PHP targets) to a per-entry status via static call reachability
inside the entry's pre-output prefix, written as `token-map.json`
beside `domain-model.json`:

- `enforced` — a learned check is called directly before any output
- `indirect` — the check is reached through resolved intermediate
  calls (branch conditions inside intermediates are NOT analysed)
- `not_enforced` — no path, with every reachability search run to
  natural exhaustion; the record carries the absence census
- `unknown` — parse failure, dynamic dispatch, a truncated search
  (call-depth cap, include depth cap, or include-splice budget), or a
  config-dependent short open tag; never downgraded to a claim in
  either direction

Every status is hint-tier.  `enforced` is a call-presence witness,
not bypass-freedom — a check behind a conditional projects as
enforced with a `conditional` flag, and NO consumer may suppress or
down-rank a finding because an entry maps as enforced.  Consumers:
entry-point audit reviews get a verify-against-source hint line; the
validate bridge attaches the fact to `attack-surface.json` entry
points (advisory, never a status write); `/project correlate`
reports per-entry drift between runs (`lost_enforcement` rows are
re-review food for token-guard disproofs, never an auto-overturn).

Operator surface:

```bash
libexec/raptor-audit token-map project --out <run-dir> --target <src>
libexec/raptor-audit token-map drift --prior <run-A> --current <run-B>
libexec/raptor-audit token-map sweep --out <run-dir> [--finding-id F-7]
```

`sweep` is the class-sweep generator: when a finding confirmed on a
token-related premise (the finding names a learned check, or carries
CWE-352), every `not_enforced` entry becomes a hypothesis seed in the
`sibling-hypotheses.json` contract above — same caps, same
guarantees, seeds never mint findings.  If another producer already
owns the co-located file, the sweep writes
`token-sweep-hypotheses.json` for an explicit `--hypothesis-seeds`
pass instead (it never overwrites).

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

### Target integer ABI

Source-directory overflow checks default to the analysis process's native C integer
layout, measured with `ctypes` and labelled `host-assumption`. This is an
assumption about the target, not evidence of its deployment platform. Audit
logs announce it; run configuration, worker receipts and memo keys preserve
the resolved widths and provenance. Resume reuses that record even on a
different host. Legacy runs without a recorded ABI remain unknown on resume.

Binary-file targets instead select the standard data model of supported
ELF, Windows PE, and thin Mach-O platforms. For example, Windows PE64 selects
LLP64 even when the analysis host uses LP64. This is recorded as
`binary-platform`; headers do not establish arbitrary compiler-specific
settings. Unrecognized platforms, EFI PE, universal Mach-O without a single
selected slice, malformed binaries, and Ghidra projects remain unknown;
they never inherit the host default.

Override with `raptor-audit run --integer-abi lp64` (or another supported
profile) when the target layout is known. Use `--integer-abi unknown` to
leave ABI-dependent SMT inconclusive. Unsupported host layouts also remain
unknown. The corpus runner accepts the same option, records it in results
and history, and partitions group checkpoints by the resolved selection.
Repository text and model output cannot override the selection.

The supported layouts use two's-complement integers without padding.
The typed model follows supported builtin declarations and C integer
promotions. Unresolved aliases, plain-char signedness and unsupported
conversions remain inconclusive. Prior integer-disproof clean verdicts
without a durable ABI binding must be reviewed again.

Manual SMT shim sweeps describe the feasibility of a supplied mathematical
model. Their `supplied-model` receipts are diagnostic, including solver
witnesses; specifying bitvector widths alone does not bind them to target
source. Source overflow verification uses the ABI-bound adapter above.

The source adapters for `check-oob`, `check-overflow-to-oob`, and
`check-negative-bypass` currently infer numeric models without binding
actual access, allocation, or conversion semantics. Their results are
`inferred-arithmetic-model` diagnostics, even with a solver witness or an
explicit ABI selection. Missing element sizes remain unknown. These
receipts cannot promote findings, refute claims, or reauthorize old clean
verdicts; independent verification can still establish a finding.


### Source-bound array read obligations

With an explicit target integer ABI, `/audit` can check a named access such
as `Data[Index]` against its local array declaration. Supported frames use
one literal-extent builtin array and a direct read indexed by an unchanged
builtin integer parameter. The checker binds the declaration and access,
retains reaching guards, models promotions and storage ranges, and checks
both negative indices and indices at or beyond the extent. It independently
checks each SAT witness against the source guards and parameter ranges.

The `smt:check-array-bounds` receipt verifies a safety violation in that
function-entry source model. The artifact records the access location,
declared extent, ABI, guards, parameter values, and assumptions. The source
is assumed to represent the active build; caller reachability and additional
calling-context constraints are outside this proof. A safe or unreachable
access never supplies a whole-function clean or claim-refutation receipt.

Pointers, array parameters, variable extents, unresolved aliases, writes,
mutation, calls, and unsupported control flow remain inconclusive. Ordinary
bounds dispatch prefers this source obligation when it can bind the access;
the existing supplied numeric-model check remains diagnostic fallback.

### Source integer proof boundaries

Source-bound overflow checks use the same explicit function-entry scope as
array reads. Integer terms, including names used only in guards, must bind
to builtin parameter inputs. A declaration supplies a type, not a symbolic
value: local initializers, static storage, aliases, and mutable value flow
need additional obligations and cannot become unconstrained parameters.
Earlier unmodeled arithmetic or memory reads also block source proof credit.

The overflow backend supports signed and unsigned addition, subtraction,
and multiplication. For a SAT source query, a separate Python-integer
checker validates storage domains and all reaching guards, then evaluates
the exact operation without wrapping. The artifact retains the checked
assignment, mathematical result, promoted result range, and assumptions.
Partial encodings and invalid counterexamples remain inconclusive. UNSAT
establishes only the admitted operation's overflow obligation under its
source premises; it does not prove an entire function safe.

Both source parsing and direct SMT obligations have budgets. Exceeding one
refuses the complete query; constraints are never discarded to earn a
verdict. Small-width exhaustive differential tests check the arithmetic
predicates against ordinary integer math, and native worker tests cover
the confined JSON boundary without executing the supplied C/C++ code.

Caller reachability remains separate. In particular, the existing generic
`bounded` caller contract carries no numeric interval and cannot establish
that a particular array or arithmetic counterexample reaches the callee.

### Literal caller-entry obligations

With an explicit integer ABI, the caller gate can mechanically check a
complete literal argument tuple against a source array-read or overflow
obligation. Every callee guard and parameter storage domain must hold for
the same tuple. An unsafe index alone is insufficient when another argument
prevents the read. Literal arithmetic uses exact integer evaluation rather
than an additional symbolic search.
Candidate discovery stays inside the same source snapshot; this proof does
not require a project-wide caller scan or an inventory call graph.

The initial supported frame is a same-file wrapper with no parameters,
whose body directly returns one call with literal arguments. The source
unit must contain plain function definitions and comments. Includes,
macros, prototypes, overloads, conditional calls, preceding work, symbolic
arguments, and unsupported conversions remain unresolved. Literals must
have unambiguous target-int semantics and retain their value on parameter
conversion; the checker does not guess narrowing or unsigned wrap.

The existing confined worker binds the result to the complete source,
callee, hypothesis, ABI, language, and call locations. The parent also
checks positive tuples independently before permitting promotion. The
`caller-entry-source-model` artifact records the callee obligation, actual
arguments, cited wrapper, and scope assumptions on both promotions and
holds. It assumes entry to that wrapper; application-entry reachability is
not established. Safe or excluded tuples never clear the function or rule
out external callers. A `sizeof` argument without a numeric relation stays
inconclusive under the generic bounded-contract channel.

### Signed guard constants and solver symbol identity

Signed source obligations admit canonical negative target-int constants in
atomic comparisons, including numeric unary minus and negative hex spelled
in source. Guard extraction normalizes negative atoms to decimal; typed
admission, Z3 encoding, independent witness checks, and literal caller
checks use the same value. This covers lower-bound errors such as
`Index >= -1` and signed arithmetic behind negative thresholds.

The predicate language accepts a signed decimal minimum at its exact
bitvector width. C source admission is stricter: the positive magnitude
must fit the target's signed `int`, so the literal's C evaluation type is
justified. Wider literals, macros, compound negation, and mixed unsigned
comparisons remain inconclusive. No host type or wrapped negative value is
substituted for an unsupported conversion. Bitvector profiles require an
integer width and boolean signedness.

Generated call symbols cannot consume source identifier spellings.
Predicate batches reserve source `_anon_N` names before allocating parser
aliases; direct intrinsic call operands use fresh internal symbols outside
the parsed identifier namespace. Sparse numeric suffixes cannot inflate
new labels, and unused reservations do not create witness values or
optimization objectives. Unresolved calls still carry the generic model's
existing SSA/purity assumptions; source-bound proofs do not admit them.

The scalar guard bridge's arithmetic fallback also handles equality and
finite `!=` exclusions. It returns a checked integer assignment when the
supported model is satisfiable, detects exhausted finite intervals, and
keeps unsupported constraints inconclusive. A missing worker cannot turn
contradictory equalities into a feasible result. This bridge models
unbounded integer constraints; it does not establish C conversion rules
or source reachability.

Default guard-consistency SMT partners remain predicate models. Their SAT
points do not establish an unsafe access, and abstract UNSAT does not refute
an actual source bug. Guard-presence and guard-predicate checks retain these
results as diagnostic corroboration, including the mathematical witness,
without promoting them into source verification or refutation. The legacy
bare guard receipt IDs and suffixed variants are detection-grade as well;
source safety verifiers must earn their own source-bound receipts. Old clean
journal entries credited to these predicate receipts require fresh review.

Literal caller obligations also run independently when a function-scoped
integer overflow query is inconclusive. A complete literal argument tuple
can prove an overflow in an unguarded callee; it does not need an abstract
SAT observation as a prerequisite. These observations use
`smt:check-overflow:literal-call`, retain the complete source/query/ABI
binding and exact mathematical counterexample, and establish only entry to
the cited wrapper. Safe, unsupported or unavailable callers remain
inconclusive and cannot refute the source claim.

The admitted wrapper contains one unconditional direct call, either as its
return expression or as a discarded expression in a void wrapper. A void
wrapper may end with a bare return. Supported scalar wrapper parameters
may be unused, but every callee argument must still be a supported literal.
Void callees may have an admitted arithmetic operation without returning
its value. Effects, symbolic arguments and unmodeled conversions still
decline proof credit.

Caller snapshots use bounded, containment-checked binary reads and strict
UTF-8 decoding; truncated inputs never become proof source. Caller checks
run outside the function-only sweep memo, so editing a caller cannot reuse
an earlier tuple's result. Persisted literal-call receipts require fresh
source revalidation because the journal's function hash does not bind the
whole caller file.

Source integer obligations support different promoted widths when all
variable operands have the same promoted signedness. The result frame
comes from the operation's operands under the explicit target ABI, rather
than from a guard variable or the alphabetically first declaration. For
example, `int + long` uses 64-bit signed arithmetic on LP64 and 32-bit
signed arithmetic on LLP64. Small supported literals retain C `int`
semantics before value-preserving conversion to that result frame.

Every narrower input keeps its declared storage range in the wider SMT
frame, including guard-only inputs. The independent mathematical witness
check derives the result range from the actual operands too. Array models
select their frame from the index, while validating all guard inputs;
a narrower flag can guard a wider index without changing its bounds
obligation. Mixed promoted signedness and guard variables wider than the
result frame remain unsupported by this single-profile comparison model.

The shared SMT conversion predicate `truncation_loses_bits` requires both
`to_signed` and an explicit `from_signed` keyword. A bit pattern alone
does not establish the source integer value: unsigned `65535` and signed
`-1` have the same 16-bit representation but different narrowing results.
The predicate compares both interpreted values in a frame one bit wider
than the source, covering narrowing and same-width signedness changes.
It models the specified bit-pattern conversion; an actual C-source
conversion still needs its source, target ABI and definedness obligations.

Low-level SMT widths are exact positive Python integers, and signedness
and model-completion flags are exact booleans. Witness signedness maps
are validated before extraction, including unused entries. Generated
witness aliases reserve all real declaration names; aliases for duplicate
names are display labels, while source-sensitive consumers use a named
expression registry through `format_vars`.

SMT tracking labels are created in the solver's own Z3 context and kept
disjoint from Boolean names in existing assertions, the complete incoming
batch and prior label mappings. Native fresh-name counters can collide
with explicit declarations, so fresh-name allocation alone is insufficient.
Tracking must preserve the original formula's satisfiability. Later batches
that reference an active tracking marker decline instead of reinterpreting
that marker as a formula variable; removed markers are pruned from the
solver's registry.

Temporary solver scopes require successful rollback. Failed `pop()` raises
an integrity error; it no longer permits normal continuation with temporary
constraints still present. When body execution and cleanup both fail, an
exception group retains both failures, including cancellation exceptions.
Solver and optimizer timeout arguments require integer values; existing
integer clamping limits are preserved.

Signed witness preferences account for Z3's unsigned bitvector objective
ordering. The legacy `wp_*` fields describe an implication-reduced summary
of the supplied constraints, conditional on supplied background axioms.
They do not prove program reachability or a program weakest precondition.
Unencoded inputs, undecided redundancy checks and failed serialization
prevent completeness. Errors in the separate reduction solver retain the
primary SAT verdict and model while leaving the summary unavailable and
incomplete.

Audit numeric queries use `reduce_constraints=False`: the complete parsed
obligation and background axioms are still asserted, but individual tautology
checks and optional post-SAT constraint reduction are skipped. This keeps
optional diagnostics out of the worker deadline used for the verdict and
witness. `wp_complete=False` with an absent predicate and empty conjuncts
means no summary was requested, independently of the primary verdict. Generic
SMT library callers retain constraint reduction by default. Necessary entry
feasibility checks and dual-profile contradiction probes still run; this mode
is not an overall wall-clock guarantee.

Path and named numeric SMT checks share one guard-encoding frame. It keeps
call placeholders, mutation boundaries, parser rejections, and background
call-summary axioms together. Repeated identical call texts share the existing
SSA-style identity within a mutation-free window; assignment-shaped steps
start a new window and remain unencoded inputs. JSON path and numeric results
report `summary_axioms` alongside the call-label map, including when optional
constraint reduction is disabled. These are model assumptions, not verified
callee definitions. Function-call operands in named numeric checks still use
independent free placeholders; a SAT result involving them remains an
approximation and cannot by itself establish a source bug.

The SMT condition and numeric-operand grammars reserve only uppercase `NULL`
as the zero constant. Other case variants are source identifiers, including
`Null` and `null`; they retain distinct values and declared source domains.
English null aliases still canonicalise to uppercase `NULL`. The shared
variable builder rejects this reserved spelling before native allocation.
This is the
shared bitvector grammar's literal convention, not a cross-language resolver.

Optional call summaries require a well-formed argument list with the expected
arity. Malformed or mismatched calls retain free placeholders without summary
axioms. Signed `abs`-family summaries relate supported arithmetic arguments
to the result; the existing two's-complement `INT_MIN` case remains admitted.
Unsupported arguments retain only the conservative result range. `strnlen`
gets a result bound only for a nonnegative literal representable at the active
width. Its bound compares unsigned result bits even in a signed frame, so
values with the sign bit set remain possible. Unknown, negative, ambiguous,
or out-of-width bounds assert no range. These remain callee-model assumptions
and do not grant source-bound audit proof authority.

Assignment-shaped inputs break call deduplication but do not establish scalar
SSA identity across a mutation. Each guard and call-summary assertion records
its mutation-free segment using its native tracking marker. An UNSAT query
containing mutations refutes only when the actual native core is wholly owned
by one segment. Cross-segment, missing, or unowned core provenance stays
inconclusive; encoded conflicts remain available for diagnostics. Intrinsic
numeric predicates have no established segment across rejected assignments.
Frame tracking requires a fresh solver, and later assertion changes invalidate
ownership. No complete constraint summary is claimed for a query with rejected
mutations.
This rule adds no solver passes and preserves independently contradictory
segments. Recovering cross-segment proofs requires a proper scalar value-flow
model rather than dropping the mutation.

Named numeric checks apply optional call summaries to each function-call
operand, retaining a separate native symbol and source label for every
occurrence. Matching operand or guard text does not prove the same execution
and never merges those values. Operand theory has no established scalar
segment across rejected mutations. The full obligation includes that theory
even when no ordinary predicates remain after tautology filtering.

Call boundaries respect quoted strings, character literals, and escapes.
English operator normalization and whitespace collapse preserve quoted bytes,
so distinct literal arguments cannot accidentally become one shared call.
These changes refine the supplied model; they do not verify callee definitions
or widen the source-bound audit proof contract.

Named numeric operands accept representable signed decimal literals under
signed profiles, using the same validation as condition literals. Unsigned
profiles reject negative decimal inputs rather than wrapping them. Generic
signed bounds checks include both negative indices and indices at or above
the extent; a narrowed call result cannot hide a lower-bound violation.


### Verification cost and reuse diagnostics

`verification-attempts.jsonl` records deterministic, memo-eligible checks:
checker outcome, bounded failure reason, elapsed call time, content-keyed
input identity, and whether the result was fresh, memoized, or checkpointed.
These are checker outcomes, not final finding verdicts. Checks bypassing the
memo boundary are outside this trail's coverage. Inconclusive results already
reuse identical semantic inputs; transient errors remain retryable.

Summarize a run with `python -m core.audit.verification_metrics <run-dir>`.
The report exposes repeated fresh inputs without suppressing retries.
Per-check monetary cost remains unknown rather than being inferred from
concurrent run-wide spend. Summed call times include waits and are not run
wall time. Corpus spend summaries additionally break down unclassified LLM
calls by their recorded caller, tokens, cost, and summed call time. These
caller totals are already included in the authoritative spend total and do
not change call classes or budget reservations.


Eager invariant compilation keeps a run-local memo of exhausted, clean control
rejections. After the existing retries and engine fallback, an unchanged
invariant does not restart paid synthesis each time a study batch reloads the
domain model. A changed invariant, evidence, source stamp, engine, or model
reopens compilation. LLM failures, scanner errors, missing fixtures, and
interrupted attempts remain retryable. A rejected checker leaves the invariant
uncompiled and the issue unverified; it is not evidence that the code is safe.
Logs distinguish fresh compilations from reused control rejections. The memo
is cleared for every new audit.

Study invariants require source locators and verbatim quotes. When a legacy
response omits its file, the parser can locate an exact quote in the supplied
focus/context snippets if it identifies one unambiguous file. The confined
on-disk source must still verify; the receipt records the recovered locator.
Explicit wrong paths, ambiguous matches and stale snippets remain unverified.


Corpus calibration accepts `--max-cost` and `--max-time` for a whole invocation,
including preparation and all repository groups. Spend uses the telemetry
ledger, not label-attributed review costs. Unreviewed budget-stopped labels
remain explicit errors. Cost caps gate dispatch using estimates and can be
overshot by in-flight requests; wall limits are cooperative. Use an external
process supervisor when a hard deadline is required. `--static-only` disables
automatic native witnesses and dynamic validation in both experimental arms.

For paired comparisons, inspect finalized coverage by class and confirm the
discovery stage actually ran. Budget-censored positive-only samples cannot
estimate precision. Place the checkout and automatic library-source cache
on a filesystem with adequate free inodes; changing `TMPDIR` alone does not
relocate every cache. Report environment failures separately from accuracy.

Cost-limited corpus runs disable semantic concept-seeding calls in the isolated
study-prep subprocess, whose client cannot share the parent reservation ledger.
Mechanical preparation and in-process study remain enabled; their paid study
calls use the governed run client. The choice is recorded in result metadata.
