# Calibrated Aggregation, CFG Dominators, WP Extraction

Three-project arc that extends RAPTOR's existing mathematical substrate.
Sequenced as 9 phases. Each phase ships independently; later phases assume
earlier ones but do not re-open them.

- **Project A (phases 1–4):** Dawid–Skene calibrated multi-model
  aggregation. *Phases 1–3 shipped (PR #793); Phase 4 deferred by design
  behind a written data gate — see the Phase summary.*
- **Project B (phases 5–7):** CFG dominator-based sanitizer suppression.
  *Shipped (PR #794).*
- **Project C (phases 8–9):** Weakest-precondition extraction from the SMT
  path validator. (Carve-out from the broader SMT theory expansion; array
  theory deferred to a separate arc.) *Shipped (Project C PR).*

**Arc status: 8 of 9 phases shipped.** The only un-shipped phase (A4) is
an intentional carve-out gated on real `/validate` ground truth, not
outstanding work — its activation gate and checkpoint are documented in
the Phase summary.

## Why this ordering

A first because it removes a structural circularity (majority defines truth,
truth grades reliability, reliability is unused). B second because it lands
ROI fastest and proves the dominator concept already prototyped in
`smt_barrier.py` generalizes. C last because it depends on neither A nor B
and is the smallest of the three; ending with it gives the arc a clean tail
that hands a new artifact to `/exploit`.

---

## Project A — Dawid–Skene calibrated aggregation

### Substrate today

- `core/llm/scorecard/consensus.py` `record_consensus_outcomes()`
  literally computes
  `majority_says_exploitable = exploitable_count > non_exploitable_count`
  and uses that as ground truth in the same function
  (`outcome = "correct" if with_majority else "incorrect"`).
- `core/llm/scorecard/scorecard.py` accumulates `(model, decision_class)`
  cells with Wilson upper bounds (`_wilson_upper_bound`, line 244).
- The scorecard is a passive observer: it records reliability data that
  nothing downstream consumes when deciding new findings.

### Problem

The pipeline is circular and self-confirming. A historically-unreliable
model on `decision_class="agentic:cwe-79"` casts the same weight as a
historically-reliable one; its votes both shape the "ground truth" and get
graded against it. The scorecard cannot be used to weight the vote without
first being purged of the bias it inherited from past votes.

### Phase 1 — Foundation: audit (1a) gates prior design (1b)

**Goal:** quantify what we actually have before committing to a prior
parameterization. The audit is a hard gate — the priors module's shape
depends on its findings, and writing the priors first risks designing
for a data regime that doesn't exist.

Storage shape grounding (verified against `scorecard.py:7–39`): the
sidecar at `out/llm_scorecard.json` (schema v2) keys cells on
`models -> <model> -> <decision_class> -> events -> <event_type> ->
"YYYY-MM" -> {correct, incorrect}`. The audit must walk the age
buckets, not flatten them — freshness weighting is downstream's call,
not the audit's.

**1a — Audit (`core/llm/scorecard/scripts/scorecard-audit`)**

- Read every scorecard JSON discoverable under `out/` plus the active
  project (the run lifecycle's `.active` symlink resolves the project
  scorecard if any).
- Per `(model, decision_class, event_type)`, total correct + incorrect
  across all age buckets. Report cell-count histograms at N=10 / 30 /
  100 thresholds.
- Breakdowns: per-event-type (multi_model_consensus is the primary
  D–S input; cheap_short_circuit / judge_review are independent
  signals worth tracking), per-decision-class (do we have enough cells
  per CWE rule to support per-class confusion matrices, or do we need
  to back off to coarser partitions like "all SQLi rules"?).
- Verdict line: green if ≥ 50 % of `(model, decision_class)` cells
  cross N=30 for `multi_model_consensus`; amber if 10–50 %; red if
  < 10 %. Red means phase 2 will be prior-dominated and the user
  should reconsider before proceeding.

**Ships from 1a:** the CLI + a written audit report on current data.
The report is what gates 1b.

**1b — Beta priors (`core/llm/scorecard/priors.py`)**

- The audit run on the current checkout returned **no-data**. We
  therefore ship 1b as *math only*, with the parameterization left
  explicit at the call site. Phase 3 picks the prior at integration
  time once real panel data exists.
- API:
    - `BetaPrior(alpha, beta)` — dataclass with `mean`, `mode`,
      `variance`, `strength`, `credible_interval(level)`.
    - `posterior_update(prior, successes, failures) -> BetaPrior`
      — conjugate Beta(α+s, β+f) update.
    - Factory helpers: `uniform_prior()` (Beta(1,1)),
      `jeffreys_prior()` (Beta(½,½)), `weak_informative_prior(mean,
      strength)` (operator supplies prior mean and the equivalent
      sample count).
- **Informed priors come from `/validate`, not the scorecard.**
  `class_base_rate_from_scorecard()` was in an earlier draft and is
  deliberately excluded: the scorecard's `correct / incorrect` counts
  measure agreement-with-majority, **not** true-positive incidence, so
  using them as a base-rate prior would re-import the same circularity
  the arc removes. The sound substrate is `/validate`'s labelled
  ground truth — its `exploitable` / `disproven` rulings are real
  positive / negative labels. `priors.priors_from_validation(
  {decision_class: (n_exploitable, n_disproven)})` builds per-class
  `Beta(1 + exploitable, 1 + disproven)` priors (the class-prevalence
  prior the EM holds fixed at its mean); a class with no labels is
  absent from the map, so the consumer's uniform `Beta(1, 1)`
  cold-start applies. This is the factory the deferred Phase 4 feeds
  into `calibrate_results`'s `priors_by_class`.
- Decision policy for downstream: cells with sample count below a
  configurable threshold fall back to vote with a logged downgrade
  reason. No silent priors — the chosen factory + parameters are
  serialized into every aggregation result for auditability.
- Pure-Python implementation. No scipy/numpy dep (incomplete-beta
  via standard continued-fraction expansion).
- **Sparse-cell behaviour (not a bug — document for operators).**
  When a `(model, decision_class)` cell has few observations, the
  conjugate update `Beta(α+s, β+f)` is dominated by the prior: with
  the cold-start `uniform_prior()` (Beta(1,1)) and little data the
  posterior mean sits near 0.5, the credible interval stays wide, and
  the *deferred* Phase 4's posterior-weighted soft updates would be
  near-zero (`correct_credit ≈ incorrect_credit ≈ 0.5`). This is the
  prior correctly dominating in the absence of evidence, not a
  malfunction — it is exactly why a real informed prior (from
  `/validate` ground truth, Phase 3/4) matters before the soft update
  carries weight. Operators landing this on a fresh install should
  expect ~0.5 posteriors until per-class panel data accumulates.

**Ships from 1b:** priors module + tests.

**Phase 1 total ships:** audit CLI + audit report + priors module.
No behavior change in `/agentic` or `/codeql`.

### Phase 2 — EM estimator

**Goal:** implement Dawid–Skene without touching the dispatch path yet.

**Important data-source clarification.** Dawid–Skene needs per-finding
per-model **raw verdicts** (`{finding_id, model, verdict}` triples) to
recover each model's confusion matrix `(α_m, β_m) =
(P(say-exploitable | truly-exploitable),
P(say-not-exploitable | truly-not-exploitable))`. The scorecard's
`correct / incorrect` counts are **not** sufficient — they record
agreement-with-majority, which is the very signal we're trying to
unwind. Using them as confusion-matrix input would reintroduce the
circularity. The scorecard is the *prior* (phase 1b), not the
likelihood input.

Source of the raw verdicts: `core/llm/multi_model/dispatch.py`
`run_multi_model()` emits per-finding panel results before they reach
the aggregator. A
prerequisite sub-task in phase 2 is verifying these are persisted to
disk; if they aren't, we add a JSONL log
(`<run_output_dir>/multi_model_panel.jsonl`, one record per
`{finding_id, model, verdict, confidence}`) before wiring the
estimator. Without this log, phase 2 has no input.

> ⚠ Superseded: never created; the estimator reads `orchestrated_report.json` (`core/llm/multi_model/panel_log.py` `load_from_orchestrated_report()`).

- Add `core/llm/multi_model/dawid_skene.py`. Inputs:
  per-finding list of `(model, verdict)` tuples loaded from the panel
  log + Beta priors from phase 1b keyed on `decision_class`. Output:
  posterior P(true-positive), 95% credible interval, per-model
  inferred confusion matrix.
- EM iterates: E-step computes per-finding posterior given current
  model reliabilities and class prior; M-step updates each model's
  `(α_m, β_m)` given the posteriors. Convergence: ‖θ_t − θ_{t−1}‖∞ <
  1e-4 or 50 iterations.
- Numerical stability: log-space E-step; clip confusion-matrix entries
  to `[ε, 1 − ε]` with `ε = 1e-6` to prevent log(0).
- Partition unit is `decision_class`. A model good at SQLi need not be
  good at SSRF. The phase 1a audit determines whether per-class
  partitions have enough findings to converge — if not, fall back to a
  coarser partition (per-CWE-category, or global) with the chosen
  fallback recorded in the result.
- Property tests:
    - Degenerate case (all models agree on all findings) → posterior ≈
      1 or 0; CI tight; confusion matrices ≈ identity.
    - Adversarial case (one model inverts verdicts on every finding) →
      its inferred α and β both ≈ 0; its effective weight in the E-step
      is negative (correctly: it's an anti-correlated oracle).
    - Symmetric noise case (all models 50/50) → posterior ≈ class base
      rate; wide CI.
    - Identifiability case: with only 2 models, D–S is not identifiable
      without a prior. Test that with the phase 1b prior, results stay
      stable; without, the test flags the degeneracy.

**Ships:** panel log (if not already present) + estimator module +
property-based tests + the offline replay harness (Phase 2d). The
harness is the **validation mechanism for the Phase 4 gate-flip
decision**, not a research side-project: it re-aggregates historical
agentic runs from the panel log and compares against the recorded
majority verdict, so the flip rate it reports on real data is what
gates landing the deferred posterior-weighted scorecard update.

### Phase 3 — Dispatch integration + output schema

**Goal:** make Dawid–Skene the default in `--consensus` while preserving
the JSON shape downstream tools depend on.

- Wire the estimator into `core/llm/multi_model/dispatch.py`
  `run_multi_model()` (`aggregator.aggregate(merged, correlation)`). Keep
  the current vote
  aggregator behind a `--consensus=vote` flag for ablation and emergency
  fallback.

  > ⚠ Superseded: `dispatch.py` `run_multi_model()` is the generic synthesis aggregator; calibration is attached in `packages/llm_analysis/orchestrator.py` `_attach_calibrated_aggregation()`.
  >
  > ⚠ Superseded: `--consensus` takes a MODEL name; vote is an automatic internal fallback, no flag.
- Output schema extension (additive, backward-compatible):
    - Existing `verdict` field unchanged (boolean / categorical).
    - New `posterior_true_positive: float`, `credible_interval: [lo, hi]`,
      `aggregation_method: "dawid_skene" | "vote"`,
      `aggregation_fallback_reason: str | null`.
- Triage ordering: when `--rank-by=expected-cost` is passed,
  sort findings by `posterior × severity` (severity from CWE map).
  Default ranking unchanged.
- Document the schema bump in `docs/internals/architecture-internals.md` (one paragraph) and
  in `core/llm/multi_model/types.py` (dataclass + docstring).

**Ships:** dispatch integration + schema + ablation flag + ordering
option. `/agentic` output now carries calibrated posteriors; nothing
existing breaks.

### Phase 4 — Break the circularity in scorecard updates  *(deferred — follow-up PR)*

**Goal:** stop using raw majority as ground truth in
`consensus.record_consensus_outcomes`. This is the structural fix.

**Status — deferred behind measurement (review of PR #793).** Phases
1–3 ship the additive `calibrated_aggregation` telemetry; they change
no verdict and no scorecard update. The Phase-1a audit returned
*no-data*, so on a fresh install Dawid–Skene is prior-dominated and a
posterior-weighted scorecard update would be near-inert at best and
prior-driven noise at worst. The scorecard-update change therefore
does **not** land in this PR. It is gated on real-data validation via
the replay harness (Phase 2d) and lands in a follow-up once the gate
clears.

**Revised design for the follow-up (review item 1 — one mode, no
fork):** do *not* introduce a second `multi_model_consensus_calibrated`
event slot beside the legacy `multi_model_consensus`. Collapse to a
single consensus mode that always records *soft* credits via
`record_event_soft` — the legacy discrete path is just the special
case `correct=1.0, incorrect=0.0`, which the same storage already
accepts, so existing readers see an unchanged schema. Then:

- Replace `with_majority = (verdict == majority_says_exploitable)` in
  `consensus.record_consensus_outcomes` with the posterior-weighted
  update: `correct_credit = p if verdict else (1 − p)`,
  `incorrect_credit = 1 − correct_credit`, where `p` is the
  Dawid–Skene posterior (falling back to the majority indicator,
  `p ∈ {0,1}`, for vote-fallback findings — which reproduces the
  legacy discrete update exactly).
- Draw the EM's Beta priors from `/validate`'s labelled ground truth
  (`exploitable` / `disproven`), not the scorecard, with `Beta(1,1)`
  as the cold-start fallback (see Phase 1b) — this is what keeps the
  update from re-introducing the very circularity it removes.
- Add a regression test that confirms a historically-mis-graded
  dissenter (verdict ⊥ majority but ⊺ posterior) now receives a
  "correct" credit.

**Ships (follow-up):** one consensus mode; scorecard update uses
posterior-weighted soft outcomes on the single event slot; legacy
discrete behaviour preserved as the `{1.0, 0.0}` special case;
circularity closed — gated on replay-harness validation.

---

## Project B — CFG dominator-based sanitizer suppression

> **Status: shipped (PR #794).** Phases 5–7 are implemented and tested —
> `cfg_builder.py` / `cfg_builder_cpp.py` / `dominators.py` (Phase 5),
> `sanitizer_catalog.py` (Phase 6), and the vertex-cut suppressor
> `sanitizer_cut.py` with the `smt_barrier` delegation (Phase 7). The
> sections below are the original design narrative, retained for context.

### Substrate today

- `core/dataflow/smt_barrier.py` already encodes the
  *concept* of "sanitizer dominates sink" via the functions
  `validator_dominates_sink`, `substitution_dominates_sink`. But the
  check is **lexical** — `line < sink_line and not
  _crosses_function_boundary(...)`. It cannot reason about a sanitizer in
  a sibling branch that does not lexically precede the sink but post-
  dominates every path to it, nor about call-graph reachability through
  helper functions.
- `core/analysis/binary_oracle_edges.py` (684 lines) extracts direct
  call edges + vtable resolution via r2. These are the natural input to
  a real dominator tree.
- `core/analysis/reach_chokepoint.py` already has the chokepoint that
  emits `suppressions.jsonl` records pre-LLM (its single writer);
  `binary_oracle.py` only supplies the `earns_suppression` verdict it consumes.

### Phase 5 — CFG construction + Lengauer–Tarjan

**Goal:** build the graph theory layer the suppressor needs.

**Language scope — narrow on purpose.** Phase 5 covers two languages
because both have ready-made substrate in tree:

- **Python intra-procedural** via the stdlib `ast` module. No external
  dep, no tree-sitter (the startup banner shows `tree-sitter ✗`).
  Covers `if / for / while / try / with / match` control-flow nodes.
- **C / C++ inter-procedural** via `core/analysis/binary_oracle_edges.py`
  (direct call edges + vtable resolution from r2). Intra-procedural
  C / C++ blocks deferred — basic-block extraction from a binary is
  a project, and for the Phase 7 suppression check we don't need it
  (function-granularity edges suffice for "every taint path crosses a
  sanitized function").

Explicitly deferred: Ruby (the existing CFG support lives inside
CodeQL queries — `barrier_synth.py` `_assemble_ruby()` imports `codeql.ruby.CFG` —
not in a Python module we can call directly), JavaScript / TypeScript,
Go, Rust. These come in a follow-on arc once Python + C/C++ have
proved the suppression substrate.

- Add `core/analysis/cfg_builder.py`:
    - `build_python_cfg(file_path, function_name) -> CFG` — walks the
      `ast` tree, emits basic blocks and branch edges.
    - `build_cpp_callgraph(binary_paths) -> CallGraph` — consumes
      `binary_oracle_edges.py` output.
    - A uniform `Graph` protocol both produce so phase 5/6/7 code is
      language-agnostic at the consumer.
- Add `core/analysis/dominators.py` — Lengauer–Tarjan iterative
  implementation. O(E·α(E)). Pure Python, no SciPy. Returns a `DomTree`
  with `idom(node)`, `dominates(a, b)`, `dominators_of(node)` queries.
- Property tests against a small hand-checked graph corpus
  (~10 graphs with known dominator trees) and against a NetworkX
  reference if available (test-only optional import; not a runtime
  dep).

**Ships:** CFG builder (Python + C/C++) + dominator tree module +
tests. No integration yet.

### Phase 6 — Sanitizer catalog + recognition

**Goal:** identify which CFG nodes are "sanitizers" for a given finding.

- Promote the implicit sanitizer list in `smt_barrier.py` and
  `core/dataflow/known_safe_calls.py` to a single declarative catalog at
  `core/dataflow/sanitizer_catalog.py`. Entries keyed by
  `(language, callable_name)` with metadata: what kind of taint it
  neutralizes (HTML, SQL, path, shell, format-string, length-bound).
- For each finding entering the chokepoint, derive the set of
  *acceptable sanitizers* from CWE class (e.g. CWE-89 → SQL-neutralizing
  sanitizers).
- Catalog is data; recognition is `match_sanitizers_in_cfg(cfg,
  finding) -> Set[CFGNode]`.

**Ships:** catalog + recognition function + per-CWE acceptable-sanitizer
mapping + tests covering the catalog entries currently scattered through
`smt_barrier.py`. No suppression behavior yet.

### Phase 7 — Chokepoint integration + generalize `smt_barrier`

**Goal:** the actual FP reduction.

**Algorithm correction.** A previous draft framed the suppression
test as "the sanitizer node dominates the sink in the dominator tree."
That is the wrong primitive for this question. The correct
formulation is a **vertex cut**:

> Suppress the finding iff `sink` is unreachable from `source` in
> `CFG \ sanitizer_nodes` — i.e. removing the sanitizer set
> disconnects every source-to-sink path.

This is a single BFS / DFS over `O(V + E)`; no dominator tree needed
for the check itself. Equivalent intuition: every path from source
to sink must cross at least one sanitizer node, so deleting all
sanitizer nodes leaves the sink unreachable.

The phase 5 dominator tree is still load-bearing, but for a
different sub-step: **enumerating sanitizer candidates**. Every
node that dominates the sink is on every path to it; intersecting
the dominators-of-sink set with the sanitizer catalog gives the
candidate sanitizers cheaply before the vertex-cut check runs. The
dominator tree narrows; the vertex-cut decides.

> ⚠ Superseded — actually shipped: no dominator pre-filter (unsound for symmetric sanitizers); candidates come from `match_sanitizers_in_cfg` over the full CFG — `core/analysis/sanitizer_cut.py` `evaluate_finding()`.

- New pre-LLM suppressor: `core/analysis/sanitizer_cut.py`. For each
  finding:
    1. `dominators_of(sink) ∩ sanitizer_catalog_nodes` → candidates.
    2. If `sink` is unreachable from `source` in `CFG \ candidates`,
       emit `verdict: "sanitizer_dominated"` in `suppressions.jsonl`
       with the witnessing cut set logged.
    3. Otherwise let the finding fall through to the LLM.
- Rewrite `smt_barrier.py` (`validator_dominates_sink`) and
  `smt_barrier.py` (`substitution_dominates_sink`) to delegate to
  the vertex-cut check. Keep the existing signatures; the lexical
  check (`line < sink_line`) becomes a fallback only when CFG
  construction failed (loud log with the failure reason).
- Integrate with the existing binary-oracle chokepoint ordering:
  `absent` (binary oracle) → `sanitizer_dominated` (this phase) →
  LLM. Both write to the same `suppressions.jsonl`.
- Multi-source semantics resolved: the vertex-cut formulation
  generalizes naturally — `sink` must be unreachable from
  `⋃ sources`, which is one BFS rooted at the source set.
- E2E test: hand-built corpus where a sanitizer in a sibling branch
  is on every dynamic path to the sink but does not lexically precede
  it — current lexical check misses it; the new vertex-cut check
  catches it.

**Ships:** vertex-cut suppressor wired into chokepoint;
`smt_barrier.py` calls upgraded; auditable suppressions; FP-rate
measurement on existing corpora.

---

## Project C — Weakest-precondition extraction

> **Status: shipped (Project C PR).** Phase 8 emits
> `PathSMTResult.wp_predicate` (minimal sat-preserving conjunct subset,
> via implication-based redundancy); Phase 9 carries it through
> `validate_path` → Tier 4 `smt_witness` → the `/exploit` prompt as a
> hard constraint. The sections below are the original design narrative,
> retained for context.

### Substrate today

- `core/smt_solver/path_feasibility.py` (1501 lines) already has
  `assert_and_track` + `unsat_core` wired in (comment at line 1435).
- Outputs today: sat/unsat verdict + one model when sat. The model is
  consumed by the LLM prompt for CWE-190/120/122/193/476.

### Phase 8 — WP predicate extraction

**Goal:** on sat, emit the *weakest* attacker-input predicate that
drives the sink — not just one witness.

**Algorithm correction.** A previous draft called this "complement
of unsat core" — that's the wrong primitive. Unsat-core extraction
applies when the formula is unsat; here the formula is sat (the path
is reachable) and we want the minimal sat-preserving subset of the
path condition. The correct algorithm:

> Given a sat path condition `C = {c_1, ..., c_n}` whose conjunction
> places execution at the sink, find a *minimal* subset `W ⊆ C` such
> that `⋀W` is still sat and any concrete model of `⋀W` projects to
> a model of `⋀C` at the sink-relevant variables. This is a *prime
> implicant* / *minimal correction set complement* extraction.

Iterative algorithm (deletion-based):

1. Start with `W = C`.
2. For each `c_i ∈ W` in deterministic lexicographic order of conjunct
   serialization:
    - Push `W \ {c_i}` to the solver. If sat *and* the sink-relevant
      variables remain unconstrained-or-equal in models, drop `c_i`
      from `W`.
    - Otherwise keep `c_i`.
3. After one pass, `W` is the minimal sat-preserving subset under that
   ordering.

The Z3 `assert_and_track` + `unsat_core` infrastructure already wired
in `path_feasibility.py` (line 1435 comment confirms it) is reused
for a *secondary* role: when an attempted drop produces unsat, the
returned unsat core tells us which other conjuncts `c_i` was
load-bearing for, useful for the trace logged into the run output.

This is not the literal weakest precondition (that requires symbolic
back-substitution through the program, which is a much larger
project), but it is the weakest predicate over the *current symbolic
variables* — adequate for `/exploit` PoC synthesis because those
variables are the attacker-controlled inputs.

- Output: `wp_predicate: SMTLIB string` alongside the existing
  `sat_model` field. Backward-compatible.
- Cost guard: cap the deletion pass at `min(len(C), 32)` solver
  calls; report partial WP with `wp_complete: false` when capped.
- Non-uniqueness disclosure: the lexicographic ordering makes the
  result deterministic, but different orderings would yield different
  minimal subsets. The chosen ordering is documented in the validator
  output so re-runs reproduce.

**Ships:** WP field on validator output; deletion-pass implementation;
cap + telemetry; property test confirming that for every `c_i ∈ W`,
`(W \ {c_i}) ∧ reaches_sink` is unsat (W is minimal), and for every
`c_j ∉ W`, `(W ∪ {c_j}) ∧ reaches_sink` is sat (W is sat-preserving).

### Phase 9 — `/exploit` integration

**Goal:** make the WP load-bearing in PoC synthesis.

- Extend `packages/exploit_feasibility` (or the `/exploit` skill
  consumer) to read `wp_predicate` when present and pass it to the
  PoC synthesis prompt as a hard constraint ("the generated input must
  satisfy this predicate").
- Add an SMT pre-flight in the synthesis path: solve `wp_predicate` for
  concrete bytes before invoking the LLM, so the LLM is handed a known-
  valid seed rather than asked to find one. Falls back to LLM-only
  synthesis when the predicate is over symbolic variables that don't
  bind cleanly to input bytes.
- E2E: pick 3 historical exploitable findings, regenerate `/exploit`
  output with and without the WP flow, compare PoC validity rate.

**Ships:** `/exploit` consumes WP predicate; concrete-byte pre-flight
when tractable; A/B measurement.

---

## Phase summary

| Phase | Project | Scope | Status |
|------:|---------|-------|--------|
| 1a | A | Audit CLI (`core/llm/scorecard/scripts/scorecard-audit`) + report | **done** (no-data verdict on current checkout) |
| 1b | A | Beta priors module (`core/llm/scorecard/priors.py`) | **done** (math-only; parameterization deferred to Phase 3) |
| 2a | A | Panel-log loader (`core/llm/multi_model/panel_log.py`) | **done** (data already on disk in `orchestrated_report.json`) |
| 2b | A | Dawid–Skene estimator (`core/llm/multi_model/dawid_skene.py`) | **done** (16 property tests pass) |
| 2c | A | D–S property tests | **done** |
| 2d | A | Offline replay harness (`core/llm/multi_model/scripts/panel-replay`) | **done** (the Phase-4 gate-flip validation mechanism; reads historical `orchestrated_report.json`, reports flip rates and per-model reliability) |
| 3 | A | Dispatch integration + output schema | **done** (additive `calibrated_aggregation` field on findings; unconditional — no flag, since the field is purely additive) |
| 4 | A | Posterior-weighted scorecard updates | **deferred by design** — not missing: gated on real `/validate` ground truth (Phase 1a returned *no-data*, so a flip now is prior-dominated noise). Gate + checkpoint are written down (see "Phase 4 gate" below); lands in a follow-up PR as one consensus mode (soft credits via `record_event_soft`, no second event slot) with priors from `/validate`. |
| 5 | B | CFG builder (Python + C/C++) + Lengauer–Tarjan | **done** (#794) — `core/analysis/cfg_builder.py`, `cfg_builder_cpp.py`, `dominators.py` |
| 6 | B | Sanitizer catalog + recognition | **done** (#794) — `core/dataflow/sanitizer_catalog.py` |
| 7 | B | Vertex-cut suppressor + `smt_barrier` upgrade | **done** (#794) — `core/analysis/sanitizer_cut.py`; `smt_barrier` dominance checks delegate to the vertex cut |
| 8 | C | WP predicate extraction (minimal sat subset) | **done** (Project C PR) — `PathSMTResult.wp_predicate` via implication-based redundancy in `core/smt_solver/path_feasibility.py` |
| 9 | C | `/exploit` consumes WP predicate | **done** (Project C PR) — surfaced through `validate_path` → Tier 4 `smt_witness` → exploit prompt as a hard constraint |

**Total: 9 phases.** Phases within a project are sequential. Across
projects, A and B are independent; C depends on neither. **Status: 8 of
9 phases shipped** (A: 1–3 in this PR #793, B: 5–7 in #794, C: 8–9 in
the Project C PR). Phase 4 is the one intentional carve-out — deferred
behind the data gate below, not outstanding work.

### Phase 4 gate (when the flip lands)

The flip activates when **all three** hold; until then the additive
telemetry shipped in Phases 1–3 stands on its own and changes no
verdict:

1. **Labels exist.** `/validate` has produced ground-truth
   (`exploitable` / `disproven`) for the active decision classes —
   target ≥30 labels/class — so `priors_from_validation` is
   data-driven, not the `Beta(1,1)` cold-start. (A per-class harvester
   that rolls `/validate` runs into `(n_exploitable, n_disproven)`
   counts is itself part of the follow-up — today those labels live
   only in per-run validation outputs.)
2. **Replay clears.** `panel-replay` over accumulated
   `orchestrated_report.json` history shows the posterior-weighted path
   moves credit in the right direction (the mis-graded-dissenter case)
   with no regression on agreed findings.
3. **One mode, no fork.** Single consensus mode recording soft credits
   via `record_event_soft`; the legacy discrete update is the
   `{1.0, 0.0}` special case.

Checkpoint: re-run `panel-replay` and report flip-rate + per-class label
counts at the next review; open the follow-up PR when the gate clears,
otherwise post the counts so the distance to the gate is visible.

## Out of scope (explicit)

- Array/select-store theory in SMT (the larger #2 ambition). Deferred to
  a separate arc — needs a source-language → SMT lowering frontend that
  is a project unto itself.
- Max-SMT for "Difficult" verdicts. Cheap to add later; not in this arc.
- SPRT for `zkpox reproduce`. Real, surgical, but unrelated substrate.
- Any change to the binary-oracle classifier itself. Phase 7 *uses*
  `binary_oracle_edges.py`; it does not modify the absent/present
  classification.

## Risks and open questions

- **Phase 1/2 sample sufficiency.** If the audit reveals most cells
  have < 10 observations, Dawid–Skene reduces to its prior and behaves
  much like vote. The 1a audit is deliberately first so this is caught
  before 1b/2 commit.
- **Phase 2 panel-log prerequisite.** D–S needs per-finding per-model
  raw verdicts, not the scorecard's
  agreement-with-majority counts. Sub-task in phase 2 verifies the
  panel log exists (or adds it). Without the log, phase 2 cannot
  start. Open: do we backfill historical runs by re-parsing
  `out/` artifacts, or is D–S valid only on data captured after the
  log is wired?
- **Phase 2 identifiability with N=2 models.** Dawid–Skene is
  formally non-identifiable with two models without a prior. Phase 1b
  priors break the symmetry, but the strength matters. Audit-informed
  prior strength may be insufficient when many `decision_class`
  partitions only ever see two models in the panel.
- **Phase 5 Python AST coverage.** Stdlib `ast` covers Python 3
  cleanly, but unusual control-flow nodes (`match`, generator
  expressions, async / await) need explicit handling. Open: do we
  enumerate every `ast` node-kind and assert coverage, or accept best-
  effort with a `cfg_construction_failed` audit trail?
- **Phase 5 C / C++ intra-procedural absence.** Phase 7 vertex-cut
  works at function granularity for C / C++ — adequate for "every
  path through a sanitized function" but not for "every path through
  a sanitized basic block within a function." This is a deliberate
  scope cut; flag it in the chokepoint output so an operator can
  reason about the limitation.
- **Phase 8 prime-implicant non-uniqueness.** Different orderings of
  the deletion pass yield different minimal sat-preserving subsets.
  The chosen lexicographic ordering on conjunct serialization makes
  the result deterministic; documented in the validator output.

Resolved during revision (no longer open):

- ~~Phase 7 reverse-CFG semantics.~~ Vertex-cut formulation
  generalizes to multi-source findings naturally; dominator-tree
  direction-choice no longer applies.
- ~~Phase 8 "complement of unsat core" ambiguity.~~ Replaced with
  explicit deletion-based minimal sat-preserving subset extraction.
