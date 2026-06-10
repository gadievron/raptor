# Sanitizer-Cut Value-Binding Arc

Follow-on to the just-merged `feat(inventory,dataflow): sanitizer-cut
suppressor` (PR #794, commit `bcdee360`). That PR shipped a pure-graph
vertex-cut suppressor: "every dynamic path from source to sink crosses
a node that contains a sanitizer call." This arc closes the latent
soundness gap that critique surfaced — the cut proves control-flow,
not value-flow.

## The hole

The shipped `evaluate_finding` will return `suppress=True` for:

```python
def handle(user, other):
    safe_other = html.escape(other)
    render(user.name)
```

For CWE-79 the graph cut removes the `html.escape(other)` node and the
sink becomes unreachable in the residual CFG. But `user.name` was
never sanitised. The vertex cut said "every path crosses a sanitizer
node"; it did not — could not — say "every tainted value crosses a
sanitizer." That's a false suppression of a real XSS.

The shipped formulation is sound only when the sanitizer's value is
actually on the source-to-sink data flow. The follow-up arc adds the
symbol-level layer that closes the gap, then extends value-bound
suppression across function boundaries (Python inter-procedural) and
into the second supported language (C/C++ intra-procedural).

The lexical fallback at `core/dataflow/smt_barrier.py:746` / `:940`
stays until A/B parity is demonstrated; only Phase 16 removes it.

## Why one arc, not three branches

Reviewer comments on PR #794 pushed for landing the substrate first,
then wiring behind a flag, then expanding language coverage. The
phases below are sequenced to allow exactly that — each phase ships
as its own PR, no behaviour change until Phase 7, no C/C++ value
layer until Phase 11, no lexical removal until Phase 16. But a
single design doc binds the contract so the substrate decisions in
Phase 1 don't drift before Phase 16 lands.

## Phase summary

| Phase | Sub-arc | Scope | Status |
|------:|---------|-------|--------|
| 1 | A (Python intra-proc) | Symbol-aware CFG nodes (`CallSite`, `defs`, `uses`, `call_sites`) | **done** (29 tests pass, ruff clean) |
| 2 | A | Intra-procedural reaching-definitions | **done** (21 tests pass, ruff clean) |
| 3 | A | Symbol-bound sanitizer recognition (`SanitizerBinding`) | not started |
| 4 | A | Value-bound `evaluate_finding` + tri-state verdict | not started |
| 5 | A | Finding-normalisation adapter (SARIF / Semgrep / CodeQL) | not started |
| 6 | A | Audit JSONL schema upgrade (witness fields, `candidate_only` records) | not started |
| 7 | A | `smt_barrier` wire-up behind `RAPTOR_SANITIZER_CUT` flag + report surfacing + E2E corpus | not started |
| 8 | B (C/C++ intra-proc) | Substrate spike + choice (libclang vs tree-sitter vs r2-decomp) | not started |
| 9 | B | C/C++ intra-procedural CFG + symbol layer | not started |
| 10 | B | Pointer / alias conservatism | not started |
| 11 | B | Value-bound suppression for C/C++ (auto-downgrade removed) | not started |
| 12 | C (Python inter-proc) | Module-local Python call graph | not started |
| 13 | C | Per-function taint summaries | not started |
| 14 | C | Inter-procedural `evaluate_finding` | not started |
| 15 | D (lexical removal) | Parity telemetry + A/B horizon | not started |
| 16 | D | Lexical fallback removal at `smt_barrier.py:746` / `:940` | not started |

Sub-arcs A → B → D and A → C → D are sequential. B and C are
independent of each other; both must land before D starts (D
depends on parity, which requires both languages on the value-bound
path).

---

## Sub-arc A — Python intra-procedural value binding

### Phase 1 — Symbol-aware CFG nodes

**Goal:** the substrate every subsequent phase reads from.

- `CallSite(name, arg_names, assigned_names, lineno)` — frozen
  dataclass. `name` is the resolved dotted callable
  (`html.escape`, `werkzeug.security.safe_join`). `arg_names` is
  the frozen set of bare-name argument identifiers passed
  positionally or by keyword. `assigned_names` is the frozen set of
  LHS names the call's return value flows to (empty when the call
  is bare or used as an expression).
- Extend `PyCFGNode` with:
    - `defs: frozenset[str]` — names this statement assigns.
    - `uses: frozenset[str]` — names this statement reads.
    - `call_sites: tuple[CallSite, ...]` — one record per call
      lexically nested in the statement-level expression
      (ordered by source position so callers can reason about
      chained calls).
- `calls: frozenset[str]` stays for back-compat — Phase 3 will
  layer `SanitizerBinding` over `call_sites` while the existing
  vertex-cut consumer keeps reading `calls`.
- AST walk extends with: `Assign.targets` → `defs`,
  `AugAssign.target` → `defs ∪ uses`, `For.target` → `defs`,
  `With.items[].optional_vars` → `defs`, every `Name` read in an
  expression-context → `uses`. Comprehensions handled as their
  generator's target → `defs` plus inner expression `uses`
  (limited to the comprehension's scope; the synthetic comp scope
  doesn't leak its defs to the enclosing function).
- Compound statements: same `expr_roots` discipline as
  `_extract_calls` — `If.test`, `While.test`, `For.target+iter`,
  `With.items`, `Try` empty. Bodies stay attributed to their own
  CFG nodes.

**Ships:** updated `core/inventory/cfg_builder.py`; new tests on
extraction correctness. No behaviour change in any consumer.

**Gates:** Phase 2 (taint propagation reads `defs`/`uses`),
Phase 3 (recognizer reads `call_sites`).

### Phase 2 — Intra-procedural reaching-definitions

**Goal:** answer "at node N, which earlier nodes last defined
symbol s?"

- New `core/inventory/dataflow.py`. Uses the existing
  `Graph[N]` Protocol and `DomTree` from Phase 5 of the
  shipped arc.
- API: `reaching_defs(cfg) -> ReachingDefs` where
  `ReachingDefs.at(node, symbol)` returns the frozenset of nodes
  that last defined `symbol` on some path from entry to `node`.
- Iterative worklist algorithm — standard textbook
  reaching-definitions, O((V+E) × |Sym|) worst case.
- Tests on straight-line def-then-use, if/else with different
  defs per branch, while loop with loop-carried def, nested loops
  with shadowed defs, def-then-redef.

**Ships:** dataflow module + tests. No consumer yet.

**Gates:** Phase 3 (`SanitizerBinding` consumes it for output
reachability), Phase 4 (gate condition #3).

### Phase 3 — Symbol-bound sanitizer recognition

**Goal:** the recognizer returns "what flowed in, what flowed out"
not just "where the call was."

- `SanitizerBinding(node, callable, input_symbols, output_symbols,
  lineno)` — frozen dataclass. `input_symbols = CallSite.arg_names`
  for the matched call. `output_symbols = CallSite.assigned_names`.
- `match_sanitizers_in_cfg(graph, cwe, language)` now returns
  `frozenset[SanitizerBinding]`. The Phase 7 vertex-cut consumer
  reads `.node` (back-compat via a `nodes_of(bindings)` helper) so
  the existing tests pass unchanged after the recognizer rev.
- Tests: bare-call (no assignment) → empty `output_symbols`;
  chained call `y = f(g(x))` correctly attributes the inner and
  outer separately; nested attribute calls
  `s.helper.escape(x)` → `name="s.helper.escape"`; keyword args
  (`f(x=tainted)`) → `input_symbols={"tainted"}`.

**Ships:** updated recognizer; updated tests. The Phase 7
vertex-cut consumer reads through the helper and behaves
identically.

**Gates:** Phase 4.

### Phase 4 — Value-bound `evaluate_finding` + tri-state verdict

**Goal:** the actual closure of Daniel's hole.

- `SuppressionVerdict = Literal["suppress", "candidate_only",
  "no_suppress"]`. New `SanitizerCutResult.verdict` field; the
  existing `suppress: bool` stays as `verdict == "suppress"` for
  back-compat.
- `evaluate_finding(graph, sources, sink, *, cwe, language,
  source_symbols, sink_arg)` — signature gains `source_symbols`
  (frozenset of taint-bearing names at sources) and `sink_arg`
  (the symbol consumed at the sink, e.g. `user.name` →
  `"user"` after attribute resolution).
- Four-condition gate:
    1. `binding.callable ∈ sanitizer_callables_for_cwe(cwe, language)`
    2. `binding.input_symbols ∩ symbols_tainted_at(binding.node)`
       is non-empty (taint actually flows into this sanitizer)
    3. `binding.output_symbols` reaches `sink_arg` via the
       reaching-defs from Phase 2 (the cleaned value is what
       arrives at the sink)
    4. Removing the value-bound subset of bindings from the
       graph cuts every `source → sink` path
- Verdict:
    - `suppress` when all four hold.
    - `candidate_only` when 1+4 hold but 2 or 3 fails — the
      control-flow argument is intact, the value-flow argument
      isn't. Useful as an LLM hint and audit record but not a
      drop.
    - `no_suppress` otherwise.
- C/C++ `CallGraphNode` path automatically returns
  `candidate_only` (no value layer at function granularity until
  Phase 11). The auto-downgrade is encoded here so phases 5–7 can
  rely on it.
- Tests covering: Daniel's `handle(user, other)` counter-example
  (must NOT suppress); symmetric-sanitize TP (must suppress);
  bypass branch with sanitizer only on one path (must NOT
  suppress); C/C++ callgraph (must downgrade to `candidate_only`);
  same-symbol straight-line (must suppress); chained sanitizer
  `y = wrap(html.escape(x))` (must suppress when `y` is the sink
  arg).

**Ships:** updated suppressor + tri-state verdict + 10+ new tests.

**Gates:** Phases 5, 6, 7.

### Phase 5 — Finding-normalisation adapter

**Goal:** take whatever shape the upstream tool emits and produce
the inputs `evaluate_finding` needs.

- `core/inventory/finding_resolver.py`. Single entry point:
  `resolve_finding(finding) -> ResolvedFinding | None` with fields
  `(file, enclosing_function, source_lineno, source_symbols,
  sink_lineno, sink_arg, cwe, language)`.
- Input formats: SARIF code-flow (CodeQL native), Semgrep finding
  JSON, RAPTOR's own dataflow validation output.
- AST-locate the enclosing function for Python; for C/C++ the
  enclosing function comes from the SARIF `physicalLocation` or
  from `nm` over the binary. Symbol resolution at source/sink uses
  Phase 1's CallSite records — match against the column-offset
  expression at that line.
- Returns `None` (with an audit reason string) when resolution
  fails — callers fall through to the LLM untouched.
- Tests against one fixture per surface.

**Ships:** resolver module + tests.

**Gates:** Phase 7.

### Phase 6 — Audit JSONL schema upgrade

**Goal:** make suppressions reviewable, and make `candidate_only`
visible without it being a silent suppression.

- `record_sanitizer_cut_suppression` extends the JSONL record:
  `sanitizer_call`, `sanitizer_input_symbols`,
  `sanitizer_output_symbols`, `sink_arg`, `witness_lines`.
- `candidate_only` results write to the same file with
  `verdict="sanitizer_candidate"` and `dropped: false` —
  greppable, but the finding survives to the LLM.
- Schema bump documented in the JSONL header (one comment line on
  first write) and in `core/inventory/reach_chokepoint.py`'s
  docstring.
- Tests on record shape for both verdicts.

**Ships:** schema upgrade + tests.

**Gates:** Phase 7.

### Phase 7 — `smt_barrier` wire-up + report surfacing + E2E corpus

**Goal:** light it up — but only behind a flag, and with the
lexical check as fallback.

- `RAPTOR_SANITIZER_CUT` env flag (default off). When on:
  `smt_barrier.py:746` (`validator_dominates_sink`) and
  `smt_barrier.py:940` (`substitution_dominates_sink`) delegate to
  `evaluate_finding` via the Phase 5 resolver.
- Fallback to the existing lexical check when (a) flag is off,
  (b) resolver returned `None`, (c) verdict is `candidate_only`.
  The lexical check is what decides in those three cases — no
  regression for findings the new path can't reason about.
- `/validate` and `/agentic` final-report renderer surfaces
  `Suppressed: Sanitizer Dominated` with sanitizer callable,
  input symbol, output symbol, sink arg, source/sink lines.
  `candidate_only` shows as a hint annotation on the surviving
  finding ("sanitizer present but value binding unproven").
- E2E corpus: 5–8 hand-built fixtures.
    - Daniel's wrong-variable case (must NOT suppress)
    - Symmetric-sanitize TP (must suppress)
    - Bypass branch TP (must NOT suppress)
    - C/C++ callgraph downgrade
    - Resolver failure → lexical fallback
    - Chained sanitizer
    - Sanitizer in helper assignment (foreshadows Phase 14)
- Ablation script: lexical-only vs. value-bound across an existing
  corpus, FP/FN deltas reported in a one-page writeup at
  `out/sanitizer-cut-ab/$timestamp/report.md`.

**Ships:** integration + report + corpus + ablation. Default off.
The follow-up to flip the default to on lives in Phase 15.

**Gates:** Phase 15 (parity telemetry consumes the value-bound
path's output).

---

## Sub-arc B — C/C++ intra-procedural value layer

### Phase 8 — Substrate choice + spike

**Goal:** decide the platform before building on it.

- Comparison doc: libclang vs tree-sitter vs r2-decomp. Axes:
  dep weight (libclang needs the LLVM dev headers; tree-sitter
  needs the C/C++ grammars at build time; r2-decomp needs r2
  which is already in tree), semantic completeness (libclang sees
  types and resolves overloads; tree-sitter is surface-level;
  r2-decomp recovers a pseudo-C that loses some bindings), error
  mode (libclang fails loudly on compile errors; tree-sitter
  recovers from partial input; r2-decomp fails on stripped
  binaries).
- Throwaway prototype against a 50-line C fixture (sanitizer in
  if-branch, sanitizer in helper, multi-argument source) under
  each candidate. Measure node count, def/use accuracy, build
  cost in CI.
- Decision recorded in this doc (replace Phase 8 row in the
  table with `done — chose <X>`).

**Ships:** comparison doc + decision.

**Gates:** Phase 9.

### Phase 9 — C/C++ intra-procedural CFG + symbol layer

**Goal:** the C/C++ analogue of Phase 1.

- `build_cpp_intraproc_cfg(source_or_binary, function_name) ->
  Graph[CPPCFGNode]` matching the existing `Graph[N]` Protocol.
- `CPPCFGNode` carries `defs`, `uses`, `call_sites` like
  `PyCFGNode`.
- Control-flow coverage: straight-line, `if`/`else`,
  `while`/`for`/`do-while`, `switch` (each `case` is a branch
  target; fallthrough modeled), `goto` (conservative — all
  labeled targets are edges from every `goto`), ternary `?:`,
  short-circuit `&&`/`||` (each operand is its own node so a
  sanitizer in the RHS is correctly attributed).
- Tests on hand-built C and C++ fixtures (same shape as Phase 5
  Python tests in the shipped arc).

**Ships:** CFG builder + tests.

**Gates:** Phase 10, Phase 11.

### Phase 10 — Pointer / alias conservatism

**Goal:** decide what to do about indirection without solving
field-sensitive aliasing.

- Policy: track direct flows only. Any indirection — `*p`, `&x`,
  `a[i]`, struct field write through a pointer, `memcpy`-style
  bulk copy — marks the touched symbol set as `may_escape`.
- `evaluate_finding` on a path through a `may_escape` node
  downgrades to `candidate_only` even when the cut otherwise
  holds. (Sound: we can't prove the cleaned value is what reaches
  the sink if the sink reads through an alias the sanitizer
  doesn't know about.)
- Field-sensitivity, points-to analysis, and inter-procedural
  alias tracking are explicitly out of scope. The conservative
  bit lets us be honest without paying for a points-to engine.
- Tests on aliased writes, struct field assignments via pointer,
  `memcpy` indirect taint.

**Ships:** policy + tests.

**Gates:** Phase 11.

### Phase 11 — Value-bound suppression for C/C++

**Goal:** retire the Phase 4 auto-downgrade for C/C++ when an
intra-proc CFG is available.

- Phase 4's C/C++ branch was "always return `candidate_only`."
  Phase 11 replaces that with: if `build_cpp_intraproc_cfg`
  succeeds, run the 4-condition gate exactly as Python does. If
  it fails (stripped binary, no source, syntax-error C), fall
  back to `candidate_only`.
- Call-graph path (function granularity) still returns
  `candidate_only` — function-level edges genuinely cannot prove
  argument binding.
- Corpus of TP/FP C/C++ fixtures + A/B against the
  `candidate_only`-only baseline. Same ablation harness as
  Phase 7.

**Ships:** wire-up + corpus + report.

**Gates:** Phase 15 (telemetry consumes the C/C++ value-bound
output too).

---

## Sub-arc C — Python inter-procedural taint

### Phase 12 — Module-local Python call graph

**Goal:** know which functions call which, within a module.

- `build_python_callgraph(package_root) -> CallGraph` over the
  same `Graph[N]` Protocol. Each node is a `PyFunction(name,
  file, lineno)`.
- Same-module call resolution by name; cross-module imports
  recorded as edges to a placeholder `UnresolvedImport(module,
  name)` node that callers can detect.
- Lambdas, nested defs, method calls (best-effort on `self.foo`
  by looking at the enclosing class), decorators (best-effort —
  the decorated function's caller of its name reaches the
  wrapped body).
- Tests on direct call, helper call, class-method call, lambda,
  closure capture, decorator wrapping.

**Ships:** call-graph builder + tests.

**Gates:** Phase 13.

### Phase 13 — Per-function taint summaries

**Goal:** "if I taint param `p`, does it reach return / does it
reach a callee's tainted-sink arg?"

- For each function `f(p1, ..., pn)`: summary mapping
  `taint_in_params → (taint_out_return, taint_out_call_args)`.
  Computed via Phase 2 reaching-defs lifted to the inter-proc
  level.
- Fixed-point over the call graph; cycle handling via summary
  widening (taint can only grow). Convergence test: at most
  3 × |callgraph nodes| iterations, then bail with
  `summary_unconverged: true` (treat unconverged callers as
  `summary_unknown`).
- Dynamic dispatch (`getattr`, `**kwargs` forwarding, `eval`,
  `exec`, `importlib.import_module` with computed name) marks
  the callee as `summary_unknown`. Callers of `summary_unknown`
  functions downgrade to `candidate_only` along the affected
  path.
- Tests on identity (`def f(x): return x`), transform
  (`def f(x): return html.escape(x)`), branching (`def f(x,
  cond): return html.escape(x) if cond else x`), recursion,
  mutual recursion.

**Ships:** summaries + tests.

**Gates:** Phase 14.

### Phase 14 — Inter-procedural `evaluate_finding`

**Goal:** a sanitizer in a callee counts toward the gate.

- `evaluate_finding` consults summaries: when the source-to-sink
  path crosses a call edge, the callee's
  `taint_out_call_args` (does the cleaned value flow into a
  parent-frame sink arg?) feeds gate condition 3.
- Cross-module resolution best-effort via
  `importlib.util.find_spec`; non-resolvable imports →
  `candidate_only`.
- Tests: sanitizer in helper called from the analysed function,
  sanitizer-only-on-some-branches-of-helper, bypass via callee
  that doesn't sanitize, recursive sanitization, cross-module
  call to a known-sanitizer callee.

**Ships:** inter-proc gate + tests. Corpus run shows additional
TPs caught that intra-proc-only misses.

**Gates:** Phase 15.

---

## Sub-arc D — Lexical fallback removal

### Phase 15 — Parity telemetry + A/B horizon

**Goal:** don't remove the fallback on vibes.

- `suppressions.jsonl` records gain `lexical_would_have_suppressed:
  bool` and `value_bound_suppressed: bool` (both computed for
  every finding, only the second is acted on when the flag is
  on).
- Horizon: collect over the smaller of 200 findings or 4 weeks of
  `/agentic` runs.
- Parity criterion: value-bound TP-rate ≥ lexical TP-rate AND
  value-bound FP-rate ≤ lexical FP-rate, with 95% confidence
  intervals reported.
- Failure mode: if value-bound regresses on either axis, file the
  specific findings as bug fixtures, fix the gap, restart the
  window. Phase 16 does not ship until parity holds twice in a
  row.

**Ships:** telemetry + horizon doc + first parity report.

**Gates:** Phase 16.

### Phase 16 — Lexical fallback removal

**Goal:** close the arc.

- Delete the lexical bodies at `smt_barrier.py:746` and `:940`.
  All callers go through `evaluate_finding`; `candidate_only`
  becomes the "we don't know" verdict instead of falling back to
  lexical.
- Existing lexical tests rewritten as regression backstops for
  the value-bound path.
- One-paragraph design-doc update marking the arc closed.

**Ships:** lexical removal + test rewrite + closure note.

**Gates:** nothing — closes the arc.

---

## Out of scope (terminal)

- Field-sensitive C/C++ aliasing — Phase 10 ships the
  conservative bit; refining it is a project of its own.
- Cross-package Python inter-proc taint with import dynamism
  (`importlib.import_module(name)` with computed `name`) —
  degrades to `candidate_only` and stays there.
- JS / TS / Go / Rust / Ruby substrate — different arc; the
  `Graph[N]` Protocol means new producers slot in without
  touching `evaluate_finding`.
- Inter-procedural reasoning about callbacks passed as arguments
  (higher-order taint). Stays `candidate_only`.

## Risks and open questions

- **Phase 1 comprehension scope.** Python's comprehension scopes
  shadow names introduced in the for-clause. The defs/uses
  extractor needs to NOT leak comprehension targets to the
  enclosing function's symbol set. Test fixture in Phase 1
  pins this.
- **Phase 2 worklist termination on cycles.** Reaching-defs is a
  monotone framework so it terminates; but the implementation
  needs a fixed-point check, not iteration count. The test for
  loop-carried defs catches off-by-one termination.
- **Phase 4 false suppression risk.** The whole arc is about
  closing one. Every Phase 4 test must include a witness for
  "current code suppresses; new code doesn't" or "current code
  misses; new code catches" — explicit deltas, not just green
  ticks.
- **Phase 8 substrate dep.** If libclang wins, RAPTOR gains a
  hard dep on LLVM. Phase 8's decision doc weighs this against
  the alternatives.
- **Phase 13 summary explosion.** A function with N taintable
  params has a summary of size up to 2^N. Cap at N=8 (typical
  function arity); over-arity functions stay `summary_unknown`.
- **Phase 15 corpus skew.** A horizon collected on the same
  finding population that's used to design the value-bound
  catches is circular. Mitigation: hold out 20% of findings as
  a verification set never seen by Phase 1–14 test design.
