# Sanitizer-Cut Value-Binding Arc

Follow-on to the shipped `feat(inventory,dataflow): sanitizer-cut
suppressor` work. The shipped phases (5–7) added a pure-graph
vertex-cut suppressor: "every dynamic path from source to sink crosses
a node that contains a sanitizer call." This arc closes the latent
soundness gap in that formulation — the cut proves control-flow, not
value-flow.

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

The phases below are sequenced to land the substrate first, then
wire it behind a flag, then expand language coverage. Each phase
ships as its own PR; no behaviour change until Phase 7, no C/C++
value layer until Phase 11, no lexical removal until Phase 16. A
single design doc binds the contract so the substrate decisions in
Phase 1 don't drift before Phase 16 lands.

## Phase summary

| Phase | Sub-arc | Scope | Status |
|------:|---------|-------|--------|
| 1 | A (Python intra-proc) | Symbol-aware CFG nodes (`CallSite`, `defs`, `uses`, `call_sites`) | **done** (29 tests pass, ruff clean) |
| 2 | A | Intra-procedural reaching-definitions | **done** (21 tests pass, ruff clean) |
| 3 | A | Symbol-bound sanitizer recognition (`SanitizerBinding`) | **done** (16 new tests + 24 existing updated; ruff clean) |
| 4 | A | Value-bound `evaluate_finding` + tri-state verdict | **done** (17 new tests + wrong-variable case pinned as candidate_only; ruff clean) |
| 5 | A | Finding-normalisation adapter (SARIF / Semgrep / RAPTOR-native) | **done** (21 tests; SARIF + Semgrep + RAPTOR-native fixtures; end-to-end wrong-variable + safe straight-line; ruff clean) |
| 6 | A | Audit JSONL schema upgrade (witness fields, `candidate_only` records) | **done** (9 new tests + binary-oracle back-compat preserved; ruff clean) |
| 7 | A | `smt_barrier` wire-up behind `RAPTOR_SANITIZER_CUT` flag + E2E corpus + ablation | **done** (13 corpus/wire-up tests; 7-fixture corpus + CORPUS.md ablation table; smt_barrier extended with optional file_path/cwe/language kwargs; ruff clean) |
| 8 | B (C/C++ intra-proc) | Substrate spike + choice (libclang vs tree-sitter vs r2-decomp) | **done — chose tree-sitter** (60-LOC C fixture parses in 1.73 ms, 6/6 canonical shapes recover defs/uses/call_sites; writeup at `docs/phase-8-substrate-spike/DECISION.md`) |
| 9 | B | C/C++ intra-procedural CFG + symbol layer | **done** (32 tests pass; `core/inventory/cfg_builder_cpp.py` mirrors `PyCFGNode`/`PythonCFG` shape; covers if/else, while/for/do-while + break/continue, switch with fallthrough, goto+labeled, return; defs/uses/call_sites match Python builder's contract; degrade-cleanly on partial parse errors; ruff clean) |
| 10 | B | Pointer / alias conservatism | **done** (27 tests pass; CPPCFGNode.may_escape stamped on `*p` / `&x` / `a[i]` / `obj->field` / bulk-copy calls (memcpy/strcpy family); evaluate_finding downgrades SUPPRESS → CANDIDATE_ONLY when any node on a source→sink path is may_escape; Python verdicts unchanged via getattr default; ruff clean) |
| 11 | B | Value-bound suppression for C/C++ (auto-downgrade removed) | **done** (10 tests pass; finding_resolver wires `build_cpp_intraproc_cfg` for c/cpp languages; 5-fixture C corpus + CORPUS.md ablation table; 4 GLib/SQLite sanitizer entries added to the known-safe table; Phase 4 callgraph-only carve-out preserved; ruff clean) |
| 12 | C (Python inter-proc) | Module-local Python call graph | **done** (32 tests pass; `core/inventory/python_callgraph.py` exposes `PyCallGraphNode` + `PyModuleCallGraph` (Graph[N] Protocol) + `build_python_module_callgraph`; resolves `name`, `self.method`, `cls.method`, `Class.method`, `Class()→__init__`; lambdas assigned to a name become nodes; cross-module / dynamic / builtin calls dropped; nested fns qualified as `outer.inner`; module-entry node implicitly reaches top-level fns; ruff clean) |
| 13 | C | Per-function taint summaries | **done** (23 tests pass; `core/inventory/python_taint_summaries.py` exposes `TaintSummary` + `build_taint_summaries`; per-function fixed-point inside intra-proc CFG tracking `(param_idx, effect_chain)` atoms; outer fixed-point over call graph bails at `3×N` iterations; `summary_unknown` on `getattr`/`eval`/`exec`/`**kwargs`; `return_effects`+`call_arg_taint` answer Phase 14's two questions; ruff clean) |
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

**Goal:** the actual closure of the value-binding hole.

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
- Tests covering: the `handle(user, other)` wrong-variable case
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
    - the wrong-variable case (must NOT suppress)
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

### Phase 8 — Substrate choice + spike  *(done — chose tree-sitter)*

**Goal:** decide the platform before building on it.

**Decision: tree-sitter** (`tree-sitter-c` + `tree-sitter-cpp`).
Full writeup at `docs/phase-8-substrate-spike/DECISION.md`. Three
load-bearing reasons:

1. **Already the substrate of every existing C/C++ inventory walk**
   in RAPTOR (`core/inventory/call_graph.py:4162` for C, `:4519`
   for C++; `core/ast/view.py`'s lazy-imported grammars). Phase 9
   is reusing existing infrastructure, not adopting a new
   dependency.
2. **No build needed.** The gate runs on source. Adding libclang
   would require either reconstructing the compile DB (often
   missing) or downgrading to header-less parse, which would cost
   libclang most of its semantic advantage. r2-decomp needs a
   built artifact and loses the named-variable bindings the
   value-bound condition depends on (`safe_other` post-decomp
   becomes `local_28`).
3. **Cost shape.** 540 KB of wheels (`tree-sitter`,
   `tree-sitter-c`, `tree-sitter-cpp`) vs 150 MB of LLVM headers
   is the difference between "ship in `requirements.txt`" and
   "docker image change."

**Spike measurements** (60-LOC fixture covering the canonical
shapes: straight-line, if-branch, wrong-variable, sanitizer-in-
helper, switch + fallthrough):

- parse time: 1.73 ms cold, no parse errors
- node count: 387 (~6.5 nodes / LOC)
- def/use/call_site accuracy: 6 / 6 fixtures recover exactly what
  Phase 9 needs, including the wrong-variable soundness witness
  (`handle_wrong`: `safe_other@40` defined, but `render@41` reads
  `user` — the gate's condition 3 will correctly refuse)

**Limits the substrate doesn't change** (these stay conservative
under any choice):

- Macros that expand to control flow are opaque — we walk pre-
  preprocessor source. Phase 10's `may_escape` policy covers what
  matters.
- Function-pointer indirection is recognised syntactically; the
  pointed-at function is unknown. Phase 10 marks the result
  `may_escape`.
- K&R-style definitions parse but only ANSI prototypes give
  parameter extraction. Vanishingly rare.

**Ships:** `docs/phase-8-substrate-spike/{fixture.c,
prototype_tree_sitter.py, prototype_tree_sitter.out, DECISION.md}`.

**Gates:** Phase 9.

### Phase 9 — C/C++ intra-procedural CFG + symbol layer  *(done)*

**Goal:** the C/C++ analogue of Phase 1.

**Shipped:** `core/inventory/cfg_builder_cpp.py` exposes
`build_cpp_intraproc_cfg(source, function_name, *, language="c") ->
Optional[CPPCFG]`. `CPPCFG` is a frozen dataclass implementing
`core.inventory.dominators.Graph` (same protocol the Python CFG
satisfies). `CPPCFGNode` carries `kind`, `lineno`, `label`, `calls`,
`defs`, `uses`, `call_sites` — same field set and same
:class:`CallSite` type as `PyCFGNode` so downstream consumers
(`reaching_defs`, `match_sanitizers_in_cfg`, evaluate_finding) need
no language branch.

Control-flow handled: straight-line statements, `if`/`else` (with
bare-statement consequences and `else if` chains), `while`, `for`
(init / cond / step / body — continue targets step), `do…while`,
`switch` with case fallthrough modelled by linking consecutive
case bodies, `break` (targets the nearest switch join then nearest
loop header), `continue` (targets the nearest loop header / for-step),
`return` (links to exit, blocks fall-through), `goto` + `labeled_statement`
(conservative: a goto with no matching label flows to exit so
analysis doesn't trap), C++ methods inside `class_specifier`, C++
functions inside `namespace_definition`.

Deferred to Phase 10/11 (documented in the module docstring):
splitting ternary `?:` and short-circuit `&&` / `||` operands into
their own CFG nodes. Phase 9 keeps them as a single statement-level
node — operand calls still appear in `call_sites`, and the
conservative collapse over-suppresses rather than under-suppresses
(no soundness loss for the value-bound gate).

**Tests:** `core/inventory/tests/test_cfg_builder_cpp.py` — 32 tests
covering basic shape (entry/exit, params, function-not-found),
symbol layer (init_declarator, assignment, compound assignment,
nested call assigned_names, field-expr callable name, calls
back-compat), if/else (with and without alternative), loops
(back-edge, for init/cond/step, do-while, break, continue), switch
(branches, fallthrough, no-default-join), goto (resolved + unknown),
return (links to exit, blocks fall-through), C++ method-in-class
and namespace-wrapped, degrade-cleanly (partial parse, declaration-
only). Suite skips automatically when the tree-sitter-c/-cpp
grammars aren't installed.

**Gates:** Phase 10, Phase 11.

### Phase 10 — Pointer / alias conservatism  *(done)*

**Goal:** decide what to do about indirection without solving
field-sensitive aliasing.

**Shipped:**

* `CPPCFGNode.may_escape: bool` (default False) — stamped True by
  the Phase 9 walker when the statement contains any of:
  * `pointer_expression` — both deref (`*p`) and address-of (`&x`)
  * `subscript_expression` — `a[i]` in load or store position
  * `field_expression` with `->` operator (arrow access through a
    pointer). Plain `obj.field` is NOT flagged — it's a value
    access through a named base.
  * a call to a bulk-copy / string-build callable from
    `_BULK_COPY_FUNCS` (`memcpy`, `memmove`, `memset`, `bzero`,
    `strcpy`/`strncpy`/`strlcpy`, `strcat`/`strncat`/`strlcat`,
    `stpcpy`/`stpncpy`, `sprintf`/`snprintf`/`vsprintf`/`vsnprintf`,
    `wcscpy` and friends, `swprintf`). These write through a
    destination pointer the value-bound gate can't follow.

* `evaluate_finding` calls `_may_escape_on_path(graph, sources,
  sink)` after a value-bound cut holds. The helper does forward
  BFS from sources ∩ backward BFS to sink over the *un-cut* graph
  (the cut nodes themselves are on path and their indirection
  still counts). Any on-path node with `may_escape=True`
  downgrades `SUPPRESS → CANDIDATE_ONLY` with a reason that names
  the witness. PyCFGNode lacks the attribute so
  `getattr(..., "may_escape", False)` keeps every Python verdict
  bit-identical.

* Out of scope by design: field sensitivity, points-to analysis,
  inter-procedural alias tracking. The conservative bit lets us
  be honest about value flow without paying for a points-to
  engine.

**Tests:** `core/inventory/tests/test_phase10_may_escape.py` — 27
tests: stamping (plain assignment is not flagged; deref load /
deref store / address-of / subscript load / subscript store /
arrow field / dot field NOT flagged / 9 bulk-copy callees / if
condition / for step / entry+exit sentinels), helper behaviour
(Python returns False; un-cut C path finds it; off-path dead
branch IS flagged — conservative by design; excluded node is
treated as removed), end-to-end (Python path unchanged;
synthetic-stamped Python sink demonstrates downgrade reason;
regression that unstamped CFG still suppresses).

**Gates:** Phase 11.

### Phase 11 — Value-bound suppression for C/C++  *(done)*

**Goal:** retire the Phase 4 auto-downgrade for C/C++ when an
intra-proc CFG is available.

**Shipped:**

* `core/inventory/finding_resolver.py` extended with
  `_resolve_from_parsed_cpp` — uses tree-sitter (via the Phase 9
  helpers) to find the smallest `function_definition` spanning
  [source_line, sink_line], builds a `CPPCFG` via
  `build_cpp_intraproc_cfg`, then runs the same source / sink
  resolution algorithm as the Python branch (`cfg.params` for
  function-entry source, `node.defs` for body-source assignment,
  `node.call_sites` for sink-arg disambiguation). `ResolvedFinding`
  widened to `Union[PythonCFG, CPPCFG]` / `Union[PyCFGNode,
  CPPCFGNode]`.

* `core/dataflow/known_safe_calls.py` extended with four C/C++
  catalog entries chosen for documented library contracts:
  `g_markup_escape_text` (xss), `g_uri_escape_string` (pathtrav),
  `g_shell_quote` (cmdi), `sqlite3_mprintf` (sqli). Selection rule
  documented inline — only "transform" sanitizers that return a
  newly-allocated value qualify; destination-buffer writers
  (`mysql_real_escape_string`, `realpath`) would be downgraded by
  Phase 10's `may_escape` policy anyway and are excluded to avoid
  audit noise.

* The Phase 4 callgraph-only carve-out is preserved (callgraph
  bindings still carry empty input/output symbol sets so condition
  2 always fails — function-level edges genuinely can't prove
  argument binding). Phase 11 only retires the auto-downgrade for
  the intra-proc CFG path, when the CFG actually has `call_sites`.

* CPPCFG `call_sites` ordering fix: sort key changed from
  `start_byte` to `end_byte` so the convention matches PyCFG —
  inner calls precede their outers, `call_sites[-1]` is the
  syntactic outermost. The resolver's outermost pick now agrees
  across languages.

**Tests:** `core/inventory/tests/test_sanitizer_cut_corpus_cpp.py`
— 10 tests parametrised over 5 C fixtures
(`straight_line_safe.c`, `symmetric_sanitize.c`,
`wrong_variable.c`, `bypass.c`, `may_escape.c`) under
`fixtures/sanitizer_cut_corpus_cpp/`. Each fixture's expected
verdict is documented in its file docstring and pinned in
`CORPUS.md`'s ablation table. The wrong-variable case is the
soundness witness for C/C++ — the lexical check would have
falsely suppressed, the auto-downgrade would have emitted
candidate_only, only Phase 11's value-bound resolution catches
the wrong-binding without losing the TP cases. Also tests:
resolver returns CPPCFG (not PythonCFG); `language="cpp"` routes
the same branch; missing enclosing function → descriptive
ResolutionFailure; callgraph-only auto-downgrade still produces
empty input/output symbols.

**Gates:** Phase 15 (telemetry consumes the C/C++ value-bound
output too).

---

## Sub-arc C — Python inter-procedural taint

### Phase 12 — Module-local Python call graph  *(done)*

**Goal:** know which functions call which, within a module.

**Shipped:** `core/inventory/python_callgraph.py` exposes
`PyCallGraphNode` (frozen, hashable on `name`+`lineno`, carries
`params` / `is_method` / `class_name`), `PyModuleCallGraph`
(implements `Graph[N]`, plus `find(name)` for callee resolution
and `function_ast(name)` for Phase 13's CFG-building), and
`build_python_module_callgraph(source) -> Optional[PyModuleCallGraph]`.

Single-file scope (cross-module deferred — the design's "package
root" framing was ahead of where Phase 12 lands). Resolution
rules:

* `["f"]` → module-level `f`, or nested `caller.f` when the call
  is inside `caller`'s body
* `["self", "m"]` / `["cls", "m"]` → `caller.class_name + "." + m`
  when the caller is a method
* `["Class", "m"]` → `Class.m` when defined
* `["Class"]` → `Class.__init__` when defined (constructor)
* Anything else (cross-module, longer chains, dynamic dispatch,
  builtins, `getattr`/`eval`) → no edge

Naming: module-level fns use unqualified name (`foo`); methods
use `Class.method`; nested fns use `outer.inner` or
`Class.method.inner`. Lambdas assigned to a name become a node
named after the LHS; anonymous lambdas in expression position
are skipped (no static name to resolve from a call site).

A synthetic `<module>` entry has edges to every top-level
function and to every module-level call's resolvable callee — so
dominator queries work over the whole module.

**Tests:** `core/inventory/tests/test_python_callgraph.py` — 32
tests covering basic shape (empty module, single fn, params,
unparseable source, module-entry edges, line range, AST
accessor), edges (caller→callee, module-level, recursion,
cross-module drop, builtin drop, undefined-local drop, lambda
invocation drop, conditional call), methods (qualified naming,
`self.m`, `cls.m`, `Class.m`, constructor→__init__, missing
__init__, `self` outside a class), nested (inner fn naming,
outer→inner, nested-method-helper, lambda-as-node,
anonymous-lambda skip), graph protocol (entry / nodes /
successors surface; unreachable fn still a node; successors of
unknown node).

**Gates:** Phase 13.

### Phase 13 — Per-function taint summaries  *(done)*

**Goal:** "if I taint param `p`, does it reach return / does it
reach a callee's tainted-sink arg — and which sanitizers did the
taint pass through on the way?"

**Shipped:** `core/inventory/python_taint_summaries.py` exposes
`TaintSummary` (frozen, hashable) carrying:

* `return_effects: FrozenSet[Tuple[int, str, int]]` — each triple
  `(param_idx, callable_name, arg_idx)` says "the taint from this
  caller-param passed through this callable's arg on its way to
  the return value." The sentinel `("", -1)` means "direct return,
  no callable in between." Phase 14's sanitizer-in-helper rescue
  keys on this set.
* `call_arg_taint: FrozenSet[Tuple[str, int, int]]` — each triple
  `(callee_name, arg_idx, param_idx)` says "this function's param
  N, when tainted at the call, taints the arg at index `arg_idx`
  of the call to `callee_name`."
* `summary_unknown` + `summary_unknown_reason` — set when the
  function contains `getattr` / `setattr` / `delattr` / `eval` /
  `exec` / `compile` / `globals` / `locals` / `__import__` /
  `importlib.*` calls, or forwards `**kwargs`. Phase 14 treats
  unknown summaries as opaque and downgrades.
* `summary_unconverged` — set when the outer call-graph
  fixed-point bails at `3 × N` iterations. Phase 14 treats this
  the same as `summary_unknown`.

Plus query helpers `param_taints_return(i)`,
`return_sanitizers_for_param(i)`, `params_tainting_call_arg(callee,
arg_idx)`.

**Algorithm:**

* Per-function fixed-point inside the intra-proc CFG. Each
  `(node, symbol)` carries a `TaintState` — a frozenset of
  `(param_idx, frozenset_of_(callable, arg_idx))` atoms. The
  per-symbol IN state is `union over reaching defs`; the OUT
  state is computed by walking the AST of the defining expression
  (positional arg accuracy beats the `sorted(arg_names)` fallback).
* Return values walked via the same AST recursion, so
  `return html.escape(x)` records `(0, "html.escape", 0)` in
  `return_effects` even though no symbol-level def captures it.
* Call sites walked at each line so positional-arg taint feeds
  `call_arg_taint` correctly.
* Outer fixed-point iterates summaries over the call graph,
  bailing at `3 × N` iterations. Functions whose summary depends
  on a `summary_unknown` callee get external-stamp fallback at
  that call site (taint flows through with the callee's name as
  the effect entry).
* Nested-function dynamic dispatch doesn't poison the outer's
  summary — the unknown-detector scopes to the immediate
  function's own body.

**Tests:** `core/inventory/tests/test_python_taint_summaries.py`
— 23 tests covering primitives (identity, constant return,
transform, branching, ordered params), call_arg_taint
(external call, intermediate var, untainted arg), inter-procedural
(sanitizer-in-helper rescue, passthrough helper, two-param helper
positional resolution), cycles (recursion converges, mutual
recursion terminates), summary_unknown (getattr / eval / exec /
**kwargs / nested-doesn't-poison / normal-is-not-unknown),
coverage (all in-module fns, no `<module>` entry, lambda → unknown).

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
- **Phase 8 substrate dep.** Resolved: tree-sitter
  (`tree-sitter`, `tree-sitter-c`, `tree-sitter-cpp` — already in
  RAPTOR's optional dep set). No LLVM headers required. The cost
  is bounded by tree-sitter's surface-level parse; Phase 10's
  conservative `may_escape` policy covers the gap.
- **Phase 13 summary explosion.** A function with N taintable
  params has a summary of size up to 2^N. Cap at N=8 (typical
  function arity); over-arity functions stay `summary_unknown`.
- **Phase 15 corpus skew.** A horizon collected on the same
  finding population that's used to design the value-bound
  catches is circular. Mitigation: hold out 20% of findings as
  a verification set never seen by Phase 1–14 test design.
