# Sanitizer-Cut: Value-Binding, Lexical Fallback, and the C/C++ Substrate Choice

Contributor-facing reference for the sanitizer-cut suppressor: the operator
interface, the `strict` end-state semantics, `shadow`-mode parity telemetry,
and the C/C++ substrate ADR. This consolidates four design/decision docs kept
during development; see `docs/_archive/2026-07-18/docs/` for the verbatim
originals (full phase-by-phase history, test counts, corpus fixtures).

## Background

The shipped sanitizer-cut suppressor started as a pure-graph vertex cut:
"every dynamic path from source to sink crosses a node that contains a
sanitizer call." That formulation is sound for control-flow but not
value-flow — it would falsely suppress cases like:

```python
def handle(user, other):
    safe_other = html.escape(other)
    render(user.name)
```

The graph cut removes the `html.escape(other)` node and the sink becomes
unreachable in the residual CFG, but `user.name` was never sanitised. A
16-phase follow-on arc closed this hole with a **value-bound** gate
(`evaluate_finding`) that additionally proves the sanitizer's *output symbol*
reaches the sink argument, across:

* **Python intra-procedural** — symbol-aware CFG (`defs`/`uses`/`call_sites`),
  reaching-definitions, symbol-bound sanitizer recognition, a four-condition
  gate producing a tri-state verdict (`suppress` / `candidate_only` /
  `no_suppress`).
* **C/C++ intra-procedural** — a tree-sitter-based CFG (see the ADR below)
  plus `may_escape` pointer/alias conservatism that downgrades `suppress` to
  `candidate_only` when indirection could route around the value check.
* **Python inter-procedural** — a module-local call graph, per-function taint
  summaries, and synthetic sanitizer bindings for in-module helper calls.

**Where this lives today** (module names below reflect the current
`core/inventory/` → `core/analysis/` split; the value-binding design predates
that move and referred to these as `core/inventory/*`):

| Concern | Module |
|---|---|
| Value-bound gate (`evaluate_finding`) | `core/analysis/sanitizer_cut.py` |
| Python / C++ CFG builders | `core/analysis/cfg_builder.py`, `core/analysis/cfg_builder_cpp.py` |
| Finding → resolved-source/sink adapter | `core/analysis/finding_resolver.py` |
| Reaching-definitions | `core/analysis/dataflow.py` |
| Python module call graph | `core/analysis/python_module_callgraph.py` |
| Inter-procedural synthetic bindings | `core/analysis/interproc.py` |
| Per-function taint summaries | `core/analysis/taint_summaries.py` |
| Reachability chokepoint | `core/analysis/reach_chokepoint.py` |
| Lexical fallback, mode config, parity telemetry | `core/dataflow/smt_barrier.py`, `core/dataflow/sanitizer_cut_config.py`, `core/dataflow/sanitizer_cut_parity.py`, `core/dataflow/known_safe_calls.py` (unchanged location) |

The lexical (regex/AST-pattern) check that predates the value-bound gate is
not removed — see "The `strict` end-state" below for why.

## Operator interface

A single mode flag on `/agentic`, `/codeql`, and `/validate` (surfaced via
`core/dataflow/sanitizer_cut_config.py`):

```
--sanitizer-cut=off|on|strict|shadow   (default: off)
--sanitizer-cut-parity-log=<path>      (default: <run_dir>/sanitizer_cut_parity.jsonl in shadow)
```

* `off` — gate disabled, lexical fallback on (default).
* `on` — gate enabled, lexical fallback on (value-bound gate decides where it
  can; lexical check decides the rest — `candidate_only`, resolver failure,
  or an uncovered shape).
* `strict` — gate enabled, lexical fallback off. See below.
* `shadow` — suppression behaves like `off`, but the value-bound verdict is
  logged alongside the lexical decision for parity telemetry (no suppression
  behaviour change).

This mode flag collapses what used to be three independent booleans, which
made two footguns representable: (1) the gate **and** the lexical fallback
both off at once (silently disabling all suppression), and (2) a
boolean-style parity-log value (`PARITY_LOG=1`) resolving to a file literally
named `1` instead of the default path. Both are fixed at the resolution
point in `sanitizer_cut_config.py`.

The legacy `RAPTOR_SANITIZER_CUT*` env vars remain a back-compat fallback and
also serve as the internal transport: a consuming command calling
`configure(..., export_env=True)` writes the resolved state to the
environment so spawned scan/analysis/codeql subprocesses inherit it.
`/validate` runs each stage as its own process, so Stage 0 additionally
persists the resolved config to `<run_dir>/sanitizer-cut-config.json` and
later stages reload it from there.

## The `strict` end-state

`--sanitizer-cut=strict` is what full lexical retirement will eventually
default to, made reachable today as a mode flip instead of a code deletion.

In `strict` mode, `validator_dominates_sink` / `substitution_dominates_sink`
treat any verdict the value-bound gate can't make — `candidate_only`,
resolver failure, or a finding shape the gate doesn't cover — as "we don't
know, so don't suppress." The finding survives to the LLM instead of falling
back to the lexical heuristic.

**Why the lexical bodies are retained, not deleted.** The literal spec for
the arc's final phase was "delete the lexical fallback bodies in
`smt_barrier.py`." They were kept, deliberately, because the parity gate
(next section) is **not cleared**: the lexical check and the value-bound gate
are *complementary*, not equivalent. The lexical check fires on
validator-guard (`if not re.match(...): return`) and substitution
(`x = re.sub(...)`) shapes; the value-bound gate fires on sanitizer-cut
(`y = escape(x); sink(y)`) shapes. Neither covers the other's population.
Deleting the lexical bodies on that basis would silently drop the
validator/substitution suppressions — exactly the "remove the fallback on
vibes" outcome the parity gate exists to prevent.

`smt_barrier.lexical_fallback_status()` is the introspection surface: it
reports whether the fallback is active and why it's retained. A closure
tripwire test
(`core/dataflow/tests/test_lexical_removal_switch.py::test_parity_gate_not_cleared_lexical_must_stay`)
asserts the parity baseline gate is NOT cleared. While that holds, the
lexical fallback must stay. When it flips, that's the signal that deletion
is finally safe.

**Remaining steps to fully retire lexical:**

1. Extend the value-bound gate/catalog to recognise validator-guard and
   substitution dominance (so those shapes suppress via `evaluate_finding`),
   **or** decide those proposal kinds stay lexical-handled permanently.
2. Collect two consecutive clearing windows from real `/agentic` runs via the
   parity shadow log (see below).
3. Flip `RAPTOR_SANITIZER_CUT_NO_LEXICAL` (`--sanitizer-cut=strict`) to the
   default and delete the `_lexical_validator_dominates` /
   `_lexical_substitution_dominates` bodies.

Until step 2 clears, the gate is closed for its soundness goal (the
wrong-variable hole is closed across Python intra+inter and C/C++, behind the
flag, with regression witnesses) and open for full lexical retirement.

## `shadow` mode: parity telemetry and regeneration

The contract for retiring the lexical fallback is empirical, not intuition:
the value-bound gate must be shown, on real findings, to suppress at least as
much noise and hide no more real findings than the lexical check before the
fallback comes out.

**Collection.** `--sanitizer-cut=shadow` records both the lexical decision
and the value-bound verdict for every finding, independent of whether the
gate is actually suppressing anything:

```bash
# /agentic, /codeql, /validate all accept:
--sanitizer-cut=shadow                                  # telemetry, default log path
--sanitizer-cut=shadow --sanitizer-cut-parity-log=/path/to/x.jsonl
```

The legacy env var still works as a back-compat fallback (resolved through
`core/dataflow/sanitizer_cut_config.py`, which fixes the `PARITY_LOG=1`
footgun described above):

```bash
export RAPTOR_SANITIZER_CUT_PARITY_LOG=/path/to/sanitizer-cut-parity.jsonl
```

The hook is a no-op with zero overhead when no log path is configured. Each
record carries the lexical decision, the value-bound verdict, the proposal
`kind`, and an optional ground-truth label (`should_suppress` /
`should_not_suppress`) from operator triage — a record without a label counts
toward the agreement matrix but not the rates.

**The window.** Collect over the smaller of 200 findings or 4 weeks of
`/agentic` runs. A window with fewer than ~30 labelled findings on either
axis is under-powered — report it, don't gate on it.

**The gate** (`parity_criterion_met` in `core/dataflow/sanitizer_cut_parity.py`)
requires all three:

1. **Both axes non-empty** — at least one `should_suppress` and one
   `should_not_suppress` finding.
2. **Rate criterion** — value-bound noise-suppression rate ≥ lexical, and
   value-bound bug-hiding rate ≤ lexical (Wilson 95% CIs reported alongside
   the point estimates).
3. **No per-finding regression** — zero findings the lexical check
   suppressed that the value-bound gate did not (`lexical_only == 0`).

Condition 3 is the one a bare rate criterion misses: equal aggregate rates
can still mean the value-bound gate abandoned a whole population (a
different finding *shape*) that the lexical check was covering.

**Failure mode.** If a window fails the gate: file the specific
`lexical_only` findings (and any rate-axis regressions) as bug fixtures, fix
the value-bound gap — typically by extending the gate or sanitizer catalog to
cover the shape the lexical check was carrying — and restart the window. The
two-in-a-row requirement resets.

**Regenerating a parity report.** The synthetic baseline/smoke-test report is
produced by:

```bash
RAPTOR_SANITIZER_CUT=1 core/dataflow/scripts/sanitizer-cut-parity-report
```

That script exercises `core/dataflow/sanitizer_cut_parity_report.py` against
a small fixture set — it proves the telemetry machinery end-to-end, it is
**not** the real gating window. To aggregate a real collected shadow-log into
a report, load it with `read_parity_records` and `render_parity_report` from
`core/dataflow/sanitizer_cut_parity.py`.

On the synthetic baseline the gate is correctly **not cleared**: the lexical
check fires on `charset`/`charset_sub` (validator-guard/substitution) kinds
the value-bound gate doesn't cover, and the value-bound gate fires on
`sanitizer_cut` kinds the lexical check doesn't reach — `lexical_only > 0`,
so removal is not yet safe. This is exactly the complementary-coverage case
condition 3 above exists to catch.

## ADR: C/C++ substrate — tree-sitter vs. libclang vs. r2-decomp

**Decision: tree-sitter** (`tree-sitter-c` + `tree-sitter-cpp`), for the
C/C++ intra-procedural CFG that the value-bound gate reads from
(`core/analysis/cfg_builder_cpp.py`).

| Axis | tree-sitter | libclang | r2-decomp |
|------|-------------|----------|-----------|
| Existing repo investment | call graph, extractors, `ast/view`, inventory all use it already | none | in tree, but never on the source path |
| Dep weight | 3 wheels, ~540 KB total | LLVM dev headers + `clang` Python pkg (~150 MB system install) | r2 binary + r2pipe; needs a built artifact |
| Source vs. binary | pre-preprocessor source — what we have | source, post-preprocessor — needs `#include` resolution + a working compile DB | binary only — useless without a build |
| Semantic completeness | surface-level AST (no types, no overload resolution) | full Sema (types, templates, overloads, macro expansion) | recovered pseudo-C — types partial, bindings lossy |
| Error mode | recovers on partial input; `has_error` flag per subtree | fails loudly on missing headers / compile errors / unknown macros | fails on stripped binaries; opaque on optimised builds |
| Macro handling | macros are tokens (`BUG_ON(x)` looks like a call to `BUG_ON`) | expands macros — sees the real `if (...)` body | post-compile, macros gone |
| Cost in CI | ~1.7 ms / 60 LOC parse; pure-C wheels | needs an LLVM install in the CI image | needs r2 + build artifacts; not a CI fit |

**Why tree-sitter wins:**

1. Already the substrate of every C/C++ inventory walk RAPTOR ships
   (`core/inventory/call_graph.py` for both C and C++) — this is reuse, not a
   new dependency.
2. No build needed. The gate runs on the source-only inventory walk; libclang
   would need either a reconstructed compile DB (often missing) or a
   header-less parse that gives up most of its semantic advantage.
3. Robust on partial input — vendored headers that can't be resolved,
   conditional `#if` blocks, custom toolchain extensions still produce a
   partial CFG instead of a hard parse failure.
4. Cost shape: 540 KB of wheels vs. 150 MB of LLVM headers is the difference
   between "ship by default" and "docker image change."

**Why not libclang.** The semantic completeness is real, but the gate's
value-bound check only needs to know which symbols are defined/used per
statement — a surface property that types don't change for the canonical
shapes. The alias policy is conservative by design (any indirection marks
`may_escape` and downgrades to `candidate_only` rather than attempting
points-to analysis), so libclang's alias-resolution machinery would go
unused. The intra-proc-CFG-availability carve-out already gives an honest
fallback for cases tree-sitter can't handle (template instantiation,
macro-heavy code, function-pointer typedefs); adding libclang doesn't change
the size of that set in a way that matters for the ablation.

**Why not r2-decomp.** It needs a built binary, but the sanitizer-cut gate
runs on findings from source-only tools (Semgrep, CodeQL, `/agentic`) —
requiring a build to validate them would gate the gate. More fundamentally,
recovered pseudo-C loses the named-variable bindings the value-bound
condition depends on: `safe_other` becomes `local_28` post-decomposition,
so there's no symbol left to compare against `user` for the wrong-variable
check. Binary evidence already feeds the reachability chokepoint via DWARF
(the binary-oracle path) — that's the right shape of "use binary evidence";
decompilation for this purpose isn't.

**Limits that hold regardless of substrate choice:** macros that expand to
control flow are opaque (pre-preprocessor source); function-pointer
indirection is recognised syntactically but the pointed-at function is
unknown (both are covered by the `may_escape` conservatism); K&R-style
definitions parse but only ANSI prototypes give parameter extraction
(vanishingly rare in practice).

**Revisit trigger:** re-open this decision if a future phase needs
cross-translation-unit analysis — inter-procedural C/C++ would lean on the
linker/LTO graph, which is a materially different problem from the
intra-procedural, single-TU parse tree-sitter answers today.
