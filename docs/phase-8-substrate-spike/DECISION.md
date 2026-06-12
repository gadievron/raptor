# Phase 8 — C/C++ substrate decision

**Decision: tree-sitter** (`tree-sitter-c` + `tree-sitter-cpp`).

This document is the spike's writeup. Numbers in the "tree-sitter"
column come from running
`docs/phase-8-substrate-spike/prototype_tree_sitter.py` against
`fixture.c` (60 lines, 6 canonical shapes — straight-line, if-branch,
wrong-variable, sanitizer-in-helper, switch, plus declarations). The
other two columns are paper-comparison; no prototype was built for
libclang or r2-decomp because they were eliminated on dependency
weight and substrate fit (see below).

## Comparison

| Axis | tree-sitter | libclang | r2-decomp |
|------|-------------|----------|-----------|
| **Existing repo investment** | call_graph, extractors, ast/view, inventory all use it | none | r2 is in tree but never on the source path |
| **Dep weight** | 3 wheels, ~540 KB total | LLVM dev headers + `clang` Python pkg (~150 MB system install) | r2 binary + r2pipe; needs a built artifact |
| **Source vs binary** | pre-preprocessor source — what we have | source, post-preprocessor — needs `#include` resolution + a working compile DB | binary only — useless without a build |
| **Semantic completeness** | surface-level AST (no types, no overload resolution) | full Sema (types, templates, overloads, macro expansion) | recovered pseudo-C — types are partial, bindings lossy |
| **Error mode** | recovers on partial input; `has_error` flag per subtree | fails loudly on missing headers, compile errors, unknown macros | fails on stripped binaries; opaque on optimised builds |
| **Macro handling** | macros are tokens; `BUG_ON(x)` looks like a call to `BUG_ON` | expands macros — sees the real `if (...)` body | post-compile, macros gone |
| **Cost in CI** | parse is ~1.7 ms / 60 LOC; grammars are pure-C wheels | needs LLVM install in CI image; significant install cost | needs r2 + build artifacts; not a CI fit |
| **Spike measurement (60 LOC fixture)** | parse 1.73 ms, 387 nodes, `has_error: False`, 6/6 canonical shapes recovered | not run | not run |

### Why tree-sitter wins

1. **Already the substrate of choice.** RAPTOR uses tree-sitter for
   every C/C++ inventory walk shipped today (`call_graph.py:4162`
   for C, `:4519` for C++). Phase 9 is reusing existing infrastructure,
   not adopting a new dependency.
2. **No build needed.** The sanitizer-cut gate runs on the inventory
   walk, which is source-only. Adding libclang would mean either
   reconstructing the compile DB (often missing) or downgrading to
   "best-effort header-less parse," which costs libclang most of
   its semantic advantage.
3. **Robustness on partial input.** Real targets include vendored
   headers we can't resolve, conditional `#if` blocks, custom
   toolchain extensions. tree-sitter's error recovery means we get
   partial CFGs for these cases; libclang refuses to parse them.
4. **Cost shape.** 540 KB of wheels vs 150 MB of LLVM is the
   difference between "ship by default in `requirements.txt`" and
   "optional extra requiring docker-image changes."

### Why not libclang

The semantic completeness is real — type resolution, overload
resolution, macro expansion. But:

* The gate's value-bound check only needs to know which symbols are
  defined/used at each statement. That's a surface property; types
  don't change the answer for the canonical shapes.
* The Phase 10 alias policy is conservative-by-design: any indirection
  marks the symbol set as `may_escape` and downgrades to
  `candidate_only`. We're not solving points-to. So libclang's
  alias-resolution machinery would be unused.
* The Phase 4 auto-downgrade gives us an honest fallback for the
  cases tree-sitter can't handle (template instantiation, macro-heavy
  kernel code, function-pointer typedefs). Phase 11 only retires the
  downgrade *when an intra-proc CFG is available* — adding libclang
  doesn't change the size of that set in a way that matters for the
  ablation.

Revisit this decision if a future phase needs cross-translation-unit
analysis (Phase 12+ inter-procedural for C/C++ would lean on the
linker / LTO graph; that's an open question for sub-arc B+1, not
now).

### Why not r2-decomp

* It needs a built binary. The sanitizer-cut gate runs on findings
  emitted by source-only tools (Semgrep, CodeQL, `/agentic`).
  Requiring a build to validate them would gate the gate.
* The recovered pseudo-C loses the named-variable bindings the
  value-bound condition relies on. `safe_other` in `handle_wrong`
  becomes `local_28` post-decomp — there is no symbol to compare
  against `user`. The wrong-variable check degenerates to "is the
  sink's argument register the same as some sanitized register,"
  which doesn't generalise.

Binary oracle already feeds the chokepoint via DWARF; that's the
right shape of "use binary evidence." Decompilation isn't.

## Spike measurements

From `prototype_tree_sitter.out` (full file co-located):

```
parse_ms: 1.73
node_count: 387
has_errors: False
```

Per-function extraction accuracy (hand-graded against `fixture.c`):

| Function | Defs expected | Defs got | Uses expected | Uses got | Call sites expected | Call sites got | Verdict |
|----------|---------------|----------|---------------|----------|---------------------|----------------|---------|
| `handle_straight` | `{y@23}` | `{y@23}` | `{x@23, y@24}` | `{x@23, y@24}` | `{escape_html@23, render@24}` | `{escape_html@23, render@24}` | ✓ |
| `handle_branch` | `{out@31, out@33}` | `{out@31, out@33}` | `{x@31, x@33, out@35}` | `{x@31, x@33, out@35}` | `{escape_html@33, render@35}` | `{escape_html@33, render@35}` | ✓ |
| `handle_wrong` | `{safe_other@40}` | `{safe_other@40}` | `{other@40, user@41}` | `{other@40, user@41}` | `{escape_html@40, render@41}` | `{escape_html@40, render@41}` | ✓ (soundness witness) |
| `_sanitize` | `{}` (leaf return) | `{}` | `{s@46}` | `{s@46}` | `{escape_html@46}` | `{escape_html@46}` | ✓ |
| `handle_helper` | `{y@48}` | `{y@48}` | `{x@48, y@49}` | `{x@48, y@49}` | `{_sanitize@48, render@49}` | `{_sanitize@48, render@49}` | ✓ |
| `handle_switch` | `{out@54, out@56}` | `{out@54, out@56}` | `{x@54, x@56, out@57, x@58}` | `{x@54, x@56, out@57, x@58}` | `{escape_html@56, render@57, render@58}` | `{escape_html@56, render@57, render@58}` | ✓ |

6 / 6 fixtures recover defs / uses / call_sites exactly. The walker
emits a duplicate call_site per `call_expression` (descent picks up
the same node twice on the `_walk_uses_and_calls` second pass) — a
known artifact of the throwaway walker, not the substrate.
Phase 9 dedupes by `(callee, lineno, args)` so this is cosmetic.

Parameters (`x`, `user`, `other`, `s`, etc.) aren't shown in the
"defs" column above — they're recovered from the
`function_declarator`'s parameter list in Phase 9's full walker
(analog of `PythonCFG.params`), not from the body init_declarator
pass the spike exercises.

## Limits the substrate doesn't change

These are conservative-by-design and stay so under any substrate:

* Macros that expand to control flow are opaque (we walk pre-preprocessor
  source). `BUG_ON(x)` looks like a call to `BUG_ON`. libclang would
  see the expanded `if (...)`, but the inventory walk already lives
  with this and Phase 10's `may_escape` policy catches the rest.
* Function-pointer indirection (`(*fp)(...)`) is recognised
  syntactically; the pointed-at function is unknown. Phase 10 marks
  the call result as `may_escape`.
* K&R-style function definitions parse but the declarator walk only
  handles ANSI prototypes. Vanishingly rare in real targets.

## Deliverables (Phase 8 ships)

This `DECISION.md` records the choice. The one-shot spike artifacts
(`fixture.c`, `prototype_tree_sitter.py`, `prototype_tree_sitter.out`)
referenced throughout this doc were research outputs that won't be
re-run; they were removed once the decision landed (review #9 on PR
\#794) and remain recoverable from git history. The production
tree-sitter walker lives in `core/inventory/cfg_builder_cpp.py`.

- `docs/design-sanitizer-cut-value-binding.md` Phase 8 row flipped
  to `done — chose tree-sitter`.

Phase 9 starts here: build `core/inventory/cfg_builder_cpp.py` (the
C/C++ analog of `cfg_builder.py`) on top of `tree-sitter-c` and
`tree-sitter-cpp`, returning `CPPCFGNode` matching the `Graph[N]`
Protocol.
