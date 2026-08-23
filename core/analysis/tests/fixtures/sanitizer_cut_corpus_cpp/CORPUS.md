# Sanitizer-cut value-binding corpus — C / C++

Phase 11's analog of the Python corpus under
``sanitizer_cut_corpus/``. Five hand-built C fixtures pinning the
ablation between the shipped lexical check and the value-bound
gate over the new C/C++ resolver wiring.

The corresponding test, `test_sanitizer_cut_corpus_cpp.py`,
parametrises over these fixtures and asserts that the value-bound
gate (now driven from a real `CPPCFG` rather than the Phase 4
auto-downgrade) lands the right verdict for each.

| Fixture | Expected verdict | Lexical-only path | Notes |
|---------|------------------|-------------------|-------|
| `straight_line_safe.c` | `suppress` | suppresses correctly | TP — both paths agree |
| `symmetric_sanitize.c` | `suppress` | misses (sibling branch) | Value-bound wins — design's motivating case |
| `wrong_variable.c` | `candidate_only` | falsely suppresses | Value-bound catches the FP — soundness witness |
| `bypass.c` | `no_suppress` | undefined | Real bug — neither suppresses |
| `may_escape.c` | `candidate_only` | undefined | Phase 10's may_escape downgrade fires |

## Ablation (Phase 11 vs pre-Phase-11 C/C++ behaviour)

* **Pre-Phase-11** (the shipped Phase 4 auto-downgrade): every C/C++
  finding returned `candidate_only` because callgraph bindings
  carried empty input/output symbol sets, so condition 2 never
  fired. 5/5 candidate_only — even the TP cases lose suppression.
* **Phase 11** (resolver builds a real `CPPCFG` via tree-sitter):
  bindings now carry real `CallSite.arg_names` and
  `CallSite.assigned_names`, so conditions 2 and 3 fire properly.
  2 suppress, 3 candidate_only / no_suppress.

The wrong-variable case is the soundness witness: the lexical
check would have falsely suppressed (a recognised sanitizer
appears in the function body), the auto-downgrade would have
emitted candidate_only, and only Phase 11's value-bound resolution
correctly catches the wrong-binding without losing the TP cases.
