# Sanitizer-cut value-binding corpus

Hand-built fixtures pinning the Phase 7 ablation between the
shipped lexical check and the value-bound gate. Each file is a
Python source with a single ``handle`` function, plus a docstring
explaining what the expected verdict is and why.

The corresponding test, `test_sanitizer_cut_corpus.py`, parametrises
over these fixtures and asserts the value-bound gate lands the
right verdict for each. The corpus is small but covers the canonical
shapes the design doc enumerates.

| Fixture | Expected verdict | Lexical-only path | Notes |
|---------|------------------|-------------------|-------|
| `straight_line_safe.py` | `suppress` | suppresses correctly | TP — both paths agree |
| `symmetric_sanitize.py` | `suppress` | misses (sibling branch) | Value-bound wins — the design's motivating case |
| `wrong_variable.py` | `candidate_only` | falsely suppresses | Value-bound catches the FP — the design's soundness witness |
| `chained_sanitizer.py` | `candidate_only` | falsely suppresses | Phase 3's empty output_symbols on the nested call |
| `sanitization_overwritten.py` | `candidate_only` | undefined (no AST handling) | Phase 2's reaching-defs catch the rebind |
| `bypass.py` | `no_suppress` | undefined | Real bug — neither suppresses |
| `sanitizer_in_helper.py` | `no_suppress` (intra) → `suppress` (inter, Phase 14) | undefined | Phase 14's inter-procedural synthetic binding rescues this |

## Ablation

The harness in `test_sanitizer_cut_corpus.py::test_ablation_report`
runs each fixture through both paths and writes a report. The
expected delta:

* **Lexical-only**: suppresses straight-line-safe, wrong-variable,
  chained-sanitizer, sanitization-overwritten — 3 of those 4 are
  false suppressions (real bugs hidden).
* **Value-bound**: suppresses straight-line-safe, symmetric-
  sanitize. Refuses the other 5 cases (candidate_only or
  no_suppress). 0 false suppressions on this corpus; 2 confirmed
  drops; 5 sent to the LLM for triage.

Phase 14 (inter-procedural) landed: with the resolver's synthetic
sanitizer bindings passed as `evaluate_finding(...,
extra_bindings=...)`, `sanitizer_in_helper.py` flips from
no_suppress to suppress — and none of the others change, because
they call `html.escape` directly or a non-sanitizing callee and
so produce no synthetic binding. The
`test_corpus_fixture_verdict_interproc` test and the
`test_corpus_ablation_summary` A/B table pin this.
