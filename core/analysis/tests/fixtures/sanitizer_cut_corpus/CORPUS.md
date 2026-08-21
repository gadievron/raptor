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
| `loop_rebind.py` | `candidate_only` | undefined | Converging defs: condition 3's exclusivity requirement — membership among reaching definers alone falsely suppressed this before the fix |
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

## b19 — element-sensitive arrays + wrapper summaries

| fixture | shape | expected verdict |
| --- | --- | --- |
| `array_element_java.java` | tracked local array, element written only by a catalog sanitizer, one scalar hop to the sink | suppress |
| `wrapper_helper_java.java` | private static same-class wrapper returning the sanitizer applied to its argument | suppress (via synthetic wrapper binding) |

The full adversarial batteries (element rebind/mismatch/aliasing/
escape/poison shapes; wrapper depth/dispatch/overload/branch/mixed-
param refusals) live in `sanitizer_cut_precision.py` —
`_java_array_fixtures()` / `_java_wrapper_fixtures()`. The
pre-existing `java_xss_array_store_escape` precision fixture was
re-shaped at b19: its array was local, fresh, and never read, which
element tracking legitimately proves irrelevant to the sanitized
scalar sink; an alias line now makes the array genuinely untracked so
the fixture keeps guarding "escaping arrays block the exemption".
| `conduit_transparency_java.java` | sanitized value through a returns-param conduit helper — value-transparent hop | suppress (conduit transparency) |
| `conduit_tainted_java.java` | the same conduit with the raw request value (decoy sanitizer keeps the catalog non-empty) — transparency must not launder taint | candidate_only (survives) |
