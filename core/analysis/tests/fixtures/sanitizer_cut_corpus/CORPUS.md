# Sanitizer-cut value-binding corpus

Hand-built fixtures pinning the Phase 7 ablation between the
shipped lexical check and the value-bound gate. Each file is a
Python source with a single ``handle`` function, plus a docstring
explaining its historical graph-cut shape. Current verdicts additionally
require the source contracts listed below.

The corresponding test, `test_sanitizer_cut_corpus.py`, parametrises
over these fixtures and asserts the value-bound gate lands the
right verdict for each. The corpus is small but covers the canonical
shapes the design doc enumerates.

| Fixture | Expected verdict | Lexical-only path | Notes |
|---------|------------------|-------------------|-------|
| `straight_line_safe.py` | `candidate_only` | historically suppresses | The untyped input has no exact builtin-string evidence |
| `symmetric_sanitize.py` | `candidate_only` | misses sibling branch | The graph cut holds; the attribute input remains untyped |
| `wrong_variable.py` | `candidate_only` | falsely suppresses | Value-bound catches the FP — the design's soundness witness |
| `chained_sanitizer.py` | `candidate_only` | falsely suppresses | Phase 3's empty output_symbols on the nested call |
| `sanitization_overwritten.py` | `candidate_only` | undefined (no AST handling) | Phase 2's reaching-defs catch the rebind |
| `bypass.py` | `no_suppress` | undefined | Real bug — neither suppresses |
| `loop_rebind.py` | `candidate_only` | undefined | Converging defs: condition 3's exclusivity requirement — membership among reaching definers alone falsely suppressed this before the fix |
| `sanitizer_in_helper.py` | `no_suppress` (intra) to `candidate_only` (inter) | undefined | The summary preserves the unresolved input requirement |

## Ablation

`test_sanitizer_cut_corpus.py::test_corpus_ablation_summary` records the
current intra/inter-procedural outcomes. No Python fixture here establishes
`exact_builtin_str_default_call`; none may suppress merely because a graph
cut or helper summary exists. The helper changes from `no_suppress` to
`candidate_only` with inter-procedural bindings. Positive primitive-input
admission is tested separately in the source-contract and value-binding
unit tests.

The original Phase 7 drop counts described a weaker graph-only model.
They are historical results, not current validation of library input
semantics. These expectations retain catalog candidates and assert the
unresolved contract instead of adding corpus-specific engine rules.

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
