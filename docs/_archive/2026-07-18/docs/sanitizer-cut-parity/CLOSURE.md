# Sanitizer-cut value-binding arc — closure record

This records the state of the 16-phase value-binding arc at the
point Phase 16 closed it. It is the answer to "is this done, and
what, exactly, is done?"

## What shipped (soundness goal: achieved)

The arc's reason for existing was a soundness hole flagged in PR
review: the shipped vertex-cut suppressor proved *control flow*
through a sanitizer but not *value flow*, so it would falsely
suppress cases where the sanitizer cleans the wrong symbol
(`safe = escape(other); render(user)`). That hole is closed.

The value-bound gate (`core/inventory/sanitizer_cut.py::evaluate_finding`)
now proves the sanitizer's cleaned value actually reaches the sink,
across:

* **Python intra-procedural** (phases 1–7) — symbol-aware CFG,
  reaching-defs, symbol-bound sanitizer recognition, the
  four-condition gate, the resolver, audit records, the
  `RAPTOR_SANITIZER_CUT` flag.
* **C/C++ intra-procedural** (phases 8–11) — tree-sitter CFG,
  `may_escape` pointer/alias conservatism, the resolver and catalog
  entries.
* **Python inter-procedural** (phases 12–14) — module call graph,
  per-function taint summaries, synthetic sanitizer bindings for
  in-module helpers.

All of it is gated behind `RAPTOR_SANITIZER_CUT`. The wrong-variable
witness is pinned as a regression test in both Python and C/C++
corpora.

## What did NOT ship (and why that is correct)

Phase 16's literal spec was "delete the lexical fallback bodies in
`smt_barrier.py`." **The lexical bodies were retained, not deleted.**

Phase 15 built the parity gate whose explicit rule is "Phase 16 does
not ship until parity holds twice in a row." The first parity report
(`first-report.md`) shows the gate is **not cleared**: the lexical
check and the value-bound gate are *complementary*, not equivalent.
The lexical check fires on validator-guard (`if not re.match(...):
return`) and substitution (`x = re.sub(...)`) shapes; the value-bound
gate fires on sanitizer-cut (`y = escape(x); sink(y)`) shapes.
Neither covers the other's population (`lexical_only > 0`). Deleting
the lexical bodies now would silently drop the validator/substitution
suppressions.

Removing the fallback on that basis is exactly the "remove the
fallback on vibes" that the parity phase was built to prevent. So
the honest close is: keep it, and make removal a gated, deliberate
future step rather than a premature deletion.

## The end-state, made reachable as a flag-flip

`--sanitizer-cut=strict` (legacy: `RAPTOR_SANITIZER_CUT_NO_LEXICAL=1`)
disables the lexical fallback: `validator_dominates_sink` /
`substitution_dominates_sink` then treat any verdict the value-bound
gate can't make (candidate_only, resolver failure, an uncovered
shape) as "we don't know — don't suppress," the finding surviving to
the LLM. This is the precise behaviour Phase 16's spec described
("candidate_only becomes the 'we don't know' verdict instead of
falling back to lexical"), now
available as a switch instead of a code deletion.

The switch lets the team A/B the removal end-state on real data
without touching code, and makes the eventual deletion a one-line
default change once justified.

## The tripwire

`core/dataflow/tests/test_lexical_removal_switch.py::test_parity_gate_not_cleared_lexical_must_stay`
asserts the parity baseline gate is NOT cleared. While that holds,
the lexical fallback must remain. When the value-bound gate is
extended to cover the validator/substitution shapes (or those
proposal kinds are otherwise migrated) and two real `/agentic`
windows clear the gate, that test is the signal that deletion is
finally safe.

## Remaining work to fully retire lexical

Tracked as the opening question in `HORIZON.md`:

1. Extend the value-bound gate / catalog to recognise validator-guard
   and substitution dominance (so those shapes suppress via
   `evaluate_finding`), **or** decide those proposal kinds stay
   lexical-handled permanently.
2. Collect two consecutive clearing windows from real `/agentic`
   runs via the parity shadow log.
3. Flip `RAPTOR_SANITIZER_CUT_NO_LEXICAL` to the default and delete
   the `_lexical_validator_dominates` / `_lexical_substitution_dominates`
   bodies.

Until step 2 clears, the arc is **closed for its soundness goal**
and **open for full lexical retirement**.
