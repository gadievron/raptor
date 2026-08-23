"""Chained sanitizer — sanitizer's output goes through an unknown
transform before reaching the sink.

Phase 4 verdict: candidate_only.

html.escape's return flows into wrap, not into the symbol the
sink reads. Phase 3's binding has empty output_symbols on the
inner call (chained). Condition 3 fails; control-flow cut still
holds (every path crosses html.escape); → candidate_only.

The lexical check would falsely suppress this (validator line <
sink line, same function, exit-on-fail check passes for the
trivial flow). Value-bound correctly refuses.
"""


def handle(x):
    y = wrap(html.escape(x))           # noqa: F821 — fixture
    render(y)                          # noqa: F821 — fixture
