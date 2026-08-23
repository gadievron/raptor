"""Sanitizer in helper — sanitisation happens in a callee.

Phase 4 verdict: candidate_only (under intra-procedural analysis).

The inner ``inner`` function's body sanitises and returns, but the
gate runs intra-procedurally on the enclosing function. The catalog
recognizer sees no html.escape directly in ``handle``'s body —
match set is empty → no_suppress, actually, not candidate_only.

This fixture demonstrates the Phase 12-14 inter-procedural gap.
Phase 14 (Sub-arc C) will use call-graph + taint summaries to
suppress this correctly. Until then, the conservative no_suppress
is the right answer.
"""


def _sanitize(s):
    return html.escape(s)              # noqa: F821 — fixture


def handle(x):
    y = _sanitize(x)
    render(y)                          # noqa: F821 — fixture
