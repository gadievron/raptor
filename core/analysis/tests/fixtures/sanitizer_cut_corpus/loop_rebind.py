"""Loop rebind — sanitized value rebound to unsanitized loop items
on some iterations; both definitions reach the sink.

Phase 4 verdict: candidate_only.

rd.at(sink, "y") = {escape_node, loop_assign_node}: the sanitizer
IS among the reaching definers, but so is the unsanitized loop
assignment. Condition 3's exclusivity requirement (every reaching
definer a sanitizer output) refuses — membership alone would have
falsely suppressed this real flaw.
"""


def handle(items, x):
    y = html.escape(x)                 # noqa: F821 — fixture
    for i in items:
        y = i
    render(y)                          # noqa: F821 — fixture
