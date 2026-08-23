"""Sanitization overwritten — sanitizer call ran but the cleaned
value is rebound to the raw input before the sink.

Phase 4 verdict: candidate_only.

The sanitizer's def of y is killed by the rebind. Phase 2's
reaching-defs show rd.at(sink, "y") = {rebind_node}; the
sanitizer's node isn't a reaching definer. Condition 3 fails.
Control-flow cut still holds structurally (html.escape on every
control-flow path entry → sanitize → rebind → sink).
→ candidate_only.
"""


def handle(x):
    y = html.escape(x)                 # noqa: F821 — fixture
    y = x                              # rebind kills the sanitization
    render(y)                          # noqa: F821 — fixture
