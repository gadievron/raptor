"""Straight-line safe — the simplest case: sanitize then sink the
sanitised value.

Phase 4 verdict: suppress.

x flows in to html.escape, y flows out, sink reads y. All four
conditions hold trivially. The lexical check also gets this right.
"""


def handle(x):
    y = html.escape(x)                 # noqa: F821 — fixture
    render(y)                          # noqa: F821 — fixture
