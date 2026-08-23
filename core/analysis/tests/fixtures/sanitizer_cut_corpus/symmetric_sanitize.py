"""Symmetric sanitize — both branches sanitize the right symbol.

Phase 4 verdict: suppress.

Every path crosses an html.escape on user.name; both bindings'
output_symbols={safe}; sink reads safe. All four conditions of the
gate hold.

The lexical check at smt_barrier.py:746 misses this case (sanitizer
in one branch doesn't lexically precede the sink — the if/else
structure has no single dominating line). Vertex-cut over the
union of both bindings correctly suppresses.
"""


def handle(user):
    if user.is_admin:
        safe = html.escape(user.name)  # noqa: F821 — fixture
    else:
        safe = html.escape(user.name)  # noqa: F821 — fixture
    render(safe)                       # noqa: F821 — fixture
