"""Bypass — sanitizer only on one branch; the other reaches the
sink unsanitised.

Phase 4 verdict: no_suppress.

The control-flow cut fails entirely (removing html.escape leaves
the else-branch path intact: entry → cond → else_assign → sink).
This is a real bug that survives to the LLM.
"""


def handle(user):
    if user.is_admin:
        safe = html.escape(user.name)  # noqa: F821 — fixture
    else:
        safe = user.name
    render(safe)                       # noqa: F821 — fixture
