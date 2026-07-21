"""Wrong-variable case — sanitizer cleans the wrong symbol.

Phase 4 verdict: candidate_only.

The control-flow cut holds (removing html.escape disconnects the
sink), but ``safe_other`` never reaches the sink — the sink reads
``user`` instead. The shipped pre-Phase-4 vertex-cut would falsely
suppress; the value-bound gate refuses.
"""


def handle(user, other):
    safe_other = html.escape(other)  # noqa: F821, F841 — fixture, not run
    render(user.name)                # noqa: F821 — fixture, not run
