"""One cell scrubber for scorecard-derived render surfaces.

``audit.py``, ``cli.py``, and ``multi_model/replay.py`` each rendered
sidecar / orchestrated_report-derived cell values (decision_class,
model, event_type) through verbatim copies of a
``sanitise_for_terminal``-based helper. That closed the terminal
control-byte lane but left markdown STRUCTURE open: cell provenance is
attacker-choosable (same-user forger; the key-unusable clamp keeps
unverified content readable), and an in-cell pipe splits the rendered
table row — forged numbers land under honest column headers in the
"paste into issues" report — while an in-cell backtick closes the
wrapping code span.

:func:`core.security.markdown_render.md_inline` is the one-home
single-line-slot discipline (newline-flattening, autofetch stripping,
control-byte escaping, pipe/backtick entity-escaping, length cap) —
this module is the scorecard-family projection of it with the cell
length bound the three copies already shared.
"""

from __future__ import annotations

from core.security.markdown_render import md_inline

# The bound the three pre-convergence copies shared: long enough for
# real rule ids / model names, short enough that a forged cell cannot
# flood a table row.
_CELL_MAX_CHARS = 64


def scrub_cell(value: object) -> str:
    """Escape + bound a sidecar-derived cell value for a single-line
    markdown/table slot."""
    return md_inline(value, max_chars=_CELL_MAX_CHARS)


__all__ = ["scrub_cell"]
