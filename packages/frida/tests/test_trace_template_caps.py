"""Per-function event caps in the trace templates.

api-trace (the default ``auto_observe`` template) and
binary-flow-trace hook HOT functions (read/write/recv) and take an
ACCURATE backtrace per event — without the per-fn cap every sibling
template carries, a hostile or merely busy target floods
events.jsonl (and pays the backtrace cost) for the whole session.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_TEMPLATES = Path(__file__).resolve().parents[1] / "templates"


@pytest.mark.parametrize("name", ["api-trace.js", "binary-flow-trace.js"])
def test_trace_template_has_per_fn_cap(name: str) -> None:
    text = (_TEMPLATES / name).read_text(encoding="utf-8")
    assert "MAX_EVENTS_PER_FN" in text, f"{name} lacks the sibling cap"
    # Cap is loud, never silent (one _meta marker per fn).
    assert "cap reached" in text
    # Null-prototype counter map: the cap must be unpoisonable via
    # __proto__-named hooks (the exec-and-load idiom).
    assert "Object.create(null)" in text


@pytest.mark.parametrize("name", ["api-trace.js", "binary-flow-trace.js"])
def test_capped_hook_skips_backtrace_work(name: str) -> None:
    """Past the cap the hook must return BEFORE the Thread.backtrace
    call — the flood must stop paying the expensive part too."""
    text = (_TEMPLATES / name).read_text(encoding="utf-8")
    on_enter = text[text.index("onEnter"):]
    assert on_enter.index("capReached(") < on_enter.index(
        "callsite(",
    ), f"{name}: cap check must precede the callsite/backtrace work"
