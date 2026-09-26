"""Pin the shared classifier context-window defaults.

These values are shipped behaviour: every per-finding classifier
prompt is sliced with them, so a change here changes what the LLM
sees for every finding (and the token bill per finding). This test
exists to make that change deliberate — edit the constant AND this
pin together, with the rationale argued in both directions at the
constant's comment.

Boundary/differential coverage lives with the consumers:
``packages/llm_analysis/tests/test_context_window_defaults.py``,
``packages/codeql/tests/test_context_window_defaults.py``,
``core/audit/tests/test_context_window_defaults.py``.
"""

from __future__ import annotations

from core.llm.context_window import (
    DATAFLOW_STEP_CONTEXT_LINES,
    DATAFLOW_VALIDATION_CONTEXT_LINES,
    FINDING_CONTEXT_LINES,
    NO_LINE_INFO_HEAD_LINES,
)


def test_defaults_pinned_exactly() -> None:
    assert FINDING_CONTEXT_LINES == 50
    assert NO_LINE_INFO_HEAD_LINES == 100
    assert DATAFLOW_STEP_CONTEXT_LINES == 5
    assert DATAFLOW_VALIDATION_CONTEXT_LINES == 10


def test_windows_are_positive_ints() -> None:
    # bool is an int subclass — a True/False slip would silently
    # produce 1/0-line windows.
    for value in (
        FINDING_CONTEXT_LINES,
        NO_LINE_INFO_HEAD_LINES,
        DATAFLOW_STEP_CONTEXT_LINES,
        DATAFLOW_VALIDATION_CONTEXT_LINES,
    ):
        assert type(value) is int
        assert value > 0
