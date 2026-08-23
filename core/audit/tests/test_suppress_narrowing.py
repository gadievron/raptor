"""suppress(Exception) narrowing sweep — representative regression tests.

The audit module's best-effort blocks used to run under
``contextlib.suppress(Exception)``, which ate miswiring-class
exceptions (TypeError from a wrong call shape, AttributeError from a
renamed symbol, KeyError from a moved field) forever — that exact
shape hid real miswirings in the earlier census.  These tests pin the
narrowed behaviour:

* a miswiring-class exception now PROPAGATES out of a previously
  suppressing site (fails-before test), and
* the legitimately suppressed path still passes.
"""

from __future__ import annotations

import pytest


def test_miswired_sage_store_propagates_typeerror(monkeypatch):
    """TypeError from a miswired SAGE hook call is no longer swallowed.

    ``_sage_store_observation`` narrows to ImportError (SAGE optional):
    a wrong call shape against ``store_audit_observation`` must now
    surface instead of silently disabling observation persistence.
    """
    from core.audit import orchestrator
    from core.sage import hooks

    def _miswired(*args, **kwargs):
        raise TypeError("unexpected keyword argument (miswired call shape)")

    monkeypatch.setattr(hooks, "store_audit_observation", _miswired)

    with pytest.raises(TypeError):
        orchestrator._sage_store_observation(
            "tool-confirmed observation " * 3,
            "tool_confirmation",
            "some_function",
        )


def test_slotted_outcome_attribute_rejection_still_suppressed():
    """Legitimate path: outcome objects that reject the optional
    ``review_result`` attribute (slotted/frozen) are still tolerated —
    ``_mark_dampened`` narrows to AttributeError, which covers exactly
    this duck-typing case.
    """
    from core.audit.pipeline import _mark_dampened

    class SlottedOutcome:
        __slots__ = ("hypothesis",)

        def __init__(self):
            self.hypothesis = "hypothesis text"

    item = SlottedOutcome()
    # Must not raise: setting item.review_result hits the slot wall
    # (AttributeError) and is suppressed by design.
    _mark_dampened(item, {"reason": "file pile-up"})
    assert not hasattr(item, "review_result")
