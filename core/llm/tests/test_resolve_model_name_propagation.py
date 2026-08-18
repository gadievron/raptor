"""Miswiring-class exceptions must propagate out of ``resolve_model_name``.

Representative fails-before test for the suppress(Exception)-narrowing
sweep: ``resolve_model_name`` used to wrap its shorthand resolution in
``except Exception: pass``, which swallowed the two deliberate fail-loud
signals raised by ``core.security.llm_family.resolve_model_shorthand``
(TypeError for a misrouted non-string, ValueError for an ambiguous
shorthand) and would also have hidden any future call-shape drift.
"""

from __future__ import annotations

import pytest

from core.llm.model_data import resolve_model_name
from core.security import llm_family


def test_miswiring_typeerror_propagates(monkeypatch) -> None:
    """A TypeError from a drifted callee signature is no longer eaten."""

    def _boom(*args, **kwargs):
        raise TypeError("simulated call-shape drift")

    monkeypatch.setattr(llm_family, "resolve_model_shorthand", _boom)
    with pytest.raises(TypeError, match="call-shape drift"):
        resolve_model_name("haiku")


def test_designed_ambiguity_valueerror_propagates(monkeypatch) -> None:
    """The operator-facing ambiguity signal reaches the operator."""

    def _ambiguous(*args, **kwargs):
        raise ValueError("ambiguous model shorthand 'haiku'")

    monkeypatch.setattr(llm_family, "resolve_model_shorthand", _ambiguous)
    with pytest.raises(ValueError, match="ambiguous model shorthand"):
        resolve_model_name("haiku")


def test_misrouted_non_string_raises() -> None:
    """End-to-end: llm_family's own non-string guard now surfaces."""
    with pytest.raises(TypeError, match="must be str or None"):
        resolve_model_name(123)  # type: ignore[arg-type]


def test_legitimate_paths_still_pass() -> None:
    """Pass-through semantics for known and unknown names are intact."""
    # A full known model name short-circuits before shorthand logic.
    assert resolve_model_name("claude-opus-4-6") == "claude-opus-4-6"
    # An unknown name with no shorthand match passes through unchanged.
    assert (
        resolve_model_name("totally-unknown-model-xyz")
        == "totally-unknown-model-xyz"
    )


def test_default_resolution_failure_falls_through(monkeypatch) -> None:
    """A legitimately unreadable models.json keeps 'default' best-effort."""
    import core.llm.config as llm_config

    def _oserror(*args, **kwargs):
        raise OSError("simulated unreadable models.json")

    monkeypatch.setattr(llm_config, "_get_default_primary_model", _oserror)
    assert resolve_model_name("default") == "default"
