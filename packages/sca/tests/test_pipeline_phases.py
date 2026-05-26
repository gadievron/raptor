"""Tests for ``packages.sca.pipeline_phases`` — the phase
description table consumed by the CLI's stage-aware error
formatter."""

from __future__ import annotations

import pytest

from packages.sca.pipeline_phases import (
    _PHASE_DESCRIPTIONS,
    describe_phase,
)


def test_describe_phase_known_returns_description():
    """Each canonical phase name resolves to a non-empty
    description so the CLI error formatter renders
    ``error during <phase> (<description>)`` rather than just
    ``error during <phase>``."""
    desc = describe_phase("osv")
    assert desc is not None
    assert "OSV" in desc


def test_describe_phase_unknown_returns_none():
    """Unknown phase → None; CLI falls back to the short name.
    Forward-compat for a new phase shipping before its description
    is added."""
    assert describe_phase("definitely-not-a-phase") is None


def test_describe_phase_none_input_returns_none():
    """``last_stage_name()`` returns ``None`` if no stage ran;
    pass-through behaviour matters for the CLI's
    ``stage = last_stage_name(); ctx = describe_phase(stage)``
    flow."""
    # type: ignore[arg-type]
    assert describe_phase(None) is None              # noqa: ARG001


@pytest.mark.parametrize("name", [
    "discovery", "cascade", "hygiene", "supply-chain",
    "license", "osv", "reach", "findings",
    "llm-review", "triage", "impact-analysis", "emit",
])
def test_all_pipeline_stages_have_descriptions(name):
    """Every stage emitted by ``pipeline.py``'s
    ``progress.stage(...)`` calls must have a description here.
    If the pipeline grows a new stage and forgets to add the
    description, the operator-facing error message degrades
    silently. Update both sides together."""
    assert describe_phase(name) is not None, (
        f"phase {name!r} is referenced by pipeline.py but missing "
        f"from _PHASE_DESCRIPTIONS"
    )


def test_descriptions_dict_has_no_empty_strings():
    """Empty descriptions defeat the purpose; guard against
    accidental empty-string entries."""
    for name, desc in _PHASE_DESCRIPTIONS.items():
        assert desc.strip(), f"phase {name!r} has an empty description"
