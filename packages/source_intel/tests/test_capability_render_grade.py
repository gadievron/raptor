"""Capability co-location grades do not establish a required privilege."""

import pytest

from packages.source_intel.analyze import CapabilityEvidence
from packages.source_intel import render


@pytest.mark.parametrize("grade", ["same_path", "same_function", "owned_unknown"])
@pytest.mark.parametrize("style", ["stage_d", "exploit_plan", "agentic_variant"])
def test_weak_capability_grade_is_informational(grade, style, monkeypatch):
    def forbidden_lookup(*args):
        raise AssertionError("weak-grade prose must not inspect capability constants")

    monkeypatch.setattr(render, "_privileged_cap_constant_on_line", forbidden_lookup)
    record = CapabilityEvidence(
        cap_function="capable", location=("owned.c", 7),
        grade=grade, enclosing_function="owned",
    )
    text = render._render_capability_line(record, style)
    assert "`capable(...)`" in text and "owned.c:7" in text
    assert "`owned`" in text
    assert "does not establish" in text
    assert "Attacker must already hold" not in text
    assert "capability required to reach sink" not in text
    assert "ROOT-EQUIVALENT" not in text


def test_dominates_capability_rendering_retains_existing_tier(monkeypatch):
    calls = []

    def owned_lookup(*args):
        calls.append(args)
        return "CAP_SYS_ADMIN"

    monkeypatch.setattr(render, "_privileged_cap_constant_on_line", owned_lookup)
    record = CapabilityEvidence(
        cap_function="capable", location=("owned.c", 7),
        grade="dominates", enclosing_function="owned",
    )
    text = render._render_capability_line(record, "stage_d")
    assert "ROOT-EQUIVALENT" in text
    assert calls == [("owned.c", 7)]
