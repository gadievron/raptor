"""Capability co-location does not establish a privilege-gate mitigation."""

import pytest

from packages.source_intel.analyze import CapabilityEvidence, SourceIntelResult
from packages.source_intel import render


@pytest.mark.parametrize("grade", ["same_function", "same_path", "owned_unknown"])
def test_weak_capability_grade_does_not_emit_gate(grade, monkeypatch):
    monkeypatch.setattr(render, "_privileged_cap_constant_on_line",
                        lambda *_: "CAP_SYS_ADMIN")
    record = CapabilityEvidence(
        cap_function="capable", location=("owned.c", 7),
        grade=grade, enclosing_function="owned",
    )
    result = SourceIntelResult(capabilities=(record,))
    assert render.derive_mitigations_found(result, finding_function="owned") == []


def test_weak_capability_grade_does_not_read_constant(monkeypatch):
    def forbidden_lookup(*args):
        raise AssertionError("weak-grade mitigation must not inspect source constants")

    monkeypatch.setattr(render, "_privileged_cap_constant_on_line", forbidden_lookup)
    record = CapabilityEvidence(
        cap_function="capable", location=("owned.c", 7),
        grade="same_function", enclosing_function="owned",
    )
    assert render.derive_mitigations_found(SourceIntelResult(capabilities=(record,))) == []


@pytest.mark.parametrize("function,constant,expected", [
    ("capable", "CAP_SYS_ADMIN", False),
    ("capable", None, False),
    ("ns_capable", "CAP_SYS_ADMIN", False),
])
def test_dominates_capability_withholds_gate_without_relation(function, constant, expected, monkeypatch):
    calls = []

    def owned_lookup(*args):
        calls.append(args)
        return constant

    monkeypatch.setattr(render, "_privileged_cap_constant_on_line", owned_lookup)
    record = CapabilityEvidence(
        cap_function=function, location=("owned.c", 7),
        grade="dominates", enclosing_function="owned",
    )
    entries = render.derive_mitigations_found(
        SourceIntelResult(capabilities=(record,)), finding_function="owned",
    )
    assert bool(entries) is expected
    assert entries == []
    assert calls == []
    assert record.cap_function == function
    assert record.grade == "dominates"
    assert record.location == ("owned.c", 7)
