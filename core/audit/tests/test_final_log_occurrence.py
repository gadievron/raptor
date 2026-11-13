"""Owned verified-log identity; no verdict assurance."""
import json

import pytest

from core.audit import orchestrator as orch
from core.audit.record import append_audit_log, load_verified_audit_log


def test_verified_sibling_status_cannot_hide_another_occurrence_correction(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    target, out = tmp_path / "target", tmp_path / "out"
    target.mkdir()
    out.mkdir()
    (target / "unit.c").write_text("#ifdef FIRST\nunsigned f(unsigned n) { return n; }\n#else\nunsigned f(unsigned n) { return n + 1; }\n#endif\n")
    append_audit_log(out, {"action": "orchestrator_review", "key": "unit.c:f:2", "status": "clean"})
    append_audit_log(out, {"action": "orchestrator_review", "key": "unit.c:f:4", "status": "suspicious"})
    rows = load_verified_audit_log(out)
    assert len(rows) == 2
    first = orch.ReviewOutcome("unit.c", "f", "suspicious", "Owned corrected first status", line=2)
    sibling = orch.ReviewOutcome("unit.c", "f", "suspicious", "Owned sibling status", line=4)
    updated = orch._relog_final_statuses(orch.OrchestratorResult(outcomes=[first, sibling], suspicious=2),
                                        orch.OrchestratorConfig(target_path=target, out_dir=out))
    rows = load_verified_audit_log(out)
    assert len(rows) == 3 and rows[-1]["key"] == "unit.c:f:2"
    assert rows[-1]["status"] == "suspicious" and rows[-1]["final_status_correction"] is True
    assert updated == 1
    assert "strategies" not in rows[-1]
    assert orch._relog_final_statuses(orch.OrchestratorResult(outcomes=[first, sibling], suspicious=2),
        orch.OrchestratorConfig(target_path=target, out_dir=out)) == 0


@pytest.mark.parametrize("mode", ["bare_only", "bare_with_sibling", "bare_with_zero", "multiple_current",
                                 "canonical_zero_only", "zero_with_sibling"])
def test_legacy_fallback_is_separate_from_canonical_occurrence_history(tmp_path, monkeypatch, mode):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    target, out = tmp_path / "target", tmp_path / "out"
    target.mkdir()
    out.mkdir()
    (target / "unit.c").write_text("#ifdef FIRST\nunsigned f(unsigned n) { return n; }\n#else\nunsigned f(unsigned n) { return n + 1; }\n#endif\n")
    unknown = mode in {"canonical_zero_only", "zero_with_sibling"}
    key = "unit.c:f:0" if unknown else "unit.c:f"
    append_audit_log(out, {"action": "orchestrator_review", "key": key, "status": "clean"})
    if mode in {"bare_with_sibling", "zero_with_sibling"}:
        append_audit_log(out, {"action": "orchestrator_review", "key": "unit.c:f:4", "status": "clean"})
    elif mode == "bare_with_zero":
        append_audit_log(out, {"action": "orchestrator_review", "key": "unit.c:f:0", "status": "clean"})
    before = len(load_verified_audit_log(out))
    first = orch.ReviewOutcome("unit.c", "f", "suspicious", "Owned final status", line=0 if unknown else 2)
    outcomes = [first]
    if mode == "multiple_current":
        outcomes.append(orch.ReviewOutcome("unit.c", "f", "suspicious", "Owned sibling status", line=4))
    eligible = mode in {"bare_only", "canonical_zero_only", "zero_with_sibling"}
    updated = orch._relog_final_statuses(orch.OrchestratorResult(outcomes=outcomes, suspicious=len(outcomes)),
                                        orch.OrchestratorConfig(target_path=target, out_dir=out))
    rows = load_verified_audit_log(out)
    assert updated == int(eligible) and len(rows) == before + int(eligible)
    if eligible:
        assert rows[-1]["key"] == f"unit.c:f:{first.line}" and rows[-1]["prior_status"] == "clean"
        assert rows[-1]["status"] == "suspicious" and "strategies" not in rows[-1]


def test_unverified_positioned_row_cannot_disable_signed_legacy_fallback(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    target, out = tmp_path / "target", tmp_path / "out"
    target.mkdir()
    out.mkdir()
    (target / "unit.c").write_text("unsigned f(unsigned n) { return n; }\n")
    append_audit_log(out, {"action": "orchestrator_review", "key": "unit.c:f", "status": "clean"})
    with (out / ".audit-log.jsonl").open("a") as stream:
        stream.write(json.dumps({"action": "orchestrator_review", "key": "unit.c:f:4", "status": "suspicious"}) + "\n")
    assert len(load_verified_audit_log(out)) == 1
    final = orch.ReviewOutcome("unit.c", "f", "suspicious", "Owned final status", line=1)
    updated = orch._relog_final_statuses(orch.OrchestratorResult(outcomes=[final], suspicious=1),
                                        orch.OrchestratorConfig(target_path=target, out_dir=out))
    rows = load_verified_audit_log(out)
    assert updated == 1 and len(rows) == 2 and rows[-1]["key"] == "unit.c:f:1"
    assert rows[-1]["prior_status"] == "clean" and rows[-1]["status"] == "suspicious"
