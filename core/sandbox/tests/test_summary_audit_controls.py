"""Summary control metadata has correct counts, persisted health and provenance."""

from copy import deepcopy
import json

import pytest

from core.sandbox import evidence, summary, telemetry_mac as mac, triage
from core.testing.state_isolation import pin_user_state_dirs


KINDS = ["audit_summary", "pid_budget_exceeded", "category_budget_exceeded",
         "category_budget_exceeded_sampling", "sampling_budget_exceeded",
         "global_budget_exceeded", "credential_keep_cap_exceeded",
         "parse_ambiguous_cap_exceeded"]


@pytest.fixture
def owned(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / "state")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setattr(mac, "_warned_paths", set())
    monkeypatch.setattr(summary, "_log_security_event", lambda *args, **kwargs: None)
    run = tmp_path / "run"
    run.mkdir()
    return run


def write_summary(run, rows):
    audit = run / evidence.AUDIT_SUBDIR
    audit.mkdir(exist_ok=True)
    path = audit / summary.DENIALS_FILE
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    result = summary.summarize_and_write(run, raise_on_io_error=True)
    assert result is not None
    assert json.loads((run / summary.SUMMARY_FILE).read_text()) == result
    assert not path.exists()
    return result


@pytest.mark.parametrize("kind", KINDS)
def test_control_only_stream_has_zero_enforcement_denials(owned, kind):
    result = write_summary(owned, [{"type": kind}])
    assert result["total_denials"] == 0
    assert result["denials"] == [] and result["by_type"] == {}
    assert result["audit_capture"]["by_type"] == {kind: 1}
    verified, integrity = triage._verify_summary(result, mac.run_binding(owned), allow_legacy=False)
    assert verified is result and integrity == triage._INTEGRITY_VERIFIED


def test_mixed_denials_allowed_events_and_controls_are_accounted_separately(owned):
    rows = [{"type": "read", "syscall": "open", "path": "/owned/denied"},
            {"type": "write", "path": "/owned/allowed", "verdict": "allow"},
            {"type": "category_budget_exceeded", "category": "read"},
            {"type": "audit_summary", "dropped_by_category": {"read": 7}}]
    result = write_summary(owned, rows)
    assert result["total_denials"] == 1 and result["by_type"] == {"read": 1}
    assert result["total_allowed_reports"] == 1 and result["allowed_by_type"] == {"write": 1}
    assert result["audit_capture"]["records"] == 2
    assert result["audit_capture"]["dropped_by_category"] == {"read": 7}
    report = triage.triage_run(owned, allow_legacy=False)
    assert report["inputs"]["total_denials"] == 1
    assert report["inputs"]["audit_capture"] == result["audit_capture"]
    assert any(signal["type"] == "volume_anomaly" for signal in report["signals"])


@pytest.mark.parametrize("status", [
    {"reader_failed": True}, {"reader_drained": False}, {"producer_reaped": False},
    {"lineage_failed": True}, {"lineage_stopped": False}, {"stdout_closed": False},
    {"append_failures": 2}, {"reader_drained": "false"},
])
def test_persisted_capture_loss_cannot_report_clean(owned, status):
    result = write_summary(owned, [{"type": "audit_summary", **status}])
    report = triage.triage_run(owned, allow_legacy=False)
    assert report["verdict"] == triage.VERDICT_NOTABLE
    assert report["inputs"]["integrity"]["sandbox_summary"] == triage._INTEGRITY_VERIFIED
    assert any(signal["type"] == "audit_capture_incomplete" for signal in report["signals"])
    assert report["inputs"]["total_denials"] == 0
    assert result["audit_capture"]["capture_incomplete"] is True


def test_summary_reported_drops_are_visible_without_markers(owned):
    write_summary(owned, [{"type": "audit_summary", "dropped_by_category": {"read": 4}}])
    report = triage.triage_run(owned, allow_legacy=False)
    assert report["verdict"] == triage.VERDICT_NOTABLE
    assert any(signal["type"] == "volume_anomaly" for signal in report["signals"])
    assert report["inputs"]["total_denials"] == 0


def test_healthy_capture_only_is_a_clean_zero_denial_report(owned):
    result = write_summary(owned, [{"type": "audit_summary", "reader_drained": True,
                                   "producer_reaped": True, "lineage_stopped": True,
                                   "stdout_closed": True}])
    report = triage.triage_run(owned, allow_legacy=False)
    assert report["verdict"] == triage.VERDICT_CLEAN
    assert report["signals"] == []
    assert report["inputs"]["total_denials"] == 0
    assert result["audit_capture"]["capture_incomplete"] is False


@pytest.mark.parametrize("mutation", ["strip", "clear-loss", "count", "invalid"])
def test_capture_metadata_is_bound_to_the_summary_token(owned, mutation):
    result = write_summary(owned, [{"type": "audit_summary", "reader_drained": False}])
    changed = deepcopy(result)
    if mutation == "strip":
        changed.pop("audit_capture")
    elif mutation == "clear-loss":
        changed["audit_capture"]["capture_incomplete"] = False
    elif mutation == "count":
        changed["audit_capture"]["records"] = 2
        changed["audit_capture"]["summaries"] = 2
        changed["audit_capture"]["by_type"]["audit_summary"] = 2
    else:
        changed["audit_capture"] = None
    assert triage._verify_summary(changed, mac.run_binding(owned), allow_legacy=False) == (
        None, triage._INTEGRITY_TAMPERED)


def test_metadata_digest_is_independent_of_dictionary_order(owned):
    result = write_summary(owned, [{"type": "audit_summary"}])
    result["audit_capture"] = dict(reversed(list(result["audit_capture"].items())))
    verified, integrity = triage._verify_summary(result, mac.run_binding(owned), allow_legacy=False)
    assert verified is result and integrity == triage._INTEGRITY_VERIFIED


def test_pre_metadata_token_keeps_its_original_fields_and_verifies(owned):
    result = {"total_denials": 0, "denials": []}
    fields = mac.summary_fields(0, triage._denials_sha256([]), mac.run_binding(owned))
    assert "audit_capture_sha256" not in fields
    result["mac"] = mac.mint(fields)
    assert result["mac"]
    verified, integrity = triage._verify_summary(result, mac.run_binding(owned), allow_legacy=False)
    assert verified is result and integrity == triage._INTEGRITY_VERIFIED


def test_unknown_event_type_is_not_hidden_by_a_control_prefix(owned):
    result = write_summary(owned, [{"type": "audit_future_event", "path": "/owned/event"}])
    assert result["total_denials"] == 1 and "audit_capture" not in result
    assert result["denials"][0]["type"] == "audit_future_event"
