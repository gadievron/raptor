"""Prepared token and dollar holds survive the existing signed attempt journal."""
import pytest

from core.audit.attempt_reservations import AttemptReservations
from core.audit.record import load_verified_audit_log
from core.json.utils import save_json
from core.run.report_identity import fresh_identity


@pytest.fixture
def run_dir(tmp_path, monkeypatch):
    out = tmp_path / "run"
    out.mkdir()
    save_json(out / ".raptor-run.json", {"command": "audit", "status": "running",
        "reporting_identity": fresh_identity()})
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "private"))
    return out


def _prepared(**changes):
    return {"call_id": "call-owned", "attempt_id": "attempt-owned", "work_id": "study-owned",
            "call_class": "study", "provider": "openai", "model": "gpt-4o",
            "beneficiaries": ["unit-first", "unit-second"], "reservation_usd": 0.25,
            "reservation_tokens": 240, "reservation_kind": "prepared", **changes}


def test_prepared_hold_is_committed_and_recovered_before_usage(run_dir):
    store = AttemptReservations(run_dir, resume=False)
    assert store.admit(_prepared())
    row, = [r for r in load_verified_audit_log(run_dir) if r.get("stage") == "admitted"]
    assert row["attempt"]["reservation_tokens"] == 240
    recovered = AttemptReservations(run_dir, resume=True)
    assert recovered.pending() == store.pending()
    assert recovered.pending()[0]["reservation_kind"] == "prepared"
    assert recovered.pending()[0]["reservation_usd"] == 0.25
    assert recovered.known_spend_usd == 0
    assert recovered.finish("attempt-owned", cost_usd=None)
    assert recovered.pending()[0]["reservation_tokens"] == 240


def test_reported_usage_releases_one_prepared_hold_once(run_dir):
    store = AttemptReservations(run_dir, resume=False)
    store.admit(_prepared())
    assert store.finish("attempt-owned", cost_usd=0.1, tokens_in=12, tokens_out=3)
    resumed = AttemptReservations(run_dir, resume=True)
    assert resumed.pending() == []
    assert resumed.known_spend_usd == pytest.approx(0.1)
    assert not resumed.finish("attempt-owned", cost_usd=0.1, tokens_in=12, tokens_out=3)
    row, = resumed.reported()
    assert row["reservation_tokens"] == 240 and row["tokens_total"] == 15
    assert row["beneficiaries"] == ["unit-first", "unit-second"]


def test_known_zero_pretransport_disposition_is_not_unknown_spend(run_dir):
    store = AttemptReservations(run_dir, resume=False)
    store.admit(_prepared())
    store.finish("attempt-owned", cost_usd=0, tokens_in=0, tokens_out=0)
    resumed = AttemptReservations(run_dir, resume=True)
    assert resumed.pending() == [] and resumed.known_spend_usd == 0
    assert resumed.reported()[0]["tokens_total"] == 0


@pytest.mark.parametrize("changes", [
    {"reservation_tokens": True}, {"reservation_tokens": -1}, {"reservation_tokens": 0},
    {"reservation_kind": []}, {"reservation_kind": "forged"},
])
def test_invalid_prepared_hold_is_refused_before_journal_admission(run_dir, changes):
    store = AttemptReservations(run_dir, resume=False)
    with pytest.raises(ValueError):
        store.admit(_prepared(**changes))
    assert store.pending() == []
    assert not any(r.get("stage") == "admitted" for r in load_verified_audit_log(run_dir))


def test_estimate_only_record_remains_explicitly_distinct(run_dir):
    store = AttemptReservations(run_dir, resume=False)
    row = _prepared()
    del row["reservation_tokens"], row["reservation_kind"]
    store.admit(row)
    restored, = AttemptReservations(run_dir, resume=True).pending()
    assert restored["reservation_kind"] == "estimate"
    assert restored["reservation_tokens"] == 0


def test_upstream_overrun_is_preserved_and_blocks_resumed_admission(run_dir):
    store = AttemptReservations(run_dir, resume=False)
    store.admit(_prepared())
    store.finish("attempt-owned", cost_usd=0.3, tokens_in=12, tokens_out=3, tokens_total=300)
    resumed = AttemptReservations(run_dir, resume=True)
    assert resumed.known_spend_usd == pytest.approx(0.3)
    assert resumed.reported()[0]["tokens_total"] == 300
    assert resumed.gap == "prepared_usage_exceeded_reservation"
    with pytest.raises(ValueError, match="prepared_usage_exceeded_reservation"):
        resumed.admit(_prepared(attempt_id="next-attempt"))
