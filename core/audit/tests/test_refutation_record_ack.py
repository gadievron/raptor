"""Recording-boundary controls with supplied witness results, without running witnesses."""
from dataclasses import asdict
import json

import pytest

from core.analysis import reach_chokepoint
from core.audit.caller_lock import CallerLockResult
from core.audit.goconc import GoroutineIsolationResult
from core.audit.orchestrator import ReviewOutcome
from core.audit import refutation


@pytest.fixture(params=["goconc", "callerlock"])
def record_case(request):
    outcome = ReviewOutcome("pkg/unit.go" if request.param == "goconc" else "unit.c",
                            "Read", "clean", "prior assessment", line=7)
    if request.param == "goconc":
        witness = GoroutineIsolationResult(isolated=True, spawn_count=0, claimed_types=("Unit",),
                                          reasoning="supplied record-only fixture")
        helper = refutation._record_goconc_discharge
    else:
        witness = CallerLockResult(held=True, lock_class="mutex", lock_object="owned",
                                   call_sites=1, callers=("Caller",), reasoning="supplied record-only fixture")
        helper = refutation._record_callerlock_discharge
    return outcome, witness, helper, request.param


def test_failed_native_record_append_refuses_discharge(tmp_path, record_case):
    outcome, witness, helper, _ = record_case
    before = asdict(outcome), asdict(witness)
    output = tmp_path / "owned-file"
    output.write_bytes(b"preserved")
    assert helper(outcome, output, mechanism="fixture", result=witness) is False
    assert output.read_bytes() == b"preserved"
    assert (asdict(outcome), asdict(witness)) == before


def test_success_requires_real_complete_append_and_preserves_row(tmp_path, record_case):
    outcome, witness, helper, kind = record_case
    assert helper(outcome, tmp_path, mechanism="fixture", result=witness) is True
    rows = [json.loads(line) for line in (tmp_path / "suppressions.jsonl").read_bytes().splitlines()]
    assert len(rows) == 1
    assert rows[0]["finding_id"] == f"audit-refutation:{outcome.file}:Read:7"
    assert rows[0]["verdict"] == f"{kind}_witness_corroborates_dismissal"
    assert rows[0]["dropped"] is False


@pytest.mark.parametrize("ack", [None, False, 1, "complete"])
def test_legacy_or_truthy_non_boolean_writer_return_cannot_acknowledge(tmp_path, record_case, monkeypatch, ack):
    outcome, witness, helper, _ = record_case
    monkeypatch.setattr(reach_chokepoint, "record_suppression", lambda *args, **kwargs: ack)
    assert helper(outcome, tmp_path, mechanism="fixture", result=witness) is False
    assert not (tmp_path / "suppressions.jsonl").exists()


def test_recording_interrupt_keeps_original_identity(tmp_path, record_case, monkeypatch):
    outcome, witness, helper, _ = record_case
    primary = KeyboardInterrupt("owned append interrupted")

    def interrupt(*args, **kwargs):
        raise primary

    monkeypatch.setattr(reach_chokepoint, "record_suppression", interrupt)
    with pytest.raises(KeyboardInterrupt) as caught:
        helper(outcome, tmp_path, mechanism="fixture", result=witness)
    assert caught.value is primary
