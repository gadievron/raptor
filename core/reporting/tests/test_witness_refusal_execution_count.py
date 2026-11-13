"""An explicit saved environment refusal cannot add an executed witness."""
import pytest

from core.reporting.witnesses import build_witness_summary, render_witness_summary
from core.sandbox.errors import SandboxFloorError
from core.sandbox.tiers import ContainmentTier
from core.witness import (
    UNVERIFIABLE_ENVIRONMENT, Witness, WitnessOutcome, WitnessSource, WitnessStore,
    compute_bytes_hash, refusal_detail,
)


@pytest.mark.parametrize("mixed", [False, True], ids=["refusal-only", "mixed"])
def test_saved_floor_refusal_does_not_count_as_execution(tmp_path, monkeypatch, mixed):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "trust"))
    # A constructed fixture error exercises only the canonical formatter;
    # these tiers are not observations of this host or a sandbox launch.
    detail = refusal_detail(SandboxFloorError(
        "fixture refusal", floor=ContainmentTier.MOUNT_NS, achievable=ContainmentTier.LANDLOCK_ONLY,
    ))
    assert detail is not None and detail["status"] == UNVERIFIABLE_ENVIRONMENT
    records = [(WitnessOutcome.UNKNOWN, {**detail, "compiled": True})]
    if mixed:
        records += [(WitnessOutcome.UNKNOWN, {"timed_out": True}), (WitnessOutcome.UNKNOWN, {}),
                    (WitnessOutcome.NO_OBVIOUS_EFFECT, {}), (WitnessOutcome.NOT_RUN, {})]
    directory = tmp_path / "witnesses"
    store = WitnessStore(directory)
    for index, (outcome, metadata) in enumerate(records):
        data = f"inert saved record {index}".encode()
        store.put(Witness(bytes_hash=compute_bytes_hash(data), bytes_len=len(data),
                          source=WitnessSource.LLM_EMIT_RUN, observed_outcome=outcome,
                          outcome_detail=metadata), data)
    before = {path.relative_to(directory): path.read_bytes()
              for path in directory.rglob("*") if path.is_file()}
    summary = build_witness_summary(directory)
    assert summary["total"] == len(records)
    assert summary["by_source"] == {"llm_emit_run": len(records)}
    assert summary["by_outcome"] == ({"unknown": 3, "no_obvious_effect": 1, "not_run": 1}
                                      if mixed else {"unknown": 1})
    assert summary["compiled"] == 1
    expected = 3 if mixed else 0
    assert summary["executed"] == expected
    assert f"Executed: {expected}/{len(records)}" in render_witness_summary(directory)
    assert {path.relative_to(directory): path.read_bytes()
            for path in directory.rglob("*") if path.is_file()} == before
