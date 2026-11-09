"""Whole-campaign bounds never turn omitted evidence into clean trends."""
import json

import pytest

from core.project import sandbox_campaign as campaign
from core.sandbox import summary
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture
def runs(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / "state")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    made = []

    def make(records, target="/owned-target"):
        run = tmp_path / f"run-{len(made)}"
        run.mkdir()
        (run / ".raptor-run.json").write_text(json.dumps({
            "target_path": target, "started_at": f"2026-10-{len(made) + 1:02d}T00:00:00Z",
        }))
        summary.record_run_posture(run, mount_ns_active=True, restrict_reads=False)
        summary._assemble_and_write_summary(
            run, records=records, refusals=[], corrupt_lines=0,
            inode_mismatch=False, planted_object="",
        )
        made.append(run)
        return run
    return make


def escape(command):
    return {"type": "seccomp", "cmd": command}


def assert_refusal(result, reason, severity):
    assert result["integrity"] == "degraded"
    assert result["campaign_severity"] == severity
    assert result["aggregation"]["complete"] is False
    assert reason in result["aggregation"]["reason"]
    # A truncated prefix must not publish resolved trends or clean targets.
    assert result["targets"] == {}


def test_run_path_overflow_refuses_before_evidence_reads(runs, monkeypatch):
    from core.project.correlate import correlate_sandbox_triage
    directories = [runs([escape("ptrace")]), runs([escape("bpf")])]
    monkeypatch.setattr(campaign, "MAX_CAMPAIGN_RUNS", 1, raising=False)
    def unexpected_read(*args):
        pytest.fail("over-budget input must be refused before reading evidence")
    monkeypatch.setattr(campaign, "_read_entry", unexpected_read)
    result = correlate_sandbox_triage(directories)
    assert_refusal(result, "run-path", "elevated")
    assert result["aggregation"]["runs_considered"] == 0


@pytest.mark.parametrize("budget", [
    "MAX_CAMPAIGN_RUNS", "MAX_CAMPAIGN_TARGETS",
    "MAX_CAMPAIGN_SIGNATURES", "MAX_CAMPAIGN_DENIALS",
])
def test_exact_budget_retains_real_authenticated_evidence(runs, monkeypatch, budget):
    run = runs([escape("ptrace")])
    monkeypatch.setattr(campaign, budget, 1)
    result = campaign.correlate_campaign([run])
    assert result["integrity"] == "verified"
    assert result["campaign_severity"] == "critical"
    target = result["targets"]["/owned-target"]
    assert target["runs_total"] == 1
    assert len(target["signatures"]) == 1
    assert next(iter(target["signatures"].values()))["total_occurrences"] == 1


@pytest.mark.parametrize("budget,records,targets,reason,expected_reads", [
    ("MAX_CAMPAIGN_SIGNATURES", [escape("ptrace"), escape("bpf")],
     ["/one", "/one", "/one"], "signature", 1),
    ("MAX_CAMPAIGN_DENIALS", [escape("ptrace"), escape("ptrace")],
     ["/one", "/one", "/one"], "denial", 1),
    ("MAX_CAMPAIGN_TARGETS", [escape("ptrace")],
     ["/one", "/two", "/three"], "target", 2),
])
def test_overflow_preserves_known_attack_and_stops_reading(
    runs, monkeypatch, budget, records, targets, reason, expected_reads,
):
    directories = [runs(records, target) for target in targets]
    monkeypatch.setattr(campaign, budget, 1)
    read = campaign._read_entry
    seen = []
    def checked_read(directory):
        seen.append(directory)
        assert len(seen) <= expected_reads, "read past the budget refusal"
        return read(directory)
    monkeypatch.setattr(campaign, "_read_entry", checked_read)
    result = campaign.correlate_campaign(directories)
    assert_refusal(result, reason, "critical")
    assert seen == directories[:expected_reads]
    assert result["aggregation"]["runs_considered"] == expected_reads


def test_duplicate_paths_do_not_manufacture_recurrence_within_budget(runs):
    run = runs([escape("ptrace")])
    result = campaign.correlate_campaign([run, run])
    target = result["targets"]["/owned-target"]
    assert target["runs_total"] == 1
    assert next(iter(target["signatures"].values()))["runs_seen"] == 1


def test_empty_campaign_remains_absent():
    assert campaign.correlate_campaign([]) is None
