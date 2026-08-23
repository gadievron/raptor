"""Run-local VerifiedOutcome sidecar tests — source 3 of
``collect_outcomes`` (``verified-outcomes.jsonl`` in run dirs).
Producers whose oracle evidence doesn't fit the LabeledAttempt shapes
(e.g. /cve-diff's pointer consensus) append records there.
"""

from __future__ import annotations

import json

from core.labeled_attempts.view import (
    VERIFIED_OUTCOMES_FILENAME,
    Oracle,
    OutcomeStatus,
    VerifiedOutcome,
    collect_outcomes,
)


def _record(finding_id="CVE-2024-1", oracle=Oracle.CONSENSUS):
    return VerifiedOutcome(
        finding_id=finding_id,
        oracle=oracle,
        status=OutcomeStatus.VERIFIED,
        reproducible=False,
        evidence={"fix_commit": "a" * 40},
        produced_by="cve-diff",
    )


def _write(run_dir, *records):
    run_dir.mkdir(parents=True, exist_ok=True)
    with open(run_dir / VERIFIED_OUTCOMES_FILENAME, "a",
              encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec.to_dict(), default=str) + "\n")


def test_collects_run_local_records(tmp_path, monkeypatch):
    # Isolate the pool-based sources so only the run-local sidecar
    # contributes.
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    run = tmp_path / "run"
    _write(run, _record())

    outcomes = collect_outcomes(run)
    consensus = [o for o in outcomes if o.oracle is Oracle.CONSENSUS]
    assert len(consensus) == 1
    assert consensus[0].finding_id == "CVE-2024-1"
    assert consensus[0].status is OutcomeStatus.VERIFIED


def test_project_root_sweeps_sibling_runs(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    project = tmp_path / "project"
    _write(project / "cve-diff-run-1", _record("CVE-2024-1"))
    _write(project / "cve-diff-run-2", _record("CVE-2024-2"))

    outcomes = collect_outcomes(
        project / "cve-diff-run-1", project_root=project,
    )
    ids = sorted(
        o.finding_id for o in outcomes if o.oracle is Oracle.CONSENSUS
    )
    assert ids == ["CVE-2024-1", "CVE-2024-2"]


def test_malformed_lines_are_skipped_not_fatal(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    run = tmp_path / "run"
    _write(run, _record())
    with open(run / VERIFIED_OUTCOMES_FILENAME, "a", encoding="utf-8") as fh:
        fh.write("this is not json\n")
        fh.write(json.dumps({"finding_id": "x"}) + "\n")  # missing keys

    outcomes = collect_outcomes(run)
    consensus = [o for o in outcomes if o.oracle is Oracle.CONSENSUS]
    assert len(consensus) == 1


def test_missing_file_and_none_output_dir_are_fine(tmp_path):
    assert isinstance(collect_outcomes(tmp_path / "nope"), list)
    assert isinstance(collect_outcomes(None), list)
