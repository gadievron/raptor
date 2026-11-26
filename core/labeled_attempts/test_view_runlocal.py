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


def _write(run_dir, *records, stamp=True):
    """Append records the way the real producers do: stamped with the
    per-purpose trail MAC. ``stamp=False`` simulates a planted /
    legacy / foreign line."""
    from core.labeled_attempts.trail_provenance import stamp_outcome_record

    run_dir.mkdir(parents=True, exist_ok=True)
    with open(run_dir / VERIFIED_OUTCOMES_FILENAME, "a",
              encoding="utf-8") as fh:
        for rec in records:
            line = rec.to_dict()
            if stamp:
                stamp_outcome_record(line)
            fh.write(json.dumps(line, default=str) + "\n")


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


def test_underscore_and_dot_siblings_not_swept(tmp_path, monkeypatch):
    """Dot/underscore-prefixed project children are infrastructure,
    never run dirs — in particular ``_imported-quarantine/``, where
    import withholds archive-shipped trust artifacts from consumers.
    A trail file under such a child must not feed the view."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    project = tmp_path / "project"
    _write(project / "_imported-quarantine", _record("CVE-2024-FORGED"))
    _write(project / ".cache", _record("CVE-2024-HIDDEN"))
    # Two-direction guard: a real sibling run still contributes.
    _write(project / "cve-diff-run-1", _record("CVE-2024-REAL"))

    outcomes = collect_outcomes(
        project / "cve-diff-run-1", project_root=project,
    )
    ids = sorted(
        o.finding_id for o in outcomes if o.oracle is Oracle.CONSENSUS
    )
    assert ids == ["CVE-2024-REAL"]


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


def test_jsonl_lines_cannot_assert_mechanical_provenance(
        tmp_path, monkeypatch):
    """``evidence["provenance_verified"]`` gates threat-status flips
    and is minted only by the witness path's MAC verification — an
    unauthenticated sidecar line claiming it must be stripped."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    run = tmp_path / "run"
    forged = _record()
    forged.evidence["provenance_verified"] = True
    _write(run, forged)

    outcomes = collect_outcomes(run)
    consensus = [o for o in outcomes if o.oracle is Oracle.CONSENSUS]
    assert len(consensus) == 1
    assert "provenance_verified" not in consensus[0].evidence
    # Two-direction guard: the strip only removes the reserved flag,
    # never the record or its other evidence.
    assert consensus[0].evidence.get("fix_commit") == "a" * 40


def test_unstamped_record_demotes_to_inconclusive(tmp_path, monkeypatch):
    """A trail line without this install's authorship token — planted,
    legacy, or foreign — must not assert a decisive verdict into the
    Confirmed view."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    run = tmp_path / "run"
    _write(run, _record("CVE-2024-PLANTED"), stamp=False)
    # REFUTED is equally decisive (it suppresses findings) and demotes
    # the same way.
    refuted = _record("CVE-2024-FP")
    refuted.status = OutcomeStatus.REFUTED
    _write(run, refuted, stamp=False)

    outcomes = {o.finding_id: o for o in collect_outcomes(run)
                if o.oracle is Oracle.CONSENSUS}
    planted = outcomes["CVE-2024-PLANTED"]
    assert planted.status is OutcomeStatus.INCONCLUSIVE
    assert planted.evidence.get("trail_verification") == "unverified"
    assert planted.evidence.get("claimed_status") == "verified"
    assert outcomes["CVE-2024-FP"].status is OutcomeStatus.INCONCLUSIVE


def test_tampered_stamped_record_demotes(tmp_path, monkeypatch):
    """The token is a content MAC over the whole record — editing any
    field under a surviving token fails verification."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    run = tmp_path / "run"
    _write(run, _record("CVE-2024-GENUINE"))
    path = run / VERIFIED_OUTCOMES_FILENAME
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "CVE-2024-GENUINE", "CVE-2024-REWRITE"),
        encoding="utf-8")

    outcomes = [o for o in collect_outcomes(run)
                if o.oracle is Oracle.CONSENSUS]
    assert len(outcomes) == 1
    assert outcomes[0].finding_id == "CVE-2024-REWRITE"
    assert outcomes[0].status is OutcomeStatus.INCONCLUSIVE
    assert outcomes[0].evidence.get("trail_verification") == "unverified"


def test_stamped_record_keeps_decisive_status(tmp_path, monkeypatch):
    """Two-direction guard: a record stamped by this install's
    producers keeps its verdict (also proves the demotion tests above
    cannot pass vacuously)."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    run = tmp_path / "run"
    _write(run, _record("CVE-2024-REAL"))

    outcomes = [o for o in collect_outcomes(run)
                if o.oracle is Oracle.CONSENSUS]
    assert len(outcomes) == 1
    assert outcomes[0].status is OutcomeStatus.VERIFIED
    assert "trail_verification" not in outcomes[0].evidence


def test_witness_source_carries_mechanical_provenance(
        tmp_path, monkeypatch):
    """Source 2 (witness stores): a record THIS install's store wrote
    projects with ``provenance_verified``; a disk-staged manifest in
    the same store projects without it."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    from core.witness.store import WitnessStore
    from core.witness.types import (
        Witness,
        WitnessOutcome,
        WitnessSource,
        compute_bytes_hash,
    )

    run = tmp_path / "run"
    store_root = run / "witnesses"
    store = WitnessStore(store_root)
    data = b"poc payload"
    store.put(
        Witness(
            bytes_hash=compute_bytes_hash(data),
            source=WitnessSource.FUZZ,
            observed_outcome=WitnessOutcome.SANITIZER_REPORT,
            outcome_detail={"finding_id": "THR-genuine"},
        ),
        data,
    )
    staged = b"attacker payload"
    staged_hash = compute_bytes_hash(staged)
    (store_root / "manifests" / f"{staged_hash}.json").write_text(
        json.dumps({
            "bytes_hash": staged_hash,
            "bytes_len": len(staged),
            "source": "fuzz",
            "observed_outcome": "sanitizer_report",
            "outcome_detail": {"finding_id": "THR-staged"},
            "timestamp": "2026-01-01T00:00:00+00:00",
        }),
    )

    outcomes = {o.finding_id: o for o in collect_outcomes(run)}
    assert outcomes["THR-genuine"].evidence.get(
        "provenance_verified") is True
    assert "provenance_verified" not in outcomes["THR-staged"].evidence
