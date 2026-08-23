"""Tests for the per-finding provenance_refs stamping
(:mod:`core.run.findings`). Deterministic — no spatch, no LLM."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.run.findings import (
    PROVENANCE_REFS_FIELD,
    build_provenance_ref,
    is_canonical_ref_shape,
    stamp_findings_in_run,
)
from core.run.metadata import (
    RUN_METADATA_FILE,
    complete_run,
    start_run,
)


def _write_manifest(d: Path, *, ts: str = "2026-05-30T12:00:00+00:00") -> None:
    """Minimal manifest enough for build_provenance_ref to read."""
    (d / RUN_METADATA_FILE).write_text(json.dumps({
        "command": "scan", "timestamp": ts, "status": "running",
    }))


# --- build_provenance_ref ------------------------------------------------


def test_build_ref_minimal_shape(tmp_path: Path) -> None:
    _write_manifest(tmp_path)
    ref = build_provenance_ref(tmp_path)
    assert ref == {
        "run_id": tmp_path.name,
        "manifest_path": RUN_METADATA_FILE,
        "ts": "2026-05-30T12:00:00+00:00",
    }


def test_build_ref_returns_none_without_manifest(tmp_path: Path) -> None:
    # No .raptor-run.json — caller must skip stamping, not synthesise a ref.
    assert build_provenance_ref(tmp_path) is None


def test_build_ref_ts_optional(tmp_path: Path) -> None:
    # Manifest with no timestamp key — ref omits ``ts`` rather than
    # injecting None or an empty string.
    (tmp_path / RUN_METADATA_FILE).write_text(json.dumps({"command": "scan"}))
    ref = build_provenance_ref(tmp_path)
    assert ref is not None
    assert "ts" not in ref


# --- stamp_findings_in_run -----------------------------------------------


def test_stamps_top_level_list_shape(tmp_path: Path) -> None:
    _write_manifest(tmp_path)
    (tmp_path / "findings.json").write_text(json.dumps([
        {"id": "F1"}, {"id": "F2"},
    ]))
    counts = stamp_findings_in_run(tmp_path)
    assert counts == {
        "files_stamped": 1, "findings_stamped": 2, "files_skipped": 0,
    }
    findings = json.loads((tmp_path / "findings.json").read_text())
    assert all(PROVENANCE_REFS_FIELD in f for f in findings)
    assert findings[0][PROVENANCE_REFS_FIELD][0]["run_id"] == tmp_path.name


def test_stamps_wrapped_dict_shape(tmp_path: Path) -> None:
    _write_manifest(tmp_path)
    (tmp_path / "findings.json").write_text(json.dumps({
        "stage": "scan", "target_path": "/x",
        "findings": [{"id": "F1"}, {"id": "F2"}],
    }))
    counts = stamp_findings_in_run(tmp_path)
    assert counts["findings_stamped"] == 2
    data = json.loads((tmp_path / "findings.json").read_text())
    # Container shape preserved (stage / target_path siblings still there).
    assert data["stage"] == "scan"
    assert all(PROVENANCE_REFS_FIELD in f for f in data["findings"])


def test_stamps_sca_subpath_too(tmp_path: Path) -> None:
    # ``/sca`` writes findings to ``<run>/sca/findings.json`` — must stamp.
    _write_manifest(tmp_path)
    (tmp_path / "sca").mkdir()
    (tmp_path / "sca" / "findings.json").write_text(json.dumps([
        {"id": "S1", "package": "lodash"},
    ]))
    counts = stamp_findings_in_run(tmp_path)
    assert counts["files_stamped"] == 1
    findings = json.loads((tmp_path / "sca" / "findings.json").read_text())
    assert findings[0][PROVENANCE_REFS_FIELD][0]["run_id"] == tmp_path.name


def test_idempotent_restamp_does_nothing(tmp_path: Path) -> None:
    _write_manifest(tmp_path)
    (tmp_path / "findings.json").write_text(json.dumps([{"id": "F1"}]))
    stamp_findings_in_run(tmp_path)
    # Second pass: no new stamps (refs by this run_id already present).
    counts = stamp_findings_in_run(tmp_path)
    assert counts == {
        "files_stamped": 0, "findings_stamped": 0, "files_skipped": 0,
    }
    # And exactly one ref on the finding, not two.
    finding = json.loads((tmp_path / "findings.json").read_text())[0]
    assert len(finding[PROVENANCE_REFS_FIELD]) == 1


def test_malformed_json_is_skipped_not_raised(tmp_path: Path) -> None:
    _write_manifest(tmp_path)
    (tmp_path / "findings.json").write_text("{ not valid json")
    counts = stamp_findings_in_run(tmp_path)
    assert counts == {
        "files_stamped": 0, "findings_stamped": 0, "files_skipped": 1,
    }


def test_unrecognised_shape_left_alone(tmp_path: Path) -> None:
    # Not a list, not a dict-with-findings — leave the file untouched.
    _write_manifest(tmp_path)
    original = json.dumps({"some_other_field": "value"})
    (tmp_path / "findings.json").write_text(original)
    counts = stamp_findings_in_run(tmp_path)
    assert counts["files_stamped"] == 0
    assert (tmp_path / "findings.json").read_text() == original


def test_non_dict_finding_entries_are_skipped(tmp_path: Path) -> None:
    # A malformed findings.json with a stray string/null in the list mustn't
    # crash the stamper — those entries get skipped, the dict entries stamp.
    _write_manifest(tmp_path)
    (tmp_path / "findings.json").write_text(json.dumps([
        {"id": "F1"}, "not a dict", None, {"id": "F2"},
    ]))
    counts = stamp_findings_in_run(tmp_path)
    assert counts["findings_stamped"] == 2  # the 2 dicts


def test_no_manifest_skips_all_files(tmp_path: Path) -> None:
    # No .raptor-run.json — must NOT synthesise refs from thin air.
    (tmp_path / "findings.json").write_text(json.dumps([{"id": "F1"}]))
    counts = stamp_findings_in_run(tmp_path)
    assert counts == {
        "files_stamped": 0, "findings_stamped": 0, "files_skipped": 0,
    }
    # Finding left untouched — no provenance_refs field synthesised.
    finding = json.loads((tmp_path / "findings.json").read_text())[0]
    assert PROVENANCE_REFS_FIELD not in finding


# --- complete_run lifecycle hook ----------------------------------------


def test_complete_run_stamps_findings_end_to_end(tmp_path: Path) -> None:
    start_run(tmp_path, command="scan", target="/x")
    (tmp_path / "findings.json").write_text(json.dumps([{"id": "F1"}]))
    complete_run(tmp_path)
    finding = json.loads((tmp_path / "findings.json").read_text())[0]
    refs = finding[PROVENANCE_REFS_FIELD]
    assert len(refs) == 1
    assert refs[0]["run_id"] == tmp_path.name
    assert "ts" in refs[0]


def test_complete_run_stamping_failure_does_not_break_lifecycle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # If the stamping helper raises, complete_run must still mark status=
    # completed (best-effort lifecycle hook contract).
    def _raise(*_args, **_kw) -> None:
        raise RuntimeError("stamping blew up")

    monkeypatch.setattr(
        "core.run.findings.stamp_findings_in_run", _raise,
    )
    start_run(tmp_path, command="scan", target="/x")
    (tmp_path / "findings.json").write_text(json.dumps([{"id": "F1"}]))
    complete_run(tmp_path)
    manifest = json.loads(
        (tmp_path / RUN_METADATA_FILE).read_text()
    )
    assert manifest["status"] == "completed"


# --- forged / pre-seeded refs must not suppress the canonical stamp ------


def test_forged_ref_claiming_run_id_does_not_suppress_stamp(
    tmp_path: Path,
) -> None:
    """A pre-seeded provenance_refs entry that merely CLAIMS the
    current run_id (attacker-chosen manifest_path / ts) must not
    suppress the canonical stamp — only the exact canonical ref this
    writer produces counts for idempotency."""
    _write_manifest(tmp_path)
    forged = {
        "run_id": tmp_path.name,
        "manifest_path": "/attacker/controlled/.raptor-run.json",
        "ts": "1999-01-01T00:00:00+00:00",
    }
    (tmp_path / "findings.json").write_text(json.dumps([
        {"id": "f1", PROVENANCE_REFS_FIELD: [dict(forged)]},
    ]))

    counts = stamp_findings_in_run(tmp_path)
    assert counts["findings_stamped"] == 1

    data = json.loads((tmp_path / "findings.json").read_text())
    refs = data[0][PROVENANCE_REFS_FIELD]
    canonical = build_provenance_ref(tmp_path)
    assert canonical in refs, "canonical stamp must be appended"
    assert forged in refs, "existing entries are preserved, not trusted"


def test_forged_ref_with_extra_keys_does_not_suppress_stamp(
    tmp_path: Path,
) -> None:
    _write_manifest(tmp_path)
    canonical = build_provenance_ref(tmp_path)
    smuggled = dict(canonical)
    smuggled["payload"] = "smuggled-content"
    (tmp_path / "findings.json").write_text(json.dumps([
        {"id": "f1", PROVENANCE_REFS_FIELD: [smuggled]},
    ]))

    counts = stamp_findings_in_run(tmp_path)
    assert counts["findings_stamped"] == 1
    data = json.loads((tmp_path / "findings.json").read_text())
    assert canonical in data[0][PROVENANCE_REFS_FIELD]


def test_canonical_stamp_still_idempotent_after_forged_entry(
    tmp_path: Path,
) -> None:
    """After the canonical stamp lands next to a forged entry,
    re-running stamps nothing further."""
    _write_manifest(tmp_path)
    forged = {"run_id": tmp_path.name, "manifest_path": "/evil"}
    (tmp_path / "findings.json").write_text(json.dumps([
        {"id": "f1", PROVENANCE_REFS_FIELD: [forged]},
    ]))
    assert stamp_findings_in_run(tmp_path)["findings_stamped"] == 1
    assert stamp_findings_in_run(tmp_path)["findings_stamped"] == 0
    data = json.loads((tmp_path / "findings.json").read_text())
    assert len(data[0][PROVENANCE_REFS_FIELD]) == 2


# --- is_canonical_ref_shape ----------------------------------------------


def test_canonical_shape_accepts_stamped_ref(tmp_path: Path) -> None:
    """The exact ref build_provenance_ref produces passes the shape
    check — with and without the optional ``ts``."""
    _write_manifest(tmp_path)
    ref = build_provenance_ref(tmp_path)
    assert is_canonical_ref_shape(ref)
    assert is_canonical_ref_shape(
        {"run_id": "scan_20260101-000000", "manifest_path": RUN_METADATA_FILE}
    )


@pytest.mark.parametrize("candidate", [
    None,
    "not-a-dict",
    {},
    {"run_id": "r"},                                        # no manifest_path
    {"manifest_path": RUN_METADATA_FILE},                   # no run_id
    {"run_id": "r", "manifest_path": "/evil"},              # wrong manifest
    {"run_id": "r", "manifest_path": RUN_METADATA_FILE,
     "smuggled": "x"},                                      # extra key
    {"run_id": "", "manifest_path": RUN_METADATA_FILE},     # empty run_id
    {"run_id": "..", "manifest_path": RUN_METADATA_FILE},   # traversal
    {"run_id": "a/b", "manifest_path": RUN_METADATA_FILE},  # separator
    {"run_id": 7, "manifest_path": RUN_METADATA_FILE},      # non-str run_id
    {"run_id": "r", "manifest_path": RUN_METADATA_FILE,
     "ts": ""},                                             # empty ts
    {"run_id": "r", "manifest_path": RUN_METADATA_FILE,
     "ts": 12345},                                          # non-str ts
])
def test_canonical_shape_rejects_forgeries(candidate) -> None:
    assert not is_canonical_ref_shape(candidate)
