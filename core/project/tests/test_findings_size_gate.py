"""Per-file byte gate on findings loaders.

Import admits archives up to a 10 GiB aggregate extraction budget;
report/merge generation then ``load_json``'s each run's
findings.json wholesale. Pre-fix there was no per-file bound, so one
huge restored findings.json OOM'd the reporting step. The loaders
now stat the file first and skip (with a warning) anything over
``MAX_FINDINGS_JSON_BYTES`` before parsing.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.project import findings_utils
from core.project.findings_utils import (
    MAX_FINDINGS_JSON_BYTES,
    load_findings_from_dir,
    load_sca_findings_from_dir,
    oversized_findings_files,
)

_FINDING = {"id": "f1", "file": "a.c", "function": "p", "line": 1,
            "status": "confirmed"}


def _write_findings(path: Path, pad: int = 0) -> None:
    doc = {"findings": [_FINDING]}
    if pad:
        doc["padding"] = "x" * pad
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc))


def test_under_gate_loads_normally(tmp_path: Path):
    _write_findings(tmp_path / "findings.json")
    assert load_findings_from_dir(tmp_path) == [_FINDING]


def test_over_gate_skipped_before_parse(tmp_path: Path, monkeypatch,
                                        caplog):
    """A VALID findings.json over the gate must be refused without
    parsing — pre-fix it parsed and returned the findings."""
    _write_findings(tmp_path / "findings.json", pad=4096)
    monkeypatch.setattr(findings_utils, "MAX_FINDINGS_JSON_BYTES", 1024,
                        raising=False)
    with caplog.at_level("WARNING"):
        assert load_findings_from_dir(tmp_path) == []
    assert any("gate" in r.message for r in caplog.records)


def test_sca_loader_shares_the_gate(tmp_path: Path, monkeypatch, caplog):
    sca = tmp_path / "sca" / "findings.json"
    sca.parent.mkdir(parents=True)
    sca.write_text(json.dumps([_FINDING]) + " " * 4096)
    monkeypatch.setattr(findings_utils, "MAX_FINDINGS_JSON_BYTES", 1024,
                        raising=False)
    with caplog.at_level("WARNING"):
        assert load_sca_findings_from_dir(tmp_path) == []
    assert any("gate" in r.message for r in caplog.records)


def test_real_gate_bound_via_sparse_file(tmp_path: Path, caplog):
    """At the real bound: an st_size over the cap is refused before
    any read (sparse file — no actual disk/parse cost)."""
    p = tmp_path / "findings.json"
    with p.open("wb") as fh:
        fh.seek(MAX_FINDINGS_JSON_BYTES)
        fh.write(b"x")
    with caplog.at_level("WARNING"):
        assert load_findings_from_dir(tmp_path) == []
    assert any("gate" in r.message for r in caplog.records), (
        "the skip must cite the byte gate, not a parse failure")


def test_merge_and_report_paths_are_gated(tmp_path: Path, monkeypatch):
    """merge_findings (used by /project report) inherits the gate."""
    from core.project.merge import merge_findings

    run = tmp_path / "run_a"
    _write_findings(run / "findings.json", pad=4096)
    monkeypatch.setattr(findings_utils, "MAX_FINDINGS_JSON_BYTES", 1024,
                        raising=False)
    assert merge_findings([run]) == []


def test_skip_warning_names_file_consequence_and_remedy(
        tmp_path: Path, monkeypatch, caplog):
    """The over-gate skip must be actionable: name the skipped FILE,
    the merged-view consequence, and a remedy — a kernel-scale run's
    findings vanishing from /project views must never be a mystery."""
    _write_findings(tmp_path / "findings.json", pad=4096)
    monkeypatch.setattr(findings_utils, "MAX_FINDINGS_JSON_BYTES", 1024,
                        raising=False)
    with caplog.at_level("WARNING"):
        load_findings_from_dir(tmp_path)
    msg = "\n".join(r.getMessage() for r in caplog.records)
    assert str(tmp_path / "findings.json") in msg
    assert "EXCLUDED" in msg
    assert "/project findings" in msg
    assert "jq" in msg


def _sparse_over_gate(path: Path) -> None:
    """st_size one byte over the gate; sparse — never read or parsed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        fh.seek(MAX_FINDINGS_JSON_BYTES)
        fh.write(b"x")


class TestOversizedFindingsFiles:
    """Stat-only preview of the gate along the loader's exact fallback
    chain — recompute-and-replace callers (the completion-time
    re-adjudication sweep) refuse to replace derived artifacts when
    the recompute would run over a gate-excluded view."""

    def test_oversized_primary_reported(self, tmp_path: Path):
        _sparse_over_gate(tmp_path / "findings.json")
        assert oversized_findings_files(tmp_path) == [
            tmp_path / "findings.json"]

    def test_fallback_checked_when_primary_missing(self, tmp_path: Path):
        _sparse_over_gate(tmp_path / "openant_findings.json")
        assert oversized_findings_files(tmp_path) == [
            tmp_path / "openant_findings.json"]

    def test_fallback_checked_when_primary_oversized(self, tmp_path: Path):
        # An over-gate primary makes the loader consult the fallback,
        # so an over-gate fallback fires a second gate — both report.
        _sparse_over_gate(tmp_path / "findings.json")
        _sparse_over_gate(tmp_path / "openant_findings.json")
        assert oversized_findings_files(tmp_path) == [
            tmp_path / "findings.json",
            tmp_path / "openant_findings.json"]

    def test_readable_primary_shadows_oversized_fallback(
            self, tmp_path: Path):
        # The loader never consults the fallback past a readable
        # primary — previewing it anyway would report a gate the
        # loader cannot fire (a phantom deferral trigger).
        _write_findings(tmp_path / "findings.json")
        _sparse_over_gate(tmp_path / "openant_findings.json")
        assert oversized_findings_files(tmp_path) == []

    def test_no_files_no_gates(self, tmp_path: Path):
        assert oversized_findings_files(tmp_path) == []

    def test_at_bound_is_not_over(self, tmp_path: Path):
        # The gate is strictly greater-than: st_size == the bound
        # loads, and the preview must agree with the loader's own
        # comparison in both directions.
        p = tmp_path / "findings.json"
        with p.open("wb") as fh:
            fh.seek(MAX_FINDINGS_JSON_BYTES - 1)
            fh.write(b"x")
        assert oversized_findings_files(tmp_path) == []


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
