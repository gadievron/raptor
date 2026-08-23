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


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
