"""Tests for the analysis-gap trail (core.run.gaps)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from core.run import gaps


@pytest.fixture(autouse=True)
def _fresh_counters(monkeypatch):
    """Each test starts with fresh cap/dedupe state."""
    monkeypatch.setattr(gaps, "_gap_count", 0)
    monkeypatch.setattr(gaps, "_suppressed", 0)
    monkeypatch.setattr(gaps, "_pending", [])
    monkeypatch.setattr(gaps, "_seen_digests", set())


def _read_trail(out_dir: Path) -> list[dict]:
    path = out_dir / gaps.GAPS_FILE
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text().splitlines() if line
    ]


def test_record_persists_and_logs_warning(tmp_path, caplog):
    with caplog.at_level("WARNING", logger="core.run.gaps"):
        ok = gaps.record_analysis_gap(
            tmp_path, file_path="src/evil.js",
            reason="parser budget exceeded", tool="inventory",
            detail="javascript parse abandoned",
        )
    assert ok is True
    records = _read_trail(tmp_path)
    assert len(records) == 1
    rec = records[0]
    assert rec["event"] == gaps.GAP_EVENT
    assert rec["file_path"] == "src/evil.js"
    assert rec["reason"] == "parser budget exceeded"
    assert rec["tool"] == "inventory"
    assert "ts" in rec
    assert any(
        "analysis gap" in m and "src/evil.js" in m
        for m in caplog.messages
    )


def test_no_run_dir_buffers_and_drains(monkeypatch, caplog):
    import core.sandbox.summary as summary
    monkeypatch.setattr(summary, "_active_run_dir", None)
    with caplog.at_level("WARNING", logger="core.run.gaps"):
        ok = gaps.record_analysis_gap(
            file_path="a.toml", reason="parse_error", tool="sca",
        )
    assert ok is False
    # Loud even when not persisted.
    assert any("analysis gap" in m for m in caplog.messages)
    drained = gaps.drain_pending_gaps()
    assert len(drained) == 1
    assert drained[0]["file_path"] == "a.toml"
    # Drain empties the buffer.
    assert gaps.drain_pending_gaps() == []


def test_active_run_dir_resolution(tmp_path, monkeypatch):
    import core.sandbox.summary as summary
    monkeypatch.setattr(summary, "_active_run_dir", tmp_path)
    ok = gaps.record_analysis_gap(
        file_path="b.yaml", reason="parse_error", tool="sca",
    )
    assert ok is True
    assert _read_trail(tmp_path)[0]["file_path"] == "b.yaml"


def test_persist_gap_records_shape_checked(tmp_path):
    good = gaps.build_gap_record(
        file_path="w.js", reason="parser budget exceeded",
        tool="inventory",
    )
    bad = [
        "not a dict",
        {"event": "something-else", "file_path": "x"},
        {"no_event": True},
    ]
    n = gaps.persist_gap_records([good, *bad], tmp_path)
    assert n == 1
    assert len(_read_trail(tmp_path)) == 1


def test_cap_boundary_warns_once_then_drops(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(gaps, "MAX_GAPS_PER_PROCESS", 3)
    with caplog.at_level("WARNING", logger="core.run.gaps"):
        for i in range(8):
            gaps.record_analysis_gap(
                tmp_path, file_path=f"f{i}", reason="parse_error",
                tool="sca",
            )
    records = _read_trail(tmp_path)
    kept = [r for r in records if r["event"] == gaps.GAP_EVENT]
    assert len(kept) == 3
    boundary = [m for m in caplog.messages if "cap reached" in m]
    assert len(boundary) == 1


def test_cap_truncation_is_durable(tmp_path, monkeypatch):
    """Post-cap suppression must be visible in the ARTIFACT, not
    only the log: doubling-milestone truncation records carry the cap
    and a lower bound on the suppressed count."""
    monkeypatch.setattr(gaps, "MAX_GAPS_PER_PROCESS", 3)
    for i in range(8):   # 3 kept, 5 suppressed
        gaps.record_analysis_gap(
            tmp_path, file_path=f"f{i}", reason="parse_error",
            tool="sca",
        )
    trunc = [
        r for r in _read_trail(tmp_path)
        if r["event"] == gaps.GAP_TRUNCATION_EVENT
    ]
    # Milestones at suppressed = 1, 2, 4 (log2-bounded, never a flood).
    assert [r["suppressed"] for r in trunc] == [1, 2, 4]
    assert all(r["cap"] == 3 for r in trunc)
    # Every surfacing path sees the truncation via gap_summary.
    summary = gaps.gap_summary(tmp_path)
    assert summary["suppressed past cap"] == 4
    assert summary["parse_error"] == 3
    # load_gaps still returns only real gap records.
    assert all(
        r["event"] == gaps.GAP_EVENT for r in gaps.load_gaps(tmp_path)
    )


def test_digest_records_deduped_per_run_dir(tmp_path):
    """Several parse sites see the same hostile content; the trail
    keeps one digest record per run dir, not one per site."""
    digest_name = "<unattributed content sha256:abcdef123456 len=56>"
    first = gaps.record_analysis_gap(
        tmp_path, file_path=digest_name,
        reason="parser budget exceeded", tool="tree-sitter",
    )
    second = gaps.record_analysis_gap(
        tmp_path, file_path=digest_name,
        reason="parser budget exceeded", tool="tree-sitter",
    )
    assert first is True and second is False
    assert len(_read_trail(tmp_path)) == 1
    other = tmp_path / "other-run"
    other.mkdir()
    assert gaps.record_analysis_gap(
        other, file_path=digest_name,
        reason="parser budget exceeded", tool="tree-sitter",
    ) is True


def test_path_attributed_records_not_deduped(tmp_path):
    for _ in range(2):
        gaps.record_analysis_gap(
            tmp_path, file_path="src/a.js",
            reason="parser budget exceeded", tool="tree-sitter",
        )
    assert len(_read_trail(tmp_path)) == 2


def test_pending_buffer_bounded(monkeypatch):
    import core.sandbox.summary as summary
    monkeypatch.setattr(summary, "_active_run_dir", None)
    monkeypatch.setattr(gaps, "_PENDING_MAX", 2)
    for i in range(5):
        gaps.record_analysis_gap(
            file_path=f"f{i}", reason="parse_error", tool="sca",
        )
    assert len(gaps.drain_pending_gaps()) == 2


def test_hostile_fields_capped_and_escaped(tmp_path):
    hostile_name = "evil\n\x1b[31m" + "A" * 5000
    hostile_detail = "err\x00" + "B" * 5000
    gaps.record_analysis_gap(
        tmp_path, file_path=hostile_name, reason="parse_error",
        tool="sca", detail=hostile_detail,
        extra={"note": "C" * 5000, "count": 7},
    )
    rec = _read_trail(tmp_path)[0]
    # Length caps hold (escaping may expand within the capped input).
    assert len(rec["file_path"]) <= gaps._FILE_PATH_MAX * 4
    assert len(rec["detail"]) <= gaps._DETAIL_MAX * 4
    assert len(rec["note"]) <= gaps._EXTRA_VAL_MAX * 4
    assert rec["count"] == 7
    # Raw control bytes never land in the trail.
    assert "\n" not in rec["file_path"]
    assert "\x1b" not in rec["file_path"]
    assert "\x00" not in rec["detail"]


def test_extra_cannot_overwrite_core_fields(tmp_path):
    gaps.record_analysis_gap(
        tmp_path, file_path="real.js", reason="parse_error",
        tool="inventory",
        extra={"file_path": "forged.js", "event": "forged"},
    )
    rec = _read_trail(tmp_path)[0]
    assert rec["file_path"] == "real.js"
    assert rec["event"] == gaps.GAP_EVENT


def test_symlinked_trail_refused(tmp_path):
    real = tmp_path / "elsewhere.jsonl"
    real.write_text("")
    os.symlink(real, tmp_path / gaps.GAPS_FILE)
    ok = gaps.record_analysis_gap(
        tmp_path, file_path="x.js", reason="parse_error",
        tool="inventory",
    )
    # O_NOFOLLOW refuses the planted symlink; recording degrades.
    assert ok is False
    assert real.read_text() == ""


def test_load_gaps_skips_junk_lines(tmp_path):
    gaps.record_analysis_gap(
        tmp_path, file_path="ok.js", reason="parse_error",
        tool="inventory",
    )
    with (tmp_path / gaps.GAPS_FILE).open("a") as fh:
        fh.write("{not json\n")
        fh.write(json.dumps({"event": "other"}) + "\n")
        fh.write(json.dumps(["a", "list"]) + "\n")
    records = gaps.load_gaps(tmp_path)
    assert len(records) == 1
    assert records[0]["file_path"] == "ok.js"


def test_gap_summary_counts_by_reason(tmp_path):
    for reason in ("parse_error", "parse_error", "parser budget exceeded"):
        gaps.record_analysis_gap(
            tmp_path, file_path="f", reason=reason, tool="sca",
        )
    assert gaps.gap_summary(tmp_path) == {
        "parse_error": 2, "parser budget exceeded": 1,
    }


def test_parse_origin_nesting():
    assert gaps.current_parse_origin() is None
    with gaps.parse_origin("outer.js"):
        assert gaps.current_parse_origin() == "outer.js"
        with gaps.parse_origin(Path("inner.js")):
            assert gaps.current_parse_origin() == "inner.js"
        assert gaps.current_parse_origin() == "outer.js"
    assert gaps.current_parse_origin() is None
