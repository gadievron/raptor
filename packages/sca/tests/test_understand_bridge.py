"""Tests for the /sca ↔ /understand bridge."""

from __future__ import annotations

import json
from pathlib import Path

from packages.sca.models import Confidence, Reachability
from packages.sca.understand_bridge import (
    annotate, annotate_all, load_context_map,
)


def _reach(verdict: str, *, evidence) -> Reachability:
    return Reachability(
        verdict=verdict,                        # type: ignore[arg-type]
        confidence=Confidence("high", reason="import found"),
        evidence=list(evidence),
    )


def _ctx_file(tmp_path: Path, payload: dict) -> Path:
    out = tmp_path / "out" / "understand_20260426_120000"
    out.mkdir(parents=True)
    cm = out / "context-map.json"
    cm.write_text(json.dumps(payload), encoding="utf-8")
    return cm


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def test_load_picks_newest_understand_run(tmp_path: Path) -> None:
    older = tmp_path / "out" / "understand_20250101_000000"
    newer = tmp_path / "out" / "understand_20260601_000000"
    older.mkdir(parents=True)
    newer.mkdir(parents=True)
    (older / "context-map.json").write_text('{"sinks": []}',
                                              encoding="utf-8")
    (newer / "context-map.json").write_text(
        '{"sink_details": [{"file": "newer.py"}]}',
        encoding="utf-8",
    )
    ctx = load_context_map(tmp_path)
    assert ctx is not None
    assert "newer.py" in ctx.sink_files


def test_load_co_located_run_dir_wins(tmp_path: Path) -> None:
    """``run_dir/context-map.json`` is preferred over scan."""
    run_dir = tmp_path / "out" / "sca-run"
    run_dir.mkdir(parents=True)
    (run_dir / "context-map.json").write_text(
        '{"entry_points": [{"file": "co-located.py"}]}',
        encoding="utf-8",
    )
    # Also a sibling (older) understand run.
    older = tmp_path / "out" / "understand_20250101_000000"
    older.mkdir(parents=True)
    (older / "context-map.json").write_text(
        '{"entry_points": [{"file": "older.py"}]}',
        encoding="utf-8",
    )
    ctx = load_context_map(tmp_path, run_dir=run_dir)
    assert ctx is not None
    assert "co-located.py" in ctx.entry_point_files
    assert "older.py" not in ctx.entry_point_files


def test_load_returns_none_when_absent(tmp_path: Path) -> None:
    assert load_context_map(tmp_path) is None


def test_load_tolerates_invalid_json(tmp_path: Path) -> None:
    out = tmp_path / "out" / "understand_x"
    out.mkdir(parents=True)
    (out / "context-map.json").write_text("not json{", encoding="utf-8")
    assert load_context_map(tmp_path) is None


# ---------------------------------------------------------------------------
# Annotate
# ---------------------------------------------------------------------------

def test_sink_match_promotes_to_likely_called(tmp_path: Path) -> None:
    _ctx_file(tmp_path, {
        "sink_details": [{"file": "src/handler.py"}],
    })
    ctx = load_context_map(tmp_path)
    assert ctx is not None
    r = _reach("imported", evidence=["src/handler.py:42",
                                      "src/util.py:17"])
    out = annotate(r, ctx)
    assert out.verdict == "likely_called"
    assert out.confidence.level == "high"
    assert "context-map" in out.confidence.reason
    assert "sink" in out.confidence.reason


def test_entry_point_match_keeps_imported(tmp_path: Path) -> None:
    """Entry-point match alone doesn't promote (``likely_called``
    requires sink intersection)."""
    _ctx_file(tmp_path, {
        "entry_points": [{"file": "src/cli.py"}],
    })
    ctx = load_context_map(tmp_path)
    assert ctx is not None
    r = _reach("imported", evidence=["src/cli.py:10"])
    out = annotate(r, ctx)
    assert out.verdict == "imported"
    assert "entry_point" in out.confidence.reason


def test_no_match_returns_input_unchanged(tmp_path: Path) -> None:
    _ctx_file(tmp_path, {"sink_details": [{"file": "other.py"}]})
    ctx = load_context_map(tmp_path)
    assert ctx is not None
    r = _reach("imported", evidence=["src/handler.py:42"])
    out = annotate(r, ctx)
    # No match → same evidence list, same verdict, same confidence.
    assert out.verdict == "imported"
    assert out.evidence == r.evidence
    assert out.confidence.reason == r.confidence.reason


def test_not_reachable_passthrough(tmp_path: Path) -> None:
    """``not_reachable`` / ``not_evaluated`` are returned unchanged."""
    _ctx_file(tmp_path, {"sink_details": [{"file": "src/handler.py"}]})
    ctx = load_context_map(tmp_path)
    assert ctx is not None
    r = Reachability(verdict="not_reachable",
                      confidence=Confidence("medium", reason=""),
                      evidence=[])
    assert annotate(r, ctx) is r


def test_annotate_all_walks_map(tmp_path: Path) -> None:
    _ctx_file(tmp_path, {"sink_details": [{"file": "src/handler.py"}]})
    ctx = load_context_map(tmp_path)
    assert ctx is not None
    inputs = {
        "PyPI:a@1": _reach("imported", evidence=["src/handler.py:1"]),
        "PyPI:b@2": _reach("imported", evidence=["src/util.py:1"]),
    }
    out = annotate_all(inputs, ctx)
    assert out["PyPI:a@1"].verdict == "likely_called"
    assert out["PyPI:b@2"].verdict == "imported"


def test_handles_string_or_dict_entries(tmp_path: Path) -> None:
    _ctx_file(tmp_path, {
        "entry_points": [{"file": "a.py"}, "b.py:42",
                          {"location": "c.py:99"}],
    })
    ctx = load_context_map(tmp_path)
    assert ctx is not None
    assert ctx.entry_point_files == {"a.py", "b.py", "c.py"}
