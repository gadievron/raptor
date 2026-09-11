"""raptor-review behavior across its layer loaders.

Covers: ``stale --source journal`` hashing against the SOURCE tree
(never the project OUTPUT dir), ``show`` folding the project index
per function, ``compact`` re-homing legacy index keys, and
``gaps``/``live`` tolerating hostile bytes in run artifacts.
"""

from __future__ import annotations

import argparse
import json
import os
import types
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[3]

TS_OLD = "2026-01-01T00:00:00.000000Z"
TS_NEW = "2026-01-02T00:00:00.000000Z"


def _load_cli():
    os.environ.setdefault("_RAPTOR_TRUSTED", "1")
    script = REPO_ROOT / "libexec" / "raptor-review"
    # Extensionless script — no default loader; exec it by hand.
    mod = types.ModuleType("raptor_review_cli_layers")
    mod.__file__ = str(script)
    code = compile(script.read_text(), str(script), "exec")
    exec(code, mod.__dict__)
    return mod


_cli = _load_cli()


def _entry(
    file: str,
    function: str,
    *,
    ts: str = TS_OLD,
    verdict: str = "clean",
    source_hash: str = "",
    line_start: int = 1,
    line_end: int | None = None,
) -> dict:
    d = {
        "ts": ts,
        "run_id": "r1",
        "file": file,
        "function": function,
        "verdict": verdict,
        "source_hash": source_hash,
        "line_start": line_start,
        "schema_version": 1,
    }
    if line_end is not None:
        d["line_end"] = line_end
    return d


def _write_index(project_dir: Path, entries: dict) -> Path:
    path = project_dir / "review-journal-index.json"
    path.write_text(json.dumps({
        "schema_version": 1,
        "updated_at": TS_OLD,
        "entries": entries,
    }), encoding="utf-8")
    return path


def _write_journal(run_dir: Path, entries: list[dict]) -> Path:
    path = run_dir / "review-journal.jsonl"
    path.write_text(
        "".join(json.dumps(e) + "\n" for e in entries), encoding="utf-8",
    )
    return path


def _ns(**kwargs) -> argparse.Namespace:
    base = {"out": None, "project": None, "target": None, "raw": False}
    base.update(kwargs)
    return argparse.Namespace(**base)


# ── stale --source journal: hash root resolution ─────────────────────

def _stale_fixture(tmp_path: Path) -> tuple[Path, Path, Path, str]:
    """Source tree + project dir + registry with one hashed entry."""
    from core.audit.record import _compute_hash

    srcroot = tmp_path / "repo"
    (srcroot / "src").mkdir(parents=True)
    (srcroot / "src" / "foo.c").write_text(
        "int a;\nint b;\nint c;\n", encoding="utf-8",
    )
    recorded = _compute_hash(srcroot, "src/foo.c", 1, 3)
    assert recorded

    project = tmp_path / "proj"
    project.mkdir()
    _write_index(project, {
        "k1": _entry(
            "src/foo.c", "foo",
            source_hash=recorded, line_start=1, line_end=3,
        ),
    })

    registry = tmp_path / "registry"
    registry.mkdir()
    (registry / "p.json").write_text(json.dumps({
        "name": "p",
        "output_dir": str(project),
        "target": str(srcroot),
    }), encoding="utf-8")
    return srcroot, project, registry, recorded


def test_stale_journal_detects_drift_via_registry_target(tmp_path, capsys):
    """No --target: the project's registry target is the hash root,
    so a drifted source function is reported stale."""
    import core.startup

    srcroot, project, registry, _ = _stale_fixture(tmp_path)
    (srcroot / "src" / "foo.c").write_text(
        "int a;\nint CHANGED;\nint c;\n", encoding="utf-8",
    )
    with patch.object(core.startup, "PROJECTS_DIR", registry):
        _cli._stale_journal(_ns(project=str(project)))
    out = capsys.readouterr().out
    assert "1 stale" in out
    assert "src/foo.c" in out


def test_stale_journal_zero_when_source_unchanged(tmp_path, capsys):
    import core.startup

    _, project, registry, _ = _stale_fixture(tmp_path)
    with patch.object(core.startup, "PROJECTS_DIR", registry):
        _cli._stale_journal(_ns(project=str(project)))
    out = capsys.readouterr().out
    assert "0 stale" in out


def test_stale_journal_explicit_target_wins(tmp_path, capsys):
    """--target hashes against the given tree even with no registry."""
    import core.startup

    srcroot, project, _, _ = _stale_fixture(tmp_path)
    (srcroot / "src" / "foo.c").write_text(
        "int a;\nint CHANGED;\nint c;\n", encoding="utf-8",
    )
    empty_registry = tmp_path / "empty-registry"
    empty_registry.mkdir()
    with patch.object(core.startup, "PROJECTS_DIR", empty_registry):
        _cli._stale_journal(
            _ns(project=str(project), target=str(srcroot)),
        )
    out = capsys.readouterr().out
    assert "1 stale" in out


def test_stale_journal_refuses_output_dir_fallback(tmp_path, capsys):
    """No --target and no resolvable source target: refuse loudly —
    hashing against the project OUTPUT dir would silently report
    every drifted review as fresh."""
    import core.startup

    import pytest

    _, project, _, _ = _stale_fixture(tmp_path)
    empty_registry = tmp_path / "empty-registry"
    empty_registry.mkdir()
    with patch.object(core.startup, "PROJECTS_DIR", empty_registry), \
            pytest.raises(SystemExit) as exc:
        _cli._stale_journal(_ns(project=str(project)))
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "--target" in err


def test_stale_journal_run_metadata_target_fallback(tmp_path, capsys):
    """With no registry entry, the newest run's recorded target_path
    resolves the hash root."""
    import core.startup

    srcroot, project, _, _ = _stale_fixture(tmp_path)
    run_dir = project / "audit_1"
    run_dir.mkdir()
    (run_dir / ".raptor-run.json").write_text(json.dumps({
        "status": "completed", "target_path": str(srcroot),
    }), encoding="utf-8")
    (srcroot / "src" / "foo.c").write_text(
        "int a;\nint CHANGED;\nint c;\n", encoding="utf-8",
    )
    empty_registry = tmp_path / "empty-registry"
    empty_registry.mkdir()
    with patch.object(core.startup, "PROJECTS_DIR", empty_registry):
        _cli._stale_journal(_ns(project=str(project)))
    out = capsys.readouterr().out
    assert "1 stale" in out


# ── show: project index folded per function ──────────────────────────

def test_show_falls_back_to_index_with_nonempty_run_journal(tmp_path, capsys):
    """A function reviewed only in a PRIOR run (project index) still
    shows its verdict when the current run's journal is non-empty."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    _write_journal(run_dir, [_entry("src/b.c", "bar", verdict="clean")])

    project = tmp_path / "proj"
    project.mkdir()
    _write_index(project, {
        "k1": _entry("src/a.c", "foo", verdict="finding"),
    })

    _cli.cmd_show(_ns(
        file="src/a.c", function="foo",
        out=str(run_dir), project=str(project),
    ))
    out = capsys.readouterr().out
    assert "(no review recorded)" not in out
    assert "finding" in out


def test_show_run_entry_wins_over_index(tmp_path, capsys):
    """The current run's journal entry takes precedence; the index is
    only the per-function fallback."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    _write_journal(run_dir, [
        _entry("src/a.c", "foo", ts=TS_NEW, verdict="clean"),
    ])

    project = tmp_path / "proj"
    project.mkdir()
    _write_index(project, {
        "k1": _entry("src/a.c", "foo", ts=TS_OLD, verdict="finding"),
    })

    _cli.cmd_show(_ns(
        file="src/a.c", function="foo",
        out=str(run_dir), project=str(project),
    ))
    out = capsys.readouterr().out
    assert "clean" in out
    assert "finding" not in out


# ── compact: legacy-key re-homing ────────────────────────────────────

def test_compact_rehomes_legacy_keys(tmp_path, capsys):
    from core.coverage.journal import _entry_from_dict

    project = tmp_path / "proj"
    project.mkdir()
    row = _entry("src/a.c", "foo")
    index_path = _write_index(project, {
        "legacy-key": row,
        "junk": {"not": "an entry"},
    })

    _cli.cmd_compact(_ns(project=str(project)))
    out = capsys.readouterr().out
    assert "1 legacy key(s) re-homed" in out

    data = json.loads(index_path.read_text(encoding="utf-8"))
    entries = data["entries"]
    expected_key = _entry_from_dict(row).index_key
    assert "legacy-key" not in entries
    assert entries[expected_key] == row
    # Unparseable rows are preserved verbatim, never dropped.
    assert entries["junk"] == {"not": "an entry"}


def test_compact_is_idempotent(tmp_path, capsys):
    project = tmp_path / "proj"
    project.mkdir()
    index_path = _write_index(project, {
        "legacy-key": _entry("src/a.c", "foo"),
    })

    _cli.cmd_compact(_ns(project=str(project)))
    capsys.readouterr()
    first = index_path.read_text(encoding="utf-8")

    _cli.cmd_compact(_ns(project=str(project)))
    out = capsys.readouterr().out
    assert "already compact" in out
    assert index_path.read_text(encoding="utf-8") == first


def test_compact_merges_legacy_duplicate_latest_wins(tmp_path, capsys):
    from core.coverage.journal import _entry_from_dict

    project = tmp_path / "proj"
    project.mkdir()
    older = _entry("src/a.c", "foo", ts=TS_OLD, verdict="clean")
    newer = _entry("src/a.c", "foo", ts=TS_NEW, verdict="finding")
    proper_key = _entry_from_dict(newer).index_key
    index_path = _write_index(project, {
        "legacy-key": older,
        proper_key: newer,
    })

    _cli.cmd_compact(_ns(project=str(project)))
    out = capsys.readouterr().out
    assert "2 -> 1 entries" in out

    data = json.loads(index_path.read_text(encoding="utf-8"))
    assert data["entries"] == {proper_key: newer}


# ── gaps: malformed run artifacts degrade, never traceback ───────────

def test_gaps_toplevel_list_degrades(tmp_path, capsys):
    import pytest

    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "gaps.json").write_text("[1, 2]", encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        _cli.cmd_gaps(_ns(out=str(run_dir)))
    assert exc.value.code == 1
    assert "Failed to read gaps.json" in capsys.readouterr().err


def test_gaps_hostile_records_degrade_and_valid_rows_render(tmp_path, capsys):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "gaps.json").write_text(json.dumps({
        "gaps": [
            42,  # non-dict record: skipped, not a traceback
            {"priority": 3, "file": "src/a.c", "name": "foo",
             "strategies": ["taint"]},
        ],
    }), encoding="utf-8")
    (run_dir / "edge-obligations.json").write_text(json.dumps({
        "tier1": ["junk", {"caller_file": "src/a.c"}],  # keys missing
        "tier2": 7,  # non-list tier
    }), encoding="utf-8")

    _cli.cmd_gaps(_ns(out=str(run_dir)))
    out = capsys.readouterr().out
    assert "1 function(s) need review" in out
    assert "src/a.c" in out


# ── live: bounded journal reads ──────────────────────────────────────

def test_live_renders_entries_and_exits_on_terminal_status(tmp_path, capsys):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / ".raptor-run.json").write_text(
        json.dumps({"status": "completed"}), encoding="utf-8",
    )
    _write_journal(run_dir, [
        {"ts": TS_OLD, "file": "src/a.c", "function": "foo",
         "verdict": "clean", "cost_usd": 0.25},
    ])

    _cli.cmd_live(_ns(out=str(run_dir)))
    out = capsys.readouterr().out
    assert "src/a.c:foo" in out
    assert "run completed." in out


def test_live_read_is_bounded_per_poll(tmp_path, capsys, monkeypatch):
    """A complete line within the byte budget renders even when the
    journal continues past the budget — the read is capped, the
    partial tail dropped."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / ".raptor-run.json").write_text(
        json.dumps({"status": "completed"}), encoding="utf-8",
    )
    good = json.dumps({
        "ts": TS_OLD, "file": "a.c", "function": "f", "verdict": "clean",
    })
    giant = "x" * 4096
    (run_dir / "review-journal.jsonl").write_text(
        good + "\n" + giant + "\n", encoding="utf-8",
    )
    monkeypatch.setattr(_cli, "_MAX_ARTIFACT_BYTES", len(good) + 16)

    _cli.cmd_live(_ns(out=str(run_dir)))
    out = capsys.readouterr().out
    assert "a.c:f" in out
    assert "xxxx" not in out


def test_live_skips_line_larger_than_budget(tmp_path, capsys, monkeypatch):
    """A single line larger than the whole budget cannot complete —
    it is skipped instead of stalling the tail or being slurped."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / ".raptor-run.json").write_text(
        json.dumps({"status": "completed"}), encoding="utf-8",
    )
    (run_dir / "review-journal.jsonl").write_text(
        "y" * 4096 + "\n", encoding="utf-8",
    )
    monkeypatch.setattr(_cli, "_MAX_ARTIFACT_BYTES", 64)

    _cli.cmd_live(_ns(out=str(run_dir)))
    out = capsys.readouterr().out
    assert "yyyy" not in out
    assert "run completed." in out
