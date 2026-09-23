"""Tests for dated-snapshot retention pruning."""

from __future__ import annotations

from pathlib import Path

import pytest

from packages.sca.calibration._snapshots import prune_dated_snapshots


def _mk(directory: Path, names: list[str]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for n in names:
        (directory / n).write_text("{}")


def test_prunes_oldest_beyond_keep(tmp_path: Path) -> None:
    _mk(tmp_path, [f"2026-01-{d:02d}.json" for d in range(1, 8)])
    deleted = prune_dated_snapshots(tmp_path, keep=3)
    assert [p.name for p in deleted] == [
        f"2026-01-{d:02d}.json" for d in range(1, 5)
    ]
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "2026-01-05.json", "2026-01-06.json", "2026-01-07.json",
    ]


def test_keeps_everything_within_window(tmp_path: Path) -> None:
    _mk(tmp_path, ["2026-01-01.json", "2026-01-02.json"])
    assert prune_dated_snapshots(tmp_path, keep=5) == []
    assert len(list(tmp_path.iterdir())) == 2


def test_never_touches_non_snapshot_files(tmp_path: Path) -> None:
    _mk(tmp_path, [
        "2026-01-01.json", "2026-01-02.json", "2026-01-03.json",
        "README.md", "notes.json", "2026-01-02.joint.json",
    ])
    prune_dated_snapshots(tmp_path, keep=1)
    survivors = sorted(p.name for p in tmp_path.iterdir())
    assert "README.md" in survivors
    assert "notes.json" in survivors
    # joint snapshots participate in the same window
    assert survivors == ["2026-01-03.json", "README.md", "notes.json"]


def test_missing_directory_is_a_noop(tmp_path: Path) -> None:
    assert prune_dated_snapshots(tmp_path / "absent", keep=3) == []


def test_keep_must_be_positive(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="keep"):
        prune_dated_snapshots(tmp_path, keep=0)


def test_validate_corpus_prunes_validation_dir(
    tmp_path: Path, monkeypatch,
) -> None:
    """The validate writer applies retention on the explicit
    snapshot-update path (and only there — the plain default is
    metrics-only and must not prune committed history)."""
    import json as _json
    from packages.sca.calibration import _snapshots
    from packages.sca.calibration.validate import validate_corpus
    monkeypatch.setattr(_snapshots, "VALIDATION_KEEP", 2)
    # VALIDATION_KEEP is read at call time via the module attr the
    # writer imports; patch the module-level constant it resolves.
    corpus_dir = tmp_path / "calibration"
    samples_dir = corpus_dir / "project_samples" / "PyPI"
    samples_dir.mkdir(parents=True)
    (samples_dir / "synthetic.json").write_text(_json.dumps({
        "_source": {"license": "MIT", "url": "x"},
        "findings": [],
    }))
    _mk(corpus_dir / "validation",
        ["2020-01-01.json", "2020-01-02.json", "2020-01-03.json"])
    validate_corpus(corpus_dir, update_snapshot=True)
    names = sorted(
        p.name for p in (corpus_dir / "validation").iterdir()
    )
    # Three stale + one fresh, window of 2 → the two newest survive.
    assert len(names) == 2
    assert "2020-01-01.json" not in names
    assert "2020-01-02.json" not in names
