"""Tests for core.orchestration.run_discovery."""

from __future__ import annotations

import json

import pytest

from core.orchestration.run_discovery import (
    collect_sibling_runs,
    find_sibling_run,
    recorded_target_matches,
)

MARKER = "context-map.json"


def _mk_run(parent, name, target=None):
    d = parent / name
    d.mkdir(parents=True)
    (d / MARKER).write_text("{}")
    if target is not None:
        (d / ".raptor-run.json").write_text(json.dumps({
            "version": 2,
            "command": "understand",
            "status": "completed",
            "target_path": str(target),
        }))
    return d


@pytest.fixture(autouse=True)
def _no_session_ledger(monkeypatch):
    # Tier 0 reads the live session's run ledger — hermetic tests must
    # not see this machine's real runs.
    import core.project.sessions as sessions
    monkeypatch.setattr(sessions, "ledger_runs", lambda: [])


@pytest.fixture
def out_root(tmp_path, monkeypatch):
    root = tmp_path / "out"
    root.mkdir()
    from core.config import RaptorConfig
    monkeypatch.setattr(RaptorConfig, "get_out_dir",
                        classmethod(lambda cls: root))
    return root


class TestTargetGateBeforeGlobalFallback:
    def test_wrong_target_sibling_does_not_suppress_global(
            self, tmp_path, out_root):
        # Pre-fix: a wrong-target sibling counted as "found", the
        # global scan never ran, and the target gate then filtered the
        # sibling out — valid prior evidence under out/ was lost.
        target = tmp_path / "target"
        target.mkdir()
        other = tmp_path / "other"
        other.mkdir()
        proj = tmp_path / "proj"
        origin = proj / "validate-1"
        origin.mkdir(parents=True)
        _mk_run(proj, "understand-wrong", target=other)
        good = _mk_run(out_root, "understand-good", target=target)

        got = find_sibling_run(origin, MARKER, target_path=target)
        assert got == good

    def test_right_target_sibling_wins_without_global(
            self, tmp_path, out_root):
        # Two-direction guard: a right-target sibling still satisfies
        # the search locally — the global fallback stays untriggered.
        target = tmp_path / "target"
        target.mkdir()
        proj = tmp_path / "proj"
        origin = proj / "validate-1"
        origin.mkdir(parents=True)
        sibling = _mk_run(proj, "understand-right", target=target)
        _mk_run(out_root, "understand-global", target=target)

        got = collect_sibling_runs(origin, MARKER, target_path=target)
        assert got == [sibling]

    def test_wrong_target_results_still_filtered(self, tmp_path):
        # The gate itself: wrong-target candidates never survive.
        target = tmp_path / "target"
        target.mkdir()
        other = tmp_path / "other"
        other.mkdir()
        proj = tmp_path / "proj"
        origin = proj / "validate-1"
        origin.mkdir(parents=True)
        _mk_run(proj, "understand-wrong", target=other)

        got = collect_sibling_runs(origin, MARKER, search_global=False,
                                   target_path=target)
        assert got == []


class TestRecordedTargetMatches:
    def test_metadata_less_dir_admitted(self, tmp_path):
        d = _mk_run(tmp_path, "legacy-run")
        assert recorded_target_matches(d, tmp_path / "anything")

    def test_recorded_other_target_rejected(self, tmp_path):
        other = tmp_path / "other"
        other.mkdir()
        d = _mk_run(tmp_path, "run", target=other)
        wanted = tmp_path / "wanted"
        wanted.mkdir()
        assert not recorded_target_matches(d, wanted)
