"""Agent-context ``--mark`` rows never earn fold coverage credit.

Review-grade marks are operator-tier (the /annotate authority rule):
``raptor-coverage-summary --mark`` journals ``producer="mark"`` rows
whose ``model`` records the invocation-context tier — ``operator``
under a corroborated interactive terminal, else ``agent-mark``. An
agent assertion carries no evidence gate (unlike ``raptor-audit
record``), so no fold route may let it retire a function from review:
crediting it is a self-coverage laundering channel. Operator rows keep
the full fold behaviour — both directions pinned. Zero LLM calls.
"""

from __future__ import annotations

import pytest

from core.audit.gaps import _verify_entries_fold, compute_gaps
from core.coverage.journal import (
    ReviewJournalEntry,
    append_entry,
    now_iso,
)
from core.staleness import hash_span

_SOURCE = """\
int check_pw(const char *pw) {
    if (!pw)
        return -1;
    return strcmp(pw, stored) == 0;
}
"""

_ITEM = {
    "name": "check_pw",
    "kind": "function",
    "line_start": 1,
    "line_end": 5,
}


@pytest.fixture(autouse=True)
def _isolated_key(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))


def _write_target(tmp_path):
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    (target / "auth.c").write_text(_SOURCE, encoding="utf-8")
    return target


def _checklist(target):
    return {
        "target_path": str(target),
        "files": [{
            "path": "auth.c",
            "language": "c",
            "items": [dict(_ITEM)],
        }],
    }


def _mark_row(target, model="agent-mark", **over):
    fields = {
        "ts": now_iso(),
        "run_id": "run1",
        "file": "auth.c",
        "function": "check_pw",
        "verdict": "clean",
        "source_hash": hash_span(target / "auth.c", 1, 5),
        "line_start": 1,
        "line_end": 5,
        "model": model,
        "producer": "mark",
    }
    fields.update(over)
    return ReviewJournalEntry(**fields)


def _run_dir(tmp_path, *entries):
    run_dir = tmp_path / "run1"
    run_dir.mkdir(exist_ok=True)
    for entry in entries:
        append_entry(run_dir, entry)
    return run_dir


def _gap_keys(gaps):
    return {f"{g['file']}:{g['name']}" for g in gaps}


class TestPlainPerRunFold:
    def test_agent_mark_does_not_suppress_gap(self, tmp_path):
        target = _write_target(tmp_path)
        run_dir = _run_dir(tmp_path, _mark_row(target))
        gaps = compute_gaps(_checklist(target), [], out_dir=run_dir)
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_operator_mark_still_suppresses(self, tmp_path):
        target = _write_target(tmp_path)
        run_dir = _run_dir(tmp_path, _mark_row(target, model="operator"))
        gaps = compute_gaps(_checklist(target), [], out_dir=run_dir)
        assert "auth.c:check_pw" not in _gap_keys(gaps)


class TestVerifiedFoldRoutes:
    def _fold(self, target, entries, reuse_sink=None):
        covered: set = set()
        _verify_entries_fold(
            covered, entries, target_path=target,
            current_spans={"auth.c:check_pw": (1, 5)},
            reuse_sink=reuse_sink,
            current_strategies_fn=lambda *_: set(),
            current_model=None, source_label="test",
        )
        return covered

    def test_agent_mark_not_credited(self, tmp_path):
        target = _write_target(tmp_path)
        covered = self._fold(target, [_mark_row(target)])
        assert covered == set()

    def test_hashless_agent_mark_not_credited(self, tmp_path):
        # The hashless-verified route credits stamped rows without
        # hash evidence — agent marks are screened before it.
        target = _write_target(tmp_path)
        covered = self._fold(
            target, [_mark_row(target, source_hash="")])
        assert covered == set()

    def test_agent_mark_never_enters_reuse_sink(self, tmp_path):
        target = _write_target(tmp_path)
        sink: dict = {}
        covered = self._fold(target, [_mark_row(target)], reuse_sink=sink)
        assert covered == set()
        assert sink == {}

    def test_operator_mark_routes_unchanged(self, tmp_path):
        # In-memory (unstamped) operator row keeps the hash-gated
        # legacy credit — the screen keys on the stamp tier, never on
        # producer="mark" alone.
        target = _write_target(tmp_path)
        covered = self._fold(target, [_mark_row(target, model="operator")])
        assert covered == {"auth.c:check_pw"}
