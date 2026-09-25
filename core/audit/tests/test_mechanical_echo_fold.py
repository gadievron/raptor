"""Mechanically-minted journal rows never earn fold coverage credit.

Post-loop pattern checks and the decomp sweep journal one
``[mechanical]`` echo row per pattern-scan finding, and the
consistency census journals one ``[consistency:...]`` row per LLM-free
synthesized outcome — producer ``audit``, settled verdict, zero LLM
review. They are written for GAP functions (the decomp sweep runs over
exactly the functions no review visited), so any fold route that
credits them retires never-reviewed functions from the queue: the
plain per-run fold on a reuse-disabled resume, and the verified fold's
plain-credit routes (reuse disabled, unstamped tier, hashless
verified). With verdict reuse ENABLED the eligibility screen already
refused the mechanical strategy tags — pinned here as the control
direction. Zero LLM calls.
"""

from __future__ import annotations

import pytest

from core.audit.gaps import _verify_entries_fold, compute_gaps
from core.audit.strategy import strategies_from_item
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


def _entry(target, **over):
    fields = {
        "ts": now_iso(),
        "run_id": "run1",
        "file": "auth.c",
        "function": "check_pw",
        "verdict": "clean",
        "source_hash": hash_span(target / "auth.c", 1, 5),
        "line_start": 1,
        "line_end": 5,
        "strategies": sorted(strategies_from_item(dict(_ITEM), "auth.c")),
        "model": "model-a",
        "body": "review body",
    }
    fields.update(over)
    return ReviewJournalEntry(**fields)


# Both mechanically-minted row kinds: pattern-scan echoes and the
# consistency census's LLM-free synthesized outcomes. Every screen
# under test must treat them identically — the census rows carry
# NEITHER of the pattern-echo markers, so a marker-list regression
# resurfaces here.
_MECH_SHAPES = {
    "pattern-echo": {
        "strategies": ["post-loop-mechanical"],
        "body": "[mechanical] pattern match in check_pw",
    },
    "consistency-census": {
        "strategies": ["consistency-census"],
        "body": "[consistency:handler-outcome] census-confirmed variant",
    },
}


def _echo(target, shape="pattern-echo", **over):
    fields = {
        "verdict": "suspicious",
        "model": None,
        **_MECH_SHAPES[shape],
    }
    fields.update(over)
    return _entry(target, **fields)


def _run_dir(tmp_path, *entries):
    run_dir = tmp_path / "run1"
    run_dir.mkdir(exist_ok=True)
    for entry in entries:
        append_entry(run_dir, entry)
    return run_dir


def _gap_keys(gaps):
    return {f"{g['file']}:{g['name']}" for g in gaps}


class TestPlainPerRunFold:
    """The reuse-DISABLED resume path (gaps: plain covered.update)."""

    @pytest.mark.parametrize("shape", sorted(_MECH_SHAPES))
    def test_echo_row_does_not_suppress_gap(self, tmp_path, shape):
        target = _write_target(tmp_path)
        run_dir = _run_dir(tmp_path, _echo(target, shape))
        gaps = compute_gaps(_checklist(target), [], out_dir=run_dir)
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_genuine_review_row_still_suppresses(self, tmp_path):
        target = _write_target(tmp_path)
        run_dir = _run_dir(tmp_path, _entry(target))
        gaps = compute_gaps(_checklist(target), [], out_dir=run_dir)
        assert "auth.c:check_pw" not in _gap_keys(gaps)

    @pytest.mark.parametrize("shape", sorted(_MECH_SHAPES))
    def test_echo_beside_genuine_review_keeps_suppression(
            self, tmp_path, shape):
        # An echo row for an already-reviewed function must not
        # RESURFACE it either — the genuine row's credit stands.
        target = _write_target(tmp_path)
        run_dir = _run_dir(tmp_path, _entry(target), _echo(target, shape))
        gaps = compute_gaps(_checklist(target), [], out_dir=run_dir)
        assert "auth.c:check_pw" not in _gap_keys(gaps)


class TestOwnRunReuseFold:
    """The same-run resume verified fold."""

    @pytest.mark.parametrize("shape", sorted(_MECH_SHAPES))
    def test_echo_row_neither_credits_nor_imports(self, tmp_path, shape):
        target = _write_target(tmp_path)
        run_dir = _run_dir(tmp_path, _echo(target, shape))
        sink: dict = {}
        gaps = compute_gaps(
            _checklist(target), [], out_dir=run_dir,
            reuse_sink=sink, own_run_reuse=True,
            current_model="model-a",
        )
        assert sink == {}
        assert "auth.c:check_pw" in _gap_keys(gaps)


class TestVerifiedFoldRoutes:
    """_verify_entries_fold's plain-credit routes, both fold modes."""

    def _fold(self, target, entries, reuse_sink):
        covered: set = set()
        _verify_entries_fold(
            covered, entries, target_path=target,
            current_spans={"auth.c:check_pw": (1, 5)},
            reuse_sink=reuse_sink,
            current_strategies_fn=lambda *_: set(),
            current_model=None, source_label="test",
        )
        return covered

    @pytest.mark.parametrize("shape", sorted(_MECH_SHAPES))
    def test_echo_row_not_credited_with_reuse_disabled(
            self, tmp_path, shape):
        target = _write_target(tmp_path)
        covered = self._fold(
            target, [_echo(target, shape)], reuse_sink=None)
        assert covered == set()

    @pytest.mark.parametrize("shape", sorted(_MECH_SHAPES))
    def test_hashless_echo_row_not_credited(self, tmp_path, shape):
        # The hashless-verified route credits stamped rows without
        # hash evidence — echo rows must be screened before it.
        target = _write_target(tmp_path)
        covered = self._fold(
            target, [_echo(target, shape, source_hash="")],
            reuse_sink=None)
        assert covered == set()

    @pytest.mark.parametrize("shape", sorted(_MECH_SHAPES))
    def test_echo_row_never_enters_reuse_sink(self, tmp_path, shape):
        # Control direction: with reuse ENABLED the outcome is the
        # same — no credit, no $0 import (previously enforced by the
        # strategy screen refusing the mechanical tags, now screened
        # before any route).
        target = _write_target(tmp_path)
        sink: dict = {}
        covered = self._fold(
            target, [_echo(target, shape)], reuse_sink=sink)
        assert covered == set()
        assert sink == {}

    def test_genuine_row_routes_unchanged(self, tmp_path):
        # An in-memory (unstamped) genuine row keeps the hash-gated
        # legacy credit — the echo screen must not widen into a
        # review-row screen. (Verdict-reuse for stamped genuine rows
        # is pinned in test_same_run_resume.)
        target = _write_target(tmp_path)
        covered = self._fold(target, [_entry(target)], reuse_sink=None)
        assert covered == {"auth.c:check_pw"}
