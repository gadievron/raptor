"""Per-function fuzz-coverage signal in the audit priority scorer.

The scorer accepted only the file-level ``files_examined`` set; the
per-function ``coverage-fuzz.json`` map (now actually produced by
/fuzz) was loaded only from the audit run's own directory and never
influenced scoring. These tests pin the new signal — unreached-by-fuzz
boost, reached-crash-free mild demotion with substantial coverage —
and the sibling-run fallback for the per-function map.
"""

from __future__ import annotations

import json

import pytest

from core.audit.loaders import load_fuzz_coverage_any
from core.audit.priority import (
    FUZZ_SUBSTANTIAL_ITERATIONS,
    SCORE_FUZZ_REACHED_CLEAN,
    SCORE_FUZZ_UNREACHED,
    score_functions,
)


def _gap(name: str = "fn", file: str = "src/a.c") -> dict:
    return {
        "file": file,
        "name": name,
        "priority": 1,
        "sloc": 0,
        "strategies": [],
    }


def _cov(entry: dict, file: str = "src/a.c", name: str = "fn") -> dict:
    return {"files": {file: {"functions": {name: entry}}}}


def _score(gaps, cov):
    return {
        f"{g['file']}:{g['name']}": g["priority_score"]
        for g in score_functions(gaps, fuzz_function_coverage=cov)
    }


class TestScorerSignal:
    def test_unreached_function_boosted(self):
        scores = _score(
            [_gap()],
            _cov({"reached": False, "iterations": 0, "crashes": 0}),
        )
        assert scores["src/a.c:fn"] == SCORE_FUZZ_UNREACHED

    def test_reached_crash_free_substantial_demoted(self):
        scores = _score(
            [_gap()],
            _cov(
                {
                    "reached": True,
                    "iterations": FUZZ_SUBSTANTIAL_ITERATIONS,
                    "crashes": 0,
                }
            ),
        )
        assert scores["src/a.c:fn"] == SCORE_FUZZ_REACHED_CLEAN
        assert SCORE_FUZZ_REACHED_CLEAN < 0

    def test_reached_thin_coverage_neutral(self):
        scores = _score(
            [_gap()],
            _cov({"reached": True, "iterations": 100, "crashes": 0}),
        )
        assert scores["src/a.c:fn"] == 0

    def test_reached_with_crashes_not_demoted(self):
        scores = _score(
            [_gap()],
            _cov(
                {
                    "reached": True,
                    "iterations": FUZZ_SUBSTANTIAL_ITERATIONS,
                    "crashes": 3,
                }
            ),
        )
        assert scores["src/a.c:fn"] == 0

    def test_function_without_record_neutral(self):
        scores = _score(
            [_gap(name="other")],
            _cov({"reached": False}),
        )
        assert scores["src/a.c:other"] == 0

    def test_none_map_no_signal(self):
        scores = _score([_gap()], None)
        assert scores["src/a.c:fn"] == 0

    def test_legacy_record_without_reached_not_boosted(self):
        # Pre-producer records carry only iterations/crashes; absence
        # of "reached" must not be read as unreached.
        scores = _score(
            [_gap()],
            _cov({"iterations": 50, "crashes": 0}),
        )
        assert scores["src/a.c:fn"] == 0

    def test_flat_key_schema_supported(self):
        cov = {"src/a.c:fn": {"reached": False}}
        scores = _score([_gap()], cov)
        assert scores["src/a.c:fn"] == SCORE_FUZZ_UNREACHED

    def test_unreached_stacks_with_high_priority_signals(self):
        context_map = {
            "entry_points": [{"file": "src/a.c", "name": "fn"}],
        }
        scored = score_functions(
            [_gap()],
            context_map=context_map,
            fuzz_function_coverage=_cov({"reached": False}),
        )
        # Entry point (10) + file-has-entry-point (1) + fuzz-unreached
        # (3): fuzz-blind attack surface floats to the top.
        assert scored[0]["priority_score"] == 10 + 1 + SCORE_FUZZ_UNREACHED


class TestSiblingLoad:
    def _write(self, d, data):
        d.mkdir(parents=True, exist_ok=True)
        (d / "coverage-fuzz.json").write_text(json.dumps(data))

    def test_own_run_wins(self, tmp_path):
        own = tmp_path / "audit-run"
        sib = tmp_path / "fuzz-run"
        self._write(own, {"files": {"a.c": {"functions": {}}}, "own": 1})
        self._write(sib, {"files": {"b.c": {"functions": {}}}})
        data = load_fuzz_coverage_any(own, [sib])
        assert data.get("own") == 1

    def test_falls_back_to_newest_sibling(self, tmp_path):
        import os

        own = tmp_path / "audit-run"
        own.mkdir()
        old = tmp_path / "fuzz-old"
        new = tmp_path / "fuzz-new"
        self._write(old, {"files": {"old.c": {"functions": {}}}})
        self._write(new, {"files": {"new.c": {"functions": {}}}})
        os.utime(old / "coverage-fuzz.json", (1, 1))
        data = load_fuzz_coverage_any(own, [old, new])
        assert "new.c" in data["files"]

    def test_sibling_without_function_map_skipped(self, tmp_path):
        own = tmp_path / "audit-run"
        own.mkdir()
        sib = tmp_path / "fuzz-run"
        self._write(sib, {"files_examined": ["a.c"]})
        assert load_fuzz_coverage_any(own, [sib]) is None

    def test_no_sources_returns_none(self, tmp_path):
        own = tmp_path / "audit-run"
        own.mkdir()
        assert load_fuzz_coverage_any(own, []) is None


class TestOrchestratorWiring:
    def test_prep_uses_sibling_fallback_and_scorer_map(self):
        import inspect

        from core.audit import orchestrator as orch_mod

        src = inspect.getsource(orch_mod._compute_audit_prep)
        assert "_load_fuzz_coverage_any" in src
        assert "fuzz_function_coverage=fuzz_coverage" in src


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
