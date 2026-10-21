"""Tests for negative-control batching in run_semgrep_sweep.

When a dynamic rule will need its negative-control fixture anyway,
the sweep folds the fixture into the main invocation as an extra
target and splits the findings back per file — one semgrep process
instead of two. The contract under test: the confirm/refute logic
sees exactly the inputs the two-process path would produce, and every
ambiguity falls back to that path.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

import core.audit.sweep as sweep_mod
from core.audit.sweep import (
    _negative_control_cache,
    negative_control_fixture,
    run_semgrep_sweep,
)

KEYWORD = "use after free"
SOURCE = "void f(char *p) { free(p); }\n"


@pytest.fixture(autouse=True)
def _clear_negative_control_cache():
    _negative_control_cache.clear()
    yield
    _negative_control_cache.clear()


class _Result:
    def __init__(self, findings=None, errors=None, returncode=0,
                 files_failed=None, files_examined=None):
        self.findings = findings or []
        self.errors = errors or []
        self.returncode = returncode
        self.files_failed = files_failed or []
        self.files_examined = files_examined or []


def _install_fake_semgrep(monkeypatch, run_rule):
    fake = types.ModuleType("packages.semgrep.runner")
    fake.run_rule = run_rule
    fake.is_available = lambda: True
    monkeypatch.setitem(sys.modules, "packages.semgrep.runner", fake)


def _finding(path: str, line: int) -> dict:
    return {"file": path, "start": {"line": line}}


def _sweep(tmp_path: Path):
    return run_semgrep_sweep(
        target_path=tmp_path,
        file_path="a.c",
        function_name="f",
        rule_config="dyn.yaml",
        rule_keyword=KEYWORD,
    )


def _batched_fake(monkeypatch, tmp_path: Path, *, control_fires: bool,
                  files_failed=None, examine_fixture: bool = True):
    """Fake runner serving BOTH targets of a batched invocation with
    file-attributed findings; records every call.

    Models the real runner's --json-output parse: scanned targets
    land in ``files_examined`` (paths.scanned). ``examine_fixture=
    False`` models semgrep silently SKIPPING the ride-along fixture
    (paths.skipped — in neither errors nor files_failed).
    """
    calls: list[dict] = []
    target_file = str(tmp_path / "a.c")

    def run_rule(target, config, **kw):
        extra = [str(t) for t in kw.get("extra_targets") or []]
        calls.append({"target": str(target), "extra_targets": extra})
        examined = [str(target)]
        if extra and examine_fixture:
            examined.extend(extra)
        findings = [_finding(target_file, 1)]
        if extra and control_fires:
            findings.append(_finding(extra[0], 3))
        if not extra and "negative_controls" in str(target):
            # Separate-process control leg (fallback path only).
            findings = [_finding(str(target), 3)] if control_fires else []
        return _Result(findings=findings, files_failed=files_failed,
                       files_examined=examined)

    _install_fake_semgrep(monkeypatch, run_rule)
    return calls


class TestBatchedControl:
    def test_fixture_rides_along_as_extra_target(self, tmp_path, monkeypatch):
        (tmp_path / "a.c").write_text(SOURCE)
        calls = _batched_fake(monkeypatch, tmp_path, control_fires=False)
        _sweep(tmp_path)
        assert len(calls) == 1
        fixture = negative_control_fixture(KEYWORD, "a.c")
        assert calls[0]["extra_targets"] == [str(fixture)]

    def test_control_firing_in_batch_caps_at_inconclusive(
        self, tmp_path, monkeypatch,
    ):
        (tmp_path / "a.c").write_text(SOURCE)
        calls = _batched_fake(monkeypatch, tmp_path, control_fires=True)
        result = _sweep(tmp_path)
        assert result.outcome == "inconclusive"
        assert "presence detector" in (result.details or {})["reason"]
        assert len(calls) == 1  # no separate control process

    def test_clean_control_in_batch_confirms(self, tmp_path, monkeypatch):
        (tmp_path / "a.c").write_text(SOURCE)
        calls = _batched_fake(monkeypatch, tmp_path, control_fires=False)
        result = _sweep(tmp_path)
        assert result.outcome == "confirmed"
        assert len(result.matches) == 1  # control findings never leak in
        assert len(calls) == 1

    def test_batched_verdict_is_cached_for_later_sweeps(
        self, tmp_path, monkeypatch,
    ):
        (tmp_path / "a.c").write_text(SOURCE)
        calls = _batched_fake(monkeypatch, tmp_path, control_fires=True)
        _sweep(tmp_path)
        _sweep(tmp_path)
        assert len(calls) == 2
        # Second sweep: cached verdict → no extra target, no control run.
        assert calls[1]["extra_targets"] == []

    def test_silently_skipped_fixture_banks_nothing(
        self, tmp_path, monkeypatch,
    ):
        """semgrep can silently SKIP a target (paths.skipped) — the
        skip surfaces in neither ``errors`` nor ``files_failed``.
        Banking ``False`` from a scan that never examined the fixture
        permanently disarmed the presence-detector cap for the
        keyword (the control cache is process-lifetime). The sweep
        must bank nothing and fall back to the separate-process
        control, which still caps."""
        (tmp_path / "a.c").write_text(SOURCE)
        calls = _batched_fake(
            monkeypatch, tmp_path, control_fires=True,
            examine_fixture=False,
        )
        result = _sweep(tmp_path)
        # Nothing was banked from the batch — the separate-process
        # control leg ran and capped the result.
        assert result.outcome == "inconclusive"
        assert "presence detector" in (result.details or {})["reason"]
        assert len(calls) == 2
        assert "negative_controls" in calls[1]["target"]
        assert list(_negative_control_cache.values()) == [True]

    def test_silently_skipped_fixture_clean_control_confirms(
        self, tmp_path, monkeypatch,
    ):
        """Skip-shape counterpart: the separate-process control that
        replaces the unbanked batch leg can also come back clean —
        the sweep then confirms exactly as the two-process path
        would."""
        (tmp_path / "a.c").write_text(SOURCE)
        calls = _batched_fake(
            monkeypatch, tmp_path, control_fires=False,
            examine_fixture=False,
        )
        result = _sweep(tmp_path)
        assert result.outcome == "confirmed"
        assert len(calls) == 2
        assert "negative_controls" in calls[1]["target"]
        assert list(_negative_control_cache.values()) == [False]

    def test_fixture_parse_failure_banks_nothing(self, tmp_path, monkeypatch):
        (tmp_path / "a.c").write_text(SOURCE)
        fixture = negative_control_fixture(KEYWORD, "a.c")
        calls = _batched_fake(
            monkeypatch, tmp_path, control_fires=True,
            files_failed=[{"path": str(fixture), "reason": "parse error"}],
        )
        result = _sweep(tmp_path)
        # The separate-process control leg ran and capped the result.
        assert result.outcome == "inconclusive"
        assert len(calls) == 2
        assert "negative_controls" in calls[1]["target"]


class TestBatchingFallbacks:
    def test_unattributed_findings_discard_the_batch(
        self, tmp_path, monkeypatch,
    ):
        (tmp_path / "a.c").write_text(SOURCE)
        calls: list[dict] = []

        def run_rule(target, config, **kw):
            extra = [str(t) for t in kw.get("extra_targets") or []]
            calls.append({"target": str(target), "extra_targets": extra})
            if "negative_controls" in str(target):
                return _Result(findings=[])
            # No file attribution on the findings.
            return _Result(findings=[{"start": {"line": 1}}])

        _install_fake_semgrep(monkeypatch, run_rule)
        result = _sweep(tmp_path)
        assert result.outcome == "confirmed"
        # Batched attempt, target-only retry, separate control run.
        assert len(calls) == 3
        assert calls[1]["extra_targets"] == []
        assert "negative_controls" in calls[2]["target"]

    def test_batch_error_retries_target_only(self, tmp_path, monkeypatch):
        (tmp_path / "a.c").write_text(SOURCE)
        calls: list[dict] = []
        target_file = str(tmp_path / "a.c")

        def run_rule(target, config, **kw):
            extra = [str(t) for t in kw.get("extra_targets") or []]
            calls.append({"target": str(target), "extra_targets": extra})
            if extra:
                return _Result(errors=["fixture leg exploded"], returncode=2)
            if "negative_controls" in str(target):
                return _Result(findings=[])
            return _Result(findings=[_finding(target_file, 1)])

        _install_fake_semgrep(monkeypatch, run_rule)
        result = _sweep(tmp_path)
        # A batch-only failure must not become the sweep's error.
        assert result.outcome == "confirmed"
        assert calls[1]["extra_targets"] == []

    def test_language_mismatch_skips_batching(self, tmp_path, monkeypatch):
        # cpp rule + .c fixture needs the re-languaged control copy —
        # stays on the separate-process path.
        (tmp_path / "a.cpp").write_text(SOURCE)
        calls: list[dict] = []

        def run_rule(target, config, **kw):
            extra = [str(t) for t in kw.get("extra_targets") or []]
            calls.append({"extra_targets": extra})
            return _Result(findings=[])

        _install_fake_semgrep(monkeypatch, run_rule)
        run_semgrep_sweep(
            target_path=tmp_path,
            file_path="a.cpp",
            function_name="f",
            rule_config="dyn.yaml",
            rule_keyword=KEYWORD,
        )
        assert all(c["extra_targets"] == [] for c in calls)

    def test_basename_collision_skips_batching(self, tmp_path, monkeypatch):
        fixture = negative_control_fixture(KEYWORD, "a.c")
        assert fixture is not None
        (tmp_path / fixture.name).write_text(SOURCE)
        calls: list[dict] = []

        def run_rule(target, config, **kw):
            extra = [str(t) for t in kw.get("extra_targets") or []]
            calls.append({"extra_targets": extra})
            return _Result(findings=[])

        _install_fake_semgrep(monkeypatch, run_rule)
        run_semgrep_sweep(
            target_path=tmp_path,
            file_path=fixture.name,
            function_name="f",
            rule_config="dyn.yaml",
            rule_keyword=KEYWORD,
        )
        assert all(c["extra_targets"] == [] for c in calls)

    def test_no_keyword_never_batches(self, tmp_path, monkeypatch):
        (tmp_path / "a.c").write_text(SOURCE)
        calls: list[dict] = []

        def run_rule(target, config, **kw):
            calls.append({"extra_targets": kw.get("extra_targets")})
            return _Result(findings=[])

        _install_fake_semgrep(monkeypatch, run_rule)
        run_semgrep_sweep(
            target_path=tmp_path,
            file_path="a.c",
            function_name="f",
            rule_config="stock.yaml",
        )
        assert calls == [{"extra_targets": None}] or calls == [
            {"extra_targets": []},
        ]


class TestBatchedUnbatchedParity:
    """Fixture-driven: the same ground-truth findings served through
    the batched path and the two-process path must yield identical
    sweep outcomes and matches."""

    CASES = (
        # (target_finding_lines, control_fires, expected_outcome)
        ([1], False, "confirmed"),
        ([1], True, "inconclusive"),
        # A keyword (dynamic per-hypothesis) rule's scanned zero-match
        # is inconclusive on BOTH paths — keyword rules are
        # confirm-only (their silence answers the regex, never the
        # class); the parity is what this class pins.
        ([], False, "inconclusive"),
        ([], True, "inconclusive"),
    )

    @pytest.mark.parametrize(
        ("match_lines", "control_fires", "expected"), CASES,
    )
    def test_outcomes_match(
        self, tmp_path, monkeypatch, match_lines, control_fires, expected,
    ):
        (tmp_path / "a.c").write_text(SOURCE)
        target_file = str(tmp_path / "a.c")

        def batched_run_rule(target, config, **kw):
            extra = [str(t) for t in kw.get("extra_targets") or []]
            findings = [_finding(target_file, ln) for ln in match_lines]
            if extra and control_fires:
                findings.append(_finding(extra[0], 3))
            if not extra and "negative_controls" in str(target):
                findings = (
                    [_finding(str(target), 3)] if control_fires else []
                )
            return _Result(findings=findings,
                           files_examined=[str(target), *extra])

        def unbatched_run_rule(target, config, **kw):
            if "negative_controls" in str(target):
                return _Result(
                    findings=(
                        [_finding(str(target), 3)] if control_fires else []
                    ),
                )
            # The scanned target rides in files_examined, as the real
            # runner reports — the refutation cases need the scanned
            # witness on both paths for the parity to hold.
            return _Result(
                findings=[_finding(target_file, ln) for ln in match_lines],
                files_examined=[str(target)],
            )

        _install_fake_semgrep(monkeypatch, batched_run_rule)
        batched = _sweep(tmp_path)

        _negative_control_cache.clear()
        # Disable the batch plan so the sweep takes the historical
        # two-process path with the same ground truth.
        monkeypatch.setattr(
            sweep_mod, "_negative_control_batch_plan",
            lambda *a, **kw: (None, None),
        )
        _install_fake_semgrep(monkeypatch, unbatched_run_rule)
        unbatched = _sweep(tmp_path)

        assert batched.outcome == unbatched.outcome == expected
        assert batched.matches == unbatched.matches
        assert (batched.details or {}).get("reason") == (
            (unbatched.details or {}).get("reason")
        )
