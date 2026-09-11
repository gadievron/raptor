"""Tests for raptor_fuzzing.py / raptor_codeql.py entry-point fixes.

Covers:
  1. ``_sage_afl_prior_enabled`` — the RAPTOR_SAGE_AFL_PRIOR opt-out
     goes through the canonical env_flag parser (two-direction:
     every documented falsy spelling disables, truthy/unset enables).
  2. ``_orchestrator_ignored_flags`` — legacy-only CLI flags are
     surfaced (not silently dropped) when the orchestrator path runs.
  3. Zero-crash campaigns record a strategy outcome before exiting.
  4. The crash-analysis banner prints AFTER the stack-hash dedup, so
     duplicates never reuse an index.
  5. raptor_codeql.py --scan-only records build reliability.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_RAPTOR_ROOT = Path(__file__).resolve().parents[3]


def _import_fuzzing():
    if str(_RAPTOR_ROOT) not in sys.path:
        sys.path.insert(0, str(_RAPTOR_ROOT))
    import raptor_fuzzing
    return raptor_fuzzing


# ---------------------------------------------------------------------------
# _sage_afl_prior_enabled
# ---------------------------------------------------------------------------


class TestSageAflPriorToggle:
    def test_documented_falsy_spellings_disable(self, monkeypatch):
        fuzzing = _import_fuzzing()
        for value in ("0", "false", "no", "off", " OFF "):
            monkeypatch.setenv("RAPTOR_SAGE_AFL_PRIOR", value)
            assert fuzzing._sage_afl_prior_enabled() is False, value

    def test_truthy_and_unset_enable(self, monkeypatch):
        fuzzing = _import_fuzzing()
        monkeypatch.delenv("RAPTOR_SAGE_AFL_PRIOR", raising=False)
        assert fuzzing._sage_afl_prior_enabled() is True
        for value in ("1", "true", "yes", "on"):
            monkeypatch.setenv("RAPTOR_SAGE_AFL_PRIOR", value)
            assert fuzzing._sage_afl_prior_enabled() is True, value


# ---------------------------------------------------------------------------
# _orchestrator_ignored_flags
# ---------------------------------------------------------------------------


def _parser_with_legacy_flags() -> argparse.ArgumentParser:
    """Minimal parser with the legacy-only flags at their real defaults."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--parallel", type=int, default=1)
    ap.add_argument("--timeout", type=int, default=1000)
    ap.add_argument("--input-mode", choices=["stdin", "file"], default="stdin")
    ap.add_argument("--max-crashes", type=int, default=10)
    ap.add_argument("--rank-crashes", action="store_true")
    ap.add_argument("--autonomous", action="store_true")
    ap.add_argument("--goal")
    ap.add_argument("--memory-file")
    ap.add_argument("--check-sanitizers", action="store_true")
    ap.add_argument("--recompile-guide", action="store_true")
    ap.add_argument("--use-showmap", action="store_true")
    return ap


class TestOrchestratorIgnoredFlags:
    def test_defaults_report_nothing(self):
        fuzzing = _import_fuzzing()
        ap = _parser_with_legacy_flags()
        args = ap.parse_args([])
        assert fuzzing._orchestrator_ignored_flags(args, ap) == []

    def test_explicit_flags_are_reported(self):
        fuzzing = _import_fuzzing()
        ap = _parser_with_legacy_flags()
        args = ap.parse_args(
            ["--parallel", "8", "--input-mode", "file", "--autonomous",
             "--max-crashes", "5"],
        )
        ignored = fuzzing._orchestrator_ignored_flags(args, ap)
        assert set(ignored) == {
            "--parallel", "--input-mode", "--autonomous", "--max-crashes",
        }

    def test_orchestrator_path_warns_before_planning(self):
        # The warning must fire on the orchestrator path itself —
        # including when it was AUTO-selected — before any campaign
        # work happens.
        src = (_RAPTOR_ROOT / "raptor_fuzzing.py").read_text(encoding="utf-8")
        warn_at = src.index("_orchestrator_ignored_flags(args, ap)")
        plan_at = src.index("orch.plan(")
        assert warn_at < plan_at


# ---------------------------------------------------------------------------
# zero-crash campaigns record a strategy outcome
# ---------------------------------------------------------------------------


class TestZeroCrashOutcomeRecorded:
    def test_recording_precedes_the_early_exit(self):
        src = (_RAPTOR_ROOT / "raptor_fuzzing.py").read_text(encoding="utf-8")
        zero_branch = src.index('"status": "no_crashes"')
        exit_at = src.index("sys.exit(0)", zero_branch)
        block = src[zero_branch:exit_at]
        assert "store_fuzzing_strategy_outcome(" in block
        assert "unique_crashes=0" in block
        # Autonomous memory learns the negative signal too.
        assert "record_strategy_success(" in block


# ---------------------------------------------------------------------------
# banner index vs. dedup ordering
# ---------------------------------------------------------------------------


class TestCrashBannerOrdering:
    def test_banner_prints_only_for_analysed_crashes(self):
        src = (_RAPTOR_ROOT / "raptor_fuzzing.py").read_text(encoding="utf-8")
        dedup_at = src.index("Duplicate crash - same stack trace")
        counter_at = src.index("attempted += 1", dedup_at)
        banner_at = src.index('print(f"CRASH {attempted}', dedup_at)
        # dedup skip → counter advance → banner: a skipped duplicate
        # never prints an index, and every printed index is unique.
        assert dedup_at < counter_at < banner_at


# ---------------------------------------------------------------------------
# raptor_codeql.py --scan-only records build reliability
# ---------------------------------------------------------------------------


class TestScanOnlyRecordsBuildReliability:
    def test_scan_only_branch_stores_outcome(self):
        src = (_RAPTOR_ROOT / "raptor_codeql.py").read_text(encoding="utf-8")
        branch_at = src.index("if args.scan_only:")
        next_branch_at = src.index("if scan_result.total_findings == 0:")
        block = src[branch_at:next_branch_at]
        assert "store_codeql_build_reliability(" in block
        # Distinguishes findings-bearing scans from empty ones.
        assert '"no_findings"' in block
