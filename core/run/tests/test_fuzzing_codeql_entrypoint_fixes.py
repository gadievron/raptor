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


# ---------------------------------------------------------------------------
# _exploitability_from_deep_analysis
# ---------------------------------------------------------------------------


class TestExploitabilityFromDeepAnalysis:
    def test_definitive_levels_map_to_verdicts(self):
        fuzzing = _import_fuzzing()
        fn = fuzzing._exploitability_from_deep_analysis
        assert fn("high") == "exploitable"
        assert fn("medium") == "exploitable"
        assert fn("low") == "not_exploitable"

    def test_abstention_and_junk_are_none_not_negative(self):
        # The multi-turn producer preserves "unknown" as a
        # non-verdict; absent and junk shapes are the same
        # abstention. Pre-fix all of these minted the definitive
        # "not_exploitable" (and a durable exploitable=False memory
        # fact) from a verdict no model produced.
        fuzzing = _import_fuzzing()
        fn = fuzzing._exploitability_from_deep_analysis
        for level in ("unknown", None, "", "critical", 0.9, ["high"], {}):
            assert fn(level) is None


# ---------------------------------------------------------------------------
# Multi-turn verdict -> exploit generation and crash-pattern memory
# ---------------------------------------------------------------------------


def _crash_loop_code():
    """Compile raptor_fuzzing.py's real crash-analysis loop, the single
    ``for crash in crash_pool`` statement, unmodified.

    Omitted enclosing setup and why it cannot change these cases: the
    code before the loop parses arguments, runs the fuzzing campaign,
    collects and ranks crashes, and constructs ``crash_analyser``,
    ``multi_turn``, ``llm_agent``, ``memory`` and the counters. The test
    supplies those names directly: one crash in ``crash_pool``, a
    ``crash_analyser`` stub that returns a fresh CrashContext (the
    loop's input) and a fixed crash type, a real MultiTurnAnalyser on
    scripted replies, a real FuzzingMemory, and an ``llm_agent`` whose
    ``generate_exploit`` is spied. The verdict, the context write, the
    crash-pattern record and the generation decision are all made by
    the production loop body. The code after the loop only prints
    totals."""
    import ast
    src = (_RAPTOR_ROOT / "raptor_fuzzing.py").read_text()
    loops = [n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.For)
             and ast.get_source_segment(src, n.target) == "crash"
             and ast.get_source_segment(src, n.iter) == "crash_pool"]
    assert len(loops) == 1, f"expected one crash loop, got {len(loops)}"
    return compile(ast.Module(body=loops, type_ignores=[]),
                   str(_RAPTOR_ROOT / "raptor_fuzzing.py"), "exec")


_N7_REPLY = ("> ```\n\"Exploitability: LEVEL\"\n> q\nExploitability: High\n"
             "Calling it not exploitable would be wrong.")


class TestCrashVerdictConsumer:
    """Runs the real crash loop (see _crash_loop_code) on real
    MultiTurnAnalyser output and a real FuzzingMemory, spying on
    generate_exploit and record_crash_pattern."""

    KEY = "crash_pattern:SIGSEGV_parse_hdr"
    OTHER = "crash_pattern:SIGILL_other_fn"

    @staticmethod
    def _run(tmp_path, replies=None, *, deep=None, before="unknown",
             seed=False):
        import contextlib
        import io
        import json
        import logging
        from types import SimpleNamespace
        from unittest.mock import MagicMock
        from packages.autonomous.dialogue import MultiTurnAnalyser
        from packages.autonomous.memory import FuzzingMemory
        from packages.binary_analysis.crash_analyser import CrashContext
        fuzzing = _import_fuzzing()
        code = _crash_loop_code()
        ctx = CrashContext(
            crash_id="c1", binary_path=Path("/bin/true"),
            input_file=Path("/dev/null"), signal="SIGSEGV",
            function_name="parse_hdr")
        ctx.exploitability = before
        if deep is not None:
            multi_turn = MagicMock()
            multi_turn.analyse_crash_deeply.return_value = deep
        else:
            llm = MagicMock()
            llm.generate.side_effect = [
                SimpleNamespace(content=r) for r in list(replies) + ["ok"] * 3]
            multi_turn = MultiTurnAnalyser(llm_client=llm)
        memory = FuzzingMemory(memory_file=tmp_path / "memory.json")
        if seed:
            # pre-existing records: same key (2 of 3 exploitable) and an
            # unrelated key
            for flag in (True, True, False):
                memory.record_crash_pattern(signal="SIGSEGV",
                                            function="parse_hdr",
                                            binary_hash="h", exploitable=flag)
            memory.record_crash_pattern(signal="SIGILL", function="other_fn",
                                        binary_hash="h", exploitable=False)
            memory.save()
        memory.record_crash_pattern = MagicMock(wraps=memory.record_crash_pattern)
        agent = MagicMock()
        agent.generate_exploit.return_value = False
        analyser = MagicMock()
        analyser.analyse_crash.return_value = ctx
        analyser.classify_crash_type.return_value = "heap-buffer-overflow"
        ns = dict(vars(fuzzing))
        ns.update(
            crash_pool=[SimpleNamespace(crash_id="c1", signal="SIGSEGV",
                                        input_file=Path("/dev/null"))],
            args=SimpleNamespace(autonomous=True, max_crashes=1,
                                 rank_crashes=False),
            attempted=0, seen_stack_hashes=set(), skipped_duplicates=0,
            crash_analyser=analyser, multi_turn=multi_turn, llm_agent=agent,
            memory=memory, binary_hash="h", analysed=0, exploitable=0,
            exploits_generated=0, exploit_validator=None, out_dir=tmp_path)
        logging.disable(logging.CRITICAL)
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                exec(code, ns)
        finally:
            logging.disable(logging.NOTSET)
        memory.save()
        stored = json.loads((tmp_path / "memory.json").read_text())
        return {
            "exploitability": ns["crash_context"].exploitability,
            "same_context": ns["crash_context"] is ctx,
            "generate_calls": [c.args for c in agent.generate_exploit.call_args_list],
            "exploitable_counter": ns["exploitable"],
            "record_calls": [c.kwargs for c in
                             memory.record_crash_pattern.call_args_list],
            "durable": {k: v["value"] for k, v in stored["knowledge"].items()},
            "ctx": ctx,
        }

    @staticmethod
    def _record(exploitable):
        return {"signal": "SIGSEGV", "function": "parse_hdr",
                "binary_hash": "h", "exploitable": exploitable}

    @classmethod
    def _value(cls, exploitable_count, total_count, *, other=False):
        if other:
            return {"signal": "SIGILL", "function": "other_fn",
                    "exploitable_count": 0, "total_count": 1}
        return {"signal": "SIGSEGV", "function": "parse_hdr",
                "exploitable_count": exploitable_count,
                "total_count": total_count}

    def _assert_effects(self, out, level, generated, durable, record=None):
        assert out["same_context"]
        assert out["exploitability"] == level
        assert out["generate_calls"] == ([(out["ctx"],)] if generated else [])
        assert out["exploitable_counter"] == (1 if generated else 0)
        assert out["record_calls"] == ([] if record is None
                                       else [self._record(record)])
        assert out["durable"] == durable

    def test_structure(self):
        _crash_loop_code()

    def test_explicit_high_despite_phrase(self, tmp_path):
        out = self._run(tmp_path, ["Exploitability: HIGH\nCalling this not "
                                   "exploitable would be wrong."])
        self._assert_effects(out, "exploitable", True,
                             {self.KEY: self._value(1, 1)}, True)

    def test_medium(self, tmp_path):
        out = self._run(tmp_path, ["Exploitability: Medium",
                                   "Exploitability: Medium"])
        self._assert_effects(out, "exploitable", True,
                             {self.KEY: self._value(1, 1)}, True)

    def test_bare_affirmative_upgrade(self, tmp_path):
        out = self._run(tmp_path, ["Exploitability: None",
                                   "Exploitability is high."])
        self._assert_effects(out, "exploitable", True,
                             {self.KEY: self._value(1, 1)}, True)

    def test_low(self, tmp_path):
        out = self._run(tmp_path, ["Exploitability: Low", "The write is bounded."])
        self._assert_effects(out, "not_exploitable", False,
                             {self.KEY: self._value(0, 1)}, False)

    def test_none_abstains_with_zero_writes(self, tmp_path):
        out = self._run(tmp_path, ["Exploitability: None", "Attacker controls "
                                   "RIP; exploitability is high."])
        self._assert_effects(out, "unknown", False, {})

    def test_unknown_abstains_with_zero_writes(self, tmp_path):
        out = self._run(tmp_path, ["Crash in parser.", "No idea."])
        self._assert_effects(out, "unknown", False, {})

    def test_missing_exploitability_key_abstains(self, tmp_path):
        out = self._run(tmp_path, deep={"confidence": 0.5,
                                        "vulnerability_type": "heap_overflow"})
        self._assert_effects(out, "unknown", False, {})

    def test_none_then_bare_low_abstains(self, tmp_path):
        # "Exploitability is low." never revises an explicit None
        out = self._run(tmp_path, ["Exploitability: None",
                                   "Exploitability is low."])
        self._assert_effects(out, "unknown", False, {})

    def test_instruction_echo_keeps_abstention(self, tmp_path):
        out = self._run(tmp_path, [
            "Crash in parser.",
            'End your answer with exactly one verdict line, '
            '"Exploitability: LEVEL", where LEVEL is one of High, Medium, '
            'Low, None.'])
        self._assert_effects(out, "unknown", False, {})

    def test_echo_and_weak_cooccurrence_abstains(self, tmp_path):
        out = self._run(tmp_path, [
            "This crash is likely not exploitable.",
            'End your answer with exactly one verdict line, '
            '"Exploitability: LEVEL", where LEVEL is one of High, Medium, '
            'Low, None.\nA working exploit would require a high degree of '
            'heap control.'])
        self._assert_effects(out, "unknown", False, {})

    def test_abstention_preserves_existing_records(self, tmp_path):
        out = self._run(tmp_path, ["Exploitability: None", "Nothing to add."],
                        seed=True)
        self._assert_effects(out, "unknown", False, {
            self.KEY: self._value(2, 3), self.OTHER: self._value(0, 0, other=True)})

    def test_high_adds_to_existing_records(self, tmp_path):
        out = self._run(tmp_path, ["Exploitability: High"], seed=True)
        self._assert_effects(out, "exploitable", True, {
            self.KEY: self._value(3, 4), self.OTHER: self._value(0, 0, other=True)},
            True)

    def test_abstention_leaves_prepopulated_context(self, tmp_path):
        # The verdict write is skipped on abstention, so a context that
        # already says "exploitable" still opens the generation gate
        # (raptor_fuzzing.py creates each context with "unknown").
        out = self._run(tmp_path, ["Exploitability: None", "Nothing to add."],
                        before="exploitable")
        self._assert_effects(out, "exploitable", True, {})

    def test_high_overrides_prepopulated_negative(self, tmp_path):
        out = self._run(tmp_path, ["Exploitability: High"],
                        before="not_exploitable")
        self._assert_effects(out, "exploitable", True,
                             {self.KEY: self._value(1, 1)}, True)

    def test_drop_exposed_syntax_after_free_none(self, tmp_path):
        out = self._run(tmp_path, ["This crash is likely not exploitable.",
                                   _N7_REPLY])
        self._assert_effects(out, "unknown", False, {})

    def test_drop_exposed_syntax_after_free_medium(self, tmp_path):
        out = self._run(tmp_path, ["Heap overflow; I'd put exploitability: "
                                   "medium for now.", _N7_REPLY])
        self._assert_effects(out, "unknown", False, {})

    def test_drop_exposed_syntax_after_explicit_none(self, tmp_path):
        out = self._run(tmp_path, ["Exploitability: None", _N7_REPLY])
        self._assert_effects(out, "unknown", False, {})

    def test_drop_exposed_syntax_after_explicit_low(self, tmp_path):
        out = self._run(tmp_path, ["Exploitability: Low", _N7_REPLY])
        self._assert_effects(out, "not_exploitable", False,
                             {self.KEY: self._value(0, 1)}, False)

    _INSTR = ('End your answer with exactly one verdict line, '
              '"Exploitability: LEVEL", where LEVEL is one of High, Medium, '
              'Low, None.')

    def test_echo_drop_capped_after_free_none(self, tmp_path):
        out = self._run(tmp_path, ["This crash is likely not exploitable.",
                                   self._INSTR + "\nThe attacker has high "
                                   "control, so the exploit works."])
        self._assert_effects(out, "unknown", False, {})

    def test_echo_drop_capped_after_free_low(self, tmp_path):
        out = self._run(tmp_path, ["Chances of a working exploit are low.",
                                   self._INSTR + "\nThe attacker has high "
                                   "control, so the exploit works."])
        self._assert_effects(out, "not_exploitable", False,
                             {self.KEY: self._value(0, 1)}, False)

    def test_echo_drop_uncapped_as_received_high(self, tmp_path):
        out = self._run(tmp_path, ["This crash is likely not exploitable.",
                                   "Exploitability: LEVEL\nExploit "
                                   "reliability is high."])
        self._assert_effects(out, "exploitable", True,
                             {self.KEY: self._value(1, 1)}, True)

    def test_pure_echo_preserves_free_medium(self, tmp_path):
        out = self._run(tmp_path, ["Heap overflow; I'd put exploitability: "
                                   "medium for now.",
                                   self._INSTR + "\nExploitability: LEVEL"])
        self._assert_effects(out, "exploitable", True,
                             {self.KEY: self._value(1, 1)}, True)

    def test_negated_high_after_echo_abstains(self, tmp_path):
        out = self._run(tmp_path, ["This crash is likely not exploitable.",
                                   "Exploitability: LEVEL\nThe claim that "
                                   "exploitability is high is wrong; it is "
                                   "none."])
        self._assert_effects(out, "unknown", False, {})

    def test_unknown_turn1_capped_by_as_received(self, tmp_path):
        # turn 1 reads no level; the sentence echo's own list makes the
        # reply as received read none, so the rest's "high" is capped
        out = self._run(tmp_path, ["Crash in parser.",
                                   self._INSTR + "\nThe exploit is high "
                                   "value."])
        self._assert_effects(out, "unknown", False, {})

    def test_unknown_turn1_as_received_high(self, tmp_path):
        out = self._run(tmp_path, ["Crash in parser.",
                                   "Exploitability: LEVEL\nExploit "
                                   "reliability is high."])
        self._assert_effects(out, "exploitable", True,
                             {self.KEY: self._value(1, 1)}, True)

    def test_pure_echo_with_crcrlf_sentence_loses_medium(self, tmp_path):
        # accepted, equal to base: the "\r\r\n" sentence is not an echo
        # form, so its level list reads none and abstains
        out = self._run(tmp_path, ["Heap overflow; I'd put exploitability: "
                                   "medium for now.",
                                   "Exploitability: LEVEL\r\n" + self._INSTR
                                   + "\r\r\n"])
        self._assert_effects(out, "unknown", False, {})
