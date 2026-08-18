"""Tests for the per-run prefilter-kill ledger (P35a).

Stubbed: the compiler-analyzer channel is patched — no compiler runs.
"""

from __future__ import annotations

import json
from unittest.mock import patch

from core.audit.prefilter_ledger import (
    CORROBORATION_CWE,
    GATE_OTHER,
    GATE_SINK_UNREACHABLE,
    GATE_TRIAGE_SKIP,
    GATE_TRIVIAL_WRAPPER,
    GATE_TRIVIALLY_CLEAN,
    LEDGER_FILENAME,
    _sample,
    corroborate_sample,
    format_summary,
    gate_for_skip_reason,
    make_kill_record,
    summarise,
    write_ledger,
)


class _StubSweep:
    def __init__(self, outcome):
        self.outcome = outcome


def _kill(file="src/a.c", function="f", gate=GATE_TRIVIALLY_CLEAN,
          line_start=10, line_end=20, **kw):
    return make_kill_record(
        file=file, function=function, gate=gate,
        reason="simple accessor (return field/constant)",
        line_start=line_start, line_end=line_end, **kw,
    )


class TestGateMapping:
    def test_trivially_clean(self):
        assert gate_for_skip_reason(
            "simple accessor (return field/constant)",
        ) == GATE_TRIVIALLY_CLEAN

    def test_wrapper(self):
        assert gate_for_skip_reason(
            "trivial wrapper delegating to memset_s()",
        ) == GATE_TRIVIAL_WRAPPER

    def test_sink_unreachable(self):
        assert gate_for_skip_reason(
            "no sink path + no logic-class signals",
        ) == GATE_SINK_UNREACHABLE

    def test_unknown_reason(self):
        assert gate_for_skip_reason("something new") == GATE_OTHER
        assert gate_for_skip_reason("") == GATE_OTHER


class TestKillRecord:
    def test_shape(self):
        rec = make_kill_record(
            file="src/a.c", function="get_len",
            gate=GATE_TRIVIALLY_CLEAN, reason="simple accessor",
            language="c", sloc=4, line_start=10, line_end=14,
        )
        assert rec["gate"] == GATE_TRIVIALLY_CLEAN
        assert rec["corroboration"] == "not_sampled"
        assert rec["file"] == "src/a.c"
        assert rec["sloc"] == 4


class TestSample:
    def test_only_c_files_with_spans(self):
        records = [
            _kill(file="src/a.py"),
            _kill(file="src/b.c", line_start=0),  # no span
            _kill(file="src/c.c"),
        ]
        sampled = _sample(records, 5)
        assert [r["file"] for r in sampled] == ["src/c.c"]

    def test_deterministic_and_bounded(self):
        records = [_kill(file=f"src/{i:02d}.c", function=f"f{i}")
                   for i in range(20)]
        s1 = _sample(records, 3)
        s2 = _sample(list(reversed(records)), 3)
        assert len(s1) == 3
        assert [r["file"] for r in s1] == [r["file"] for r in s2]


class TestCorroborateSample:
    def _run(self, records, outcomes):
        calls = []

        def _fake_sweep(**kw):
            calls.append(kw)
            return _StubSweep(outcomes[len(calls) - 1])

        with patch(
            "core.audit.compiler_sweep._gcc_analyzer",
            return_value=("/usr/bin/gcc", "sarif-file"),
        ), patch(
            "core.audit.compiler_sweep._clang_path", return_value=None,
        ), patch(
            "core.audit.compiler_sweep.run_compiler_analyzer_sweep",
            side_effect=lambda **kw: _fake_sweep(**kw),
        ):
            audited = corroborate_sample(records, "/repo", sample_size=3)
        return audited, calls

    def test_quiet_and_noisy_marked(self):
        records = [
            _kill(file="src/a.c", function="f1"),
            _kill(file="src/b.c", function="f2"),
        ]
        audited, calls = self._run(records, ["refuted", "confirmed"])
        assert audited == 2
        assert records[0]["corroboration"] == "analyzer_quiet"
        assert records[1]["corroboration"] == "analyzer_noisy"
        assert records[0]["corroboration_channel"] == (
            f"compiler:{CORROBORATION_CWE}"
        )
        assert all(kw["cwe"] == CORROBORATION_CWE for kw in calls)

    def test_inconclusive_marked(self):
        records = [_kill()]
        audited, _ = self._run(records, ["inconclusive"])
        assert audited == 1
        assert records[0]["corroboration"] == "analyzer_inconclusive"

    def test_no_analyzer_skips_fast(self):
        records = [_kill()]
        with patch(
            "core.audit.compiler_sweep._gcc_analyzer", return_value=None,
        ), patch(
            "core.audit.compiler_sweep._clang_path", return_value=None,
        ):
            assert corroborate_sample(records, "/repo") == 0
        assert records[0]["corroboration"] == "not_sampled"


class TestLedgerOutput:
    def test_write_and_summarise(self, tmp_path):
        records = [
            _kill(file="src/a.c", function="f1"),
            _kill(file="src/b.c", function="f2",
                  gate=GATE_TRIAGE_SKIP),
        ]
        records[0]["corroboration"] = "analyzer_quiet"
        path = write_ledger(records, tmp_path)
        assert path == tmp_path / LEDGER_FILENAME
        lines = [json.loads(line) for line in
                 path.read_text().splitlines()]
        assert lines[0]["summary"]["total_kills"] == 2
        assert lines[0]["summary"]["by_gate"][GATE_TRIAGE_SKIP] == 1
        assert lines[0]["summary"]["corroborated"] == 1
        assert lines[1]["function"] == "f1"

    def test_empty_records_write_nothing(self, tmp_path):
        assert write_ledger([], tmp_path) is None
        assert not (tmp_path / LEDGER_FILENAME).exists()

    def test_format_summary_reports_contradictions(self):
        records = [_kill(), _kill(function="g")]
        records[0]["corroboration"] = "analyzer_noisy"
        text = format_summary(records)
        assert "1 CONTRADICTED" in text
        assert LEDGER_FILENAME in text

    def test_summary_counts_sampled(self):
        records = [_kill(), _kill(function="g")]
        records[0]["corroboration"] = "analyzer_inconclusive"
        s = summarise(records)
        assert s["sampled"] == 1
        assert s["corroborated"] == 0
        assert s["contradicted"] == 0


class TestOrchestratorWiring:
    def test_result_has_prefilter_kills_field(self):
        from core.audit.orchestrator import OrchestratorResult

        r = OrchestratorResult()
        assert r.prefilter_kills == []

    def test_kill_sites_record_to_ledger(self):
        """Both the prefilter kill site and the triage SKIP site
        append structured records (source-level regression guard)."""
        import inspect

        import core.audit.orchestrator as orch_mod

        src = inspect.getsource(orch_mod)
        assert src.count("result.prefilter_kills.append") >= 2
        assert "gate_for_skip_reason(pf_result.skip_reason)" in src
        assert "GATE_TRIAGE_SKIP" in src
        # End-of-run: ledger written + corroborated before hooks/export.
        assert "write_ledger(result.prefilter_kills" in src
        assert "corroborate_sample(" in src
