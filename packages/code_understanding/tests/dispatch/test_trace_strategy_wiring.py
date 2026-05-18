"""Tests for the cwe_strategies wire-in into /understand --trace's
user message.

When the trace batch carries CWE ids (in ``cwe`` / ``cwe_id`` /
``rule_id`` or anywhere else in the JSON-serialised dicts) or
recognisable bug-class vocabulary (function / entry / sink names
matching strategy keywords), the operator-curated cwe_strategies
bug-class lenses are appended to the user message after the
``</traces>`` close.

Mirrors test_hunt_strategy_wiring.py for the trace-dispatch sibling.
"""

from __future__ import annotations

from unittest.mock import patch


from packages.code_understanding.dispatch.trace_dispatch import (
    _build_strategy_block,
    _format_user_message,
)


# ---------------------------------------------------------------------------
# CWE-id pin via various trace fields
# ---------------------------------------------------------------------------


class TestCweTriggersStrategy:
    def test_cwe_id_field_pins_input_handling(self):
        traces = [{"trace_id": "T1", "cwe_id": "CWE-22"}]
        out = _format_user_message(traces)
        assert "## Strategy: input_handling" in out
        assert "CVE-2023-0179" in out  # input_handling exemplar

    def test_cwe_field_alias_pins_memory_management(self):
        # Producers may use ``cwe`` rather than ``cwe_id``. Regex scan
        # over the serialised trace catches both.
        traces = [{"trace_id": "T1", "cwe": "CWE-416"}]
        out = _format_user_message(traces)
        assert "## Strategy: memory_management" in out

    def test_cwe_embedded_in_rule_id_pins_concurrency(self):
        traces = [{
            "trace_id": "T1",
            "rule_id": "cpp/race-condition CWE-362 critical",
        }]
        out = _format_user_message(traces)
        assert "## Strategy: concurrency" in out

    def test_cwe_in_nested_field_pins(self):
        # CWE id buried in a sub-dict — regex over serialised JSON
        # still finds it.
        traces = [{
            "trace_id": "T1",
            "metadata": {"classification": "CWE-22", "severity": "high"},
        }]
        out = _format_user_message(traces)
        assert "## Strategy: input_handling" in out

    def test_multiple_traces_different_cwes_aggregated(self):
        # Two traces, each carrying a different CWE that's unique to
        # one strategy. Both bug classes should appear.
        traces = [
            {"trace_id": "T1", "cwe": "CWE-22"},   # input_handling only
            {"trace_id": "T2", "cwe": "CWE-401"},  # memory_management only
        ]
        out = _format_user_message(traces)
        assert "## Strategy: input_handling" in out
        assert "## Strategy: memory_management" in out


# ---------------------------------------------------------------------------
# Keyword-only fall-through (no CWE in any trace field)
# ---------------------------------------------------------------------------


class TestKeywordTriggersStrategy:
    def test_entry_name_parse_pins_input_handling(self):
        # ``parse`` matches input_handling's keyword set even with
        # no CWE field.
        traces = [{
            "trace_id": "T1",
            "entry": "parse_request_body",
            "sink": "open",
        }]
        out = _build_strategy_block(traces)
        assert "## Strategy: input_handling" in out

    def test_sink_name_free_pins_memory_management(self):
        # ``free`` is a memory_management keyword.
        traces = [{
            "trace_id": "T1",
            "entry": "release_buf",
            "sink": "free",
        }]
        out = _build_strategy_block(traces)
        assert "## Strategy: memory_management" in out

    def test_step_function_mutex_lock_pins_concurrency(self):
        traces = [{
            "trace_id": "T1",
            "entry": "do_thing",
            "steps": [
                {"function": "mutex_lock"},
                {"function": "do_work"},
            ],
        }]
        out = _build_strategy_block(traces)
        assert "## Strategy: concurrency" in out


# ---------------------------------------------------------------------------
# Fall-through: no signals → general only
# ---------------------------------------------------------------------------


class TestNoSignalFallthrough:
    def test_traces_with_no_signals_still_includes_general(self):
        traces = [{"trace_id": "T1", "entry": "xyz", "sink": "abc"}]
        out = _format_user_message(traces)
        assert "Bug-class lenses for these traces" in out
        assert "## Strategy: general" in out


# ---------------------------------------------------------------------------
# Robustness
# ---------------------------------------------------------------------------


class TestRobustness:
    def test_substrate_import_failure_returns_base_message(self):
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "core.llm.cwe_strategies":
                raise ImportError("substrate missing")
            return real_import(name, *args, **kwargs)

        with patch.object(builtins, "__import__", fake_import):
            out = _format_user_message([{"trace_id": "T1", "cwe": "CWE-22"}])
            assert "<traces>" in out
            assert "</traces>" in out
            assert "Bug-class lenses" not in out

    def test_picker_exception_returns_base_message(self):
        def boom(**kwargs):
            raise RuntimeError("simulated picker failure")

        with patch("core.llm.cwe_strategies.pick_strategies", boom):
            out = _format_user_message([{"trace_id": "T1", "cwe": "CWE-22"}])
            assert "<traces>" in out
            assert "Bug-class lenses" not in out

    def test_render_exception_returns_base_message(self):
        def boom(*args, **kwargs):
            raise RuntimeError("simulated render failure")

        with patch("core.llm.cwe_strategies.render_strategies", boom):
            out = _format_user_message([{"trace_id": "T1", "cwe": "CWE-22"}])
            assert "Bug-class lenses" not in out

    def test_helper_handles_non_json_value_gracefully(self):
        # The base trace contract (``default_trace_dispatch``) requires
        # JSON-native traces and raises TypeError if violated. The
        # strategy block helper, however, uses ``default=str`` so that
        # an internal serialisation hiccup never blocks the loop —
        # pin defence-in-depth behaviour at the helper level.
        from pathlib import Path
        block = _build_strategy_block([
            {"trace_id": "T1", "cwe": "CWE-22",
             "config_path": Path("/etc/example")},
        ])
        # ``default=str`` lets the picker still see ``CWE-22`` in the
        # serialised text.
        assert "## Strategy: input_handling" in block


# ---------------------------------------------------------------------------
# Strategy block placement (after </traces>)
# ---------------------------------------------------------------------------


class TestStrategyBlockPlacement:
    def test_strategy_block_after_traces_close(self):
        traces = [{"trace_id": "T1", "cwe": "CWE-22"}]
        out = _format_user_message(traces)
        traces_close = out.index("</traces>")
        bug_pos = out.index("Bug-class lenses for these traces")
        assert bug_pos > traces_close


# ---------------------------------------------------------------------------
# E2E — distinct CWEs produce distinct strategy stacks
# ---------------------------------------------------------------------------


class TestE2EDistinctStrategies:
    def test_path_traversal_vs_uaf_produce_different_blocks(self):
        out_path = _format_user_message([{"trace_id": "T1", "cwe": "CWE-22"}])
        out_uaf = _format_user_message([{"trace_id": "T1", "cwe": "CWE-416"}])
        assert out_path != out_uaf
        assert "input_handling" in out_path
        assert "memory_management" in out_uaf


# ---------------------------------------------------------------------------
# Size bound
# ---------------------------------------------------------------------------


class TestSizeBounds:
    def test_realistic_trace_batch_stays_bounded(self):
        # 20-trace batch with multiple CWEs and rich step lists.
        traces = []
        for i in range(20):
            traces.append({
                "trace_id": f"T{i}",
                "cwe_id": "CWE-22" if i % 2 == 0 else "CWE-416",
                "entry": f"http_handler_{i}",
                "sink": "open" if i % 2 == 0 else "free",
                "steps": [{"function": f"helper_{j}"} for j in range(5)],
            })
        out = _format_user_message(traces)
        # Realistic trace batch + 3-strategy cap → bounded total.
        assert len(out) < 32_000


# ---------------------------------------------------------------------------
# _build_strategy_block direct unit tests
# ---------------------------------------------------------------------------


class TestStrategyBlockDirect:
    def test_returns_empty_when_substrate_missing(self):
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "core.llm.cwe_strategies":
                raise ImportError("substrate missing")
            return real_import(name, *args, **kwargs)

        with patch.object(builtins, "__import__", fake_import):
            assert _build_strategy_block(
                [{"trace_id": "T1", "cwe": "CWE-22"}],
            ) == ""

    def test_empty_traces_list_returns_block_with_general(self):
        # Empty list serialises to "[]"; no signals → general only.
        block = _build_strategy_block([])
        assert "## Strategy: general" in block

    def test_returns_block_with_keyword_only_no_cwe(self):
        block = _build_strategy_block([
            {"trace_id": "T1", "entry": "parse_input", "sink": "exec"},
        ])
        assert "## Strategy: input_handling" in block
