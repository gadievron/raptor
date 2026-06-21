"""Tests for frida runtime-trace reachability integration.

Covers:
  - frida_runtime_trace_present() accessor on inventory items
  - _stage_frida_runtime_trace in the PRECEDENCE chain
  - frida evidence overriding binary_oracle_absent
"""

from __future__ import annotations


def _make_inventory(file_path: str, name: str, frida_observed: bool = True):
    """Build a minimal inventory with one item that has frida metadata."""
    item = {
        "name": name,
        "line_start": 10,
        "line_end": 20,
        "metadata": {},
    }
    if frida_observed:
        item["metadata"]["frida_runtime_trace"] = {
            "observed": True,
            "call_count": 5,
            "trace_id": "/tmp/frida_run",
        }
    return {"files": [{"path": file_path, "items": [item]}]}


class TestFridaRuntimeTracePresent:
    def test_returns_true_when_observed(self):
        from core.inventory.reachability import frida_runtime_trace_present

        inv = _make_inventory("src/main.c", "process_input")
        assert frida_runtime_trace_present(inv, "src/main.c", "process_input") is True

    def test_returns_false_when_no_metadata(self):
        from core.inventory.reachability import frida_runtime_trace_present

        inv = _make_inventory("src/main.c", "process_input", frida_observed=False)
        assert frida_runtime_trace_present(inv, "src/main.c", "process_input") is False

    def test_returns_false_for_wrong_function(self):
        from core.inventory.reachability import frida_runtime_trace_present

        inv = _make_inventory("src/main.c", "process_input")
        assert frida_runtime_trace_present(inv, "src/main.c", "other_func") is False

    def test_returns_false_for_wrong_file(self):
        from core.inventory.reachability import frida_runtime_trace_present

        inv = _make_inventory("src/main.c", "process_input")
        assert frida_runtime_trace_present(inv, "src/other.c", "process_input") is False

    def test_returns_false_for_empty_inputs(self):
        from core.inventory.reachability import frida_runtime_trace_present

        inv = _make_inventory("src/main.c", "process_input")
        assert frida_runtime_trace_present(inv, "", "process_input") is False
        assert frida_runtime_trace_present(inv, "src/main.c", "") is False

    def test_line_disambiguation(self):
        from core.inventory.reachability import frida_runtime_trace_present

        inv = {"files": [{"path": "src/x.c", "items": [
            {"name": "foo", "line_start": 1, "line_end": 10, "metadata": {}},
            {"name": "foo", "line_start": 20, "line_end": 30, "metadata": {
                "frida_runtime_trace": {"observed": True, "call_count": 1,
                                        "trace_id": "t"},
            }},
        ]}]}
        assert frida_runtime_trace_present(inv, "src/x.c", "foo", line=5) is False
        assert frida_runtime_trace_present(inv, "src/x.c", "foo", line=25) is True


class TestStageInPrecedence:
    def test_frida_stage_before_binary_oracle(self):
        from core.inventory.reach_audit import (
            PRECEDENCE,
            _stage_binary_oracle_absent,
            _stage_frida_runtime_trace,
        )

        frida_idx = list(PRECEDENCE).index(_stage_frida_runtime_trace)
        oracle_idx = list(PRECEDENCE).index(_stage_binary_oracle_absent)
        assert frida_idx < oracle_idx, (
            "frida runtime trace must precede binary_oracle_absent "
            "so runtime evidence overrides stale absent verdicts"
        )

    def test_frida_is_live_verdict(self):
        from core.inventory.reach_audit import _LIVE_VERDICTS

        assert "frida_runtime_trace" in _LIVE_VERDICTS

    def test_classify_returns_frida_verdict(self):
        from core.inventory.reach_audit import classify_reachability
        from core.inventory import reachability as R

        inv = _make_inventory("src/vuln.c", "vulnerable_fn")
        verdict = classify_reachability(inv, "src/vuln.c", "vulnerable_fn", 15, R)
        assert verdict == "frida_runtime_trace"

    def test_frida_overrides_binary_oracle_absent(self):
        """A function observed by frida should get frida verdict even if
        binary oracle would say absent."""
        from core.inventory.reach_audit import classify_reachability
        from core.inventory import reachability as R

        inv = _make_inventory("src/vuln.c", "vulnerable_fn")
        item = inv["files"][0]["items"][0]
        item["metadata"]["binary_oracle"] = {
            "verdict": "absent",
            "tier": "full_dwarf",
        }

        verdict = classify_reachability(inv, "src/vuln.c", "vulnerable_fn", 15, R)
        assert verdict == "frida_runtime_trace"


class TestEnrichWithFridaTraces:
    def test_enriches_checklist_items(self, tmp_path):
        from core.orchestration.reachability_enrichment import enrich_with_frida_traces
        import json

        events = [
            {"type": "send", "payload": {"fn": "process_input", "args": ["/etc/passwd"]}},
            {"type": "send", "payload": {"fn": "process_input", "args": ["/etc/shadow"]}},
            {"type": "send", "payload": {"fn": "write_output", "args": ["/tmp/out"]}},
        ]
        run_dir = tmp_path / "frida_run"
        run_dir.mkdir()
        (run_dir / "events.jsonl").write_text(
            "\n".join(json.dumps(e) for e in events) + "\n")
        (run_dir / "metadata.json").write_text(json.dumps({
            "ok": True, "target": {"binary": "/usr/bin/test"},
            "events_captured": 3,
        }))

        checklist = {"files": [{"path": "src/main.c", "items": [
            {"name": "process_input", "line_start": 10, "line_end": 20},
            {"name": "unrelated_fn", "line_start": 30, "line_end": 40},
        ]}]}

        from pathlib import Path
        count = enrich_with_frida_traces(
            checklist, Path("/usr/bin/test"),
            search_dirs=[tmp_path],
        )
        assert count == 1
        item = checklist["files"][0]["items"][0]
        assert item["metadata"]["frida_runtime_trace"]["observed"] is True
        assert item["metadata"]["frida_runtime_trace"]["call_count"] == 2

        unrelated = checklist["files"][0]["items"][1]
        assert "metadata" not in unrelated or "frida_runtime_trace" not in unrelated.get("metadata", {})

    def test_skips_non_native_files(self, tmp_path):
        from core.orchestration.reachability_enrichment import enrich_with_frida_traces
        import json

        events = [{"type": "send", "payload": {"fn": "handle_request", "args": []}}]
        run_dir = tmp_path / "frida_run"
        run_dir.mkdir()
        (run_dir / "events.jsonl").write_text(json.dumps(events[0]) + "\n")
        (run_dir / "metadata.json").write_text(json.dumps({
            "ok": True, "target": {"binary": "/usr/bin/test"},
            "events_captured": 1,
        }))

        checklist = {"files": [{"path": "src/app.py", "items": [
            {"name": "handle_request", "line_start": 1, "line_end": 10},
        ]}]}

        from pathlib import Path
        count = enrich_with_frida_traces(
            checklist, Path("/usr/bin/test"),
            search_dirs=[tmp_path],
        )
        assert count == 0
