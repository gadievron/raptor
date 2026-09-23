"""Tests for core.orchestration.frida_validation_bridge."""

import copy
import json
from pathlib import Path

import pytest

from core.orchestration.frida_validation_bridge import (
    RuntimeEvidence,
    collect_runtime_evidence,
    annotate_attack_paths,
    PROXIMITY_FLOOR,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_events(run_dir: Path, events: list[dict]) -> None:
    """Write synthetic events.jsonl into a frida run directory."""
    run_dir.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(e) for e in events]
    (run_dir / "events.jsonl").write_text("\n".join(lines) + "\n")


def _write_metadata(run_dir: Path, target_raw: str = "", target_binary: str = "",
                     target_name: str = "") -> None:
    """Write a minimal metadata.json."""
    meta = {
        "ok": True,
        "target": {
            "raw": target_raw,
            "kind": "binary" if target_binary else "name",
            "pid": None,
            "name": target_name,
            "binary": target_binary,
        },
    }
    (run_dir / "metadata.json").write_text(json.dumps(meta))


def _make_frida_run(tmp_path: Path, name: str, events: list[dict],
                     target_raw: str = "", target_binary: str = "",
                     target_name: str = "") -> Path:
    """Create a complete synthetic frida run directory."""
    run_dir = tmp_path / name
    _write_events(run_dir, events)
    _write_metadata(run_dir, target_raw, target_binary, target_name)
    return run_dir


def _heap_event(kind: str, fn: str, caller_module: str) -> dict:
    return {"ts": 0.2, "type": "send", "payload": {
        "category": "heap", "kind": kind, "fn": fn,
        "caller_module": caller_module, "caller_offset": "0x12c0",
        "tid": 0}}


def _api_event(fn: str, args: dict | None = None) -> dict:
    """Build a single api-trace style event record."""
    payload: dict = {"category": "file", "fn": fn, "tid": 1}
    if args is not None:
        payload["args"] = args
    return {"ts": 0.1, "type": "send", "payload": payload}


SAMPLE_EVENTS = [
    _api_event("open", {"path": "/etc/passwd", "flags": 0, "ret": 3}),
    _api_event("read", {"fd": 3, "count": 4096, "ret": 512}),
    _api_event("open", {"path": "/etc/shadow", "flags": 0, "ret": -1}),
    _api_event("close", {"fd": 3, "ret": 0}),
    _api_event("write", {"fd": 1, "count": 512, "ret": 512}),
]


def _make_attack_path(path_id: str, steps: list[dict], proximity: int | float = 3) -> dict:
    return {
        "id": path_id,
        "name": f"Path {path_id}",
        "finding": "FIND-001",
        "steps": steps,
        "proximity": proximity,
        "blockers": [],
        "status": "uncertain",
    }


# ---------------------------------------------------------------------------
# Tests: collect_runtime_evidence
# ---------------------------------------------------------------------------


class TestCollectRuntimeEvidence:

    def test_from_events(self, tmp_path: Path):
        """Synthetic events.jsonl produces an evidence map with function names."""
        _make_frida_run(tmp_path, "frida_run", SAMPLE_EVENTS)
        result = collect_runtime_evidence([tmp_path])
        assert "open" in result
        assert "read" in result
        assert "write" in result
        assert "close" in result
        assert result["open"].function_observed is True
        assert result["open"].call_count == 2
        assert result["read"].call_count == 1

    def test_no_evidence(self, tmp_path: Path):
        """No frida output yields an empty dict."""
        result = collect_runtime_evidence([tmp_path])
        assert result == {}

    def test_empty_search_dirs(self):
        result = collect_runtime_evidence([])
        assert result == {}

    def test_nonexistent_dir(self, tmp_path: Path):
        result = collect_runtime_evidence([tmp_path / "nope"])
        assert result == {}

    def test_target_mismatch(self, tmp_path: Path):
        """Wrong target path yields empty dict when target_path filter is set."""
        _make_frida_run(
            tmp_path, "frida_run", SAMPLE_EVENTS,
            target_binary="/usr/bin/other_binary",
        )
        result = collect_runtime_evidence(
            [tmp_path],
            target_path="/usr/bin/my_target",
        )
        assert result == {}

    def test_target_match(self, tmp_path: Path):
        """Matching target path includes the evidence."""
        target = str(tmp_path / "my_binary")
        (tmp_path / "my_binary").touch()
        _make_frida_run(
            tmp_path, "frida_run", SAMPLE_EVENTS,
            target_binary=target,
        )
        result = collect_runtime_evidence([tmp_path], target_path=target)
        assert "open" in result

    def test_target_match_by_name(self, tmp_path: Path):
        """Match by process name when target_path basename matches."""
        _make_frida_run(
            tmp_path, "frida_run", SAMPLE_EVENTS,
            target_name="my_binary",
        )
        result = collect_runtime_evidence(
            [tmp_path],
            target_path="/some/path/my_binary",
        )
        assert "open" in result

    def test_corrupt_events_graceful(self, tmp_path: Path):
        """Corrupt events.jsonl lines are skipped gracefully."""
        run_dir = tmp_path / "frida_run"
        run_dir.mkdir()
        (run_dir / "events.jsonl").write_text(
            "NOT JSON\n"
            + json.dumps(_api_event("open")) + "\n"
            + "{truncated\n"
        )
        _write_metadata(run_dir)
        result = collect_runtime_evidence([tmp_path])
        assert "open" in result
        assert len(result) == 1

    def test_missing_events_file(self, tmp_path: Path):
        """Run dir with metadata.json but no events.jsonl yields nothing."""
        run_dir = tmp_path / "frida_run"
        run_dir.mkdir()
        _write_metadata(run_dir)
        result = collect_runtime_evidence([tmp_path])
        assert result == {}

    def test_observed_args_captured(self, tmp_path: Path):
        """First observed args for a function are captured."""
        events = [_api_event("open", {"path": "/etc/passwd", "flags": 0})]
        _make_frida_run(tmp_path, "frida_run", events)
        result = collect_runtime_evidence([tmp_path])
        assert result["open"].observed_args is not None
        assert "/etc/passwd" in result["open"].observed_args

    def test_observed_args_updated_from_later_event(self, tmp_path: Path):
        """If first event has no args, later event fills in observed_args."""
        events = [
            _api_event("custom_fn", None),
            _api_event("custom_fn", {"path": "/real/arg", "flags": 2}),
        ]
        _make_frida_run(tmp_path, "frida_run", events)
        result = collect_runtime_evidence([tmp_path])
        assert result["custom_fn"].observed_args is not None
        assert "/real/arg" in result["custom_fn"].observed_args
        assert result["custom_fn"].call_count == 2

    def test_provenance_trace_id(self, tmp_path: Path):
        """RuntimeEvidence carries the run directory as trace_id."""
        run_dir = _make_frida_run(tmp_path, "frida_run", SAMPLE_EVENTS)
        result = collect_runtime_evidence([tmp_path])
        assert result["open"].trace_id == str(run_dir)

    def test_non_send_events_ignored(self, tmp_path: Path):
        """Error events and other types are not treated as function calls."""
        events = [
            {"ts": 0.1, "type": "error", "error": {"description": "boom"}},
            _api_event("read"),
        ]
        _make_frida_run(tmp_path, "frida_run", events)
        result = collect_runtime_evidence([tmp_path])
        assert "read" in result
        assert len(result) == 1


# ---------------------------------------------------------------------------
# Tests: annotate_attack_paths
# ---------------------------------------------------------------------------


class TestHeapEvidenceFlow:
    """heap-trace anomaly events are attributed call observations and
    feed runtime evidence; the aggregate summary (a _meta record)
    must not."""

    def test_anomalies_feed_evidence_summary_does_not(self, tmp_path):
        summary = {"ts": 0.3, "type": "send", "payload": {
            "_meta": "heap summary", "category": "heap",
            "kind": "summary", "fn": "_heap_summary", "allocs": 5,
            "tid": 0}}
        _make_frida_run(
            tmp_path, "run_heap",
            [_heap_event("uaf_candidate", "memcpy", "victim"),
             _heap_event("double_free", "free", "victim"),
             summary],
            target_binary="/bin/victim")
        evidence = collect_runtime_evidence([tmp_path],
                                            target_path="/bin/victim")
        assert "memcpy" in evidence
        assert "free" in evidence
        assert "_heap_summary" not in evidence

    def test_unattributed_heap_anomaly_dropped(self, tmp_path):
        _make_frida_run(
            tmp_path, "run_heap2",
            [_heap_event("double_free", "free", "libother.so")],
            target_binary="/bin/victim")
        evidence = collect_runtime_evidence([tmp_path],
                                            target_path="/bin/victim")
        assert "free" not in evidence


class TestAnnotateAttackPaths:

    def _evidence_map(self, trace_id: str = "/out/frida_run") -> dict[str, RuntimeEvidence]:
        return {
            "open": RuntimeEvidence(
                function_observed=True, call_count=5,
                observed_args=["/etc/passwd", 0], trace_id=trace_id,
            ),
            "strcpy": RuntimeEvidence(
                function_observed=True, call_count=2,
                observed_args=None, trace_id=trace_id,
            ),
        }

    def test_paths_with_evidence(self):
        """Attack path step matching evidence gets runtime_evidence dict."""
        paths = [_make_attack_path("P1", [
            {"step": 1, "action": "call open(path)", "function": "open"},
            {"step": 2, "action": "copy into buffer", "function": "strcpy"},
        ])]
        evidence = self._evidence_map()
        result = annotate_attack_paths(paths, evidence)

        step0 = result[0]["steps"][0]
        assert "runtime_evidence" in step0
        assert step0["runtime_evidence"]["function_observed"] is True
        assert step0["runtime_evidence"]["call_count"] == 5
        assert step0["runtime_evidence"]["observed_args"] == ["/etc/passwd", 0]

    def test_floors_proximity(self):
        """Path with runtime evidence gets proximity >= PROXIMITY_FLOOR."""
        paths = [_make_attack_path("P1", [
            {"step": 1, "action": "open file", "function": "open"},
        ], proximity=2)]
        result = annotate_attack_paths(paths, self._evidence_map())
        assert result[0]["proximity"] >= PROXIMITY_FLOOR

    def test_no_evidence_unchanged(self):
        """No matching functions means paths are unchanged."""
        paths = [_make_attack_path("P1", [
            {"step": 1, "action": "call unrelated_func()", "function": "unrelated_func"},
        ])]
        result = annotate_attack_paths(paths, self._evidence_map())
        assert "runtime_evidence" not in result[0]["steps"][0]
        assert "runtime_evidence_available" not in result[0]
        assert result[0]["proximity"] == 3

    def test_preserves_original(self):
        """Original attack_paths list is not mutated."""
        original_paths = [_make_attack_path("P1", [
            {"step": 1, "action": "call open()", "function": "open"},
        ], proximity=2)]
        frozen = copy.deepcopy(original_paths)
        annotate_attack_paths(original_paths, self._evidence_map())
        assert original_paths == frozen

    def test_multiple_steps_partial(self):
        """Only steps with evidence get runtime_evidence; others are untouched."""
        paths = [_make_attack_path("P1", [
            {"step": 1, "action": "call open(path)", "function": "open"},
            {"step": 2, "action": "parse input", "function": "parse_input"},
            {"step": 3, "action": "call strcpy()", "function": "strcpy"},
        ])]
        result = annotate_attack_paths(paths, self._evidence_map())

        assert "runtime_evidence" in result[0]["steps"][0]
        assert "runtime_evidence" not in result[0]["steps"][1]
        assert "runtime_evidence" in result[0]["steps"][2]
        assert result[0]["runtime_evidence_available"] is True

    def test_proximity_floor_respects_higher(self):
        """Path already at proximity 8 stays at 8 (floor, not clamp)."""
        paths = [_make_attack_path("P1", [
            {"step": 1, "action": "call open()", "function": "open"},
        ], proximity=8)]
        result = annotate_attack_paths(paths, self._evidence_map())
        assert result[0]["proximity"] == 8

    def test_empty_evidence_map(self):
        """Empty evidence map returns an equal COPY — the docstring
        contract (callers own the result, original never aliased)
        holds on every path, including the no-evidence early
        return."""
        paths = [_make_attack_path("P1", [
            {"step": 1, "action": "call open()", "function": "open"},
        ])]
        result = annotate_attack_paths(paths, {})
        assert result == paths
        assert result is not paths

    def test_frida_trace_id_on_path(self):
        """Annotated paths carry frida_trace_id for provenance."""
        paths = [_make_attack_path("P1", [
            {"step": 1, "action": "call open()", "function": "open"},
        ])]
        evidence = self._evidence_map(trace_id="/out/frida_20260621_143000/")
        result = annotate_attack_paths(paths, evidence)
        assert result[0]["frida_trace_id"] == "/out/frida_20260621_143000/"

    def test_function_name_from_action_regex(self):
        """Function name extracted from action string via regex when no function key."""
        paths = [_make_attack_path("P1", [
            {"step": 1, "action": "call open(\"/etc/passwd\", O_RDONLY)"},
        ])]
        result = annotate_attack_paths(paths, self._evidence_map())
        assert "runtime_evidence" in result[0]["steps"][0]

    def test_string_steps_skipped(self):
        """String-typed steps (legacy format) are skipped without error."""
        paths = [_make_attack_path("P1", [
            "Step 1: call open()",
            {"step": 2, "action": "call strcpy()", "function": "strcpy"},
        ])]
        result = annotate_attack_paths(paths, self._evidence_map())
        assert result[0]["steps"][0] == "Step 1: call open()"
        assert "runtime_evidence" in result[0]["steps"][1]

    def test_action_regex_takes_last_function(self):
        """Action with multiple calls extracts the last (callee, not caller)."""
        evidence = {"strcpy": RuntimeEvidence(function_observed=True, call_count=1)}
        paths = [_make_attack_path("P1", [
            {"step": 1, "action": "validate_input() calls strcpy(buf, in)"},
        ])]
        result = annotate_attack_paths(paths, evidence)
        assert "runtime_evidence" in result[0]["steps"][0]

    def test_empty_paths_list(self):
        """Empty attack paths list returns empty list."""
        result = annotate_attack_paths([], self._evidence_map())
        assert result == []

    def test_float_proximity_is_floored(self):
        """Float proximity (e.g., from SMT) gets floored correctly."""
        paths = [_make_attack_path("P1", [
            {"step": 1, "action": "call open()", "function": "open"},
        ], proximity=3.5)]
        result = annotate_attack_paths(paths, self._evidence_map())
        assert result[0]["proximity"] == PROXIMITY_FLOOR

    def test_float_proximity_above_floor_preserved(self):
        """Float proximity above floor stays unchanged."""
        paths = [_make_attack_path("P1", [
            {"step": 1, "action": "call open()", "function": "open"},
        ], proximity=7.5)]
        result = annotate_attack_paths(paths, self._evidence_map())
        assert result[0]["proximity"] == 7.5

    def test_trace_id_uses_first_matched_step(self):
        """frida_trace_id reflects the first matched step, not the last."""
        evidence = {
            "open": RuntimeEvidence(
                function_observed=True, call_count=1,
                trace_id="/run/first"),
            "strcpy": RuntimeEvidence(
                function_observed=True, call_count=1,
                trace_id="/run/second"),
        }
        paths = [_make_attack_path("P1", [
            {"step": 1, "function": "open"},
            {"step": 2, "function": "strcpy"},
        ])]
        result = annotate_attack_paths(paths, evidence)
        assert result[0]["frida_trace_id"] == "/run/first"


# ---------------------------------------------------------------------------
# Target attribution, alias crediting, args bounding
# ---------------------------------------------------------------------------


def _sink_event(fn: str, caller_module: str | None = None, **extra) -> dict:
    payload = {
        "category": "sink",
        "fn": fn,
        "args": {"dst": "0x1", "src": "0x2", "n": 512},
        "tid": 7,
    }
    if caller_module is not None:
        payload["caller_module"] = caller_module
    payload.update(extra)
    return {"ts": 1.0, "type": "send", "payload": payload}


class TestTargetAttribution:
    """Sink/exec/load/ingest events count only when the target's own
    code made the call — library sinks fire constantly from libc
    internals, and crediting those floors proximity on unrelated
    findings."""

    def test_target_called_sink_counts(self, tmp_path):
        run = tmp_path / "run"
        _write_events(run, [_sink_event("memcpy", caller_module="srv")])
        _write_metadata(run, target_binary=str(tmp_path / "srv"))
        evidence = collect_runtime_evidence([tmp_path])
        assert "memcpy" in evidence

    def test_library_internal_sink_ignored(self, tmp_path):
        run = tmp_path / "run"
        _write_events(run, [_sink_event("memcpy", caller_module="libc.so.6")])
        _write_metadata(run, target_binary=str(tmp_path / "srv"))
        assert collect_runtime_evidence([tmp_path]) == {}

    def test_unattributable_sink_ignored(self, tmp_path):
        # No caller_module at all, or an attach-by-name run with no
        # binary to attribute against.
        run = tmp_path / "run"
        _write_events(run, [_sink_event("memcpy")])
        _write_metadata(run, target_binary=str(tmp_path / "srv"))
        assert collect_runtime_evidence([tmp_path]) == {}

        run2 = tmp_path / "run2"
        _write_events(run2, [_sink_event("memcpy", caller_module="srv")])
        _write_metadata(run2, target_name="srv")
        assert collect_runtime_evidence([run2]) == {}

    def test_legacy_categories_keep_semantics(self, tmp_path):
        run = tmp_path / "run"
        _write_events(run, [{
            "ts": 1.0, "type": "send",
            "payload": {"category": "file", "fn": "open",
                        "args": {"path": "/etc/hosts"}, "tid": 1},
        }])
        _write_metadata(run, target_binary=str(tmp_path / "srv"))
        assert "open" in collect_runtime_evidence([tmp_path])

    def test_meta_markers_never_count(self, tmp_path):
        run = tmp_path / "run"
        _write_events(run, [{
            "ts": 1.0, "type": "send",
            "payload": {"_meta": "sink-watch cap reached",
                        "fn": "memcpy", "cap": 500},
        }])
        _write_metadata(run, target_binary=str(tmp_path / "srv"))
        assert collect_runtime_evidence([tmp_path]) == {}


class TestAliasCrediting:
    def test_alias_group_credits_every_name(self, tmp_path):
        # glibc resolves memcpy/memmove to one implementation; the
        # hook cannot know which name the call site used, so a finding
        # naming either must see the evidence.
        run = tmp_path / "run"
        _write_events(run, [
            _sink_event("memcpy", caller_module="srv",
                        aliases=["memmove"]),
        ])
        _write_metadata(run, target_binary=str(tmp_path / "srv"))
        evidence = collect_runtime_evidence([tmp_path])
        assert evidence["memcpy"].call_count == 1
        assert evidence["memmove"].call_count == 1
        assert evidence["memmove"].observed_args is not None


class TestObservedArgsBounds:
    def test_data_hex_never_reaches_observed_args(self, tmp_path):
        # Top-level AND nested data_hex (a custom script may reuse the
        # convention inside a sub-object).
        run = tmp_path / "run"
        _write_events(run, [{
            "ts": 1.0, "type": "send",
            "payload": {"category": "sink", "fn": "recv",
                        "caller_module": "srv",
                        "args": {"fd": 5, "len": 8192,
                                 "data_hex": "41" * 8192,
                                 "detail": {"data_hex": "42" * 8192}},
                        "tid": 1},
        }])
        _write_metadata(run, target_binary=str(tmp_path / "srv"))
        evidence = collect_runtime_evidence([tmp_path])
        serialized = json.dumps(evidence["recv"].observed_args)
        assert "4141" not in serialized
        assert "4242" not in serialized
        assert len(serialized) < 2048

    def test_long_strings_truncated_and_list_capped(self, tmp_path):
        run = tmp_path / "run"
        _write_events(run, [{
            "ts": 1.0, "type": "send",
            "payload": {"category": "exec", "fn": "system",
                        "caller_module": "srv",
                        "args": {"command": "x" * 5000,
                                 **{f"a{i}": i for i in range(20)}},
                        "tid": 1},
        }])
        _write_metadata(run, target_binary=str(tmp_path / "srv"))
        args = collect_runtime_evidence([tmp_path])["system"].observed_args
        assert len(args) <= 8
        assert all(not (isinstance(a, str) and len(a) > 200) for a in args)


class TestBacktraceAttribution:
    """The target on the CALL STACK attributes an event — real projects
    ship vulnerable code in their own libraries and call sinks through
    wrappers, so the immediate caller alone is not enough."""

    def test_shipped_library_call_with_target_on_stack_counts(self, tmp_path):
        run = tmp_path / "run"
        _write_events(run, [{
            "ts": 1.0, "type": "send",
            "payload": {
                "category": "sink", "fn": "memcpy",
                "caller_module": "libfoo.so",
                "backtrace_frames": [
                    {"address": "0x1", "module": "libfoo.so"},
                    {"address": "0x2", "module": "srv"},
                    {"address": "0x3", "module": "libc.so.6"},
                ],
                "args": {"n": 64}, "tid": 1,
            },
        }])
        _write_metadata(run, target_binary=str(tmp_path / "srv"))
        assert "memcpy" in collect_runtime_evidence([tmp_path])

    def test_pure_library_stack_still_dropped_with_warning(
            self, tmp_path, caplog):
        import logging
        run = tmp_path / "run"
        _write_events(run, [{
            "ts": 1.0, "type": "send",
            "payload": {
                "category": "sink", "fn": "memcpy",
                "caller_module": "libc.so.6",
                "backtrace_frames": [
                    {"address": "0x1", "module": "libc.so.6"},
                    {"address": "0x2", "module": "ld-linux-x86-64.so.2"},
                ],
                "args": {"n": 64}, "tid": 1,
            },
        }])
        _write_metadata(run, target_binary=str(tmp_path / "srv"))
        with caplog.at_level(logging.WARNING):
            assert collect_runtime_evidence([tmp_path]) == {}
        # Attribution loss must never look like "no sink calls
        # occurred".
        assert any("failed target attribution" in r.message
                   and "libc.so.6" in r.message
                   for r in caplog.records)


class TestEvidenceExcludedCategories:
    def test_ingest_and_jni_never_count(self, tmp_path):
        # seed-harvest produces seeds (no callsite is captured); jni
        # maps registrations. Neither is call evidence.
        run = tmp_path / "run"
        _write_events(run, [
            {"ts": 1.0, "type": "send",
             "payload": {"category": "ingest", "fn": "read",
                         "args": {"len": 4, "data_hex": "41414141"},
                         "tid": 1}},
            {"ts": 1.0, "type": "send",
             "payload": {"category": "jni", "fn": "RegisterNatives",
                         "caller_module": "srv",
                         "args": {"method": "doIt"}, "tid": 1}},
        ])
        _write_metadata(run, target_binary=str(tmp_path / "srv"))
        assert collect_runtime_evidence([tmp_path]) == {}


class TestObservedArgsNestedBounds:
    def test_argv_list_is_bounded(self, tmp_path):
        run = tmp_path / "run"
        argv = ["x" * 256 for _ in range(33)]
        _write_events(run, [{
            "ts": 1.0, "type": "send",
            "payload": {"category": "exec", "fn": "execve",
                        "caller_module": "srv",
                        "args": {"path": "/bin/sh", "argv": argv},
                        "tid": 1},
        }])
        _write_metadata(run, target_binary=str(tmp_path / "srv"))
        serialized = json.dumps(
            collect_runtime_evidence([tmp_path])["execve"].observed_args)
        assert len(serialized) < 2048


class TestSelfAliasDedup:
    def test_alias_repeating_fn_counts_once(self, tmp_path):
        # The same fn watched plain and module-scoped resolves to one
        # address; the event's alias group repeating the primary name
        # must not double-count.
        run = tmp_path / "run"
        _write_events(run, [_sink_event(
            "memcpy", caller_module="srv", aliases=["memcpy"])])
        _write_metadata(run, target_binary=str(tmp_path / "srv"))
        assert collect_runtime_evidence([tmp_path])["memcpy"].call_count == 1


class TestTraceIdCoherence:
    def test_trace_id_follows_the_max_count_run(self, tmp_path):
        # Newest-first discovery: the newer run has 1 call, the older
        # run has 3 — the record must cite the run that showed 3.
        import os
        import time
        newer = tmp_path / "run_newer"
        _write_events(newer, [_sink_event("memcpy", caller_module="srv")])
        _write_metadata(newer, target_binary=str(tmp_path / "srv"))
        older = tmp_path / "run_older"
        _write_events(older, [
            _sink_event("memcpy", caller_module="srv") for _ in range(3)])
        _write_metadata(older, target_binary=str(tmp_path / "srv"))
        old_time = time.time() - 1000
        os.utime(older / "metadata.json", (old_time, old_time))

        evidence = collect_runtime_evidence([tmp_path])
        assert evidence["memcpy"].call_count == 3
        assert evidence["memcpy"].trace_id == str(older)


class TestAliasBounds:
    def test_forged_alias_flood_is_bounded(self, tmp_path):
        # The agent runs inside the target process; one forged event
        # must not mint evidence for thousands of names.
        run = tmp_path / "run"
        _write_events(run, [_sink_event(
            "memcpy", caller_module="srv",
            aliases=[f"fn_{i}" for i in range(1000)] + ["x" * 4096])])
        _write_metadata(run, target_binary=str(tmp_path / "srv"))
        evidence = collect_runtime_evidence([tmp_path])
        assert len(evidence) <= 9   # fn + at most 8 aliases


class TestDropDiagnosticLevel:
    def _events(self, tmp_path, extra):
        run = tmp_path / "run"
        _write_events(run, [
            _sink_event("memcpy", caller_module="libc.so.6"),
        ] + extra)
        _write_metadata(run, target_binary=str(tmp_path / "srv"))
        return run

    def test_healthy_run_with_evidence_does_not_warn(self, tmp_path, caplog):
        # A few pre-main libc startup calls drop on EVERY healthy spawn
        # run; warning each time would train operators to ignore it.
        import logging
        self._events(tmp_path, [_sink_event("memcpy", caller_module="srv")])
        with caplog.at_level(logging.WARNING):
            evidence = collect_runtime_evidence([tmp_path])
        assert "memcpy" in evidence
        assert not any("failed target attribution" in r.message
                       for r in caplog.records)

    def test_zero_evidence_run_warns(self, tmp_path, caplog):
        import logging
        self._events(tmp_path, [])
        with caplog.at_level(logging.WARNING):
            assert collect_runtime_evidence([tmp_path]) == {}
        assert any("NO evidence was collected" in r.message
                   for r in caplog.records)


class TestCallerPathAttribution:
    def test_project_shipped_library_by_path_counts(self, tmp_path):
        # A caller module living under the target binary's directory
        # tree attributes even with no target frame on the stack —
        # plugin callbacks and dlopen'd codecs never touch main.
        run = tmp_path / "run"
        _write_events(run, [{
            "ts": 1.0, "type": "send",
            "payload": {
                "category": "sink", "fn": "memcpy",
                "caller_module": "libfoo.so",
                "caller_module_path": str(tmp_path / "libfoo.so"),
                "backtrace_frames": [
                    {"address": "0x1", "module": "libfoo.so"},
                    {"address": "0x2", "module": "libc.so.6"},
                ],
                "args": {"n": 64}, "tid": 1,
            },
        }])
        _write_metadata(run, target_binary=str(tmp_path / "srv"))
        assert "memcpy" in collect_runtime_evidence([tmp_path])

    def test_system_library_path_does_not_count(self, tmp_path):
        run = tmp_path / "run"
        _write_events(run, [{
            "ts": 1.0, "type": "send",
            "payload": {
                "category": "sink", "fn": "memcpy",
                "caller_module": "libc.so.6",
                "caller_module_path": "/usr/lib/x86_64-linux-gnu/libc.so.6",
                "backtrace_frames": [
                    {"address": "0x1", "module": "libc.so.6"},
                ],
                "args": {"n": 64}, "tid": 1,
            },
        }])
        _write_metadata(run, target_binary=str(tmp_path / "srv"))
        assert collect_runtime_evidence([tmp_path]) == {}

    def test_prefix_cousin_directory_does_not_count(self, tmp_path):
        # /opt/app2/lib must not attribute for a target in /opt/app
        # (string-prefix cousins).
        run = tmp_path / "run"
        cousin = str(tmp_path) + "-cousin/libx.so"
        _write_events(run, [{
            "ts": 1.0, "type": "send",
            "payload": {
                "category": "sink", "fn": "memcpy",
                "caller_module": "libx.so",
                "caller_module_path": cousin,
                "args": {"n": 64}, "tid": 1,
            },
        }])
        _write_metadata(run, target_binary=str(tmp_path / "srv"))
        assert collect_runtime_evidence([tmp_path]) == {}

    def test_symlinked_project_dir_still_attributes(self, tmp_path):
        # The loader reports the dlopen'd (symlinked) path; the
        # metadata binary path is resolved — raw string comparison
        # would silently no-op in exactly the motivating scenario.
        real = tmp_path / "real"
        real.mkdir()
        (real / "libleaf.so").write_bytes(b"")
        link = tmp_path / "link"
        link.symlink_to(real)
        run = tmp_path / "run"
        _write_events(run, [{
            "ts": 1.0, "type": "send",
            "payload": {
                "category": "load", "fn": "dlopen",
                "caller_module": "libleaf.so",
                "caller_module_path": str(link / "libleaf.so"),
                "args": {"path": "x"}, "tid": 1,
            },
        }])
        _write_metadata(run, target_binary=str(real / "srv"))
        assert "dlopen" in collect_runtime_evidence([tmp_path])

    def test_dotdot_escape_normalized_out(self, tmp_path):
        # <target_dir>/../elsewhere must not pass the prefix check.
        run = tmp_path / "run"
        target_dir = tmp_path / "app"
        target_dir.mkdir()
        _write_events(run, [{
            "ts": 1.0, "type": "send",
            "payload": {
                "category": "sink", "fn": "memcpy",
                "caller_module": "libx.so",
                "caller_module_path": str(target_dir / ".." / "evil"
                                          / "libx.so"),
                "args": {"n": 4}, "tid": 1,
            },
        }])
        _write_metadata(run, target_binary=str(target_dir / "srv"))
        assert collect_runtime_evidence([tmp_path]) == {}


class TestObservedCallsites:
    def _run(self, tmp_path, payload_extra: dict, binary: Path):
        run = tmp_path / "run"
        _write_events(run, [{
            "ts": 1.0, "type": "send",
            "payload": {
                "category": "sink", "fn": "memcpy",
                "caller_module": binary.name,
                "args": {"n": 4}, "tid": 1,
                **payload_extra,
            },
        }])
        _write_metadata(run, target_binary=str(binary))
        return run

    def test_callsites_captured_and_bounded(self, tmp_path):
        binary = tmp_path / "srv"          # not a real file: no resolve
        run = tmp_path / "run"
        events = []
        for i in range(20):
            events.append({
                "ts": 1.0, "type": "send",
                "payload": {"category": "sink", "fn": "memcpy",
                            "caller_module": "srv",
                            "caller_offset": hex(0x1000 + i),
                            "args": {"n": 4}, "tid": 1},
            })
        _write_events(run, events)
        _write_metadata(run, target_binary=str(binary))
        ev = collect_runtime_evidence([tmp_path])["memcpy"]
        assert ev.observed_callsites is not None
        assert len(ev.observed_callsites) <= 8
        site = ev.observed_callsites[0]
        assert site["module"] == "srv"
        assert site["source"] is None          # nothing to resolve
        assert "_base" not in site             # working keys stripped

    @pytest.mark.slow
    def test_real_binary_resolves_to_source(self, tmp_path):
        import shutil as sh
        import subprocess
        if not (sh.which("gcc") and sh.which("addr2line")):
            import pytest
            pytest.skip("gcc/addr2line unavailable")
        src = tmp_path / "victim.c"
        src.write_text(
            "#include <string.h>\n"
            "char d[64], s[64];\n"
            "int main(void) {\n"
            "    memcpy(d, s, 32);\n"        # line 4
            "    return 0;\n"
            "}\n", encoding="utf-8")
        binary = tmp_path / "victim"
        subprocess.run(["gcc", "-O0", "-g", "-no-pie", "-o",
                        str(binary), str(src)],
                       check=True, capture_output=True, timeout=60)
        # Find the call instruction's address from the symbol table:
        # use the main symbol's address + a small scan is overkill —
        # instead resolve main's address and let the dual-candidate
        # logic prove the plumbing: emit a callsite whose offset IS
        # main's vaddr (non-PIE → file vaddr == runtime address).
        # 60s: generous headroom for a starved runner (nm on this tiny
        # binary is milliseconds when healthy — the timeout exists only
        # to bound a hung process, not to assert speed; a CI runner
        # under disk/CPU pressure has been observed blowing a 10s
        # budget here). Matches the gcc-class tool-subprocess budgets
        # this tier uses elsewhere.
        nm = subprocess.run(["nm", str(binary)], capture_output=True,
                            text=True, timeout=60, check=True)
        main_addr = next(int(line.split()[0], 16)
                         for line in nm.stdout.splitlines()
                         if line.strip().endswith(" T main"))
        run = self._run(
            tmp_path,
            {"caller_offset": hex(main_addr),
             "caller_module_base": "0x0"},
            binary)
        ev = collect_runtime_evidence([run])["memcpy"]
        sites = ev.observed_callsites
        assert sites and sites[0]["source"] is not None
        assert sites[0]["source"].endswith((".c:3", ".c:4"))


class TestCallsiteMatch:
    def _evidence(self, source: str | None):
        return {"memcpy": RuntimeEvidence(
            function_observed=True, call_count=1,
            observed_callsites=[{"module": "srv", "offset": "0x10",
                                 "source": source}])}

    def test_step_call_site_match(self):
        paths = [{"steps": [{"function": "memcpy",
                             "call_site": "src/parse.c:48"}],
                  "proximity": 1}]
        out = annotate_attack_paths(
            paths, self._evidence("/build/src/parse.c:49"))
        re_dict = out[0]["steps"][0]["runtime_evidence"]
        assert re_dict["callsite_match"] is True
        assert re_dict["observed_callsites"][0]["source"].endswith(
            "parse.c:49")

    def test_mismatch_is_false_not_missing(self):
        paths = [{"steps": [{"function": "memcpy",
                             "call_site": "src/parse.c:48"}],
                  "proximity": 1}]
        out = annotate_attack_paths(
            paths, self._evidence("/build/src/other.c:200"))
        assert out[0]["steps"][0]["runtime_evidence"][
            "callsite_match"] is False

    def test_no_location_no_verdict(self):
        paths = [{"steps": [{"function": "memcpy"}], "proximity": 1}]
        out = annotate_attack_paths(paths, self._evidence("/x/y.c:1"))
        assert "callsite_match" not in out[0]["steps"][0][
            "runtime_evidence"]

    def test_finding_location_join(self):
        paths = [{"finding": "F-1",
                  "steps": [{"function": "memcpy"}], "proximity": 1}]
        out = annotate_attack_paths(
            paths, self._evidence("/build/src/parse.c:50"),
            finding_locations={"F-1": ("src/parse.c", 48)})
        assert out[0]["steps"][0]["runtime_evidence"][
            "callsite_match"] is True

    def test_basename_collision_rejected(self):
        # other/parse.c must not match src/parse.c (whole-component
        # suffix comparison).
        paths = [{"steps": [{"function": "memcpy",
                             "call_site": "src/parse.c:48"}],
                  "proximity": 1}]
        out = annotate_attack_paths(
            paths, self._evidence("/build/other/parse.c:48"))
        assert out[0]["steps"][0]["runtime_evidence"][
            "callsite_match"] is False

    def test_unresolved_callsites_yield_no_verdict(self):
        # Release builds / library callsites resolve nothing — that is
        # UNKNOWN, never a mismatch.
        paths = [{"steps": [{"function": "memcpy",
                             "call_site": "src/parse.c:48"}],
                  "proximity": 1}]
        out = annotate_attack_paths(paths, self._evidence(None))
        re_dict = out[0]["steps"][0]["runtime_evidence"]
        assert "callsite_match" not in re_dict
        assert re_dict["observed_callsites"][0]["source"] is None


class TestContradictedCallsiteFloor:
    """A callsite_match of False means the resolved call sites
    CONTRADICT the step — contradicting evidence must not establish
    the proximity floor (None — nothing resolved — still floors)."""

    def _evidence(self, source: str | None):
        return {"memcpy": RuntimeEvidence(
            function_observed=True, call_count=1,
            observed_callsites=[{"module": "srv", "offset": "0x10",
                                 "source": source}])}

    def test_contradicted_step_does_not_floor(self):
        paths = [{"steps": [{"function": "memcpy",
                             "call_site": "src/parse.c:48"}],
                  "proximity": 1}]
        out = annotate_attack_paths(
            paths, self._evidence("/build/src/other.c:200"))
        step = out[0]["steps"][0]
        assert step["runtime_evidence"]["callsite_match"] is False
        # Evidence is still recorded and surfaced...
        assert out[0]["runtime_evidence_available"] is True
        # ...but the floor is withheld: the trace points elsewhere.
        assert out[0]["proximity"] == 1

    def test_corroborated_sibling_step_still_floors(self):
        evidence = self._evidence("/build/src/other.c:200")
        evidence["open"] = RuntimeEvidence(
            function_observed=True, call_count=4, trace_id="/out/run")
        paths = [{"steps": [
            {"function": "memcpy", "call_site": "src/parse.c:48"},
            {"function": "open"},
        ], "proximity": 1}]
        out = annotate_attack_paths(paths, evidence)
        assert out[0]["steps"][0]["runtime_evidence"][
            "callsite_match"] is False
        assert out[0]["proximity"] >= PROXIMITY_FLOOR

    def test_matching_callsite_floors(self):
        paths = [{"steps": [{"function": "memcpy",
                             "call_site": "src/parse.c:48"}],
                  "proximity": 1}]
        out = annotate_attack_paths(
            paths, self._evidence("/build/src/parse.c:48"))
        assert out[0]["steps"][0]["runtime_evidence"][
            "callsite_match"] is True
        assert out[0]["proximity"] >= PROXIMITY_FLOOR


class TestEmptyEvidenceCopyContract:
    def test_empty_map_early_return_is_a_copy(self):
        """Docstring contract: callers always own the result — the
        no-evidence early return handed back the ORIGINAL list
        object, inviting aliased mutation on that path only."""
        paths = [{"steps": [{"function": "open"}], "proximity": 1}]
        out = annotate_attack_paths(paths, {})
        assert out == paths
        assert out is not paths
        assert out[0] is not paths[0]
