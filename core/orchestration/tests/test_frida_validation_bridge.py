"""Tests for core.orchestration.frida_validation_bridge."""

import copy
import json
from pathlib import Path

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
        """Empty evidence map returns input unchanged (no copy needed)."""
        paths = [_make_attack_path("P1", [
            {"step": 1, "action": "call open()", "function": "open"},
        ])]
        result = annotate_attack_paths(paths, {})
        assert result == paths
        assert result is paths

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
