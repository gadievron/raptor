"""End-to-end test: frida events → evidence → coverage → observe → context → validation.

Exercises the full data flow pipeline using synthetic events.jsonl
and metadata.json, without requiring an actual frida binary or
target process. Each layer consumes the output of the previous one,
verifying that the contracts between modules are correct.

Pipeline under test:
  events.jsonl ──→ evidence.discover_evidence()
                       │
            ┌──────────┼──────────────┐
            ▼          ▼              ▼
   frida_bridge    observe_adapter   validation_bridge
   (coverage)      (ObserveProfile)  (attack path annotations)
                       │
                       ▼
               context_bridge
               (context map merge)
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest


def _api_event(fn: str, category: str = "file", args=None, tid: int = 1):
    payload = {"category": category, "fn": fn, "tid": tid}
    if args is not None:
        payload["args"] = args
    return {"ts": 0.1, "type": "send", "payload": payload}


def _make_frida_run(
    base: Path,
    target_binary: str,
    events: list[dict],
    *,
    include_drcov: bool = False,
) -> Path:
    """Create a complete synthetic frida run directory."""
    run_dir = base / "frida_20260621_120000_99"
    run_dir.mkdir(parents=True, exist_ok=True)

    lines = [json.dumps(e) for e in events]
    (run_dir / "events.jsonl").write_text("\n".join(lines) + "\n")

    metadata = {
        "ok": True,
        "target": {
            "raw": target_binary,
            "kind": "binary",
            "pid": None,
            "name": None,
            "binary": target_binary,
        },
        "script_origin": "template:api-trace",
        "duration_requested_sec": 30,
        "duration_actual_sec": 29.5,
        "events_captured": len(events),
        "device": {"id": "local", "host": None, "usb": False},
        "host": {
            "system": "Linux", "arch": "x86_64",
            "frida_version": "16.5.0", "frida_bin": "/usr/bin/frida",
            "sip_status": None, "ptrace_scope": 1,
        },
        "spawn": True,
        "unsafe_attach": False,
        "resolved_pid": 12345,
    }
    (run_dir / "metadata.json").write_text(json.dumps(metadata, indent=2))

    if include_drcov:
        header = (
            b"DRCOV VERSION: 2\n"
            b"DRCOV FLAVOR: drcov\n"
            b"Module Table: version 2, count 1\n"
            b"Columns: id, base, end, entry, checksum, timestamp, path\n"
            b" 0, 0x400000, 0x401000, 0x400080, 0, 0, " +
            target_binary.encode() + b"\n"
            b"BB Table: 1 bbs\n"
        )
        bb_entry = struct.pack("<IHH", 0x80, 16, 0)  # offset=0x80, size=16, mod=0
        (run_dir / "coverage.drcov").write_bytes(header + bb_entry)

    return run_dir


EVENTS = [
    _api_event("open", args={"path": "/etc/passwd", "flags": 0, "ret": 3}),
    _api_event("read", args={"fd": 3, "count": 4096, "ret": 512}),
    _api_event("open", args={"path": "/etc/shadow", "flags": 0, "ret": -1}),
    _api_event("write", args={"fd": 1, "count": 512, "ret": 512}),
    _api_event("stat", args={"path": "/usr/lib/libc.so.6"}),
    _api_event("connect", category="network",
               args={"ip": "10.0.0.1", "port": 8080, "family": "AF_INET"}),
    _api_event("open", args={"path": "/tmp/output.bin", "flags": 0o101, "ret": 4}),
]


class TestPipelineE2E:
    """Full pipeline integration: one frida run feeds all consumers."""

    @pytest.fixture
    def frida_run(self, tmp_path):
        target = str(tmp_path / "vulnerable_binary")
        (tmp_path / "vulnerable_binary").touch()
        return _make_frida_run(tmp_path, target, EVENTS, include_drcov=True)

    @pytest.fixture
    def target_binary(self, tmp_path):
        return str(tmp_path / "vulnerable_binary")

    def test_evidence_discovery(self, frida_run, tmp_path):
        """Layer 1: discover_evidence finds the run and matches target."""
        from packages.frida.evidence import discover_evidence

        target = str(tmp_path / "vulnerable_binary")
        evidence = discover_evidence([tmp_path], target_path=target)
        assert len(evidence) == 1
        assert evidence[0].run_dir == frida_run
        assert evidence[0].has_events is True
        assert evidence[0].has_drcov is True
        assert evidence[0].target_binary == target

    def test_observe_adapter(self, frida_run):
        """Layer 2a: events → ObserveProfile with correct classification."""
        from packages.frida.observe_adapter import events_to_observe_profile

        events_path = frida_run / "events.jsonl"
        profile = events_to_observe_profile(events_path)

        assert "/etc/passwd" in profile.paths_read
        assert "/etc/shadow" in profile.paths_read
        assert "/tmp/output.bin" in profile.paths_written
        assert "/tmp/output.bin" not in profile.paths_read
        assert "/usr/lib/libc.so.6" in profile.paths_stat
        assert len(profile.connect_targets) == 1
        assert profile.connect_targets[0].ip == "10.0.0.1"
        assert profile.connect_targets[0].port == 8080

    def test_context_bridge(self, frida_run, tmp_path, target_binary):
        """Layer 2b: observe profile merges into context map."""
        from packages.frida.context_bridge import enrich_context_map_with_frida

        context_map = {
            "entry_points": [],
            "sinks": [],
            "trust_boundaries": [],
        }

        result = enrich_context_map_with_frida(
            context_map, [tmp_path], target_path=target_binary)

        assert result is not context_map

    def test_validation_bridge(self, frida_run, tmp_path, target_binary):
        """Layer 2c: runtime evidence annotates attack paths."""
        from core.orchestration.frida_validation_bridge import (
            PROXIMITY_FLOOR,
            annotate_attack_paths,
            collect_runtime_evidence,
        )

        evidence_map = collect_runtime_evidence(
            [tmp_path], target_path=target_binary)

        assert "open" in evidence_map
        assert "read" in evidence_map
        assert "write" in evidence_map
        assert "stat" in evidence_map
        assert evidence_map["open"].function_observed is True
        assert evidence_map["open"].call_count == 3

        attack_paths = [{
            "id": "PATH-001",
            "name": "Path to /etc/shadow read",
            "finding": "FIND-001",
            "steps": [
                {"step": 1, "function": "open", "action": "open /etc/shadow"},
                {"step": 2, "function": "read", "action": "read file content"},
                {"step": 3, "function": "process_data", "action": "parse content"},
            ],
            "proximity": 3,
            "blockers": [],
            "status": "uncertain",
        }]

        result = annotate_attack_paths(attack_paths, evidence_map)

        assert result[0]["runtime_evidence_available"] is True
        assert result[0]["proximity"] >= PROXIMITY_FLOOR
        assert "runtime_evidence" in result[0]["steps"][0]
        assert "runtime_evidence" in result[0]["steps"][1]
        assert "runtime_evidence" not in result[0]["steps"][2]
        assert result[0]["steps"][0]["runtime_evidence"]["call_count"] == 3
        assert result[0]["frida_trace_id"] == str(frida_run)

    def test_full_pipeline_no_mutation(self, frida_run, tmp_path, target_binary):
        """End-to-end: no layer mutates its input data."""
        from packages.frida.context_bridge import enrich_context_map_with_frida
        from core.orchestration.frida_validation_bridge import (
            annotate_attack_paths,
            collect_runtime_evidence,
        )
        import copy

        original_context = {"entry_points": [{"name": "main"}], "sinks": []}
        frozen_context = copy.deepcopy(original_context)

        enrich_context_map_with_frida(
            original_context, [tmp_path], target_path=target_binary)
        assert original_context == frozen_context

        evidence_map = collect_runtime_evidence(
            [tmp_path], target_path=target_binary)

        paths = [{"id": "P1", "steps": [{"function": "open"}], "proximity": 2}]
        frozen_paths = copy.deepcopy(paths)
        annotate_attack_paths(paths, evidence_map)
        assert paths == frozen_paths

    def test_graceful_degradation_no_evidence(self, tmp_path):
        """All layers degrade gracefully when no evidence exists."""
        from packages.frida.context_bridge import enrich_context_map_with_frida
        from core.orchestration.frida_validation_bridge import (
            annotate_attack_paths,
            collect_runtime_evidence,
        )

        evidence_map = collect_runtime_evidence([tmp_path])
        assert evidence_map == {}

        context = {"entry_points": [], "sinks": []}
        result = enrich_context_map_with_frida(context, [tmp_path])
        assert result is context

        paths = [{"id": "P1", "steps": [{"function": "open"}], "proximity": 5}]
        result = annotate_attack_paths(paths, {})
        assert result is paths
