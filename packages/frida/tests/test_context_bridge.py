"""Tests for packages.frida.context_bridge."""

from __future__ import annotations

import json
from pathlib import Path

from packages.frida.context_bridge import enrich_context_map_with_frida


def _write_frida_run(run_dir: Path, events: list[dict],
                     binary: str = "/tmp/build/myapp") -> None:
    """Create a frida run directory with metadata.json + events.jsonl."""
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "metadata.json").write_text(json.dumps({
        "ok": True,
        "error": None,
        "target": {
            "raw": binary,
            "kind": "binary",
            "pid": None,
            "name": None,
            "binary": binary,
        },
        "script_origin": "template:api-trace",
        "duration_requested_sec": 60.0,
        "duration_actual_sec": 5.0,
        "events_captured": len(events),
        "device": {"id": "local", "host": None, "usb": False},
        "host": {"system": "Linux", "arch": "x86_64",
                 "frida_version": "16.0.0", "frida_bin": "/usr/bin/frida",
                 "sip_status": None, "ptrace_scope": 0},
        "spawn": True,
        "unsafe_attach": False,
        "resolved_pid": 1234,
    }), encoding="utf-8")
    (run_dir / "events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in events) + "\n",
        encoding="utf-8",
    )


def _send_event(category: str, fn: str, args: list) -> dict:
    return {
        "ts": 1.0,
        "type": "send",
        "payload": {"category": category, "fn": fn, "args": args, "tid": 1},
    }


def _make_context_map(target: str = "/repo") -> dict:
    return {
        "meta": {"target": target, "generated_at": "2026-01-01T00:00:00Z"},
        "entry_points": [
            {"id": "EP-1", "file": "src/main.py", "function": "main"},
        ],
        "sink_details": [
            {"id": "SINK-1", "file": "src/output.py", "function": "write_log"},
        ],
    }


class TestEnrichWithFridaEvidence:
    def test_merge_adds_runtime_observation(self, tmp_path):
        run_dir = tmp_path / "frida-run"
        _write_frida_run(run_dir, [
            _send_event("file", "open", ["/repo/src/main.py", 0]),
            _send_event("network", "connect", ["10.0.0.1", 8080, "AF_INET"]),
        ])

        ctx = _make_context_map("/repo")
        result = enrich_context_map_with_frida(ctx, [tmp_path])

        assert "runtime_observation" in result
        obs = result["runtime_observation"]
        assert "/repo/src/main.py" in obs["paths_read"]
        assert len(obs["connect_targets"]) == 1

    def test_multiple_runs_merged(self, tmp_path):
        run1 = tmp_path / "run-1"
        _write_frida_run(run1, [
            _send_event("file", "open", ["/repo/src/a.py", 0]),
        ])
        run2 = tmp_path / "run-2"
        _write_frida_run(run2, [
            _send_event("file", "open", ["/repo/src/b.py", 0]),
        ])

        ctx = _make_context_map("/repo")
        result = enrich_context_map_with_frida(ctx, [tmp_path])
        assert "runtime_observation" in result


class TestEnrichNoEvidence:
    def test_no_frida_output(self, tmp_path):
        ctx = _make_context_map()
        result = enrich_context_map_with_frida(ctx, [tmp_path])
        assert "runtime_observation" not in result
        assert result == ctx

    def test_empty_search_dirs(self):
        ctx = _make_context_map()
        result = enrich_context_map_with_frida(ctx, [])
        assert result == ctx


class TestEnrichTargetMismatch:
    def test_different_binary_filtered(self, tmp_path):
        run_dir = tmp_path / "frida-run"
        _write_frida_run(
            run_dir,
            [_send_event("file", "open", ["/other/file.py", 0])],
            binary="/opt/other_binary",
        )
        ctx = _make_context_map("/repo")
        result = enrich_context_map_with_frida(
            ctx, [tmp_path], target_path="/home/user/my_app",
        )
        assert "runtime_observation" not in result


class TestEnrichPreservesOriginal:
    def test_original_not_mutated(self, tmp_path):
        run_dir = tmp_path / "frida-run"
        _write_frida_run(run_dir, [
            _send_event("file", "open", ["/etc/passwd", 0]),
        ])
        ctx = _make_context_map()
        original_keys = set(ctx.keys())
        _ = enrich_context_map_with_frida(ctx, [tmp_path])
        assert set(ctx.keys()) == original_keys
        assert "runtime_observation" not in ctx


class TestEnrichEmptyEvents:
    def test_run_with_no_file_events(self, tmp_path):
        run_dir = tmp_path / "frida-run"
        _write_frida_run(run_dir, [
            {"ts": 1.0, "type": "error", "error": {"description": "attach failed"}},
        ])
        ctx = _make_context_map()
        result = enrich_context_map_with_frida(ctx, [tmp_path])
        assert "runtime_observation" not in result
