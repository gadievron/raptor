"""Live E2E test: compile a C binary, instrument with frida, feed through pipeline.

Requires:
  - frida CLI on PATH (pipx/venv install)
  - gcc
  - ptrace_scope <= 1 (spawn mode only needs own-child)

Skipped automatically when any prerequisite is missing.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    not shutil.which("frida") or not shutil.which("gcc"),
    reason="frida CLI or gcc not on PATH",
)

_VICTIM_C = """\
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

int main(void) {
    /* open + read */
    int fd = open("/etc/hostname", O_RDONLY);
    if (fd >= 0) {
        char buf[256];
        read(fd, buf, sizeof(buf));
        close(fd);
    }
    /* stat */
    struct stat st;
    stat("/etc/os-release", &st);
    /* write to stdout */
    const char *msg = "hello from victim\\n";
    write(STDOUT_FILENO, msg, 18);
    return 0;
}
"""

RAPTOR_DIR = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def victim_binary(tmp_path_factory):
    """Compile the victim binary once per module."""
    build_dir = tmp_path_factory.mktemp("victim")
    src = build_dir / "victim.c"
    src.write_text(_VICTIM_C)
    binary = build_dir / "victim"
    result = subprocess.run(
        ["gcc", "-o", str(binary), str(src)],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        pytest.skip(f"gcc failed: {result.stderr[:200]}")
    assert binary.is_file()
    return binary


@pytest.fixture
def run_dir(tmp_path):
    """Fresh run directory for each test."""
    d = tmp_path / "frida_run"
    d.mkdir()
    return d


def _run_frida_cli(binary: Path, run_dir: Path, duration: int = 3) -> int:
    """Run the frida CLI in spawn mode via the packages.frida.cli module."""
    env = os.environ.copy()
    env["RAPTOR_DIR"] = str(RAPTOR_DIR)
    env["PYTHONPATH"] = str(RAPTOR_DIR)
    env.pop("_RAPTOR_TRUSTED", None)

    frida_python = _find_frida_python()
    if not frida_python:
        pytest.skip("cannot find frida-python interpreter")

    cmd = [
        frida_python, "-m", "packages.frida.cli",
        "--target", str(binary),
        "--template", "api-trace",
        "--duration", str(duration),
        "--spawn",
        "--out", str(run_dir),
    ]
    result = subprocess.run(
        cmd, capture_output=True, text=True,
        timeout=duration + 30, env=env,
    )
    return result.returncode


def _find_frida_python() -> str | None:
    """Find the Python interpreter that has frida-python installed."""
    frida_bin = shutil.which("frida")
    if not frida_bin:
        return None
    try:
        with open(frida_bin, "r") as f:
            shebang = f.readline(256).strip()
        if shebang.startswith("#!"):
            python = shebang[2:].strip().split()[0]
            if os.path.isfile(python):
                return python
    except OSError:
        pass
    return sys.executable


class TestLiveE2E:
    """Real frida instrumentation of a compiled binary."""

    def test_spawn_captures_events(self, victim_binary, run_dir):
        """Spawn victim, api-trace template captures open/read/write/stat."""
        rc = _run_frida_cli(victim_binary, run_dir)
        assert rc == 0, f"frida CLI returned {rc}"

        events_path = run_dir / "events.jsonl"
        assert events_path.is_file(), "events.jsonl not created"
        assert events_path.stat().st_size > 0, "events.jsonl is empty"

        metadata_path = run_dir / "metadata.json"
        assert metadata_path.is_file()
        meta = json.loads(metadata_path.read_text())
        assert meta["ok"] is True
        assert meta["target"]["binary"] == str(victim_binary)
        assert meta["events_captured"] > 0

    def test_events_contain_expected_syscalls(self, victim_binary, run_dir):
        """Captured events include the syscalls our victim binary makes."""
        rc = _run_frida_cli(victim_binary, run_dir)
        assert rc == 0

        from packages.frida import parse_events

        fns_seen = set()
        for record in parse_events(run_dir / "events.jsonl"):
            if record.get("type") != "send":
                continue
            payload = record.get("payload", {})
            fn = payload.get("fn")
            if fn:
                fns_seen.add(fn)

        assert "open" in fns_seen or "openat" in fns_seen, (
            f"expected open/openat in {fns_seen}")
        assert "read" in fns_seen, f"expected read in {fns_seen}"
        assert "write" in fns_seen, f"expected write in {fns_seen}"

    def test_evidence_discovery_finds_run(self, victim_binary, run_dir):
        """Evidence layer discovers the run and matches the target."""
        rc = _run_frida_cli(victim_binary, run_dir)
        assert rc == 0

        from packages.frida.evidence import discover_evidence

        evidence = discover_evidence(
            [run_dir.parent], target_path=str(victim_binary))
        assert len(evidence) >= 1
        ev = evidence[0]
        assert ev.has_events is True
        assert ev.target_binary == str(victim_binary)

    def test_observe_adapter_produces_profile(self, victim_binary, run_dir):
        """ObserveProfile from real events has file operations populated."""
        rc = _run_frida_cli(victim_binary, run_dir)
        assert rc == 0

        from packages.frida.observe_adapter import events_to_observe_profile

        profile = events_to_observe_profile(run_dir / "events.jsonl")
        total_paths = (len(profile.paths_read) + len(profile.paths_written)
                       + len(profile.paths_stat))
        assert total_paths > 0, (
            f"no file paths from real events: "
            f"read={profile.paths_read}, write={profile.paths_written}, "
            f"stat={profile.paths_stat}")

    def test_validation_bridge_full_pipeline(self, victim_binary, run_dir):
        """Full pipeline: real events → collect_runtime_evidence → annotate."""
        rc = _run_frida_cli(victim_binary, run_dir)
        assert rc == 0

        from core.orchestration.frida_validation_bridge import (
            PROXIMITY_FLOOR,
            annotate_attack_paths,
            collect_runtime_evidence,
        )

        evidence_map = collect_runtime_evidence(
            [run_dir.parent], target_path=str(victim_binary))
        assert len(evidence_map) > 0, "no runtime evidence collected"

        has_open = "open" in evidence_map or "openat" in evidence_map
        assert has_open, f"expected open/openat in {list(evidence_map.keys())}"

        fn = "open" if "open" in evidence_map else "openat"
        attack_paths = [{
            "id": "LIVE-001",
            "steps": [{"step": 1, "function": fn, "action": f"{fn}()"}],
            "proximity": 2,
        }]
        result = annotate_attack_paths(attack_paths, evidence_map)
        assert result[0]["proximity"] >= PROXIMITY_FLOOR
        assert result[0]["runtime_evidence_available"] is True
        step_ev = result[0]["steps"][0]["runtime_evidence"]
        assert step_ev["function_observed"] is True
        assert step_ev["call_count"] >= 1
