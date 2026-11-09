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

from core.testing.standalone_cli import run_standalone_cli

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


def _run_frida_cli(binary: Path, run_dir: Path, duration: int = 3,
                   template: str = "api-trace") -> int:
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
        "--template", template,
        "--duration", str(duration),
        "--spawn",
        "--out", str(run_dir),
    ]
    result = run_standalone_cli(
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


@pytest.fixture(scope="module")
def api_trace_capture(victim_binary, tmp_path_factory):
    """Capture once per worker; share immutable bytes, not writable run files."""
    directory = tmp_path_factory.mktemp("api-trace") / "frida_run"
    directory.mkdir()
    returncode = _run_frida_cli(victim_binary, directory)
    artifacts = tuple((path.relative_to(directory), path.read_bytes())
                      for path in sorted(directory.rglob("*")) if path.is_file())
    return returncode, artifacts


@pytest.fixture
def api_trace_returncode(api_trace_capture, run_dir):
    """Each consumer receives its own copy of the real capture's artifacts."""
    returncode, artifacts = api_trace_capture
    for relative, content in artifacts:
        path = run_dir / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    return returncode


class TestLiveE2E:
    """Real frida instrumentation of a compiled binary."""

    def test_spawn_captures_events(self, victim_binary, run_dir, api_trace_returncode):
        """Spawn victim, api-trace template captures open/read/write/stat."""
        rc = api_trace_returncode
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

    def test_events_contain_expected_syscalls(self, victim_binary, run_dir, api_trace_returncode):
        """Captured events include the syscalls our victim binary makes."""
        rc = api_trace_returncode
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

    def test_evidence_discovery_finds_run(self, victim_binary, run_dir, api_trace_returncode):
        """Evidence layer discovers the run and matches the target."""
        rc = api_trace_returncode
        assert rc == 0

        from packages.frida.evidence import discover_evidence

        evidence = discover_evidence(
            [run_dir.parent], target_path=str(victim_binary))
        assert len(evidence) >= 1
        ev = evidence[0]
        assert ev.has_events is True
        assert ev.target_binary == str(victim_binary)

    def test_observe_adapter_produces_profile(self, victim_binary, run_dir, api_trace_returncode):
        """ObserveProfile from real events has file operations populated."""
        rc = api_trace_returncode
        assert rc == 0

        from packages.frida.observe_adapter import events_to_observe_profile

        profile = events_to_observe_profile(run_dir / "events.jsonl")
        total_paths = (len(profile.paths_read) + len(profile.paths_written)
                       + len(profile.paths_stat))
        assert total_paths > 0, (
            f"no file paths from real events: "
            f"read={profile.paths_read}, write={profile.paths_written}, "
            f"stat={profile.paths_stat}")
        # STRING CONTENT, not just presence: string reads regressed to
        # '<unreadable>' once before (Memory.readUtf8String removed in
        # Frida 17) and this assertion was the only live surface that
        # could have caught it — but it passed vacuously on placeholder
        # values. The victim opens /etc/hostname by literal path.
        all_paths = (profile.paths_read + profile.paths_written
                     + profile.paths_stat)
        assert "/etc/hostname" in all_paths, (
            f"expected a real decoded path, got: {all_paths}")

    def test_validation_bridge_full_pipeline(self, victim_binary, run_dir, api_trace_returncode):
        """Full pipeline: real events → collect_runtime_evidence → annotate."""
        rc = api_trace_returncode
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


_SLEEPER_C = """\
#include <unistd.h>
static int work(int x) { return x * 3; }
int main(void) {
    sleep(1);
    volatile int v = 0;
    for (int i = 0; i < 3; i++) { v += work(i); usleep(100000); }
    sleep(1);
    return v & 0x7f;
}
"""


class TestBbCoverageLive:
    """bb-coverage template end to end: stalk a real process, emit
    drcov, and round-trip it through RAPTOR's own parser.

    The victim sleeps briefly so the controller's flush clock gets a
    chance to follow the main thread (a target that exits before the
    first flush yields little coverage — documented limitation).
    """

    @pytest.fixture(scope="class")
    @staticmethod
    def sleeper_binary(tmp_path_factory):
        build_dir = tmp_path_factory.mktemp("sleeper")
        src = build_dir / "sleeper.c"
        src.write_text(_SLEEPER_C)
        binary = build_dir / "sleeper"
        result = subprocess.run(
            ["gcc", "-o", str(binary), str(src)],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            pytest.skip(f"gcc failed: {result.stderr[:200]}")
        return binary

    @pytest.mark.slow  # real spawn + instrumentation window, ~5s by construction
    def test_drcov_round_trips_through_parser(self, sleeper_binary, run_dir):
        rc = _run_frida_cli(sleeper_binary, run_dir, duration=5,
                            template="bb-coverage")
        assert rc == 0

        drcov = run_dir / "coverage.drcov"
        assert drcov.is_file(), "flush clock produced no coverage.drcov"

        from core.coverage.collect import parse_drcov

        modules = parse_drcov(drcov)
        victim = [m for path, m in modules.items()
                  if Path(path).name == sleeper_binary.name]
        assert victim, (
            f"target module missing from drcov module table: "
            f"{list(modules)}")
        # Real coverage, not a header-only blob: main + work + the
        # loop span multiple basic blocks.
        assert len(victim[0]["offsets"]) >= 3


_PATCH_VULN_C = """\
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main(void) {
    char buf[128];
    if (!fgets(buf, sizeof(buf), stdin)) return 1;
    if (strncmp(buf, "RUN", 3) == 0) {
        char cmd[160];
        snprintf(cmd, sizeof(cmd), "echo triggered %s", buf + 3);
        system(cmd);
    }
    return 0;
}
"""

_PATCH_FIXED_C = """\
#include <stdio.h>
#include <string.h>
int main(void) {
    char buf[128];
    if (!fgets(buf, sizeof(buf), stdin)) return 1;
    if (strncmp(buf, "RUN", 3) == 0) {
        fputs("command execution disabled\\n", stdout);
    }
    return 0;
}
"""


class TestPatchOracleLive:
    """Patch oracle end to end: the same PoC drives an unpatched and a
    patched build under a sink watch, and the verdict comes out
    Closed."""

    @pytest.fixture(scope="class")
    @staticmethod
    def patch_pair(tmp_path_factory):
        build_dir = tmp_path_factory.mktemp("patchpair")
        pair = []
        for name, src_text in (("vuln", _PATCH_VULN_C),
                               ("fixed", _PATCH_FIXED_C)):
            src = build_dir / f"{name}.c"
            src.write_text(src_text)
            binary = build_dir / name
            result = subprocess.run(
                ["gcc", "-g", "-o", str(binary), str(src)],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                pytest.skip(f"gcc failed: {result.stderr[:200]}")
            pair.append(binary)
        return tuple(pair)

    @pytest.mark.slow  # two real instrumented runs (pre/post patch), ~8s by construction
    def test_closed_verdict_on_real_patch(self, patch_pair, tmp_path,
                                          monkeypatch):
        before, after = patch_pair
        poc = tmp_path / "poc.txt"
        poc.write_text("RUN hello\n")

        monkeypatch.setenv("RAPTOR_DIR", str(RAPTOR_DIR))
        monkeypatch.setenv("PYTHONPATH", str(RAPTOR_DIR))
        from packages.frida.patch_oracle import verify_patch

        report = verify_patch(
            before, after, ["system"], tmp_path / "out",
            poc=poc, finding_location=("vuln.c", 10), duration=4)

        assert report["verdict"] == "closed"
        assert report["before"]["fired"]["system"]["call_count"] >= 1
        if shutil.which("addr2line"):
            assert report["confidence"] == "site"


_HEAP_VICTIM_C = """\
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
char *make_buffer(size_t n) { return malloc(n); }
/* volatile pointer defeats gcc's builtin-memcpy inlining: the libc
 * call must actually happen for the boundary hook to see it */
void *(*volatile vmemcpy)(void *, const void *, size_t) = memcpy;
int main(void) {
    usleep(500000);
    for (int i = 0; i < 8; i++) {
        char *l = make_buffer(4096);
        if (l) l[0] = 'x';
    }
    char *p = make_buffer(256);
    char dst[64];
    p[0] = 'x';
    free(p);
    vmemcpy(dst, p, 64);
    usleep(500000);
    char *q = make_buffer(128);
    free(q);
    free(q);  /* glibc aborts here; the hook records it first */
    usleep(1500000);
    return 0;
}
"""


class TestHeapTraceLive:
    """heap-trace end to end: a victim with a real use-after-free and
    a real double free, both reported with owned-caller attribution,
    plus leak-candidate sites in the summary."""

    @pytest.fixture(scope="class")
    @staticmethod
    def heap_victim(tmp_path_factory):
        build_dir = tmp_path_factory.mktemp("heapvictim")
        src = build_dir / "victim.c"
        src.write_text(_HEAP_VICTIM_C)
        binary = build_dir / "victim"
        result = subprocess.run(
            ["gcc", "-g", "-o", str(binary), str(src)],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            pytest.skip(f"gcc failed: {result.stderr[:200]}")
        return binary

    @pytest.mark.slow  # real heap-trace instrumentation window, ~5s by construction
    def test_anomalies_and_summary(self, heap_victim, run_dir):
        rc = _run_frida_cli(heap_victim, run_dir, duration=5,
                            template="heap-trace")
        assert rc == 0

        from packages.frida import parse_events

        anomalies: dict[str, list[dict]] = {}
        summary = None
        for record in parse_events(run_dir / "events.jsonl"):
            payload = record.get("payload", {})
            if payload.get("category") != "heap":
                continue
            kind = payload.get("kind")
            if kind == "summary":
                summary = payload
            elif kind:
                anomalies.setdefault(kind, []).append(payload)

        assert "uaf_candidate" in anomalies, f"kinds: {list(anomalies)}"
        assert "double_free" in anomalies, f"kinds: {list(anomalies)}"
        # Attribution: both anomalies called from the victim itself.
        for kind in ("uaf_candidate", "double_free"):
            assert any(a.get("caller_module") == heap_victim.name
                       for a in anomalies[kind]), anomalies[kind]
        # The alias pair (memcpy/memmove) must not double-report.
        assert len(anomalies["uaf_candidate"]) == 1

        assert summary is not None, "no flush summary arrived"
        assert summary["allocs"] > summary["frees"]
        sites = summary["top_owned_sites"]
        assert sites and sites[0]["outstanding_bytes"] >= 8 * 4096


class TestWrapperLiveE2E:
    """The surface every doc example points at — libexec/raptor-frida
    with the sandbox engaged — previously had no live coverage at all;
    the raw-CLI tests above cannot catch wrapper/sandbox regressions
    (read grants, relative-path absolutization, spawn detection)."""

    # Documented host friction: some sandboxes block frida's
    # agent-injection channel. That is a host property, not a wrapper
    # regression — skip on its signature, fail on anything else.
    # frida_memory_file_descriptor_from_bytes: the restricted-reads
    # sandbox posture hard-denies memfd_create (fileless-exec
    # hardening), and frida-core stages its agent through a memfd —
    # the CLI aborts on the EPERM (GLib assertion n == data.length)
    # before it can do anything. The sandboxed frida lane needs its
    # own accommodation in the sandbox policy before this can run
    # under that posture; until then it is the same blocked-injection
    # class as the signatures above.
    _INJECTION_BLOCKED = (
        "Error sending credentials",
        "ProcessNotRespondingError",
        "unexpected early end-of-stream",
        "frida_memory_file_descriptor_from_bytes",
    )

    def test_wrapper_spawn_relative_target(self, victim_binary, tmp_path):

        run_dir = tmp_path / "wrap_run"
        env = os.environ.copy()
        env["CLAUDECODE"] = "1"
        env.pop("_RAPTOR_TRUSTED", None)
        # Relative ./victim from the binary's own directory — the form
        # every doc example uses.
        result = run_standalone_cli(
            [str(RAPTOR_DIR / "libexec" / "raptor-frida"),
             "--target", f"./{victim_binary.name}",
             "--template", "api-trace",
             "--duration", "3",
             "--out", str(run_dir)],
            cwd=str(victim_binary.parent),
            capture_output=True, text=True, timeout=90, env=env,
        )
        combined = result.stdout + result.stderr
        blocked = result.returncode != 0 and any(
            sig in combined for sig in self._INJECTION_BLOCKED
        )

        # Wrapper-side handling must have worked regardless of the
        # sandbox outcome: the target was absolutized and classified
        # as a binary (metadata is written even for failed runs) —
        # EXCEPT when a blocked injection channel aborts the CLI
        # process itself (the memfd signature) before it writes
        # anything; a blocked host proves nothing about the wrapper.
        meta_path = run_dir / "metadata.json"
        if blocked and not meta_path.is_file():
            pytest.skip("sandbox blocks frida agent injection on "
                        "this host (documented friction)")
        assert meta_path.is_file(), combined[-2000:]
        meta = json.loads(meta_path.read_text())
        assert meta["target"]["kind"] == "binary"
        assert meta["target"]["binary"] == str(victim_binary)

        if result.returncode != 0:
            if blocked:
                pytest.skip("sandbox blocks frida agent injection on "
                            "this host (documented friction)")
            raise AssertionError(
                f"wrapper run failed (rc={result.returncode}):\n"
                f"{combined[-2000:]}")

        assert meta["ok"] is True
        assert meta["events_captured"] > 0
