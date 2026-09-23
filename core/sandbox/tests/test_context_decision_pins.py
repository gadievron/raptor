"""Decision-spine pins for ``core.sandbox.context``.

Each test pins one decision the sandbox()/run() spine takes on the way
to the backend: refusal gates, lane routing, posture stamps, floor
attribution, degrade bookkeeping, and the module-level helpers those
decisions ride on. No real kernel feature is exercised — availability
probes are patched and the spawn backend is a recorder, following the
established fake-spawn pattern (test_fresh_procfs_contract,
test_context_backend_dispatch); the oracles are raised typed errors,
``result.sandbox_info`` stamps, recorder kwargs, and run-dir marker
files.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from core.sandbox import _spawn as spawn_mod  # noqa: E402
from core.sandbox import context  # noqa: E402
from core.sandbox import landlock as landlock_mod  # noqa: E402
from core.sandbox import probes as probes_mod  # noqa: E402
from core.sandbox import seccomp as seccomp_mod  # noqa: E402
from core.sandbox import state  # noqa: E402
from core.sandbox.errors import SandboxSetupError  # noqa: E402

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="exercises the Linux decision spine (probes patched, no "
           "real kernel features used)",
)


# ---------------------------------------------------------------------------
# module-level helpers
# ---------------------------------------------------------------------------


def test_audit_degrade_reason_prefers_upstream_fallback_reason() -> None:
    # A B-fallback / cache-hit reason set upstream is the most
    # specific cause (it names the binary) and must be returned as the
    # (reason, instructions) PAIR — callers tuple-unpack it.
    got = context._audit_degrade_reason("cmd outside tree", "fix it",
                                        None, None, {})
    assert got == ("cmd outside tree", "fix it")


def test_count_lines_bounded_reports_exact_count_without_overflow(
        tmp_path: Path) -> None:
    p = tmp_path / "events.jsonl"
    p.write_text("a\nb\nc\n")
    assert context._count_lines_bounded(p) == (3, False)


def test_count_lines_bounded_flags_overflow(tmp_path: Path) -> None:
    p = tmp_path / "events.jsonl"
    p.write_text("a\nb\nc\n")
    count, overflowed = context._count_lines_bounded(p, max_bytes=2)
    assert overflowed is True


def test_proxy_count_sidecar_read_error_is_tamper_evidence(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A sidecar that EXISTS but cannot be read is tamper evidence in
    # itself: the triple must be (None, set(), True) — callers
    # 3-unpack and grade integrity off the third element.
    from core.sandbox import proxy as proxy_mod
    sidecar = tmp_path / proxy_mod.PROXY_EVENTS_COUNT_FILENAME
    sidecar.write_text("{}")
    import os as _os
    monkeypatch.setattr(_os, "fstat",
                        mock.Mock(side_effect=OSError(5, "io")))
    assert context._read_proxy_count_sidecar(
        str(tmp_path), None) == (None, set(), True)


def test_proxy_count_sidecar_absent_is_not_tamper(tmp_path: Path) -> None:
    assert context._read_proxy_count_sidecar(
        str(tmp_path), None) == (None, set(), False)


def test_cmd_resolves_nowhere_classification() -> None:
    # bare name, on PATH / not on PATH
    assert context._cmd_resolves_nowhere(["sh"], None) is False
    assert context._cmd_resolves_nowhere(
        ["definitely-no-such-tool-zq9"], None) is True
    # caller PATH keeps resolving even when the child PATH would not
    assert context._cmd_resolves_nowhere(
        ["sh"], "/nonexistent-dir") is False
    # a child PATH value alone cannot rescue a name that also misses
    # the caller's PATH unless it actually contains the tool
    sh_dir = str(Path(shutil.which("sh")).parent)
    assert context._cmd_resolves_nowhere(
        ["definitely-no-such-tool-zq9"], sh_dir) is True
    # absolute: existence decides
    assert context._cmd_resolves_nowhere(["/bin/sh"], None) is False
    assert context._cmd_resolves_nowhere(
        ["/no/such/abs/tool"], None) is True
    # relative-with-separator: cwd-dependent, never classified
    assert context._cmd_resolves_nowhere(
        ["./no/such/rel"], None) is False


# ---------------------------------------------------------------------------
# fake-spawn driver
# ---------------------------------------------------------------------------


class _SpawnRecorder:
    """Recorder for _spawn.run_sandboxed: returns one scripted
    ``_setup_status`` per call (clean when the script runs out)."""

    def __init__(self, statuses: list[Any] | None = None,
                 exc: Exception | None = None) -> None:
        self.statuses = list(statuses or [])
        self.exc = exc
        self.calls: list[dict[str, Any]] = []

    def __call__(self, cmd: Any, **kw: Any) -> subprocess.CompletedProcess:
        self.calls.append(kw)
        if self.exc is not None:
            raise self.exc
        cp = subprocess.CompletedProcess(cmd, returncode=0,
                                         stdout="", stderr="")
        cp._setup_status = (self.statuses.pop(0)
                            if self.statuses else None)
        return cp


class _Driver:
    def __init__(self, monkeypatch: pytest.MonkeyPatch,
                 recorder: _SpawnRecorder, *,
                 mount: bool = True, net: bool = True,
                 seccomp: bool = True, landlock: bool = True) -> None:
        self.recorder = recorder
        self.preexec_calls: list[dict[str, Any]] = []
        monkeypatch.setattr(context, "check_mount_available",
                            lambda: mount)
        monkeypatch.setattr(context, "check_net_available", lambda: net)
        monkeypatch.setattr(context, "check_seatbelt_available",
                            lambda: False)
        monkeypatch.setattr(seccomp_mod, "check_seccomp_available",
                            lambda: seccomp)
        monkeypatch.setattr(landlock_mod, "check_landlock_available",
                            lambda: landlock)
        monkeypatch.setattr(landlock_mod, "_get_landlock_abi",
                            lambda: 8 if landlock else 0)
        monkeypatch.setattr(probes_mod, "check_unshare_engages",
                            lambda flags: (True, ""))
        monkeypatch.setattr(spawn_mod, "run_sandboxed", recorder)
        monkeypatch.setattr(spawn_mod, "mount_ns_available",
                            lambda: mount)

        def _fake_preexec(*a: Any, **kw: Any) -> None:
            self.preexec_calls.append(kw)
            return None

        monkeypatch.setattr(context, "_make_preexec_fn", _fake_preexec)


def _clean_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
               *, sandbox_kwargs: dict | None = None,
               run_kwargs: dict | None = None,
               statuses: list | None = None,
               **driver_kwargs: Any) -> tuple[Any, _SpawnRecorder, _Driver]:
    rec = _SpawnRecorder(statuses)
    drv = _Driver(monkeypatch, rec, **driver_kwargs)
    skw = {"target": str(tmp_path)}
    skw.update(sandbox_kwargs or {})
    rkw = {"capture_output": True, "timeout": 60}
    rkw.update(run_kwargs or {})
    with context.sandbox(**skw) as run:
        result = run(["/bin/true"], **rkw)
    return result, rec, drv


# ---------------------------------------------------------------------------
# entry-time refusal gates
# ---------------------------------------------------------------------------


def test_strict_refuses_when_seccomp_probe_fails(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """strict is fail-closed: a requested seccomp filter that cannot
    engage refuses the context (names the missing layer) instead of
    silently running filterless — and the gate keys on the probe's
    FAILURE, never its success."""
    _Driver(monkeypatch, _SpawnRecorder(), seccomp=False)
    with pytest.raises(SandboxSetupError) as exc:
        with context.sandbox(profile="strict", target=str(tmp_path)):
            pass
    assert "seccomp" in str(exc.value)


def test_strict_requires_mount_ns_for_target_or_output_alone(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The mount-ns unmet item triggers on target OR output — a call
    carrying only one of them still relies on the bind tree."""
    _Driver(monkeypatch, _SpawnRecorder(), mount=False)
    with pytest.raises(SandboxSetupError):
        with context.sandbox(profile="strict", target=str(tmp_path)):
            pass
    with pytest.raises(SandboxSetupError):
        with context.sandbox(profile="strict", output=str(tmp_path)):
            pass


def test_strict_engages_when_probes_pass(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    result, rec, _ = _clean_run(monkeypatch, tmp_path,
                                sandbox_kwargs={"profile": "strict"})
    assert result.returncode == 0
    assert rec.calls, "strict run never reached the spawn backend"


def test_disabled_info_vs_unavailable_warning(
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture) -> None:
    """Two distinct operator messages: a deliberate disabled=True gets
    the INFO note; a host with no isolation backend gets the loud
    WARNING. Neither may borrow the other's condition."""
    _Driver(monkeypatch, _SpawnRecorder(), mount=False, net=False,
            seccomp=False, landlock=False)
    state._warned_flags.discard("_sandbox_unavailable_warned") \
        if hasattr(state, "_warned_flags") else None
    with caplog.at_level("INFO"):
        with context.sandbox(disabled=True):
            pass
    assert any("Sandbox disabled for this call" in r.message
               for r in caplog.records)
    assert not any("Sandbox unavailable" in r.message
                   for r in caplog.records)


# ---------------------------------------------------------------------------
# posture stamps + floor attribution (stubbed spawn lane)
# ---------------------------------------------------------------------------


def test_trusted_default_floor_is_none(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A plain run() without the untrusted-contract kwarg is TRUSTED:
    floor 'none', source 'default'. Classifying absent-kwarg as
    untrusted would raise every plain call's floor to mount-ns."""
    result, _, _ = _clean_run(monkeypatch, tmp_path)
    assert result.sandbox_info["containment_floor"] == "none"
    assert result.sandbox_info["floor_source"] == "default"


def test_spawn_lane_stamps_mount_ns_tier(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    result, _, _ = _clean_run(monkeypatch, tmp_path)
    assert result.sandbox_info["containment_tier"] == "mount-ns"


def test_dev_shm_joins_writable_baseline(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """POSIX shm/semaphores live in /dev/shm — on hosts that have it,
    the writable baseline must include it or multiprocessing inside
    the sandbox breaks."""
    if not Path("/dev/shm").is_dir():
        pytest.skip("host has no /dev/shm")
    _result, rec, drv = _clean_run(monkeypatch, tmp_path)
    pools = [kw.get("writable_paths") or [] for kw in rec.calls]
    pools += [kw.get("writable_paths") or [] for kw in drv.preexec_calls]
    assert any("/dev/shm" in pool for pool in pools)


def test_stdin_pipe_sentinels_are_exempt_from_fd_audit(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """subprocess.PIPE / DEVNULL are negative int sentinels, not
    file-likes — the stdin fd-policy audit must not probe them for
    fileno()."""
    result, _, _ = _clean_run(
        monkeypatch, tmp_path,
        run_kwargs={"stdin": subprocess.PIPE})
    assert result.returncode == 0
    result, _, _ = _clean_run(
        monkeypatch, tmp_path,
        run_kwargs={"stdin": subprocess.DEVNULL})
    assert result.returncode == 0


def test_setup_status_instructions_follow_the_failed_layer(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """'U' (namespace unshare died) needs the engagement remedy;
    'L'/'S' (a policy layer failed to apply) need the layer remedy —
    network-only drops those layers, so it is a real downgrade for
    them but not for 'U'."""
    from core.sandbox.probes import (
        ENGAGE_FAIL_INSTRUCTIONS,
        LAYER_FAIL_INSTRUCTIONS,
    )
    # 'L' on a trusted call fails loud with the layer remedy.
    with pytest.raises(SandboxSetupError) as exc:
        _clean_run(monkeypatch, tmp_path,
                   statuses=[("L", "landlock apply failed")])
    assert exc.value.setup_category == "L"
    assert exc.value.instructions == LAYER_FAIL_INSTRUCTIONS
    # 'U' additionally resets used_spawn so a FLOORED call reaches the
    # fallback dispatch's floor refusal with the 'U' failure (and its
    # engagement remedy) chained as the cause — never the setup
    # child's CompletedProcess as a fabricated target result.
    with pytest.raises(SandboxSetupError) as exc:
        _clean_run(monkeypatch, tmp_path,
                   sandbox_kwargs={"output": str(tmp_path)},
                   run_kwargs={"require_fresh_procfs": True},
                   statuses=[("U", "unshare died")])
    cause_chain = []
    node: BaseException | None = exc.value
    while node is not None:
        cause_chain.append(node)
        node = node.__cause__
    assert any(getattr(n, "setup_category", None) == "U"
               for n in cause_chain), (
        f"no 'U'-categorised cause in {cause_chain!r}")
    assert any(getattr(n, "instructions", None) == ENGAGE_FAIL_INSTRUCTIONS
               for n in cause_chain), (
        "the unshare failure's engagement remedy is missing from the "
        f"refusal chain: {cause_chain!r}")


def test_floor_refusal_achievable_follows_failed_layer(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """On a floored call, a seccomp apply failure ('S') voids EVERY
    tier (the filter is part of all of them) → achievable 'none'; a
    Landlock failure ('L') with a working seccomp filter leaves the
    namespace tier's own promise → 'ns-only'."""
    from core.sandbox import summary as summary_mod
    records: list[dict[str, Any]] = []

    def spy(run_dir: Any, **kw: Any) -> None:
        records.append(kw)

    monkeypatch.setattr(summary_mod, "record_floor_refusal", spy)
    with pytest.raises(SandboxSetupError):
        _clean_run(monkeypatch, tmp_path,
                   sandbox_kwargs={"output": str(tmp_path)},
                   run_kwargs={"require_fresh_procfs": True},
                   statuses=[("S", "seccomp apply failed")])
    assert records and records[-1]["achievable"] == "none"

    records.clear()
    with pytest.raises(SandboxSetupError):
        _clean_run(monkeypatch, tmp_path,
                   sandbox_kwargs={"output": str(tmp_path)},
                   run_kwargs={"require_fresh_procfs": True},
                   statuses=[("L", "landlock apply failed")])
    assert records and records[-1]["achievable"] == "ns-only"


def test_mx_retry_memoises_failing_command_as_true(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """An M/X bind-tree failure memoises the RESOLVED cmd[0] (PATH
    lookup, falling back to the literal) with value True — later calls
    skip the doomed mount attempt, keyed by the resolved path."""
    result, rec, _ = _clean_run(monkeypatch, tmp_path,
                                statuses=[("X", "exec failed in tree")])
    assert result.returncode == 0
    assert len(rec.calls) == 2  # mount attempt + mountless retry
    resolved = shutil.which("/bin/true") or "/bin/true"
    assert state._speculative_failure_cache.get(resolved) is True


def test_speculative_cache_hit_routes_mountless_by_resolved_path(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The cache lookup key is the RESOLVED command path: a bare name
    that PATH-resolves to a cached-failing binary takes the mountless
    route on its first attempt."""
    resolved = shutil.which("true")
    assert resolved
    monkeypatch.setitem(state._speculative_failure_cache, resolved, True)
    rec = _SpawnRecorder()
    _Driver(monkeypatch, rec)
    with context.sandbox(target=str(tmp_path)) as run:
        result = run(["true"], capture_output=True, timeout=60)
    assert result.returncode == 0
    assert rec.calls and rec.calls[0].get("skip_mount_ns") is True


def test_pidns_degradation_stamp_skips_contract_and_skip_pid_runs(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The pidns_proc_mount_unavailable stamp marks spawn runs that
    MIGHT carry a host-procfs view. A fresh-procfs CONTRACT run proved
    freshness (fail-closed 'F' otherwise) and must not be stamped; a
    plain spawn run on a degraded host must be."""
    monkeypatch.setattr(state, "_pidns_fresh_proc_cache", False)
    result, _, _ = _clean_run(
        monkeypatch, tmp_path,
        sandbox_kwargs={"output": str(tmp_path)},
        run_kwargs={"require_fresh_procfs": True})
    assert "pidns_proc_mount_unavailable" not in result.sandbox_info
    result, _, _ = _clean_run(monkeypatch, tmp_path)
    assert result.sandbox_info.get("pidns_proc_mount_unavailable") is True


def test_private_scratch_stamped_for_context_level_scratch(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Landlock-only restricted posture (no mount-ns) swaps the
    host-shared /tmp grants for a private scratch — the stamp must
    fire on the context-level scratch ALONE (the per-call demoted
    scratch is the other, independent trigger)."""
    rec = _SpawnRecorder()
    _Driver(monkeypatch, rec, mount=False)
    with context.sandbox(target=str(tmp_path),
                         restrict_reads=True) as run:
        result = run(["/bin/true"], capture_output=True, timeout=60)
    assert result.sandbox_info.get("private_scratch") is True


# ---------------------------------------------------------------------------
# nproc host-usage scan
# ---------------------------------------------------------------------------


def test_nproc_cap_counts_same_uid_task_threads(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The RLIMIT_NPROC ceiling is host usage + budget, where usage is
    the same-UID TASK (thread) count summed over numeric /proc
    entries only — non-PID entries (self, sys, ...) stat to this UID
    and would poison the count."""
    import os as _os

    real_listdir = _os.listdir

    def fake_listdir(path: str = ".") -> list[str]:
        if path == "/proc":
            # "self" twice: a scan that wrongly counts NON-digit
            # entries would double-count this process through the
            # magic links while skipping the real pid entry.
            return [str(_os.getpid()), "self", "self", "sys",
                    "not-a-pid"]
        return real_listdir(path)

    monkeypatch.setattr(_os, "listdir", fake_listdir)
    my_threads = 0
    with open(f"/proc/{_os.getpid()}/status", "rb") as f:
        for line in f.read(4096).splitlines():
            if line.startswith(b"Threads:"):
                my_threads = int(line.split()[1])
                break
    rec = _SpawnRecorder()
    drv = _Driver(monkeypatch, rec)
    with context.sandbox(target=str(tmp_path),
                         limits={"nproc": 100}) as run:
        run(["/bin/true"], capture_output=True, timeout=60)
    caps = [kw.get("host_nproc_cap") for kw in drv.preexec_calls
            if "host_nproc_cap" in kw]
    assert caps, "preexec build never received host_nproc_cap"
    assert caps[0] == my_threads + 100


# ---------------------------------------------------------------------------
# host-fingerprint persona gates
# ---------------------------------------------------------------------------


def test_fingerprint_gate_is_opt_in(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Without sanitise_host_fingerprint the persona machinery must
    not run at all: no support probe, no warning, no RuntimeError even
    on unsupported hosts."""
    from core.sandbox import fingerprint as fp_mod
    probe = mock.Mock(return_value=False)
    monkeypatch.setattr(fp_mod, "is_supported", probe)
    _clean_run(monkeypatch, tmp_path)
    assert not probe.called


def test_fingerprint_required_but_unsupported_raises(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from core.sandbox import fingerprint as fp_mod
    monkeypatch.setattr(fp_mod, "is_supported", lambda: False)
    _Driver(monkeypatch, _SpawnRecorder())
    with pytest.raises(RuntimeError, match="sanitise_host_fingerprint"):
        with context.sandbox(target=str(tmp_path),
                             sanitise_host_fingerprint=True,
                             require_sanitisation=True):
            pass


def test_fingerprint_needs_target_or_output_for_overlays(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Persona file overlays ride mount-ns, which only engages with a
    target or output: one of them present passes the gate; neither
    present is a hard refusal under require_sanitisation (a half-
    applied persona must never look like sanitisation)."""
    from core.sandbox import fingerprint as fp_mod
    monkeypatch.setattr(fp_mod, "is_supported", lambda: True)
    monkeypatch.setattr(fp_mod, "build_persona",
                        mock.Mock(return_value=None))
    rec = _SpawnRecorder()
    _Driver(monkeypatch, rec)
    with pytest.raises(RuntimeError, match="target/output"):
        with context.sandbox(sanitise_host_fingerprint=True,
                             require_sanitisation=True):
            pass
    # target alone satisfies the overlay gate (no raise).
    with context.sandbox(target=str(tmp_path),
                         sanitise_host_fingerprint=True,
                         require_sanitisation=True):
        pass


# ---------------------------------------------------------------------------
# audit degrade marker + Landlock-audit lane
# ---------------------------------------------------------------------------


def test_audit_degrade_marker_lands_in_audit_run_dir_alone(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """When audit was requested but no audit-capable lane exists, the
    degrade marker must land in audit_run_dir even when output= is
    unset — codeql-style callers pass audit_run_dir alone."""
    from core.sandbox import summary as summary_mod
    audit_dir = tmp_path / "auditdir"
    audit_dir.mkdir()
    target = tmp_path / "tgt"
    target.mkdir()
    rec = _SpawnRecorder()
    _Driver(monkeypatch, rec, mount=False, seccomp=False)
    with context.sandbox(target=str(target), audit=True,
                         audit_run_dir=str(audit_dir)) as run:
        run(["/bin/true"], capture_output=True, timeout=60)
    assert (audit_dir / summary_mod.AUDIT_DEGRADED_FILE).exists()


def _landlock_audit_lane(monkeypatch: pytest.MonkeyPatch,
                         tmp_path: Path, **sandbox_extra: Any
                         ) -> dict[str, Any]:
    """Drive the Landlock-only audit lane with the tracer helper
    stubbed; return its captured kwargs."""
    from core.sandbox import _landlock_audit as la_mod
    from core.sandbox import ptrace_probe as ptrace_mod
    captured: dict[str, Any] = {}

    def fake_la(cmd: Any, **kw: Any) -> subprocess.CompletedProcess:
        captured.update(kw)
        return subprocess.CompletedProcess(cmd, returncode=0,
                                           stdout="", stderr="")

    monkeypatch.setattr(la_mod, "run_landlock_audit", fake_la)
    monkeypatch.setattr(ptrace_mod, "check_ptrace_available",
                        lambda: True)
    # The lane builds its own Landlock/seccomp preexecs before handing
    # off to the (stubbed) tracer helper — libseccomp itself is not
    # under test here.
    monkeypatch.setattr(seccomp_mod, "_make_seccomp_preexec",
                        lambda *a, **kw: None)
    rec = _SpawnRecorder()
    _Driver(monkeypatch, rec, mount=False)
    target = tmp_path / "tgt"
    target.mkdir(exist_ok=True)
    audit_dir = tmp_path / "auditdir"
    audit_dir.mkdir(exist_ok=True)
    with context.sandbox(target=str(target), audit=True,
                         audit_run_dir=str(audit_dir),
                         **sandbox_extra) as run:
        run(["/bin/true"], capture_output=True, timeout=60)
    assert captured, "Landlock-audit lane never engaged"
    captured["_audit_dir"] = str(audit_dir)
    return captured


def test_landlock_audit_lane_uses_audit_run_dir_alone(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    kw = _landlock_audit_lane(monkeypatch, tmp_path)
    assert kw["audit_run_dir"] == kw["_audit_dir"]


def test_landlock_audit_lane_appends_tool_paths_to_read_allowlist(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Under restrict_reads the tool dirs must ride the read allowlist
    into the audit helper; without a read allowlist the tool_paths
    hint has nowhere to apply and must be a clean no-op."""
    tooldir = tmp_path / "tools"
    tooldir.mkdir()
    readable = tmp_path / "readable"
    readable.mkdir()
    kw = _landlock_audit_lane(
        monkeypatch, tmp_path,
        restrict_reads=True,
        readable_paths=[str(readable)],
        tool_paths=[str(tooldir)])
    assert any(str(tooldir) in p for p in kw["readable_paths"])
    # no read allowlist: still engages, no crash, reads stay wide
    kw = _landlock_audit_lane(
        monkeypatch, tmp_path,
        tool_paths=[str(tooldir)])
    assert kw["restrict_reads"] is False


# ---------------------------------------------------------------------------
# demotion rebuild + mountless write policy
# ---------------------------------------------------------------------------


def test_demoted_plain_lane_keeps_ns_creation_deny(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """After a spawn-ladder failure the plain-subprocess fallback
    rebuilds its preexec — the namespace-creation seccomp deny must
    survive the rebuild (the plain lane's payload never legitimately
    unshares; losing the deny would hand demoted runs an escape
    primitive)."""
    out = tmp_path / "out"
    out.mkdir()
    rec = _SpawnRecorder(exc=RuntimeError("spawn backend down"))
    drv = _Driver(monkeypatch, rec)
    with context.sandbox(output=str(out), restrict_reads=True) as run:
        result = run(["/bin/true"], capture_output=True, timeout=60)
    assert result.returncode == 0
    rebuilds = [kw for kw in drv.preexec_calls
                if "seccomp_block_ns_creation" in kw]
    assert rebuilds, "no preexec rebuild recorded"
    assert rebuilds[-1]["seccomp_block_ns_creation"] is True


def test_skip_mount_run_keeps_output_write_grant(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A per-call skip_mount_ns run that does not qualify for the
    private-scratch swap keeps its construction-time write grants —
    the output dir must stay writable, not be silently dropped."""
    out = tmp_path / "out"
    out.mkdir()
    rec = _SpawnRecorder()
    _Driver(monkeypatch, rec)
    with context.sandbox(output=str(out),
                         restrict_reads=False) as run:
        run(["/bin/true"], capture_output=True, timeout=60,
            skip_mount_ns=True)
    assert rec.calls
    kw = rec.calls[-1]
    assert kw.get("skip_mount_ns") is True
    assert any(str(out) in p for p in (kw.get("writable_paths") or []))


# ---------------------------------------------------------------------------
# egress-proxy netns tier
# ---------------------------------------------------------------------------


class _FakeProxy:
    port = 18080

    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def bind_unix(self, path: str, *, label: str = "sandbox",
                  allowed_hosts: Any = None,
                  allowed_ports: Any = None) -> None:
        self.calls.append(("bind_unix", path))

    def unbind_unix(self, path: str) -> None:
        self.calls.append(("unbind_unix", path))

    def bind_tcp_lane(self, **kw: Any) -> int:
        self.calls.append(("bind_tcp_lane",))
        return 18081

    def close_tcp_lane(self, port: int) -> None:
        self.calls.append(("close_tcp_lane", port))

    def set_lane_audit(self, key: Any, value: Any) -> bool:
        return True

    def acquire_audit_log_only(self) -> None:
        pass

    def release_audit_log_only(self) -> None:
        pass

    def register_sandbox(self, caller_label: Any = None,
                         lane_key: Any = None,
                         host_recon_threshold: Any = None) -> int:
        return 1

    def unregister_sandbox(self, token: int) -> list:
        return []

    def add_hosts(self, hosts: Any) -> None:
        pass

    def update_idle_timeout(self, seconds: Any) -> None:
        pass


def test_proxy_netns_tier_forces_fresh_netns(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The netns egress tier gives the child a FRESH empty netns —
    block_network is forced True (a caller's False would leave the
    host netns reachable around the proxy) and the port allowlist is
    cleared; the forwarder rides the proxy's own port. The default
    no-bridge entry must also enter cleanly (no bridge bookkeeping
    when none was declared)."""
    from core.sandbox import proxy as proxy_mod
    fake = _FakeProxy()
    monkeypatch.setattr(proxy_mod, "get_proxy", lambda *a, **k: fake)
    rec = _SpawnRecorder()
    _Driver(monkeypatch, rec)
    with context.sandbox(target=str(tmp_path), output=str(tmp_path),
                         use_egress_proxy=True,
                         proxy_hosts=["allowed.example"],
                         block_network=False) as run:
        run(["/bin/true"], capture_output=True, timeout=60)
    assert rec.calls
    kw = rec.calls[-1]
    assert kw["block_network"] is True
    assert kw["allowed_tcp_ports"] is None
    assert kw.get("proxy_forwarder_port") == fake.port


# ---------------------------------------------------------------------------
# proxy-count sidecar: every unverifiable-shape arm is tamper evidence
# ---------------------------------------------------------------------------


def _sidecar_path(tmp_path: Path) -> Path:
    from core.sandbox import proxy as proxy_mod
    return tmp_path / proxy_mod.PROXY_EVENTS_COUNT_FILENAME


@pytest.mark.parametrize("shape", [
    "unopenable", "not-regular", "oversized", "garbage-json",
    "non-dict", "unverified-mac",
])
def test_proxy_count_sidecar_unverifiable_shapes_are_tamper(
        tmp_path: Path, shape: str) -> None:
    """A sidecar that EXISTS in any unverifiable shape — unopenable,
    non-regular, oversized, unparseable, wrongly-typed, MAC-less —
    must return the full (None, set(), True) tamper triple; collapsing
    any arm to a bare None crashes the 3-unpacking caller instead of
    grading integrity."""
    import os as _os
    p = _sidecar_path(tmp_path)
    if shape == "unopenable":
        p.symlink_to(p)  # self-referential symlink: O_NOFOLLOW ELOOP
    elif shape == "not-regular":
        _os.mkfifo(p)
    elif shape == "oversized":
        p.write_bytes(b"{" + b" " * context._COUNT_SIDECAR_MAX_BYTES
                      + b"}")
    elif shape == "garbage-json":
        p.write_bytes(b"\xff not json")
    elif shape == "non-dict":
        p.write_text("[1, 2]")
    elif shape == "unverified-mac":
        p.write_text('{"count": 3, "flags": [], "mac": "forged"}')
    assert context._read_proxy_count_sidecar(
        str(tmp_path), None) == (None, set(), True)


# ---------------------------------------------------------------------------
# unavailable-host warning + Landlock-only-mode warning conditions
# ---------------------------------------------------------------------------


def test_unavailable_host_warns_and_does_not_claim_disabled(
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture) -> None:
    """A host with no namespace backend gets the loud unavailable
    WARNING; the 'disabled for this call' INFO belongs exclusively to
    a deliberate disabled=True."""
    _Driver(monkeypatch, _SpawnRecorder(), mount=False, net=False)
    with caplog.at_level("INFO"):
        with context.sandbox():
            pass
    assert any("Sandbox unavailable" in r.message
               for r in caplog.records)
    assert not any("Sandbox disabled for this call" in r.message
                   for r in caplog.records)


def test_landlock_only_mode_warns_for_target_alone(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
        caplog: pytest.LogCaptureFixture) -> None:
    """Landlock-only mode ($HOME visible, no mount-ns) warns whenever
    the call has a target OR an output — a target-only scan is exactly
    the shape whose repo contents are at stake."""
    _Driver(monkeypatch, _SpawnRecorder(), mount=False)
    with caplog.at_level("WARNING"):
        with context.sandbox(target=str(tmp_path)):
            pass
    assert any("Landlock-only" in r.message or "mount" in r.message
               for r in caplog.records), (
        [r.message for r in caplog.records])


# ---------------------------------------------------------------------------
# M/X retry bookkeeping + grant-identity pinning
# ---------------------------------------------------------------------------


def test_mx_retry_stamps_spawn_lane_posture(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The successful mountless retry is still a SPAWN-lane run: its
    posture stamp must reflect the namespace tier it delivered, not
    fall through to plain-lane stamping."""
    result, rec, _ = _clean_run(monkeypatch, tmp_path,
                                statuses=[("X", "exec failed in tree")])
    assert len(rec.calls) == 2
    assert result.sandbox_info.get("containment_tier") in (
        "mountless-ns", "ns-only")
    assert result.sandbox_info.get("mount_ns_degraded")


def test_readable_grants_join_the_identity_pin(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The pre-spawn grant-identity pin covers READABLE grants too: a
    readable path swapped for a different inode between the failed
    mount attempt and the mountless retry is a pin violation
    (fail-closed), not a silent retry against the attacker's swap."""
    import os

    readable = tmp_path / "readable"
    readable.mkdir()
    swap_me = readable
    # Hold an fd on the original directory across the swap: ext4 hands
    # the freed inode NUMBER to the very next mkdir (tmpfs allocates
    # monotonically), and a recycled number is a genuinely identical
    # (st_dev, st_ino) identity — indistinguishable from no swap, so
    # the pin correctly stays silent there. The open fd keeps the
    # stale inode allocated so the swapped-in directory provably
    # differs on every filesystem and the pin has a real violation
    # to detect.
    stale_dir_fd = os.open(readable, os.O_RDONLY)

    class _SwappingRecorder(_SpawnRecorder):
        def __call__(self, cmd: Any, **kw: Any):
            if not self.calls:
                # first (mount) attempt: report bind-tree failure and
                # swap the readable grant's inode before the retry.
                import shutil as _shutil
                _shutil.rmtree(swap_me)
                swap_me.mkdir()
                cp = subprocess.CompletedProcess(cmd, returncode=126,
                                                 stdout="", stderr="")
                cp._setup_status = ("X", "exec failed in tree")
                self.calls.append(kw)
                return cp
            return super().__call__(cmd, **kw)

    rec = _SwappingRecorder()
    _Driver(monkeypatch, rec)
    try:
        with pytest.raises(SandboxSetupError, match="pin violation"):
            with context.sandbox(target=str(tmp_path),
                                 restrict_reads=True,
                                 readable_paths=[str(readable)]) as run:
                run(["/bin/true"], capture_output=True, timeout=60)
    finally:
        os.close(stale_dir_fd)


# ---------------------------------------------------------------------------
# audit dirs + audit-fallback filter posture
# ---------------------------------------------------------------------------


def test_spawn_lane_audit_dir_prefers_audit_run_dir_alone(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from core.sandbox import ptrace_probe as ptrace_mod
    monkeypatch.setattr(ptrace_mod, "check_ptrace_available",
                        lambda: True)
    audit_dir = tmp_path / "auditdir"
    audit_dir.mkdir()
    result, rec, _ = _clean_run(
        monkeypatch, tmp_path,
        sandbox_kwargs={"audit": True,
                        "audit_run_dir": str(audit_dir)})
    assert rec.calls
    assert rec.calls[-1].get("audit_run_dir") == str(audit_dir)


def test_landlock_audit_fallback_filter_keeps_ns_creation_deny(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The Landlock-only audit fallback builds its own seccomp filter
    — the payload it execs never legitimately unshares, so the
    namespace-creation deny applies there exactly as on the plain
    lane (an audited child must not gain the escape primitive the
    enforcement run refuses)."""
    from core.sandbox import _landlock_audit as la_mod
    from core.sandbox import ptrace_probe as ptrace_mod
    seccomp_builds: list[dict[str, Any]] = []

    def fake_seccomp_preexec(*a: Any, **kw: Any) -> None:
        seccomp_builds.append(kw)
        return None

    monkeypatch.setattr(la_mod, "run_landlock_audit",
                        lambda cmd, **kw: subprocess.CompletedProcess(
                            cmd, returncode=0, stdout="", stderr=""))
    monkeypatch.setattr(ptrace_mod, "check_ptrace_available",
                        lambda: True)
    monkeypatch.setattr(seccomp_mod, "_make_seccomp_preexec",
                        fake_seccomp_preexec)
    rec = _SpawnRecorder()
    _Driver(monkeypatch, rec, mount=False)
    target = tmp_path / "tgt"
    target.mkdir()
    audit_dir = tmp_path / "auditdir"
    audit_dir.mkdir()
    with context.sandbox(target=str(target), audit=True,
                         audit_run_dir=str(audit_dir)) as run:
        run(["/bin/true"], capture_output=True, timeout=60)
    audited = [kw for kw in seccomp_builds if kw.get("audit_mode")]
    assert audited, "audit-fallback seccomp filter never built"
    assert audited[-1].get("block_ns_creation") is True


# ---------------------------------------------------------------------------
# extra write grants survive the skip-mount early return
# ---------------------------------------------------------------------------


def test_mountless_retry_keeps_extra_write_grants_without_restriction(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A trusted (read-everywhere) call demoted to the mountless lane
    does not qualify for the private-scratch swap — its
    construction-time write grants pass through UNCHANGED to the
    retry, extra writable_paths included."""
    extra = tmp_path / "extra"
    extra.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    rec = _SpawnRecorder([("X", "exec failed in tree")])
    _Driver(monkeypatch, rec)
    with context.sandbox(output=str(out),
                         writable_paths=[str(extra)],
                         restrict_reads=False) as run:
        result = run(["/bin/true"], capture_output=True, timeout=60)
    assert result.returncode == 0
    assert len(rec.calls) == 2
    retry_kw = rec.calls[1]
    assert retry_kw.get("skip_mount_ns") is True
    assert any(str(extra) in p
               for p in (retry_kw.get("writable_paths") or []))


def test_seatbelt_lane_audit_dir_prefers_audit_run_dir_alone(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The darwin seatbelt dispatch computes its audit dir the same
    way as the Linux lanes: audit_run_dir alone must reach the backend
    even with output= unset."""
    from core.sandbox import _macos_spawn as macos_mod
    captured: dict[str, Any] = {}

    def fake_mac(cmd: Any, **kw: Any) -> subprocess.CompletedProcess:
        captured.update(kw)
        cp = subprocess.CompletedProcess(cmd, returncode=0,
                                         stdout="", stderr="")
        cp._setup_status = None
        cp.sandbox_info = {"backend": "macos-seatbelt"}
        return cp

    audit_dir = tmp_path / "auditdir"
    audit_dir.mkdir()
    target = tmp_path / "tgt"
    target.mkdir()
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(context, "check_seatbelt_available",
                        lambda: True)
    monkeypatch.setattr(context, "check_mount_available", lambda: False)
    monkeypatch.setattr(context, "check_net_available", lambda: False)
    monkeypatch.setattr(macos_mod, "run_sandboxed", fake_mac)
    with context.sandbox(target=str(target), audit=True,
                         audit_run_dir=str(audit_dir)) as run:
        run(["/usr/bin/true"], capture_output=True, timeout=60)
    assert captured.get("audit_run_dir") == str(audit_dir)


def test_mountless_retry_scratch_swap_keeps_non_shared_grants(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The read-restricted mountless retry swaps host-shared /tmp and
    /dev/shm grants for a private scratch — every OTHER write grant
    must survive the swap alongside the scratch dir."""
    extra = tmp_path / "extra"
    extra.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    rec = _SpawnRecorder([("X", "exec failed in tree")])
    _Driver(monkeypatch, rec)
    with context.sandbox(output=str(out), restrict_reads=True,
                         writable_paths=[str(extra), "/tmp"]) as run:
        result = run(["/bin/true"], capture_output=True, timeout=60)
    assert result.returncode == 0
    assert len(rec.calls) == 2
    grants = rec.calls[1].get("writable_paths") or []
    assert any(str(extra) in p for p in grants)
    assert "/tmp" not in grants  # host-shared grant swapped out
    assert result.sandbox_info.get("private_scratch") is True
