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
    # A fresh latch keeps the negative assertion meaningful: with the
    # once-per-process flag already tripped by an earlier test on this
    # worker, "no unavailable warning" would pass vacuously.
    monkeypatch.setattr(state, "_sandbox_unavailable_warned", False)
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
    """The RLIMIT_NPROC ceiling is host usage + budget + fluctuation
    headroom, where usage is the same-UID TASK (thread) count summed
    over numeric /proc entries only — non-PID entries (self, sys, ...)
    stat to this UID and would poison the count."""
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
    assert caps[0] == my_threads + 100 + context._NPROC_CLAMP_HEADROOM


def test_nproc_clamp_formula_is_exact_and_headroom_bounded(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """Two-direction pin on the clamp derivation.

    Direction 1 (headroom present): the ceiling must sit ABOVE
    snapshot + budget by exactly the headroom — drop it and ordinary
    same-uid thread churn strands the child at the boundary (the
    EAGAIN race this margin exists for). Exact equality also catches
    the other direction at the formula level: any inflation (doubling,
    max()-ing against a previous value) hands a fork bomb a bigger
    allowance than the documented formula.

    Direction 2 (headroom bounded): the margin must stay a small
    fraction of the configured budget or the clamp stops binding —
    the containment property is snapshot + budget + a SMALL constant,
    not snapshot + 2x budget.
    """
    monkeypatch.setattr(context, "_count_same_uid_tasks", lambda: 5000)
    assert context._derive_host_nproc_cap(100) == (
        5000 + 100 + context._NPROC_CLAMP_HEADROOM)
    # No budget → no cap; unreadable /proc → no cap (never a made-up
    # ceiling).
    assert context._derive_host_nproc_cap(0) is None
    monkeypatch.setattr(context, "_count_same_uid_tasks", lambda: None)
    assert context._derive_host_nproc_cap(100) is None
    # Bounds: big enough to absorb transient churn, small enough that
    # the default budget (preexec._DEFAULT_LIMITS, jittered 1024±128)
    # still dominates the ceiling's growth allowance.
    from core.sandbox.preexec import _DEFAULT_LIMITS
    assert 64 <= context._NPROC_CLAMP_HEADROOM
    assert context._NPROC_CLAMP_HEADROOM <= _DEFAULT_LIMITS["nproc"] // 3


def test_nproc_pressure_evidence_requires_finite_limit_and_proximity(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """The pressure attribution is self-measured (rlimit + /proc) and
    fires only when a finite RLIMIT_NPROC binds AND the same-uid task
    count sits within one headroom of it — no finite limit or a count
    comfortably below the ceiling must never attribute to pressure."""
    import resource as _resource

    real_getrlimit = _resource.getrlimit

    def fake_getrlimit(which: int) -> tuple[int, int]:
        if which == _resource.RLIMIT_NPROC:
            return (1100, 1100)
        return real_getrlimit(which)

    monkeypatch.setattr(context.resource, "getrlimit", fake_getrlimit)
    monkeypatch.setattr(context, "_count_same_uid_tasks", lambda: 1050)
    evidence = context._nproc_pressure_evidence()
    assert evidence is not None
    assert "1050" in evidence and "1100" in evidence
    # Count far below the ceiling → not pressure.
    monkeypatch.setattr(
        context, "_count_same_uid_tasks",
        lambda: 1100 - context._NPROC_CLAMP_HEADROOM - 1)
    assert context._nproc_pressure_evidence() is None
    # No finite limit → never pressure, whatever the count.
    monkeypatch.setattr(
        context.resource, "getrlimit",
        lambda which: (_resource.RLIM_INFINITY, _resource.RLIM_INFINITY))
    monkeypatch.setattr(context, "_count_same_uid_tasks", lambda: 10**6)
    assert context._nproc_pressure_evidence() is None


def test_nproc_retry_decision_gates(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """Every gate of the one-retry decision, pinned directly.

    The `already_retried` gate is the retry-once bound: even with
    maximal pressure and a perfect EAGAIN shape it must return None —
    a mutant that drops it turns sustained load into a retry storm
    that amplifies the exhausted per-uid ceiling."""
    eagain = "BlockingIOError: [Errno 11] Resource temporarily unavailable"
    monkeypatch.setattr(context, "_nproc_pressure_evidence",
                        lambda: "same-uid task count 9999 vs "
                                "RLIMIT_NPROC soft limit 10000")
    # Retry-once bound outranks everything.
    assert context._nproc_eagain_retry_decision(
        ("X", eagain), already_retried=True) is None
    # Eligible categories: the stages with fork sites under the
    # inherited limit.
    for cat in ("M", "X", "U"):
        assert context._nproc_eagain_retry_decision(
            (cat, eagain), already_retried=False) is not None
    # Fail-closed categories never retry (no fork race to rescue).
    for cat in ("P", "C", "F", "L", "S", "!"):
        assert context._nproc_eagain_retry_decision(
            (cat, eagain), already_retried=False) is None
    # Clean status / non-EAGAIN shape never retry.
    assert context._nproc_eagain_retry_decision(
        None, already_retried=False) is None
    assert context._nproc_eagain_retry_decision(
        ("X", "exec: file not found"), already_retried=False) is None
    # Shape without corroborating pressure never retries — the detail
    # text can embed target-influenced substrings.
    monkeypatch.setattr(context, "_nproc_pressure_evidence", lambda: None)
    assert context._nproc_eagain_retry_decision(
        ("X", eagain), already_retried=False) is None


_EAGAIN_DETAIL = (
    "BlockingIOError: [Errno 11] Resource temporarily unavailable")
_PRESSURE = "same-uid task count 4999 vs RLIMIT_NPROC soft limit 5000"


def _pressure_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
                  statuses: list, *, pressure: bool,
                  ) -> tuple[Any, _SpawnRecorder, _Driver]:
    """_clean_run under a simulated (or absent) NPROC-pressure verdict,
    with the memoisation cache and both degrade warn-once latches
    fresh so warning assertions are meaningful."""
    monkeypatch.setattr(context, "_nproc_pressure_evidence",
                        lambda: _PRESSURE if pressure else None)
    monkeypatch.setattr(state, "_speculative_failure_cache", {})
    monkeypatch.setattr(state, "_mountless_backend_warned", False)
    monkeypatch.setattr(state, "_nproc_pressure_degrade_warned", False)
    return _clean_run(monkeypatch, tmp_path, statuses=statuses)


def test_nproc_pressure_eagain_retries_same_lane_once_and_rescues(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
        caplog: pytest.LogCaptureFixture) -> None:
    """The stale-snapshot race, simulated: the spawn child dies EAGAIN
    (same-uid count grew past the setup-time snapshot), live pressure
    corroborates → ONE retry of the SAME mount lane rescues the run.
    No mountless degrade, no capability warning, no cache poisoning —
    and the retry persists NO mid-call snapshot: the derivation ran
    exactly once (context entry); a retry-time resample would be
    load-peak-biased for every later consumer (the no-namespace lanes
    resample at dispatch instead, `_consumption_nproc_cap`)."""
    derivations: list[int] = []
    real_derive = context._derive_host_nproc_cap

    def spying_derive(budget: int) -> "int | None":
        derivations.append(budget)
        return real_derive(budget)

    monkeypatch.setattr(context, "_derive_host_nproc_cap", spying_derive)
    with caplog.at_level("INFO"):
        result, rec, _ = _pressure_run(
            monkeypatch, tmp_path,
            [("X", _EAGAIN_DETAIL)], pressure=True)
    assert result.returncode == 0
    # Mount attempt + same-lane retry — and NOT the mountless fallback.
    assert [kw.get("skip_mount_ns") for kw in rec.calls] == [False, False]
    # Context-entry derivation only — the retry itself neither needs
    # the cap (spawn children fork under the inherited limit) nor
    # persists a peak-biased resample.
    assert len(derivations) == 1
    # The transient failure is not memoised against the binary.
    assert not state._speculative_failure_cache
    # No misattributed capability warning; the honest INFO names
    # pressure.
    assert not any("bind-tree isolation unavailable" in r.getMessage()
                   for r in caplog.records)
    assert any("process-count pressure" in r.getMessage()
               for r in caplog.records)


def test_nproc_eagain_without_pressure_keeps_existing_degrade(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
        caplog: pytest.LogCaptureFixture) -> None:
    """EAGAIN shape WITHOUT self-measured pressure (the shape is
    target-influenceable text) must change nothing: no same-lane
    retry, the existing mountless degrade with the existing
    capability warning, and the cache memoises as before."""
    with caplog.at_level("DEBUG"):
        result, rec, _ = _pressure_run(
            monkeypatch, tmp_path,
            [("X", _EAGAIN_DETAIL)], pressure=False)
    assert result.returncode == 0
    assert [kw.get("skip_mount_ns") for kw in rec.calls] == [False, True]
    warnings = [r.getMessage() for r in caplog.records
                if "bind-tree isolation unavailable" in r.getMessage()]
    assert len(warnings) == 1
    assert "process-count pressure" not in warnings[0]
    resolved = shutil.which("/bin/true") or "/bin/true"
    assert state._speculative_failure_cache.get(resolved) is True


def test_genuine_policy_failure_never_hijacked_by_pressure(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
        caplog: pytest.LogCaptureFixture) -> None:
    """Live pressure with a NON-EAGAIN child failure is a genuine
    bind-tree/policy problem that happens to occur on a loaded host:
    no same-lane retry, and the warning keeps the original capability
    text — pressure alone must never rewrite the attribution."""
    with caplog.at_level("DEBUG"):
        result, rec, _ = _pressure_run(
            monkeypatch, tmp_path,
            [("X", "exec: permission denied")], pressure=True)
    assert result.returncode == 0
    assert [kw.get("skip_mount_ns") for kw in rec.calls] == [False, True]
    warnings = [r.getMessage() for r in caplog.records
                if "bind-tree isolation unavailable" in r.getMessage()]
    assert len(warnings) == 1
    assert "process-count pressure" not in warnings[0]


def test_nproc_pressure_double_eagain_degrades_with_honest_warning(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
        caplog: pytest.LogCaptureFixture) -> None:
    """Retry-once bound + honest degrade, end to end: two EAGAIN
    failures under pressure produce exactly mount → same-lane retry →
    mountless fallback (a looping mutant would keep re-running the
    mount lane instead of falling back), the warning names the actual
    cause and explicitly rules out the policy reading, and the
    transient failure still isn't memoised against the binary."""
    with caplog.at_level("DEBUG"):
        result, rec, _ = _pressure_run(
            monkeypatch, tmp_path,
            [("X", _EAGAIN_DETAIL), ("X", _EAGAIN_DETAIL)],
            pressure=True)
    assert result.returncode == 0
    assert [kw.get("skip_mount_ns") for kw in rec.calls] == [
        False, False, True]
    pressure_warnings = [
        r.getMessage() for r in caplog.records
        if r.levelname == "WARNING"
        and "process-count pressure" in r.getMessage()]
    assert len(pressure_warnings) == 1
    assert "RLIMIT_NPROC" in pressure_warnings[0]
    assert "NOT a kernel capability or policy refusal" in (
        pressure_warnings[0])
    assert not any("bind-tree isolation unavailable" in r.getMessage()
                   for r in caplog.records)
    assert not state._speculative_failure_cache


def test_nproc_pressure_u_category_retry_and_honest_terminal_cause(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The namespace-staging forks ('U') race the same inherited limit:
    a pressure EAGAIN there gets the one same-lane retry (rescue →
    genuine result), and when the retry also dies the terminal 'U'
    failure names process-count pressure in its cause chain instead of
    sending the operator after namespace capabilities."""
    result, rec, _ = _pressure_run(
        monkeypatch, tmp_path, [("U", _EAGAIN_DETAIL)], pressure=True)
    assert result.returncode == 0
    assert [kw.get("skip_mount_ns") for kw in rec.calls] == [False, False]
    # Floored call, retry fails too → the raised chain carries the
    # honest cause (idiom of
    # test_setup_status_instructions_follow_the_failed_layer).
    monkeypatch.setattr(context, "_nproc_pressure_evidence",
                        lambda: _PRESSURE)
    rec2 = _SpawnRecorder([("U", _EAGAIN_DETAIL), ("U", _EAGAIN_DETAIL)])
    _Driver(monkeypatch, rec2)
    with pytest.raises(SandboxSetupError) as exc:
        with context.sandbox(target=str(tmp_path), output=str(tmp_path)) \
                as run:
            run(["/bin/true"], capture_output=True, timeout=60,
                require_fresh_procfs=True)
    chain: list[BaseException] = []
    node: BaseException | None = exc.value
    while node is not None:
        chain.append(node)
        node = node.__cause__
    assert any("process-count pressure" in str(n) for n in chain), (
        f"no honest pressure cause in {chain!r}")


def test_retry_policy_failure_restores_original_attribution(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
        caplog: pytest.LogCaptureFixture) -> None:
    """Retry-side twin of the genuine-policy test above: the FIRST
    attempt is a real pressure EAGAIN, the retry then fails with a
    non-EAGAIN policy detail. The first attempt's pressure verdict
    must not describe the adopted terminal failure — the degrade
    keeps the original capability warning and the cache memoises the
    binary as before (a pressure-attributed terminal would skip
    both)."""
    with caplog.at_level("DEBUG"):
        result, rec, _ = _pressure_run(
            monkeypatch, tmp_path,
            [("X", _EAGAIN_DETAIL), ("X", "exec: permission denied")],
            pressure=True)
    assert result.returncode == 0
    assert [kw.get("skip_mount_ns") for kw in rec.calls] == [
        False, False, True]
    warnings = [r.getMessage() for r in caplog.records
                if "bind-tree isolation unavailable" in r.getMessage()]
    assert len(warnings) == 1
    assert "process-count pressure" not in warnings[0]
    assert not any(
        "NOT a kernel capability or policy refusal" in r.getMessage()
        for r in caplog.records)
    resolved = shutil.which("/bin/true") or "/bin/true"
    assert state._speculative_failure_cache.get(resolved) is True


def test_retry_landlock_failure_fail_loud_without_pressure_claim(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Pressure EAGAIN, then the retry dies at the Landlock APPLY step
    ('L' — a genuine capability loss, fail-loud). The raised message
    must attribute THAT failure, not append the first attempt's
    pressure cause — 'Landlock setup failed ... not a kernel
    capability or policy refusal' is self-contradictory."""
    monkeypatch.setattr(context, "_nproc_pressure_evidence",
                        lambda: _PRESSURE)
    rec = _SpawnRecorder(
        [("X", _EAGAIN_DETAIL), ("L", "landlock apply failed: EPERM")])
    _Driver(monkeypatch, rec)
    with pytest.raises(SandboxSetupError) as exc:
        with context.sandbox(target=str(tmp_path), output=str(tmp_path)) \
                as run:
            run(["/bin/true"], capture_output=True, timeout=60)
    msg = str(exc.value)
    assert "landlock apply failed" in msg
    assert "process-count pressure" not in msg
    assert "not a kernel capability or policy refusal" not in msg


def test_consumption_nproc_cap_two_directions(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """Dispatch-time NPROC resample, both directions pinned.

    Direction 1 (freshness): when the derivation works, the fresh
    value wins outright — no max()-ing against the setup-time cap,
    which would ratchet the ceiling to the highest load peak the
    context ever saw.

    Direction 2 (containment): a failed resample (unreadable /proc)
    keeps the setup-time cap — returning None would shed the
    fork-bomb bound the context already holds. And a lane configured
    with NO cap stays uncapped: consumption never invents a ceiling
    setup didn't grant."""
    monkeypatch.setattr(context, "_count_same_uid_tasks", lambda: 500)
    fresh = 500 + 100 + context._NPROC_CLAMP_HEADROOM
    # Fresh sample dominates, in both directions of the comparison.
    assert context._consumption_nproc_cap(fresh + 4000, 100) == fresh
    assert context._consumption_nproc_cap(fresh - 400, 100) == fresh
    # Failed resample → setup-time cap survives.
    monkeypatch.setattr(context, "_count_same_uid_tasks", lambda: None)
    assert context._consumption_nproc_cap(1234, 100) == 1234
    # No setup-time cap → stays uncapped, no derivation invented.
    assert context._consumption_nproc_cap(None, 100) is None


def test_no_namespace_consumers_resample_via_consumption_helper() -> None:
    """Wiring pin: the demoted-lane preexec rebuild and the
    Landlock-audit lane hand `_make_preexec_fn` a dispatch-time
    resample (`_consumption_nproc_cap`), and only the construction-
    time kwargs use the raw setup snapshot. Rewiring a consumer back
    to the raw snapshot silently reintroduces the stale-/peak-biased
    cap this helper exists to replace."""
    src = Path(context.__file__).read_text()
    assert src.count("host_nproc_cap=_consumption_nproc_cap(") == 2
    assert src.count("host_nproc_cap=_host_nproc_cap") == 1


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
    # The latch is once-per-PROCESS: any earlier sandbox() on this
    # worker that found the host unavailable already consumed it, and
    # the conftest state guard restores the PRE-test value — reset so
    # the assertion is order-independent (see reset_warn_once).
    state.reset_warn_once("_sandbox_unavailable_warned")
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
    # Same once-per-process latch exposure as the unavailable warning
    # above — reset so the assertion holds regardless of worker order.
    monkeypatch.setattr(state, "_sandbox_landlock_only_warned", False)
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


# ---------------------------------------------------------------------------
# grant-identity pin: fd-anchored identity (recycling-proof)
# ---------------------------------------------------------------------------

import os  # noqa: E402  (section-local: only the pin tests below use it)


class _StatForger:
    """os.stat wrapper that reports a chosen (st_dev, st_ino) for one
    path — the observable a recycling filesystem hands an attacker:
    the freed inode number reused for the very next create, making the
    replacement stat-identical to the original."""

    def __init__(self, path: str, dev: int, ino: int) -> None:
        self.path = path
        self.dev = dev
        self.ino = ino
        self.armed = False
        self._real_stat = os.stat

    def __call__(self, target: Any, *args: Any, **kwargs: Any) -> Any:
        st = self._real_stat(target, *args, **kwargs)
        if self.armed and isinstance(target, (str, bytes)) and \
                os.fspath(target) == self.path:
            class _Doctored:
                st_dev = self.dev
                st_ino = self.ino

                def __getattr__(self, name: str) -> Any:
                    return getattr(st, name)
            return _Doctored()
        return st


def test_grant_pin_refuses_simulated_inode_recycling(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Recycled-inode swap: the readable grant dir is removed and
    recreated between the failed mount attempt and the mountless
    retry, and the filesystem hands the replacement the ORIGINAL
    inode number (simulated via a stat forger — ext4 does this for
    real; tmpfs allocates monotonically). A snapshot-vs-resnapshot
    (st_dev, st_ino) comparison is blind to this swap; the pin must
    refuse anyway, because its held O_PATH fd is kernel truth for the
    validated object (the unlinked pinned inode has st_nlink == 0 and
    can never be re-minted while the fd is open)."""
    readable = tmp_path / "readable"
    readable.mkdir()
    orig = os.stat(readable)
    forger = _StatForger(str(readable), orig.st_dev, orig.st_ino)

    class _RecyclingRecorder(_SpawnRecorder):
        def __call__(self, cmd: Any, **kw: Any):
            if not self.calls:
                import shutil as _shutil
                _shutil.rmtree(readable)
                readable.mkdir()
                forger.armed = True
                cp = subprocess.CompletedProcess(cmd, returncode=126,
                                                 stdout="", stderr="")
                cp._setup_status = ("X", "exec failed in tree")
                self.calls.append(kw)
                return cp
            return super().__call__(cmd, **kw)

    rec = _RecyclingRecorder()
    _Driver(monkeypatch, rec)
    monkeypatch.setattr(os, "stat", forger)
    with pytest.raises(SandboxSetupError, match="pin violation"):
        with context.sandbox(target=str(tmp_path),
                             restrict_reads=True,
                             readable_paths=[str(readable)]) as run:
            run(["/bin/true"], capture_output=True, timeout=60)


def test_grant_pin_refuses_real_swap_on_any_filesystem(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Plain unlink+recreate swap with NO forgery: because the pin
    holds an O_PATH fd on the validated inode, no filesystem can
    recycle its number for the replacement — the refusal is
    deterministic on every filesystem (ext4 included), with no
    fixture-side fd needed to keep the test honest."""
    readable = tmp_path / "readable"
    readable.mkdir()

    class _SwappingRecorder(_SpawnRecorder):
        def __call__(self, cmd: Any, **kw: Any):
            if not self.calls:
                import shutil as _shutil
                _shutil.rmtree(readable)
                readable.mkdir()
                cp = subprocess.CompletedProcess(cmd, returncode=126,
                                                 stdout="", stderr="")
                cp._setup_status = ("X", "exec failed in tree")
                self.calls.append(kw)
                return cp
            return super().__call__(cmd, **kw)

    rec = _SwappingRecorder()
    _Driver(monkeypatch, rec)
    with pytest.raises(SandboxSetupError, match="pin violation"):
        with context.sandbox(target=str(tmp_path),
                             restrict_reads=True,
                             readable_paths=[str(readable)]) as run:
            run(["/bin/true"], capture_output=True, timeout=60)


def test_grant_pin_covers_spawn_ladder_demotion(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The demotion ladder is a grant consumer too: when the spawn
    backend dies mid-setup (environmental exception) the plain
    subprocess fallback re-consumes the caller's grants on the HOST
    filesystem — a grant root swapped in that window must refuse with
    the pin violation, not be silently granted to the demoted lane."""
    readable = tmp_path / "readable"
    readable.mkdir()

    class _SwapThenDieRecorder(_SpawnRecorder):
        def __call__(self, cmd: Any, **kw: Any):
            self.calls.append(kw)
            import shutil as _shutil
            _shutil.rmtree(readable)
            readable.mkdir()
            raise RuntimeError("spawn backend down")

    rec = _SwapThenDieRecorder()
    _Driver(monkeypatch, rec)
    with pytest.raises(SandboxSetupError, match="pin violation"):
        with context.sandbox(target=str(tmp_path),
                             restrict_reads=True,
                             readable_paths=[str(readable)]) as run:
            run(["/bin/true"], capture_output=True, timeout=60)


def test_grant_pin_unpinnable_path_that_appears_is_refused(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A readable grant that did NOT resolve at validation and is
    created inside the retry window is a violation (the old snapshot
    semantics, kept): the retry must not consume a grant the
    validation never saw."""
    ghost = tmp_path / "ghost"  # absent at validation

    class _PlantingRecorder(_SpawnRecorder):
        def __call__(self, cmd: Any, **kw: Any):
            if not self.calls:
                ghost.mkdir()
                cp = subprocess.CompletedProcess(cmd, returncode=126,
                                                 stdout="", stderr="")
                cp._setup_status = ("X", "exec failed in tree")
                self.calls.append(kw)
                return cp
            return super().__call__(cmd, **kw)

    rec = _PlantingRecorder()
    _Driver(monkeypatch, rec)
    with pytest.raises(SandboxSetupError, match="pin violation"):
        with context.sandbox(target=str(tmp_path),
                             restrict_reads=True,
                             readable_paths=[str(ghost)]) as run:
            run(["/bin/true"], capture_output=True, timeout=60)


def test_grant_pin_benign_retry_unchanged_and_no_fd_leak(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Differential: a benign M/X retry (no swap) is unaffected by the
    pin, and the held pin fds are released when the call finishes —
    on the success path AND on a refused call."""
    readable = tmp_path / "readable"
    readable.mkdir()

    def _run_once() -> Any:
        rec = _SpawnRecorder([("X", "exec failed in tree")])
        _Driver(monkeypatch, rec)
        with context.sandbox(target=str(tmp_path),
                             restrict_reads=True,
                             readable_paths=[str(readable)]) as run:
            result = run(["/bin/true"], capture_output=True, timeout=60)
        assert result.returncode == 0
        assert len(rec.calls) == 2
        return result

    _run_once()  # warm-up: one-time lazy imports may open fds
    before = set(os.listdir("/proc/self/fd"))
    _run_once()
    after = set(os.listdir("/proc/self/fd"))
    assert len(after - before) == 0, (
        f"fds leaked across a pinned run: {sorted(after - before)}")
