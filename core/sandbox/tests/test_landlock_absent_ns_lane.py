"""The redefined ns-only tier: the spawn backend's Landlock-absent mode.

The unshare-CLI lane (namespaces via the CLI chain, HOST procfs
visible) is deleted; the ns-only tier is now delivered by the modern
fork-based spawn backend running WITHOUT the Landlock layer — full
namespace set, FRESH pid-ns procfs (fail-closed), seccomp, rlimits.
Four properties pinned here:

1. PORT HONESTY — on a Landlock-less host shape, floor-consented
   untrusted work runs on the ported lane and actually GETS the
   isolation the tier declares (live probes: isolated pid namespace,
   fresh procfs), with honest posture stamps; the tier collapses to
   BARE (and consented work refuses) when any promised layer (seccomp,
   the fresh-procfs remount) is unavailable up front.
2. FLOOR-RESOLUTION REACHABILITY — the mode is reachable ONLY via the
   resolved containment floor: run() refuses a ``landlock_required=``
   caller kwarg outright, and an unconsented untrusted call on the
   same host shape refuses instead of engaging the mode.
3. DELETION CONTINUITY — the per-call network-block recheck replaces
   the netns the deleted lane used to give demoted block_network
   calls: Landlock TCP-deny per call, else waiver acceptance, else
   refusal (the construction-time arms, mirrored per call).

(The run-level floor-refusal evidence record is pinned separately in
test_floor_refusal_evidence.py.)
"""

from __future__ import annotations

import logging
import subprocess
import sys

import pytest

from core.sandbox.errors import SandboxFloorError, SandboxSetupError
from core.sandbox.tiers import ContainmentTier

from .capability import requires_userns

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="Linux namespace lanes")


def _seccomp_ok() -> bool:
    from core.sandbox.seccomp import check_seccomp_available
    return check_seccomp_available()


def _fresh_proc_ok() -> bool:
    from core.sandbox.probes import check_pidns_fresh_proc_available
    return check_pidns_fresh_proc_available()


def _emulate_landlock_absent(monkeypatch, *, mount_capable: bool):
    """Patch the availability probes so context routes as on a
    Landlock-less kernel. The spawn backend's own ``_ll_avail``
    (imported from .landlock) is patched too, so the child genuinely
    SKIPS the Landlock install when the mode consents — on a real
    Landlock-less kernel the skip happens for the same reason
    (``check_landlock_available`` is False there without any patch;
    the feature-matrix no-landlock lane runs these tests unpatched-
    equivalent)."""
    from core.sandbox import context as _ctx
    from core.sandbox import landlock as _landlock_mod
    monkeypatch.setattr(_ctx, "check_landlock_available", lambda: False)
    monkeypatch.setattr(_landlock_mod, "check_landlock_available",
                        lambda: False)
    if not mount_capable:
        monkeypatch.setattr(_ctx, "check_mount_available", lambda: False)


def _simulate_ns_capable(monkeypatch):
    """Pin the NAMESPACE-capability probes True for the simulated
    (spawn-stubbed) tests, so the routing under test runs identically
    on degraded feature-matrix lanes (userns denied) — the same
    pattern as test_floor_contract._simulate_capable_host."""
    from core.sandbox import context as _ctx
    from core.sandbox import probes as _probes_mod
    monkeypatch.setattr(_ctx, "check_net_available", lambda: True)
    monkeypatch.setattr(_probes_mod, "check_unshare_engages",
                        lambda flags: (True, ""))


@requires_userns
@pytest.mark.integration
def test_waived_untrusted_runs_ported_lane_with_fresh_procfs(
        tmp_path, monkeypatch, caplog):
    """LL-absent × mount-denied host shape, waiver set: the run lands
    on the PORTED lane live — an isolated pid namespace with a fresh
    procfs — and the posture stamps say so honestly."""
    if not (_seccomp_ok() and _fresh_proc_ok()):
        pytest.skip("ported lane needs libseccomp + the procfs remount")
    from core.sandbox import context as _ctx
    monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
    _emulate_landlock_absent(monkeypatch, mount_capable=False)
    with caplog.at_level(logging.WARNING, logger="core.sandbox.context"):
        try:
            r = _ctx.run_untrusted(
                ["sh", "-c",
                 "cat /proc/1/comm; ls /proc | grep -c '^[0-9]'"],
                target=str(tmp_path), output=str(tmp_path),
                timeout=60, capture_output=True, text=True)
        except SandboxSetupError as e:
            pytest.skip(f"namespace lane unavailable live: {e}")
    assert r.returncode == 0, r.stderr
    comm, pid_count = r.stdout.strip().splitlines()
    # Fresh pid-ns procfs: pid 1 is the sandbox tree's own init (the
    # exec'd shell or the spawn grandchild), never the host init, and
    # the process listing is the sandbox's own handful, not the host
    # table.
    assert comm in ("sh", "python3", "python"), r.stdout
    assert int(pid_count) < 10, r.stdout
    info = r.sandbox_info
    assert info["containment_tier"] == "ns-only"
    assert info["backend"] == "pidns-nomount"
    assert info["fresh_procfs"] is True
    assert info["floor_source"] == "env"
    assert info["mount_ns_active"] is False
    # Posture honesty: the read restriction was REQUESTED
    # (run_untrusted defaults restrict_reads=True) but nothing
    # enforced it on this lane — stamping the request would
    # contradict the tier stamp and defeat the telemetry-key
    # forgery demotion (mac_key_hidden).
    assert info["restrict_reads"] is False
    assert info["read_enforcement"] == "unenforced"
    # The consented-degrade warning names the real exposure (missing
    # Landlock policy), NOT a host-procfs exposure this lane closed.
    waived = [rec.getMessage() for rec in caplog.records
              if "waives the untrusted containment floor" in
              rec.getMessage()]
    assert waived, caplog.text
    assert any("WITHOUT Landlock" in m for m in waived), waived
    assert not any("HOST process table" in m for m in waived), waived


@requires_userns
@pytest.mark.integration
def test_ported_lane_fresh_procfs_is_fail_closed(
        tmp_path, monkeypatch):
    """The tier's fresh-procfs promise is enforced in the child: the
    ported lane passes require_fresh_procfs through to the backend,
    so a runtime remount failure aborts 'F' instead of delivering the
    host view under an ns-only stamp."""
    if not (_seccomp_ok() and _fresh_proc_ok()):
        pytest.skip("ported lane needs libseccomp + the procfs remount")
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
    _emulate_landlock_absent(monkeypatch, mount_capable=False)
    captured: dict = {}
    real = _spawn_mod.run_sandboxed

    def capture(cmd, **kwargs):
        captured.update(kwargs)
        return real(cmd, **kwargs)

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", capture)
    try:
        _ctx.run_untrusted(["true"], target=str(tmp_path),
                           output=str(tmp_path), timeout=60)
    except SandboxSetupError as e:
        pytest.skip(f"namespace lane unavailable live: {e}")
    # The waived call's own contract flag is False (that is what the
    # waiver zeroes) — the LANE's tier promise is what forces the
    # mount.
    assert captured["require_fresh_procfs"] is True
    assert captured["landlock_required"] is False
    assert captured["skip_mount_ns"] is True


def test_ported_lane_forces_fresh_procfs_at_the_backend(
        tmp_path, monkeypatch):
    """Default-tier twin of the live fail-closed probe: the ported
    lane must pass require_fresh_procfs=True to the backend even
    though the waived call's own contract flag is False — a stubbed
    capture, so the guard is exercised on every host and CI tier
    (the live 'F'-abort variant is integration-only and skips on
    userns-less runners)."""
    import subprocess as _subprocess

    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
    _emulate_landlock_absent(monkeypatch, mount_capable=False)
    _simulate_ns_capable(monkeypatch)
    monkeypatch.setattr(_spawn_mod, "mount_ns_available", lambda: True)
    captured: dict = {}

    def ok_spawn(cmd, **kwargs):
        captured.update(kwargs)
        return _subprocess.CompletedProcess(cmd, returncode=0,
                                            stdout="", stderr="")

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", ok_spawn)
    r = _ctx.run_untrusted(["true"], target=str(tmp_path),
                           output=str(tmp_path), timeout=60)
    assert captured["require_fresh_procfs"] is True
    assert captured["landlock_required"] is False
    assert captured["skip_mount_ns"] is True
    assert r.sandbox_info["containment_tier"] == "ns-only"


def test_ported_tier_collapses_without_seccomp(tmp_path, monkeypatch):
    """No libseccomp → the ported lane cannot claim ns-only (the tier
    promises seccomp) → consented-untrusted work refuses at the entry
    contract rather than running at an overstated tier."""
    from core.sandbox import context as _ctx
    monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
    _emulate_landlock_absent(monkeypatch, mount_capable=False)
    _simulate_ns_capable(monkeypatch)
    from core.sandbox import seccomp as _seccomp_mod
    monkeypatch.setattr(_ctx._seccomp, "check_seccomp_available",
                        lambda: False)
    monkeypatch.setattr(_seccomp_mod, "check_seccomp_available",
                        lambda: False)
    with pytest.raises(SandboxSetupError):
        _ctx.run_untrusted(["true"], target=str(tmp_path),
                           output=str(tmp_path), timeout=60)


def test_ported_tier_collapses_without_fresh_procfs_probe(
        tmp_path, monkeypatch):
    """Host refuses the pid-ns procfs remount → the ported lane cannot
    claim ns-only (the tier promises a FRESH procfs) → consented-
    untrusted work refuses instead of running host-procfs-visible
    under an ns-only stamp."""
    from core.sandbox import context as _ctx
    from core.sandbox import probes as _probes_mod
    monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
    _emulate_landlock_absent(monkeypatch, mount_capable=False)
    _simulate_ns_capable(monkeypatch)
    monkeypatch.setattr(_probes_mod, "check_pidns_fresh_proc_available",
                        lambda: False)
    with pytest.raises(SandboxFloorError) as excinfo:
        _ctx.run_untrusted(["true"], target=str(tmp_path),
                           output=str(tmp_path), timeout=60)
    assert excinfo.value.achievable is ContainmentTier.BARE


def test_unwaived_untrusted_refuses_on_landlock_less_shape(
        tmp_path, monkeypatch):
    """No consent → no mode: the same host shape refuses unconsented
    untrusted work (the construction-time enforceability gate, kept),
    and the target never executes."""
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", raising=False)
    _emulate_landlock_absent(monkeypatch, mount_capable=False)
    _simulate_ns_capable(monkeypatch)
    spawns: list = []
    monkeypatch.setattr(
        _spawn_mod, "run_sandboxed",
        lambda cmd, **kw: spawns.append(1))
    with pytest.raises(SandboxSetupError) as excinfo:
        _ctx.run_untrusted(["true"], target=str(tmp_path),
                           output=str(tmp_path), timeout=60)
    assert "Landlock is unavailable" in str(excinfo.value)
    assert not spawns


def test_landlock_required_kwarg_is_refused(tmp_path):
    """Floor-resolution reachability: the backend's mode parameter is
    not part of run()'s surface — a caller kwarg raises instead of
    riding the loose **kwargs into silence (or worse, into the
    backend). Policy-free shape so the TypeError is the FIRST gate on
    every host class (a policy-bearing shape can hit construction
    refusals earlier on degraded hosts)."""
    from core.sandbox import context as _ctx
    with pytest.raises(TypeError) as excinfo:
        _ctx.run(["true"], block_network=False, timeout=30,
                 landlock_required=False)
    assert "landlock_required" in str(excinfo.value)


def test_mode_off_for_unwaived_floor_even_with_mount(
        tmp_path, monkeypatch):
    """LL-absent × mount-CAPABLE: an unwaived untrusted call's floor
    (mount-ns) does not admit the ns-only tier, so the backend is told
    landlock_required=True — on a real Landlock-less kernel the spawn
    then aborts 'L' fail-loud rather than quietly dropping the layer
    (matrix no-landlock lane exercises the real abort)."""
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", raising=False)
    monkeypatch.setattr(_ctx, "check_landlock_available", lambda: False)
    monkeypatch.setattr(_ctx, "check_mount_available", lambda: True)
    monkeypatch.setattr(_spawn_mod, "mount_ns_available", lambda: True)
    _simulate_ns_capable(monkeypatch)
    captured: dict = {}

    def ok_spawn(cmd, **kwargs):
        captured.update(kwargs)
        return subprocess.CompletedProcess(cmd, returncode=0,
                                           stdout="", stderr="")

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", ok_spawn)
    r = _ctx.run_untrusted(["true"], target=str(tmp_path),
                           output=str(tmp_path), timeout=60)
    assert captured["landlock_required"] is True
    assert r.sandbox_info["containment_tier"] == "mount-ns"


def test_trusted_mount_lane_tolerates_landlock_absence(
        tmp_path, monkeypatch):
    """LL-absent × mount-capable × trusted (floor BARE ≤ ns-only): the
    mode engages, the mount lane keeps its MOUNT_NS declaration (the
    bind tree is that tier's filesystem enforcement), and the backend
    is told the absence is floor-consented."""
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", raising=False)
    monkeypatch.setattr(_ctx, "check_landlock_available", lambda: False)
    monkeypatch.setattr(_ctx, "check_mount_available", lambda: True)
    monkeypatch.setattr(_spawn_mod, "mount_ns_available", lambda: True)
    _simulate_ns_capable(monkeypatch)
    captured: dict = {}

    def ok_spawn(cmd, **kwargs):
        captured.update(kwargs)
        return subprocess.CompletedProcess(cmd, returncode=0,
                                           stdout="", stderr="")

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", ok_spawn)
    r = _ctx.run(["true"], target=str(tmp_path), output=str(tmp_path),
                 timeout=60)
    assert captured["landlock_required"] is False
    assert captured["skip_mount_ns"] is False
    # The mount lane's fresh-procfs behaviour is unchanged by the
    # mode (best-effort for trusted work; the 'F' contract stays the
    # caller's flag).
    assert captured["require_fresh_procfs"] is False
    assert r.sandbox_info["containment_tier"] == "mount-ns"


# ------------------------------------------------ deletion continuity

def _trusted_block_network_demotion(monkeypatch, tmp_path, *, abi):
    """Route a trusted block_network call through the spawn-exception
    ladder onto the plain lane, with the Landlock ABI pinned."""
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    from core.sandbox import probes as _probes_mod
    monkeypatch.setattr(_ctx, "check_net_available", lambda: True)
    monkeypatch.setattr(_ctx, "check_mount_available", lambda: True)
    monkeypatch.setattr(_ctx, "check_landlock_available", lambda: True)
    monkeypatch.setattr(_ctx, "_get_landlock_abi", lambda: abi)
    monkeypatch.setattr(_spawn_mod, "mount_ns_available", lambda: True)
    monkeypatch.setattr(_probes_mod, "check_unshare_engages",
                        lambda flags: (True, ""))

    def raising_spawn(cmd, **kwargs):
        raise OSError("forced spawn setup failure")

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", raising_spawn)
    return _ctx


def test_demoted_block_network_gets_percall_tcp_deny(
        tmp_path, monkeypatch, caplog):
    """Continuity for the deleted lane's netns: a trusted
    block_network call whose spawn backend fails per call now lands
    on the plain lane WITH a per-call Landlock TCP-connect deny
    (mirroring the construction-time degraded arm), loudly."""
    from core.sandbox import preexec as _preexec_mod
    from core.sandbox import state
    _ctx = _trusted_block_network_demotion(monkeypatch, tmp_path, abi=4)
    # The "falling back to Landlock TCP-connect deny" WARNING asserted
    # below is once-per-PROCESS (warn_once latch); an earlier demoted
    # call anywhere in the same process — including tests from
    # directories whose conftest doesn't snapshot the sandbox warn-once
    # flags — would eat the once under shuffled orders. Own the latch;
    # this directory's autouse state guard restores the pre-test value.
    state.reset_warn_once("_demoted_tcp_deny_warned")
    built: list[dict] = []
    real_make = _ctx._make_preexec_fn

    def record_make(limits, **kwargs):
        built.append(kwargs)
        return real_make(limits, **kwargs)

    monkeypatch.setattr(_ctx, "_make_preexec_fn", record_make)
    with caplog.at_level(logging.WARNING, logger="core.sandbox.context"):
        r = _ctx.run(["true"], block_network=True, target=str(tmp_path),
                     output=str(tmp_path), timeout=60)
    assert r.returncode == 0
    rebuilds = [k for k in built if k.get("deny_all_tcp_connect")]
    assert rebuilds, "demoted block_network call lost the TCP deny"
    assert all(k.get("seccomp_block_ns_creation") for k in rebuilds), (
        "the demoted rebuild dropped the namespace-creation deny")
    assert any("falling back to Landlock TCP-connect deny for this call"
               in rec.getMessage() for rec in caplog.records), caplog.text
    assert r.sandbox_info["containment_tier"] == "landlock"
    _preexec_mod  # imported for parity with siblings


def test_demoted_block_network_refuses_without_abi4(
        tmp_path, monkeypatch):
    """Same demotion on an ABI<4 kernel with no waiver: no layer can
    enforce the requested block — refuse with the construction arm's
    acceptance levers, exactly as the environmental shape always
    did."""
    monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", raising=False)
    _ctx = _trusted_block_network_demotion(monkeypatch, tmp_path, abi=3)
    with pytest.raises(SandboxSetupError) as excinfo:
        _ctx.run(["true"], block_network=True, target=str(tmp_path),
                 output=str(tmp_path), timeout=60)
    msg = str(excinfo.value)
    assert "no layer can enforce the requested network block" in msg
    assert "degraded_net_deny=False" in msg
    assert "RAPTOR_ALLOW_DEGRADED_UNTRUSTED" in msg


def test_demoted_block_network_percall_optout_still_runs(
        tmp_path, monkeypatch):
    """degraded_net_deny=False is the caller's documented per-call
    "this run may egress" opt-out — honoured on the demoted shape
    exactly as at construction."""
    _ctx = _trusted_block_network_demotion(monkeypatch, tmp_path, abi=3)
    r = _ctx.run(["true"], block_network=True, target=str(tmp_path),
                 output=str(tmp_path), timeout=60,
                 degraded_net_deny=False)
    assert r.returncode == 0
    assert r.sandbox_info["containment_tier"] == "landlock"


def test_unenforced_reads_posture_is_stamped_honestly(
        tmp_path, monkeypatch):
    """Stubbed twin of the live posture assertions (runs on every
    host class): a read-restricted call on a Landlock-less kernel
    without a mount tree must stamp restrict_reads=False +
    read_enforcement="unenforced", and the persisted posture must
    carry mac_key_hidden=False — the child could read the
    telemetry-MAC key, so token-verified telemetry for the run is
    mintable and triage must demote it."""
    import subprocess as _subprocess

    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    from core.sandbox import summary as _summary
    monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
    _emulate_landlock_absent(monkeypatch, mount_capable=False)
    _simulate_ns_capable(monkeypatch)
    monkeypatch.setattr(_spawn_mod, "mount_ns_available", lambda: True)

    def ok_spawn(cmd, **kwargs):
        return _subprocess.CompletedProcess(cmd, returncode=0,
                                            stdout="", stderr="")

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", ok_spawn)
    out = tmp_path / "run"
    out.mkdir()
    r = _ctx.run_untrusted(["true"], target=str(tmp_path),
                           output=str(out), timeout=60)
    assert r.sandbox_info["restrict_reads"] is False
    assert r.sandbox_info["read_enforcement"] == "unenforced"
    posture = _summary.get_run_posture(out)
    assert posture is not None
    assert posture["mac_key_hidden"] is False


def test_trusted_tolerance_bite_warns_once(tmp_path, monkeypatch, caplog):
    """A TRUSTED call that requested filesystem policy and rides the
    tolerance mode without a mount tree must not degrade silently:
    one warning per process names the unenforced policy (the waived
    class gets its own per-call warning instead). Shape: mount-capable
    host (so the construction-time enforceability gate does not own
    the refusal) with a per-call skip_mount_ns — the mountless route
    with an output write policy nothing can enforce."""
    import subprocess as _subprocess

    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    from core.sandbox import state
    monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", raising=False)
    _emulate_landlock_absent(monkeypatch, mount_capable=True)
    _simulate_ns_capable(monkeypatch)
    monkeypatch.setattr(_ctx, "check_mount_available", lambda: True)
    monkeypatch.setattr(_spawn_mod, "mount_ns_available", lambda: True)
    state.reset_warn_once("_tolerated_policy_unenforced_warned")

    def ok_spawn(cmd, **kwargs):
        return _subprocess.CompletedProcess(cmd, returncode=0,
                                            stdout="", stderr="")

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", ok_spawn)
    out = tmp_path / "out"
    out.mkdir()
    with caplog.at_level(logging.WARNING, logger="core.sandbox.context"):
        r = _ctx.run(["true"], block_network=True, output=str(out),
                     skip_mount_ns=True, timeout=60)
    assert r.returncode == 0
    assert r.sandbox_info["containment_tier"] == "ns-only"
    assert any("policy" in rec.getMessage()
               and "NOT" in rec.getMessage()
               for rec in caplog.records), caplog.text


@pytest.mark.integration
def test_demoted_block_network_deny_covers_audit_mode(
        tmp_path, monkeypatch):
    """The audit fallback builds its own preexecs, so the per-call
    demoted TCP deny must ride them too — pre-fix an audit-mode
    demoted block_network call connected freely while the demotion
    warning claimed EACCES. Live: a child TCP-connect to a real
    listener must fail under the deny."""
    import socket
    import textwrap

    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    from core.sandbox.landlock import (
        _get_landlock_abi,
        check_landlock_available,
    )
    from core.sandbox.ptrace_probe import check_ptrace_available
    from core.sandbox.seccomp import check_seccomp_available
    if not (check_landlock_available() and _get_landlock_abi() >= 4):
        pytest.skip("needs Landlock ABI v4+ for the TCP deny")
    if not (check_seccomp_available() and check_ptrace_available()):
        pytest.skip("audit lane needs libseccomp + ptrace")

    def raising_spawn(cmd, **kwargs):
        raise OSError("forced spawn setup failure")

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", raising_spawn)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        code = textwrap.dedent(f"""
            import socket
            s = socket.socket()
            try:
                s.connect(("127.0.0.1", {port}))
                print("CONNECT-OK")
            except OSError as e:
                print("CONNECT-ERR", e.errno)
        """)
        out = tmp_path / "run"
        out.mkdir()
        r = _ctx.run(["/usr/bin/python3", "-c", code],
                     block_network=True, target=str(tmp_path),
                     output=str(out), audit=True,
                     capture_output=True, text=True, timeout=60)
    finally:
        srv.close()
    assert r.returncode == 0, r.stderr
    assert "CONNECT-OK" not in r.stdout, (
        "audit-mode demoted block_network call escaped the per-call "
        "TCP deny")
    # errno 13 (EACCES): specifically the Landlock connect deny, not
    # an unrelated network failure shape.
    assert "CONNECT-ERR 13" in r.stdout, r.stdout
