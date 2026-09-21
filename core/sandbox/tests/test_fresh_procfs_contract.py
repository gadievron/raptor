"""The fresh-procfs contract and the spawn chain's environ hygiene.

Three properties, each independently load-bearing:

1. The grandchild's fresh /proc mount happens BEFORE Landlock installs
   (a landlocked process is denied every mount(2) topology change, so
   the reverse order silently left the host-pid procfs bind visible to
   the target on every Landlock-capable host).
2. Untrusted runs refuse the degraded host-procfs posture (status byte
   'F') unless the operator explicitly accepts it.
3. The spawn chain's un-exec'd forks scrub the sensitive values from
   their inherited environ image — the image is the orchestrator's
   full pre-strip environment, and same-userns readers pass the
   kernel's ptrace gate on any lane where host procfs stays visible.
"""

import os
import subprocess
import sys
import textwrap
import threading
import time
import types
from pathlib import Path

import pytest

from .capability import requires_landlock

_REPO_ROOT = Path(__file__).resolve().parents[3]


# ---------------------------------------------------------- unit tier

def test_f_status_byte_roundtrip():
    from core.sandbox._spawn import _parse_setup_status
    parsed = _parse_setup_status(b"F:fresh procfs mount failed")
    assert parsed == ("F", "fresh procfs mount failed")


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="scrubs the /proc/self/environ image — Linux procfs only",
)
def test_scrub_env_image_values_zeroes_only_named_values():
    """The helper zeroes the named variables' VALUES in the execve-time
    environ image (what /proc/<pid>/environ serves) and touches nothing
    else. Runs in a subprocess so the image is fully controlled."""
    code = textwrap.dedent("""
        import os, sys
        sys.path.insert(0, %r)
        from core.sandbox._spawn import _scrub_env_image_values
        _scrub_env_image_values((b"SCRUB_ME", b"SCRUB_ME_TOO"))
        img = open("/proc/self/environ", "rb").read()
        entries = [e for e in img.split(b"\\0") if e]
        by_name = dict(e.split(b"=", 1) for e in entries if b"=" in e)
        assert by_name[b"SCRUB_ME"].strip(b"\\0") == b"", by_name[b"SCRUB_ME"]
        assert by_name[b"SCRUB_ME_TOO"].strip(b"\\0") == b""
        assert by_name[b"KEEP_ME"] == b"keep-value"
        # PATH must survive untouched — libc consumers keep working.
        assert by_name.get(b"PATH"), "PATH was damaged by the scrub"
        print("scrub-ok")
    """) % str(_REPO_ROOT)
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "SCRUB_ME": "secret-one",
        "SCRUB_ME_TOO": "secret-two",
        "KEEP_ME": "keep-value",
        "RAPTOR_DIR": str(_REPO_ROOT),
    }
    r = subprocess.run(
        [sys.executable, "-c", code], env=env,
        capture_output=True, text=True, timeout=60, check=False,
    )
    assert r.returncode == 0, r.stderr
    assert "scrub-ok" in r.stdout


def test_scrub_names_cover_credentials_and_provider_keys():
    """Source pin: the pre-fork scrub-name computation covers the
    target strip set, the LLM provider credentials, RAPTOR_DIR, and —
    derived from the canonical credential vocabulary, not hand-typed —
    the credential-bearing tier (the first-party session credentials
    live there; the enumerated LLM_API_KEY_VARS list misses them)."""
    src = (_REPO_ROOT / "core" / "sandbox" / "_spawn.py").read_text(
        encoding="utf-8")
    import_at = src.index(
        "from core.security.credential_env import",
        src.index("def run_sandboxed"))
    block = src[import_at:][:2600]
    assert "CREDENTIAL_BEARING_ENV_VARS" in block
    assert "is_credential_shaped" in block
    assert "/proc/self/environ" in block
    assert "_env_image_scrub_names = tuple" in block
    assert "TARGET_ENV_STRIP_SET" in block
    assert "LLM_API_KEY_VARS" in block
    assert '"RAPTOR_DIR"' in block


def test_layer_install_ordering_source_pin():
    """Source pin: Landlock/seccomp install in the GRANDCHILD after the
    fresh /proc mount; the pre-fork child block no longer calls them.
    A landlocked process cannot mount, so any regression of this order
    reintroduces the host-procfs-visible degrade on every spawn."""
    src = (_REPO_ROOT / "core" / "sandbox" / "_spawn.py").read_text(
        encoding="utf-8")
    grand = src.index("if grand == 0:")
    mount_at = src.index('b"proc", b"/proc", b"proc"', grand)
    landlock_at = src.index("landlock_fn()", grand)
    seccomp_at = src.index("seccomp_fn()", grand)
    assert grand < mount_at < landlock_at < seccomp_at, (
        "fresh-proc mount must precede Landlock/seccomp install in the "
        "grandchild")
    # No install calls anywhere before the grandchild branch (the old
    # child-side step 10/11 block).
    pre_fork_region = src[:grand]
    assert "landlock_fn()" not in pre_fork_region
    assert "seccomp_fn()" not in pre_fork_region


def test_branded_tmp_regex_copies_in_sync():
    """The branded-temp matcher exists in context.py AND mount_ns.py
    (the mount-ns child cannot import context) — a drift between them
    re-opens either the env value or the replanted directory name."""
    ctx = (_REPO_ROOT / "core" / "sandbox" / "context.py").read_text(
        encoding="utf-8")
    mns = (_REPO_ROOT / "core" / "sandbox" / "mount_ns.py").read_text(
        encoding="utf-8")
    import re as _re
    pat = _re.compile(r"_BRANDED_TMP_RE = re\.compile\((.+)\)")
    m_ctx = pat.search(ctx)
    m_mns = pat.search(mns)
    assert m_ctx and m_mns, "matcher missing from one of the copies"
    assert m_ctx.group(1) == m_mns.group(1), (
        "context.py and mount_ns.py branded-temp matchers drifted")


# --------------------------------------------------- integration tier

def _run_untrusted_or_skip(cmd, tmp_path, **kw):
    from core.sandbox import context as _ctx
    from core.sandbox.errors import SandboxSetupError
    try:
        result = _ctx.run_untrusted(
            cmd, target=str(tmp_path), output=str(tmp_path),
            timeout=kw.pop("timeout", 90), **kw,
        )
    except SandboxSetupError as e:
        # Derives from BaseException by design — the bare Exception
        # arm below never catches it, which on mount-ns-less hosts
        # turned these into failures instead of skips.
        pytest.skip(f"sandbox unavailable: {e}")
    except Exception as e:  # noqa: BLE001 — host without userns etc.
        pytest.skip(f"sandbox unavailable: {e}")
    if getattr(result, "returncode", 1) != 0:
        pytest.skip(f"sandboxed child did not run: rc="
                    f"{getattr(result, 'returncode', None)}")
    return result


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_untrusted_procfs_is_pid_ns_local(tmp_path):
    """Inside run_untrusted the target sees a pid-ns-local /proc: a
    handful of pids, itself as pid 1, and the seccomp layer active —
    NOT the host process table."""
    marker = tmp_path / "probe-out"
    _run_untrusted_or_skip(
        ["sh", "-c",
         "{ ls /proc | grep -c '^[0-9]'; echo $$; "
         "grep -E '^(Seccomp|NoNewPrivs):' /proc/self/status; } > "
         f"{marker}"],
        tmp_path,
    )
    if not marker.exists():
        pytest.skip("probe produced no output")
    lines = marker.read_text(encoding="utf-8").split()
    pid_count, self_pid = int(lines[0]), int(lines[1])
    assert pid_count <= 8, (
        f"{pid_count} pids visible in /proc — host procfs is leaking "
        f"into the untrusted sandbox (fresh proc mount regressed?)")
    # pid-ns-local pid 2: PID 1 is the in-ns init waiter (the target
    # must not be pid-1, or the kernel's pid-1 signal filter distorts
    # its crash identities).
    assert self_pid == 2
    joined = " ".join(lines)
    assert "NoNewPrivs: 1" in joined
    assert "Seccomp: 2" in joined, (
        "seccomp filter not active in the target — the grandchild "
        "install path regressed")


def _decoy_value() -> str:
    # Unique per test run: another session running this same suite on
    # a shared host must not cross-match our watcher or payloads.
    import uuid
    return f"chain-scrub-decoy-{uuid.uuid4().hex[:12]}"


def _drive_run_in_subprocess(tmp_path, beacon_name, payload_sh,
                             decoy_value="chain-scrub-decoy",
                             timeout=120, extra_env=None):
    """Launch run_untrusted from a SUBPROCESS whose execve-time env
    carries the decoy credential and a beacon marker.

    The environ IMAGE (/proc/<pid>/environ) is fixed at execve —
    ``monkeypatch.setenv`` only mutates the heap copy — so a valid
    reproduction of the leak needs the decoy in the driver's execve
    env, exactly where a real orchestrator's credential lives.
    """
    driver = textwrap.dedent("""
        import os, sys
        sys.path.insert(0, os.environ["RAPTOR_DIR"])
        from core.sandbox.context import run_untrusted
        r = run_untrusted(
            ["sh", "-c", %r],
            target=%r, output=%r, cwd=%r, timeout=90,
            capture_output=True, text=True,
        )
        print("RC=%%d" %% r.returncode)
    """) % (payload_sh, str(tmp_path), str(tmp_path), str(tmp_path))
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "RAPTOR_DIR": str(_REPO_ROOT),
        beacon_name: "1",
        "RAPTOR_SESSION_TOKEN": decoy_value,
    }
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [sys.executable, "-c", driver], env=env,
        capture_output=True, text=True, timeout=timeout, check=False,
    )


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_untrusted_cannot_read_spawn_chain_credentials(tmp_path):
    """End-to-end for the audit's headline channel: with a decoy
    session credential in the ORCHESTRATOR'S execve env, no environ
    readable from inside the sandbox carries its value."""
    marker = tmp_path / "hunt-out"
    decoy = _decoy_value()
    payload = (
        "hits=0; for d in /proc/[0-9]*; do "
        "tr '\\0' '\\n' < $d/environ 2>/dev/null "
        f"| grep -q {decoy} && hits=$((hits+1)); done; "
        f"echo $hits > {marker}"
    )
    r = _drive_run_in_subprocess(tmp_path, "SBX_HUNT_BEACON", payload,
                                 decoy_value=decoy)
    if "RC=0" not in r.stdout:
        pytest.skip(f"sandbox unavailable: {r.stdout} {r.stderr[-300:]}")
    if not marker.exists():
        pytest.skip("probe produced no output")
    assert marker.read_text(encoding="utf-8").strip() == "0", (
        "a sandboxed payload can read the session credential out of a "
        "spawn-chain process's environ image")


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_spawn_chain_environ_image_is_scrubbed(tmp_path):
    """Mid-run, every beacon-carrying process inside a FOREIGN user
    namespace (= the class a sandboxed same-userns reader could reach)
    must show a ZEROED session-token value in its /proc/<pid>/environ.

    Carriers still in OUR user namespace are excluded: the driver
    itself, pre-unshare setup-child snapshots, and transient
    capability-probe forks are only readable here because this test
    runs unsandboxed — a sandboxed payload is denied their environ by
    the kernel's cross-userns ptrace gate, so they are out of scope
    for the scrub (which runs immediately AFTER unshare, before the
    process becomes same-userns-readable to any target)."""
    import uuid
    beacon = f"SBX_CHAIN_SCRUB_BEACON_{uuid.uuid4().hex[:8].upper()}"
    decoy = _decoy_value()
    my_userns = os.readlink("/proc/self/ns/user")
    seen: dict[str, tuple[str, bytes]] = {}
    stop = threading.Event()

    def watcher() -> None:
        me = str(os.getpid())
        while not stop.is_set():
            for pid in os.listdir("/proc"):
                if not pid.isdigit() or pid == me:
                    continue
                try:
                    with open(f"/proc/{pid}/environ", "rb") as f:
                        img = f.read()
                    userns = os.readlink(f"/proc/{pid}/ns/user")
                except OSError:
                    continue
                if beacon.encode() + b"=1" in img:
                    # Keep the LAST snapshot per pid — the scrub runs
                    # moments after fork+unshare.
                    seen[pid] = (userns, img)
            time.sleep(0.005)

    t = threading.Thread(target=watcher)
    t.start()
    try:
        r = _drive_run_in_subprocess(
            tmp_path, beacon, "sleep 1.5", decoy_value=decoy,
            timeout=150)
    finally:
        stop.set()
        t.join()
    if "RC=0" not in r.stdout:
        pytest.skip(f"sandbox unavailable: {r.stdout} {r.stderr[-300:]}")
    foreign = {pid: img for pid, (ns, img) in seen.items()
               if ns != my_userns}
    if not foreign:
        pytest.skip("no foreign-userns chain process observed")
    leaky = sorted(pid for pid, img in foreign.items()
                   if b"RAPTOR_SESSION_TOKEN=" + decoy.encode() in img)
    assert not leaky, (
        f"spawn-chain forks readable from inside the sandbox still "
        f"publish the session credential: {leaky}")
    for img in foreign.values():
        assert b"RAPTOR_SESSION_TOKEN=" in img, (
            "scrub should empty the value, not remove the name")


_FORCED_MOUNT_FAIL_PRELUDE = """
import ctypes, os, sys
sys.path.insert(0, os.environ["RAPTOR_DIR"])
_real_CDLL = ctypes.CDLL
class _FakeLibc:
    def __init__(self, real): self._r = real
    def __getattr__(self, n): return getattr(self._r, n)
    def __getitem__(self, k): return self._r[k]
    def mount(self, *a):
        # Refuse exactly the fresh-proc mount; everything else passes
        # through (persona re-binds use an fd-path source).
        if a and a[0] == b"proc":
            return -1
        return self._r.mount(*a)
def _patched(name=None, *a, **k):
    real = _real_CDLL(name, *a, **k)
    return _FakeLibc(real) if (name is None or "libc" in str(name)) else real
ctypes.CDLL = _patched
"""


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_fresh_procfs_failure_aborts_untrusted_run(tmp_path):
    """A forced fresh-proc mount failure ABORTS the untrusted run with
    the typed SandboxSetupError (status byte 'F') — and proceeds
    warn-only under the documented operator override. The failure is
    injected by a fork-inherited CDLL wrapper that refuses exactly the
    proc mount, so the whole real spawn chain runs."""
    driver = _FORCED_MOUNT_FAIL_PRELUDE + textwrap.dedent("""
        from core.sandbox.context import run_untrusted
        from core.sandbox.errors import SandboxSetupError
        try:
            r = run_untrusted(["true"], target=%r, output=%r, cwd=%r,
                              timeout=90, capture_output=True, text=True)
            print("NO-RAISE rc=%%d" %% r.returncode)
            if r.returncode != 0:
                # A degraded run that then FAILS is otherwise a bare
                # returncode: every sandbox fail-closed site writes a
                # one-line reason to the child's stderr — surface it so
                # a runner-only failure is diagnosable from the CI log.
                print("CHILD-STDERR:",
                      (r.stderr or "")[-400:].replace("\\n", " | "))
        except SandboxSetupError as e:
            print("RAISED:", str(e)[:120].replace("\\n", " "))
    """) % (str(tmp_path), str(tmp_path), str(tmp_path))
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "RAPTOR_DIR": str(_REPO_ROOT),
    }
    r = subprocess.run([sys.executable, "-c", driver], env=env,
                       capture_output=True, text=True, timeout=150,
                       check=False)
    if r.returncode != 0:
        pytest.skip(f"driver failed: {r.stderr[-300:]}")
    if "NO-RAISE" in r.stdout and "RAISED" not in r.stdout:
        # Mount-ns lane not taken at all on this host — nothing to test.
        pytest.skip(f"forced failure did not reach the spawn lane: "
                    f"{r.stdout}")
    assert "RAISED: sandbox fresh-procfs mount failed" in r.stdout, (
        f"untrusted run survived a fresh-procfs failure: {r.stdout}")

    env["RAPTOR_ALLOW_DEGRADED_UNTRUSTED"] = "1"
    r = subprocess.run([sys.executable, "-c", driver], env=env,
                       capture_output=True, text=True, timeout=150,
                       check=False)
    if r.returncode != 0:
        pytest.skip(f"override driver failed: {r.stderr[-300:]}")
    assert "NO-RAISE rc=0" in r.stdout, (
        f"operator override did not restore the warn-only degrade: "
        f"{r.stdout}")


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_require_fresh_procfs_reaches_the_spawn_layer(tmp_path, monkeypatch):
    """run_untrusted passes require_fresh_procfs=True to run_sandboxed
    by default, False under the documented operator override."""
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    captured: list[dict] = []
    real = _spawn_mod.run_sandboxed

    def recorder(cmd, **kwargs):
        captured.append(kwargs)
        return real(cmd, **kwargs)

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", recorder)
    monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", raising=False)
    try:
        _ctx.run_untrusted(["true"], target=str(tmp_path),
                           output=str(tmp_path), timeout=90)
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"sandbox unavailable: {e}")
    if not captured:
        pytest.skip("mount-ns spawn path not taken on this host")
    assert captured[-1].get("require_fresh_procfs") is True

    captured.clear()
    monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
    try:
        _ctx.run_untrusted(["true"], target=str(tmp_path),
                           output=str(tmp_path), timeout=90)
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"sandbox unavailable under override: {e}")
    if not captured:
        pytest.skip("mount-ns spawn path not taken on this host")
    assert captured[-1].get("require_fresh_procfs") is False


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_mount_ns_failure_refuses_mountless_untrusted_without_opt_in(
        tmp_path, monkeypatch):
    """Untrusted work does not lose bind-tree isolation automatically."""
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    from core.sandbox.errors import SandboxSetupError
    calls = []

    def fake_spawn(cmd, **kwargs):
        calls.append(kwargs)
        cp = subprocess.CompletedProcess(cmd, returncode=126,
                                         stdout="", stderr="")
        cp._setup_status = ("M", "forced mount-ns failure")
        return cp

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", fake_spawn)
    monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", raising=False)
    with pytest.raises(SandboxSetupError) as excinfo:
        _ctx.run_untrusted(
            ["sh", "-c", "test $$ -eq 1 && test -r /proc/1/status"],
            target=str(tmp_path), output=str(tmp_path), timeout=60,
            capture_output=True, text=True)
    assert len(calls) == 1
    assert calls[0]["skip_mount_ns"] is False
    assert excinfo.value.setup_category == "M"
    assert "RAPTOR_ALLOW_DEGRADED_UNTRUSTED=1" in str(excinfo.value)


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_mount_ns_failure_preserves_trusted_policy_and_tmp_baseline(
        tmp_path, monkeypatch):
    """Trusted fallback keeps the caller's reads and documented /tmp."""
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    calls = []

    def fake_spawn(cmd, **kwargs):
        calls.append(kwargs)
        cp = subprocess.CompletedProcess(cmd, returncode=0,
                                         stdout="", stderr="")
        cp._setup_status = (
            ("M", "forced mount-ns failure")
            if len(calls) == 1 else None)
        return cp

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", fake_spawn)
    try:
        with _ctx.sandbox(
                block_network=True, target=str(tmp_path),
                output=str(tmp_path), restrict_reads=False) as run:
            result = run(["true"], timeout=60)
    except (pytest.skip.Exception, pytest.fail.Exception):
        raise
    except Exception as exc:  # noqa: BLE001 - host capability gate
        pytest.skip(f"mount-ns lane unavailable: {exc}")
    assert result.returncode == 0
    assert len(calls) == 2
    assert calls[0]["restrict_reads"] is False
    assert calls[1]["restrict_reads"] is False
    assert "/tmp" in calls[1]["writable_paths"]
    # context.sandbox() already scrubbed the caller environment. The lower
    # backend must not strip wrapper-owned environment values a second time.
    assert calls[1]["strict_env"] is False


@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_read_restricted_mountless_retry_and_cache_use_private_scratch(
        tmp_path, monkeypatch, caplog):
    """Every host-visible namespace lane replaces shared temporary grants."""
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    from core.sandbox import state as _state
    calls = []

    def fake_spawn(cmd, **kwargs):
        calls.append(kwargs)
        cp = subprocess.CompletedProcess(cmd, returncode=0,
                                         stdout="", stderr="")
        cp._setup_status = (
            ("M", "forced mount-ns failure")
            if len(calls) == 1 else None)
        return cp

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", fake_spawn)
    # Pin every capability probe the routing consults — the spawn
    # backend is fully faked, so nothing real engages. Without the
    # net (user-namespace foundation) and engagement-gate pins, a
    # userns-denied host computes use_sandbox=False (or refuses at the
    # gate) and never reaches the faked backend this test observes.
    from core.sandbox import probes as _probes
    monkeypatch.setattr(_ctx, "check_net_available", lambda: True)
    monkeypatch.setattr(_probes, "check_unshare_engages",
                        lambda flags: (True, ""))
    monkeypatch.setattr(_ctx, "check_mount_available", lambda: True)
    monkeypatch.setattr(_ctx, "check_landlock_available", lambda: True)
    monkeypatch.setattr(_ctx, "_get_landlock_abi", lambda: 6)
    monkeypatch.setattr(_state, "_speculative_failure_cache", {})
    monkeypatch.setattr(_state, "_mountless_backend_warned", False)
    scratch_paths = []
    with _ctx.sandbox(
            block_network=True, target=str(tmp_path),
            output=str(tmp_path), restrict_reads=True) as run:
        first = run(["true"], timeout=60)
        second = run(["true"], timeout=60)
        assert first.sandbox_info["private_scratch"] is True
        assert second.sandbox_info["private_scratch"] is True

        assert [call["skip_mount_ns"] for call in calls] == [
            False, True, True,
        ]
        for call in calls[1:]:
            scratch = call["env"]["TMPDIR"]
            scratch_paths.append(scratch)
            assert call["env"]["TEMP"] == scratch
            assert call["env"]["TMP"] == scratch
            assert call["writable_paths"][0] == scratch
            assert "/tmp" not in call["writable_paths"]
            assert "/dev/shm" not in call["writable_paths"]
            assert Path(scratch).stat().st_mode & 0o777 == 0o700
        assert scratch_paths[0] != scratch_paths[1]

    assert all(not Path(path).exists() for path in scratch_paths)
    warnings = [
        record for record in caplog.records
        if "bind-tree isolation unavailable" in record.getMessage()
    ]
    assert len(warnings) == 1


@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
@pytest.mark.parametrize("selection", ["outside-bind-tree", "explicit-skip"])
def test_read_restricted_direct_mountless_selection_uses_private_scratch(
        tmp_path, monkeypatch, selection):
    """Every direct mountless selection gets the same private write policy."""
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    from core.sandbox import state as _state
    calls = []

    def fake_spawn(cmd, **kwargs):
        calls.append(kwargs)
        cp = subprocess.CompletedProcess(cmd, returncode=0,
                                         stdout="", stderr="")
        cp._setup_status = None
        return cp

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", fake_spawn)
    # Same probe pinning as the retry/cache test above: the backend is
    # faked, so force the routing probes rather than inherit the host's.
    from core.sandbox import probes as _probes
    monkeypatch.setattr(_ctx, "check_net_available", lambda: True)
    monkeypatch.setattr(_probes, "check_unshare_engages",
                        lambda flags: (True, ""))
    monkeypatch.setattr(_ctx, "check_mount_available", lambda: True)
    monkeypatch.setattr(_ctx, "check_landlock_available", lambda: True)
    monkeypatch.setattr(_ctx, "_get_landlock_abi", lambda: 6)
    if selection == "outside-bind-tree":
        monkeypatch.setattr(
            _ctx, "_cmd_visible_in_mount_tree", lambda *args: False,
        )
    monkeypatch.setattr(_state, "_mountless_backend_warned", False)
    scratch = None
    with _ctx.sandbox(
            block_network=True, target=str(tmp_path),
            output=str(tmp_path), restrict_reads=True) as run:
        result = run(
            ["true"], timeout=60,
            skip_mount_ns=(selection == "explicit-skip"),
        )
        assert result.sandbox_info["private_scratch"] is True
        assert len(calls) == 1
        assert calls[0]["skip_mount_ns"] is True
        scratch = calls[0]["env"]["TMPDIR"]
        assert calls[0]["writable_paths"][0] == scratch
        assert "/tmp" not in calls[0]["writable_paths"]
        assert "/dev/shm" not in calls[0]["writable_paths"]

    assert scratch is not None
    assert not Path(scratch).exists()


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
@pytest.mark.parametrize("restrict_reads", [True, False])
def test_mountless_unwaived_untrusted_refuses_on_abi_below_three(
        tmp_path, monkeypatch, restrict_reads):
    """ABI 1/2 removes the mountless lane from the achievable set for
    untrusted work (no TRUNCATE right — the write policy cannot be
    enforced on a host-visible filesystem). An UNWAIVED untrusted run
    then has no admitted lane left below its mount-tier floor: it is
    refused at the mountless dispatch, category carried, override
    named, exactly one spawn attempt."""
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    from core.sandbox.errors import SandboxFloorError, SandboxSetupError
    calls = []

    def fail_bind(cmd, **kwargs):
        calls.append(kwargs)
        cp = subprocess.CompletedProcess(cmd, returncode=126,
                                         stdout="", stderr="")
        cp._setup_status = ("M", "forced mount-ns failure")
        return cp

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", fail_bind)
    monkeypatch.setattr(_ctx, "check_landlock_available", lambda: True)
    monkeypatch.setattr(_ctx, "_get_landlock_abi", lambda: 2)
    monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", raising=False)
    with pytest.raises(SandboxSetupError) as excinfo:
        _ctx.run_untrusted(
            ["true"], target=str(tmp_path), output=str(tmp_path), timeout=60,
            restrict_reads=restrict_reads,
        )
    assert len(calls) == 1
    assert isinstance(excinfo.value, SandboxFloorError)
    assert excinfo.value.setup_category == "M"
    assert "RAPTOR_ALLOW_DEGRADED_UNTRUSTED" in str(excinfo.value)


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_mountless_waived_untrusted_continues_down_ladder_on_low_abi(
        tmp_path, monkeypatch, caplog):
    """With the waiver set, the same ABI-1/2 host no longer produces a
    refusal ABOVE a reachable weaker lane (the old shape: the mountless
    retry hard-refused while the spawn-exception ladder landed the same
    workload on the unshare-CLI lane under the same waiver). The waived
    run skips the unachievable mountless retry and continues down the
    demotion ladder to a lane its consented floor admits, with the
    per-call consented-degrade warning naming the exposure."""
    import logging as _logging
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    from core.sandbox.errors import SandboxSetupError
    calls = []

    def fail_bind(cmd, **kwargs):
        calls.append(kwargs)
        cp = subprocess.CompletedProcess(cmd, returncode=126,
                                         stdout="", stderr="")
        cp._setup_status = ("M", "forced mount-ns failure")
        return cp

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", fail_bind)
    monkeypatch.setattr(_ctx, "check_landlock_available", lambda: True)
    monkeypatch.setattr(_ctx, "_get_landlock_abi", lambda: 2)
    monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
    with caplog.at_level(_logging.WARNING, logger="core.sandbox.context"):
        try:
            r = _ctx.run_untrusted(
                ["true"], target=str(tmp_path), output=str(tmp_path),
                timeout=60)
        except SandboxSetupError as e:
            if "containment floor" in str(e):
                pytest.fail(f"waived run was refused by the floor: {e}")
            pytest.skip(f"fallback lane unavailable on this host: {e}")
    if r.returncode != 0:
        pytest.skip(f"fallback-lane child failed: rc={r.returncode}")
    # No mountless retry was attempted — the one spawn call is the
    # failed mount attempt; the run continued on the subprocess lane.
    assert len(calls) == 1
    assert "not achievable" in r.sandbox_info.get("mount_ns_degraded", "")
    assert r.sandbox_info["containment_tier"] == "landlock"
    assert any("HOST process table" in rec.getMessage()
               for rec in caplog.records), caplog.text


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_mountless_retry_blocks_home_credentials(tmp_path, monkeypatch):
    """An opted-in read-restricted fallback blocks home credentials."""
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    real_spawn = _spawn_mod.run_sandboxed
    calls = []
    secret = Path.home() / f".raptor_mountless_read_test_{os.getpid()}"
    secret.write_text("SECRET-CREDENTIAL\n")

    def fail_first_bind(cmd, **kwargs):
        calls.append(kwargs)
        if len(calls) == 1:
            cp = subprocess.CompletedProcess(cmd, returncode=126,
                                             stdout="", stderr="")
            cp._setup_status = ("M", "forced mount-ns failure")
            return cp
        return real_spawn(cmd, **kwargs)

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", fail_first_bind)
    monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
    try:
        try:
            result = _ctx.run_untrusted(
                ["cat", str(secret)], target=str(tmp_path),
                output=str(tmp_path), timeout=60,
                capture_output=True, text=True)
        except Exception as exc:  # noqa: BLE001 - host capability gate
            pytest.skip(f"mount-ns lane unavailable: {exc}")
        assert len(calls) == 2
        assert calls[1]["restrict_reads"] is True
        assert result.returncode != 0
        assert "SECRET-CREDENTIAL" not in result.stdout
        assert result.sandbox_info["restrict_reads"] is True
        assert result.sandbox_info["mount_ns_active"] is False
    finally:
        secret.unlink(missing_ok=True)


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_secure_namespace_retry_fails_closed(tmp_path, monkeypatch):
    """The target never runs when the reduced backend cannot engage."""
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    from core.sandbox.errors import SandboxSetupError
    calls = []

    def fake_spawn(cmd, **kwargs):
        calls.append(kwargs)
        cp = subprocess.CompletedProcess(cmd, returncode=126,
                                         stdout="", stderr="")
        cp._setup_status = (
            "M" if len(calls) == 1 else "F",
            "forced setup failure",
        )
        return cp

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", fake_spawn)
    with pytest.raises(SandboxSetupError) as excinfo:
        with _ctx.sandbox(
                block_network=True, target=str(tmp_path),
                output=str(tmp_path), restrict_reads=False) as run:
            run(["true"], timeout=60)
    assert excinfo.value.setup_category == "F"
    assert [call["skip_mount_ns"] for call in calls] == [False, True]


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_exec_failure_refusal_carries_setup_category(tmp_path, monkeypatch):
    """The fresh-procfs refusal on an in-sandbox exec failure ('X'
    status — e.g. ETXTBSY on the target's own execve) exposes the
    category STRUCTURALLY (SandboxSetupError.setup_category), so a
    retry-capable consumer (zkpox reproduce) can tell "the sandbox
    engaged and the target never exec'd" from "isolation could not
    engage" without parsing message text."""
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    from core.sandbox.errors import SandboxSetupError

    def fake_spawn(cmd, **kwargs):
        cp = subprocess.CompletedProcess(cmd, returncode=126,
                                         stdout="", stderr="")
        cp._setup_status = ("X", "exec: [ETXTBSY] Text file busy")
        return cp

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", fake_spawn)
    monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", raising=False)
    try:
        with pytest.raises(SandboxSetupError) as excinfo:
            _ctx.run_untrusted(["true"], target=str(tmp_path),
                               output=str(tmp_path), timeout=60)
    except (pytest.skip.Exception, pytest.fail.Exception):
        raise
    except Exception as e:  # noqa: BLE001 — host can't reach the lane
        pytest.skip(f"mount-ns lane unavailable: {e}")
    assert excinfo.value.setup_category == "X"
    assert "ETXTBSY" in str(excinfo.value)


def _make_ladder_exc(shape: str) -> BaseException:
    """One representative exception per arm of context.py's mid-setup
    spawn-exception ladder (the environmental ``except`` around
    ``_spawn.run_sandboxed``)."""
    from core.sandbox.errors import SandboxSetupError
    if shape == "filenotfound":
        return FileNotFoundError("newuidmap: no such file or directory")
    if shape == "oserror":
        return OSError("libc soname absent (ctypes.CDLL)")
    if shape == "runtimeerror":
        return RuntimeError("userns refused at runtime")
    assert shape == "setup-category-u"
    return SandboxSetupError(
        "spawn child died at its unshare stage",
        "environment hint", setup_category="U")


def _untrusted_lane_or_skip(
        ctx_mod: "types.ModuleType", spawn_mod: "types.ModuleType",
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Pre-flight: prove run_untrusted() reaches the spawn dispatch on
    this host (probes, entry gates) with a stubbed-successful backend.
    Any failure here is host environment, not the property under test
    — skip so the gated assertions below stay attributable."""

    def ok_spawn(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, returncode=0,
                                           stdout="", stderr="")

    monkeypatch.setattr(spawn_mod, "run_sandboxed", ok_spawn)
    try:
        r = ctx_mod.run_untrusted(["true"], target=str(tmp_path),
                                  output=str(tmp_path), timeout=60)
    except BaseException as e:  # noqa: BLE001 — includes SandboxSetupError
        pytest.skip(f"untrusted lane unavailable on this host: {e}")
    if r.returncode != 0:
        pytest.skip("untrusted lane pre-flight did not run cleanly")


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
@pytest.mark.parametrize("shape", ["filenotfound", "oserror",
                                   "runtimeerror", "setup-category-u"])
def test_spawn_exception_refuses_landlock_only_for_untrusted(
        tmp_path, monkeypatch, shape):
    """A mid-setup spawn EXCEPTION on an untrusted run must not ride
    the environmental-degradation ladder onto the Landlock-only
    subprocess lane — that lane runs with no pid namespace and the
    HOST /proc visible, the exact posture the fresh-procfs contract
    refuses (the status-byte M/X demotions already refuse; pre-fix the
    exception ladder silently proceeded). All four except-arm shapes
    hit the same chokepoint: the refusal names the operator override,
    chains the original backend failure, and the target never
    executes."""
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    from core.sandbox.errors import SandboxSetupError
    monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", raising=False)
    _untrusted_lane_or_skip(_ctx, _spawn_mod, monkeypatch, tmp_path)

    original = _make_ladder_exc(shape)
    attempts: list[int] = []
    sentinel = tmp_path / "child-ran.marker"

    def raising_spawn(cmd, **kwargs):
        attempts.append(1)
        raise original

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", raising_spawn)
    with pytest.raises(SandboxSetupError) as excinfo:
        _ctx.run_untrusted(["touch", str(sentinel)],
                           target=str(tmp_path), output=str(tmp_path),
                           timeout=60)
    msg = str(excinfo.value)
    assert "RAPTOR_ALLOW_DEGRADED_UNTRUSTED" in msg
    assert "host-pid /proc" in msg
    # The original backend failure stays diagnosable: named in the
    # message AND chained as the cause.
    assert type(original).__name__ in msg
    assert excinfo.value.__cause__ is original
    if shape == "setup-category-u":
        assert excinfo.value.setup_category == "U"
    assert len(attempts) == 1, "expected exactly one spawn attempt"
    assert not sentinel.exists(), (
        "the refused call must never execute the target")


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_spawn_exception_still_demotes_trusted_runs(
        tmp_path, monkeypatch, caplog):
    """Trusted runs keep the environmental-degradation ladder: a
    mid-setup spawn exception falls back to the Landlock-only
    subprocess lane, loudly (warning + sandbox_info marker), and the
    child actually runs there."""
    import logging as _logging
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    from core.sandbox.errors import SandboxSetupError

    def raising_spawn(cmd, **kwargs):
        raise OSError("forced spawn setup failure")

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", raising_spawn)
    monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", raising=False)
    sentinel = tmp_path / "child-ran.marker"
    with caplog.at_level(_logging.WARNING, logger="core.sandbox.context"):
        try:
            r = _ctx.run(["touch", str(sentinel)], target=str(tmp_path),
                         output=str(tmp_path), timeout=60)
        except SandboxSetupError as e:
            # A refusal from the untrusted gate here would be an
            # over-blocking regression, never a skip.
            assert "untrusted run" not in str(e), str(e)
            pytest.skip(f"Landlock-only lane unavailable: {e}")
        except Exception as e:  # noqa: BLE001 — host can't reach the lane
            pytest.skip(f"Landlock-only lane unavailable: {e}")
    if r.returncode != 0:
        pytest.skip(f"legacy lane child failed on this host: "
                    f"rc={r.returncode}")
    assert sentinel.exists(), "trusted demoted child did not run"
    assert r.sandbox_info.get("mount_ns_degraded") == (
        "spawn setup failed: forced spawn setup failure")
    assert any("falling back to Landlock-only" in rec.getMessage()
               for rec in caplog.records), caplog.text


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
@requires_landlock
def test_spawn_exception_optin_keeps_degraded_lane_for_untrusted(
        tmp_path, monkeypatch):
    """RAPTOR_ALLOW_DEGRADED_UNTRUSTED=1 is exactly the consent the
    refusal names: with it set, the same spawn exception demotes the
    untrusted run onto the plain Landlock-only lane (the frozen waiver
    floor). Positive control for the refusal test: the child really
    runs there and really sees the HOST /proc — the exposure the
    override consents to. Same observable contract the deleted
    unshare-CLI fallback used to satisfy (its pid-ns never remounted
    /proc either). requires_landlock: on a Landlock-less kernel the
    plain lane delivers nothing the waived floor accepts, so this
    shape correctly refuses there."""
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    from core.sandbox.errors import SandboxSetupError

    def raising_spawn(cmd, **kwargs):
        raise RuntimeError("userns refused at runtime")

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", raising_spawn)
    monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
    try:
        r = _ctx.run_untrusted(["cat", "/proc/1/comm"],
                               target=str(tmp_path),
                               output=str(tmp_path), timeout=60,
                               capture_output=True, text=True)
    except SandboxSetupError as e:
        pytest.fail(f"opted-in untrusted run was refused: {e}")
    except Exception as e:  # noqa: BLE001 — host can't reach the lane
        pytest.skip(f"legacy lane unavailable: {e}")
    if r.returncode != 0:
        pytest.skip(f"fallback-lane child failed on this host: "
                    f"rc={r.returncode}")
    host_init = Path("/proc/1/comm").read_text()
    assert r.stdout == host_init, (
        "the opted-in fallback lane is expected to expose the host-pid "
        "/proc — that is exactly what the override consents to")
    assert r.sandbox_info["containment_tier"] == "landlock"


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_no_mount_ns_host_refuses_untrusted_run(tmp_path):
    """On a host whose mount-ns backend cannot engage, untrusted runs
    fail closed up front (the fallback lanes leave the host-pid /proc
    visible); the override restores the old degrade. Simulated by
    poisoning the mount-ns availability cache in a driver subprocess."""
    driver = textwrap.dedent("""
        import os, sys
        sys.path.insert(0, os.environ["RAPTOR_DIR"])
        from core.sandbox import state
        state._mount_ns_available_cache = False
        from core.sandbox.context import run_untrusted
        from core.sandbox.errors import SandboxSetupError
        try:
            r = run_untrusted(["true"], target=%r, output=%r, cwd=%r,
                              timeout=60, capture_output=True, text=True)
            print("NO-RAISE rc=%%d" %% r.returncode)
        except SandboxSetupError as e:
            print("RAISED:", str(e)[:100].replace("\\n", " "))
    """) % (str(tmp_path), str(tmp_path), str(tmp_path))
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "RAPTOR_DIR": str(_REPO_ROOT),
    }
    r = subprocess.run([sys.executable, "-c", driver], env=env,
                       capture_output=True, text=True, timeout=150,
                       check=False)
    if r.returncode != 0:
        pytest.skip(f"driver failed: {r.stderr[-300:]}")
    assert "RAISED: sandbox run(): the fresh-procfs contract" in r.stdout, (
        f"untrusted run proceeded on a no-mount-ns host: {r.stdout}")

    env["RAPTOR_ALLOW_DEGRADED_UNTRUSTED"] = "1"
    r = subprocess.run([sys.executable, "-c", driver], env=env,
                       capture_output=True, text=True, timeout=150,
                       check=False)
    if r.returncode != 0 or "NO-RAISE" not in r.stdout:
        pytest.skip(f"override lane unavailable: {r.stdout} "
                    f"{r.stderr[-200:]}")
    assert "NO-RAISE rc=0" in r.stdout


@pytest.mark.skipif(sys.platform != "linux", reason="linux-only waiver")
def test_waived_pass_fds_demotion_warns_per_call(
        tmp_path, monkeypatch, caplog):
    """A waived untrusted call carrying pass_fds= lands on the
    subprocess fallback even on a fully capable host — the consented-
    degrade branch of the dispatch floor check must warn on that
    per-call shape, naming the pass_fds demotion and the HOST process
    table exposure. Without the waiver the same shape is refused (the
    refusal path owns the messaging) with the demotion named."""
    import logging as _logging
    from core.sandbox import context as _ctx
    from core.sandbox.errors import SandboxFloorError, SandboxSetupError
    if not (_ctx.check_net_available() and _ctx.check_mount_available()):
        pytest.skip("mount-capable host required for the pass_fds shape")
    _r, _w = os.pipe()
    try:
        monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
        with caplog.at_level(_logging.WARNING,
                             logger="core.sandbox.context"):
            try:
                _ctx.run_untrusted(
                    ["true"], target=str(tmp_path), output=str(tmp_path),
                    timeout=60, pass_fds=[_r])
            except SandboxSetupError as e:
                pytest.skip(f"fallback lane unavailable: {e}")
        assert any("pass_fds" in rec.getMessage()
                   and "HOST process table" in rec.getMessage()
                   for rec in caplog.records), caplog.text

        monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED",
                           raising=False)
        with pytest.raises(SandboxFloorError) as excinfo:
            _ctx.run_untrusted(
                ["true"], target=str(tmp_path), output=str(tmp_path),
                timeout=60, pass_fds=[_r])
        assert "pass_fds" in str(excinfo.value)
        assert "RAPTOR_ALLOW_DEGRADED_UNTRUSTED" in str(excinfo.value)
    finally:
        os.close(_r)
        os.close(_w)


# ------------------------------- environmental use_sandbox=False gate
#
# When the isolation backend cannot engage AT ALL (userns probe
# refused: container default seccomp, Ubuntu 24.04 AppArmor sysctl,
# missing uidmap; sandbox-exec smoke-test failure on macOS),
# `use_sandbox` computes False and every OTHER fresh-procfs gate —
# all guarded by `use_sandbox` — goes quiet. These tests pin the
# environmental gate that refuses instead, and the three flows it
# must NOT touch (opt-in, trusted, operator-disabled). Hermetic: the
# environment is simulated at the probe seam (context.py's
# module-level wrapper indirection exists exactly for this patch
# point), no real namespace work.


@pytest.mark.skipif(sys.platform != "linux", reason="linux probe seam")
def test_environmental_no_sandbox_refuses_fresh_procfs_contract(
        tmp_path, monkeypatch):
    """A run carrying the resolved fresh-procfs contract on an
    environmentally userns-less host must refuse up front — pre-fix
    it proceeded on the plain-subprocess lane with the HOST process
    table visible behind a once-per-process warning. The refusal
    names the override, and neither the spawn backend nor the target
    ever runs."""
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    from core.sandbox.errors import SandboxSetupError
    monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", raising=False)
    monkeypatch.setattr(_ctx, "check_net_available", lambda: False)

    # Pre-flight: the same shape WITHOUT the contract flag must run on
    # this host (plain-subprocess lane) — otherwise a refusal below
    # would be unattributable to the gate under test.
    try:
        pre = _ctx.run(["true"], target=str(tmp_path),
                       output=str(tmp_path), timeout=60)
    except BaseException as e:  # noqa: BLE001 — includes SandboxSetupError
        pytest.skip(f"degraded lane unavailable on this host: {e}")
    if pre.returncode != 0:
        pytest.skip("degraded-lane pre-flight did not run cleanly")

    spawn_attempts: list[int] = []

    def counting_spawn(cmd, **kwargs):
        spawn_attempts.append(1)
        return subprocess.CompletedProcess(cmd, returncode=0,
                                           stdout="", stderr="")

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", counting_spawn)
    sentinel = tmp_path / "child-ran.marker"
    with pytest.raises(SandboxSetupError) as excinfo:
        _ctx.run(["touch", str(sentinel)], target=str(tmp_path),
                 output=str(tmp_path), timeout=60,
                 require_fresh_procfs=(
                     _ctx.untrusted_fresh_procfs_required()))
    msg = str(excinfo.value)
    assert "fresh-procfs contract" in msg
    assert "HOST process table" in msg
    assert "RAPTOR_ALLOW_DEGRADED_UNTRUSTED" in msg
    assert not spawn_attempts, "the refused call reached the spawn backend"
    assert not sentinel.exists(), (
        "the refused call must never execute the target")


@pytest.mark.skipif(sys.platform != "linux", reason="linux probe seam")
def test_environmental_no_sandbox_optin_keeps_degraded_lane(
        tmp_path, monkeypatch, caplog):
    """RAPTOR_ALLOW_DEGRADED_UNTRUSTED=1 is exactly the consent the
    refusal names: the helper resolves the contract flag to False, no
    gate fires, and the run proceeds on the degraded lane behind the
    existing once-per-process warning (text pinned)."""
    import logging as _logging
    from core.sandbox import context as _ctx
    from core.sandbox import state
    from core.sandbox.errors import SandboxSetupError
    monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
    monkeypatch.setattr(_ctx, "check_net_available", lambda: False)
    monkeypatch.setattr(state, "_sandbox_unavailable_warned", False)
    sentinel = tmp_path / "child-ran.marker"
    with caplog.at_level(_logging.WARNING, logger="core.sandbox.context"):
        try:
            r = _ctx.run(["touch", str(sentinel)], target=str(tmp_path),
                         output=str(tmp_path), timeout=60,
                         require_fresh_procfs=(
                             _ctx.untrusted_fresh_procfs_required()))
        except SandboxSetupError as e:
            if "fresh-procfs" in str(e):
                pytest.fail(f"opted-in run was refused: {e}")
            pytest.skip(f"degraded lane unavailable on this host: {e}")
    if r.returncode != 0:
        pytest.skip(f"degraded-lane child failed on this host: "
                    f"rc={r.returncode}")
    assert sentinel.exists(), "opted-in degraded child did not run"
    assert any(
        rec.getMessage() == "Sandbox unavailable — subprocesses run "
                            "without namespace isolation"
        for rec in caplog.records), caplog.text


@pytest.mark.skipif(sys.platform != "linux", reason="linux probe seam")
def test_environmental_no_sandbox_trusted_flow_unchanged(
        tmp_path, monkeypatch):
    """A trusted run (contract flag absent) on the same userns-less
    host keeps today's degrade-with-warning behavior — the gate keys
    on the resolved flag, not on the environment."""
    from core.sandbox import context as _ctx
    from core.sandbox.errors import SandboxSetupError
    monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", raising=False)
    monkeypatch.setattr(_ctx, "check_net_available", lambda: False)
    sentinel = tmp_path / "child-ran.marker"
    try:
        r = _ctx.run(["touch", str(sentinel)], target=str(tmp_path),
                     output=str(tmp_path), timeout=60)
    except SandboxSetupError as e:
        if "fresh-procfs" in str(e):
            pytest.fail(f"trusted run was refused by the untrusted "
                        f"gate: {e}")
        pytest.skip(f"degraded lane unavailable on this host: {e}")
    if r.returncode != 0:
        pytest.skip(f"degraded-lane child failed: rc={r.returncode}")
    assert sentinel.exists(), "trusted degraded child did not run"


@pytest.mark.skipif(sys.platform != "linux", reason="linux probe seam")
def test_operator_disabled_sandbox_ignores_contract_flag(
        tmp_path, monkeypatch):
    """The operator's explicit sandbox-off surface stays authoritative:
    under `disabled=True` or the CLI `--sandbox none` the per-call
    contract flag is (today, deliberately) silenced along with every
    other containment layer — the environmental gate must NOT fire
    even on a userns-less host. Pins the pre-existing behavior in
    both flag states and both operator-explicit disable spellings.
    (A LIBRARY caller's `profile='none'` is not operator consent —
    `effectively_disabled` derives from the CLI choice and the
    `disabled=` kwarg only — so it is deliberately absent here.)"""
    from core.sandbox import context as _ctx
    from core.sandbox import state
    monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", raising=False)
    monkeypatch.setattr(_ctx, "check_net_available", lambda: False)
    for spelling in ("disabled-kwarg", "cli-sandbox-none"):
        if spelling == "cli-sandbox-none":
            monkeypatch.setattr(state, "_cli_sandbox_profile", "none")
            disable_kw = {}
        else:
            disable_kw = {"disabled": True}
        for flag in (True, False):
            sentinel = tmp_path / f"ran-{spelling}-{flag}"
            r = _ctx.run(["touch", str(sentinel)], timeout=60,
                         require_fresh_procfs=flag, **disable_kw)
            assert r.returncode == 0, (spelling, flag, r)
            assert sentinel.exists(), (spelling, flag)


@pytest.mark.skipif(sys.platform != "linux", reason="linux probe seam")
def test_environmental_gate_literal_true_hint_is_honest(
        tmp_path, monkeypatch):
    """A caller passing a LITERAL require_fresh_procfs=True made an
    explicit ask the env var does not relax: with the waiver set the
    gate still fires, and the hint says the override will not relax
    it instead of advertising it."""
    from core.sandbox import context as _ctx
    from core.sandbox.errors import SandboxSetupError
    monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
    monkeypatch.setattr(_ctx, "check_net_available", lambda: False)
    with pytest.raises(SandboxSetupError) as excinfo:
        _ctx.run(["true"], target=str(tmp_path), output=str(tmp_path),
                 timeout=60, require_fresh_procfs=True)
    msg = str(excinfo.value)
    if "fresh-procfs contract" not in msg:
        pytest.skip(f"different environmental refusal on this host: {msg}")
    assert "does not relax" in msg


def test_env_refusal_darwin_arm_names_seatbelt(monkeypatch):
    """The darwin arm of the environmental refusal (seatbelt probe
    failed + fresh-procfs contract) names the seatbelt remedy, not
    the Linux userns diagnostics — unit-tested off-platform via the
    module's `sys` attribute (the helper consults only
    ``sys.platform``)."""
    from core.sandbox import context as _ctx
    monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", raising=False)
    monkeypatch.setattr(_ctx, "sys",
                        types.SimpleNamespace(platform="darwin"))
    text = str(_ctx._fresh_procfs_env_refusal())
    assert "sandbox-exec" in text
    assert "rlimits-only" in text
    assert "RAPTOR_ALLOW_DEGRADED_UNTRUSTED" in text
    assert "mount-ns blocked" not in text, (
        "darwin refusal carries the Linux userns diagnostic")


def test_payload_executors_derive_contract_flag_from_helper():
    """Source pin: the three direct payload executors derive
    require_fresh_procfs= from the env-var-honouring helper — a
    literal True at those call sites would make the operator waiver
    a lie (the refusal hint tells literal-True callers so)."""
    callers = {
        "packages/llm_analysis/exploit_verify.py":
            "require_fresh_procfs=untrusted_fresh_procfs_required()",
        "packages/exploit_feasibility/under_mitigations.py":
            "require_fresh_procfs=untrusted_fresh_procfs_required()",
        "core/audit/dark_verify/_execute.py":
            "require_fresh_procfs=_fresh_procfs_required()",
    }
    for rel, needle in callers.items():
        src = (_REPO_ROOT / rel).read_text(encoding="utf-8")
        assert needle in src, f"{rel}: contract-flag derivation drifted"
        assert "require_fresh_procfs=True" not in src, (
            f"{rel}: literal require_fresh_procfs=True bypasses the "
            f"operator waiver")
    # dark_verify's local helper must itself delegate to the reader.
    dv = (_REPO_ROOT / "core/audit/dark_verify/_execute.py").read_text(
        encoding="utf-8")
    assert "untrusted_fresh_procfs_required()" in dv, (
        "_fresh_procfs_required() no longer delegates to the env-var "
        "reader")


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_no_branded_names_in_target_view(tmp_path):
    """The target's mount view and env must not name the framework:
    no launcher session-scratch dir replanted in the private /tmp, no
    RAPTOR checkout path bound in (the pid1-shim grant is an
    unshare-lane Landlock rule, not a mount-ns bind), and no
    framework-identity env values."""
    import re as _re
    marker = tmp_path / "brand-probe"
    _run_untrusted_or_skip(
        ["sh", "-c",
         f"{{ ls -a /tmp; echo ---MI---; "
         f"grep -io 'raptor[^ ]*' /proc/self/mountinfo; "
         f"echo ---ENV---; env; }} > {marker}"],
        tmp_path,
    )
    if not marker.exists():
        pytest.skip("probe produced no output")
    text = marker.read_text(encoding="utf-8")
    listing, _, rest = text.partition("---MI---")
    mi_block, _, envblock = rest.partition("---ENV---")
    # The caller-chosen target/output ancestry is target-visible by
    # definition (here: pytest's own basetemp components) — only
    # entries OUTSIDE that ancestry count as leaks.
    own_components = set(tmp_path.parts) | set(Path(__file__).parts)
    hits = [ln for ln in listing.split()
            if _re.search(r"raptor", ln, _re.IGNORECASE)
            and ln not in own_components]
    assert not hits, (
        f"framework-named entries visible in the sandbox /tmp: {hits}")
    mi_hits = [ln for ln in mi_block.split()
               if ln and ln not in own_components
               and not any(c in ln for c in own_components
                           if "raptor" in c.lower())]
    assert not mi_hits, (
        f"framework-named mount sources visible in mountinfo: "
        f"{mi_hits[:6]}")
    for name in ("RAPTOR_DIR=", "RAPTOR_OUT_DIR=", "RAPTOR_TARGET_KIND=",
                 "_RAPTOR_", "CLAUDECODE="):
        assert name not in envblock, (
            f"framework-identity env reached the target: {name}")


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_run_marker_content_masked_in_target_view(tmp_path):
    """.raptor-run.json (RAPTOR git sha, finder identity, target
    provenance, command line) sits inside the rw output bind — the
    child view must serve an empty mask, writes must land on the mask,
    and the real file must stay intact for the parent-side machinery."""
    marker = tmp_path / ".raptor-run.json"
    marker.write_text('{"manifest":{"base_sha":"mask-me-sha"}}',
                      encoding="utf-8")
    probe_out = tmp_path / "probe-out"
    _run_untrusted_or_skip(
        ["sh", "-c",
         f"cat {marker} > {probe_out} 2>&1; "
         f"echo tamper >> {marker} 2>/dev/null || true"],
        tmp_path,
    )
    if not probe_out.exists():
        pytest.skip("probe produced no output")
    assert "mask-me-sha" not in probe_out.read_text(encoding="utf-8"), (
        "run-marker content readable through the output bind")
    real = marker.read_text(encoding="utf-8")
    assert "mask-me-sha" in real and "tamper" not in real, (
        "the real run marker was altered through the child view")


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_agent_credentials_scrubbed_from_chain_environ(tmp_path):
    """Same channel as test_spawn_chain_environ_image_is_scrubbed, for
    the agent-credential class: a session running under Claude Code
    first-party auth carries CLAUDE_CODE_OAUTH_TOKEN /
    ANTHROPIC_AUTH_TOKEN (and possibly ANTHROPIC_CUSTOM_HEADERS, which
    rides Authorization overrides). The scrub set is derived from the
    credential-bearing vocabulary tier, so every foreign-userns chain
    process must publish ZEROED values for them — pre-fix the
    hand-typed union missed all three and the operator's primary
    session credential was one /proc read away from the target on
    host-procfs-visible lanes."""
    import uuid
    beacon = f"SBX_CRED_SCRUB_BEACON_{uuid.uuid4().hex[:8].upper()}"
    run_tag = uuid.uuid4().hex[:12]
    decoys = {
        name: f"{name.lower()}-decoy-{run_tag}"
        # GITHUB_TOKEN pins the name-SHAPE sweep: it is in no
        # consumed exact-name set, only the shape grammar covers it.
        for name in ("CLAUDE_CODE_OAUTH_TOKEN",
                     "ANTHROPIC_AUTH_TOKEN",
                     "ANTHROPIC_CUSTOM_HEADERS",
                     "GITHUB_TOKEN")
    }
    my_userns = os.readlink("/proc/self/ns/user")
    seen: dict[str, tuple[str, bytes]] = {}
    stop = threading.Event()

    def watcher() -> None:
        me = str(os.getpid())
        while not stop.is_set():
            for pid in os.listdir("/proc"):
                if not pid.isdigit() or pid == me:
                    continue
                try:
                    with open(f"/proc/{pid}/environ", "rb") as f:
                        img = f.read()
                    userns = os.readlink(f"/proc/{pid}/ns/user")
                except OSError:
                    continue
                if beacon.encode() + b"=1" in img:
                    seen[pid] = (userns, img)
            time.sleep(0.005)

    t = threading.Thread(target=watcher)
    t.start()
    try:
        r = _drive_run_in_subprocess(
            tmp_path, beacon, "sleep 1.5", timeout=150,
            extra_env=decoys)
    finally:
        stop.set()
        t.join()
    if "RC=0" not in r.stdout:
        pytest.skip(f"sandbox unavailable: {r.stdout} {r.stderr[-300:]}")
    foreign = {pid: img for pid, (ns, img) in seen.items()
               if ns != my_userns}
    if not foreign:
        pytest.skip("no foreign-userns chain process observed")
    leaks = sorted(
        f"{pid}:{name}"
        for pid, img in foreign.items()
        for name, value in decoys.items()
        if f"{name}={value}".encode() in img)
    assert not leaks, (
        f"spawn-chain forks readable from inside the sandbox still "
        f"publish agent credentials: {leaks}")
    for img in foreign.values():
        for name in decoys:
            assert f"{name}=".encode() in img, (
                "scrub should empty the value, not remove the name")
