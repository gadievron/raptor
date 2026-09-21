"""Exec-status protocol integrity: no silent fail-closed child exits,
no unknown-category fall-through.

The parent treats EOF-with-no-byte on the exec-status pipe as "the
target execed", so a fail-closed child ``os._exit`` that skips the
status write turns an aborted SETUP into a genuine-looking target
result — rc=127/126 collide with the shell not-found/not-executable
conventions and feed downstream returncode oracles fabricated target
behaviour. Two invariants pinned here:

1. Every fail-closed child abort (unusable cwd=, extra_ro bind
   failure, mandatory RLIMIT_CORE) writes category 'C' first, and the
   parent raises the typed SandboxSetupError instead of returning a
   CompletedProcess.
2. The parent default-DENIES status categories it does not recognise
   (the old fall-through was the same default-allow shape that let a
   new demotion lane ship ungated).
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from core.sandbox.errors import SandboxSetupError

_REPO_ROOT = Path(__file__).resolve().parents[3]


# ---------------------------------------------------------- unit tier

def test_c_status_byte_roundtrip():
    from core.sandbox._spawn import _parse_setup_status
    parsed = _parse_setup_status(b"C:cwd '/nope' unusable inside sandbox")
    assert parsed == ("C", "cwd '/nope' unusable inside sandbox")


def test_exec_confirmation_reads_as_genuine_run():
    # 'G' then EOF is the ONLY shape that parses as "the target ran".
    from core.sandbox._spawn import _parse_setup_status
    assert _parse_setup_status(b"G:") is None


def test_eof_without_confirmation_is_typed_not_genuine():
    """Bare EOF used to mean "the target execed" — but an involuntary
    pre-exec child death (SIGKILL mid-rlimits, OOM kill) produces the
    same bare EOF, so the parent returned the dead setup child's wait
    status as a genuine-looking target result. Missing confirmation
    now maps to the synthetic '!' category."""
    from core.sandbox._spawn import _parse_setup_status
    parsed = _parse_setup_status(b"")
    assert parsed is not None
    assert parsed[0] == "!"
    assert "without reporting" in parsed[1]


def test_exec_failure_after_confirmation_keeps_its_category():
    # The child writes 'G' immediately before execvpe; an exec failure
    # then appends its 'X' payload — same pipe, ordered writes.
    from core.sandbox._spawn import _parse_setup_status
    parsed = _parse_setup_status(b"G:X:exec: file not found")
    assert parsed == ("X", "exec: file not found")


def test_extra_ro_bind_error_preserves_errno():
    import errno

    from core.sandbox.mount_ns import ExtraRoBindError
    exc = ExtraRoBindError(errno.EINVAL, "extra_ro_paths bind failed "
                                         "for '/opt/tool'")
    assert isinstance(exc, OSError)
    assert exc.errno == errno.EINVAL


def test_fail_closed_child_sites_write_status_bytes():
    """Source pin: the three fail-closed child aborts that used to
    ``os._exit`` with NO status byte now report before exiting —
    cwd and RLIMIT_CORE write 'C' directly; the extra_ro bind site
    raises the typed error that _spawn's setup handler categorises as
    'C' (with the pin-tamper 'P' check outranking it)."""
    spawn_src = (_REPO_ROOT / "core/sandbox/_spawn.py").read_text(
        encoding="utf-8")
    # cwd site: the status write precedes the exit.
    cwd_at = spawn_src.index("unusable inside sandbox ")
    region = spawn_src[cwd_at - 600:cwd_at]
    assert '_write_setup_status(' in region and 'b"C"' in region, (
        "the bad-cwd abort no longer writes its status byte")
    # RLIMIT_CORE site.
    core_at = spawn_src.index("RLIMIT_CORE setrlimit failed")
    assert 'b"C"' in spawn_src[core_at - 600:core_at], (
        "the RLIMIT_CORE abort no longer writes its status byte")
    # extra_ro site: typed raise instead of a bare exit, mapped to 'C'
    # in _spawn after the 'P' tamper check.
    mns_src = (_REPO_ROOT / "core/sandbox/mount_ns.py").read_text(
        encoding="utf-8")
    assert "raise ExtraRoBindError(" in mns_src
    assert "SANDBOX_EXIT_MOUNT_NS_BIND_FAIL" not in mns_src, (
        "the extra_ro fail-closed abort regressed to a bare os._exit")
    p_at = spawn_src.index("_PIN_TAMPER_ERRNO):", 2000)
    c_map = spawn_src[p_at:p_at + 800]
    assert "_ExtraRoBindError" in c_map and 'b"C"' in c_map, (
        "_spawn no longer maps the extra_ro failure to category 'C'")


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="exercises the Linux spawn-lane status arms via the Linux "
           "spawn seam; the darwin seatbelt lane has its own readiness "
           "protocol ('E') whose unknown-category posture belongs to "
           "the darwin parity work")
def test_parent_default_denies_unknown_status_category(
        tmp_path, monkeypatch):
    """A status byte from a future writer that this parent does not
    recognise must fail loud, never fall through as a genuine target
    result. (Linux spawn lane: on darwin the monkeypatched seam is
    never dispatched — the seatbelt branch runs — so the arms under
    test are unreachable there.)"""
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    calls = []

    def fake_spawn(cmd, **kwargs):
        calls.append(kwargs)
        cp = subprocess.CompletedProcess(cmd, returncode=0,
                                         stdout="", stderr="")
        cp._setup_status = ("Z", "from a future status writer")
        return cp

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", fake_spawn)
    try:
        with pytest.raises(SandboxSetupError) as excinfo:
            _ctx.run(["true"], target=str(tmp_path),
                     output=str(tmp_path), timeout=60)
    except (pytest.skip.Exception, pytest.fail.Exception):
        if not calls:
            # Hosts where the spawn backend never dispatches (userns
            # denied): the run completed on a subprocess lane and the
            # faked status was never consumed — nothing to test.
            pytest.skip("spawn backend not dispatched on this host")
        raise
    except Exception as e:  # noqa: BLE001 — host can't reach the lane
        if calls:
            # The faked status WAS consumed and the parent then blew
            # up some other way — a capable-host regression, not lane
            # unavailability. Fail loud.
            raise
        pytest.skip(f"mount-ns lane unavailable: {e}")
    if not calls:
        # pytest.raises accepted a SandboxSetupError, but the fake
        # spawn was never dispatched — the refusal came from an
        # earlier gate (e.g. the construction-time "block_network
        # with no namespace backend and no Landlock ABI v4+" refusal
        # on a fully degraded host), not from the status-protocol
        # arms under test. Same nothing-to-test shape as the
        # subprocess-lane completion handled above.
        pytest.skip("spawn backend not dispatched on this host "
                    "(refused before the status seam)")
    assert "unrecognised setup-status category 'Z'" in str(excinfo.value)
    assert excinfo.value.setup_category == "Z"


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="exercises the Linux spawn-lane status arms via the Linux "
           "spawn seam; the darwin seatbelt lane has its own readiness "
           "protocol ('E') whose unknown-category posture belongs to "
           "the darwin parity work")
def test_parent_raises_typed_error_on_c_status(tmp_path, monkeypatch):
    """The 'C' category is fail-loud with no degrade path: no mountless
    retry, no fallback lane, the failed result never returned. (Linux
    spawn lane — see the platform gate's rationale above.)"""
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    calls = []

    def fake_spawn(cmd, **kwargs):
        calls.append(kwargs)
        cp = subprocess.CompletedProcess(cmd, returncode=127,
                                         stdout="", stderr="")
        cp._setup_status = ("C", "cwd '/gone' unusable inside sandbox")
        return cp

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", fake_spawn)
    try:
        with pytest.raises(SandboxSetupError) as excinfo:
            _ctx.run(["true"], target=str(tmp_path),
                     output=str(tmp_path), timeout=60)
    except (pytest.skip.Exception, pytest.fail.Exception):
        if not calls:
            # Hosts where the spawn backend never dispatches (userns
            # denied): the run completed on a subprocess lane and the
            # faked status was never consumed — nothing to test.
            pytest.skip("spawn backend not dispatched on this host")
        raise
    except Exception as e:  # noqa: BLE001 — host can't reach the lane
        if calls:
            # The faked status WAS consumed and the parent then blew
            # up some other way — a capable-host regression, not lane
            # unavailability. Fail loud.
            raise
        pytest.skip(f"mount-ns lane unavailable: {e}")
    if not calls:
        # pytest.raises accepted a SandboxSetupError, but the fake
        # spawn was never dispatched — the refusal came from an
        # earlier gate (e.g. the construction-time "block_network
        # with no namespace backend and no Landlock ABI v4+" refusal
        # on a fully degraded host), not from the status-protocol
        # arms under test. Same nothing-to-test shape as the
        # subprocess-lane completion handled above.
        pytest.skip("spawn backend not dispatched on this host "
                    "(refused before the status seam)")
    assert excinfo.value.setup_category == "C"
    assert "aborted fail-closed" in str(excinfo.value)
    assert "cwd '/gone'" in str(excinfo.value)
    assert len(calls) == 1, "the 'C' category must not ride any ladder"


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="exercises the Linux spawn-lane status arms via the Linux "
           "spawn seam; the darwin seatbelt lane has its own readiness "
           "protocol ('E') — same platform gate as the sibling "
           "fake-spawn tests above")
def test_parent_raises_typed_error_on_missing_confirmation(
        tmp_path, monkeypatch):
    """The '!' category (EOF, no exec confirmation) is a typed refusal
    naming the involuntary-death shape — never a ladder ride, never a
    result. (Linux spawn lane: on darwin the monkeypatched seam is
    never dispatched — the seatbelt branch runs.)"""
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    calls = []

    def fake_spawn(cmd, **kwargs):
        calls.append(kwargs)
        cp = subprocess.CompletedProcess(cmd, returncode=-9,
                                         stdout="", stderr="")
        cp._setup_status = (
            "!", "child terminated during sandbox setup without "
                 "reporting")
        return cp

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", fake_spawn)
    try:
        with pytest.raises(SandboxSetupError) as excinfo:
            _ctx.run(["true"], target=str(tmp_path),
                     output=str(tmp_path), timeout=60)
    except (pytest.skip.Exception, pytest.fail.Exception):
        if not calls:
            # Hosts where the spawn backend never dispatches (userns
            # denied): the run completed on a subprocess lane and the
            # faked status was never consumed — nothing to test.
            pytest.skip("spawn backend not dispatched on this host")
        raise
    except Exception as e:  # noqa: BLE001 — host can't reach the lane
        if calls:
            # The faked status WAS consumed and the parent then blew
            # up some other way — a capable-host regression, not lane
            # unavailability. Fail loud.
            raise
        pytest.skip(f"mount-ns lane unavailable: {e}")
    if not calls:
        # pytest.raises accepted a SandboxSetupError, but the fake
        # spawn was never dispatched — the refusal came from an
        # earlier gate (e.g. the construction-time "block_network
        # with no namespace backend and no Landlock ABI v4+" refusal
        # on a fully degraded host), not from the status-protocol
        # arms under test. Same nothing-to-test shape as the
        # subprocess-lane completion handled above.
        pytest.skip("spawn backend not dispatched on this host "
                    "(refused before the status seam)")
    assert excinfo.value.setup_category == "!"
    assert "died during setup" in str(excinfo.value)
    assert "rc=-9" in str(excinfo.value)
    assert len(calls) == 1, "the '!' category must not ride any ladder"


# --------------------------------------------------- integration tier

@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_bad_cwd_raises_typed_error_not_fake_result(tmp_path):
    """Live: a cwd= that does not exist inside the sandbox aborts the
    spawn child; the parent must raise the typed category-'C' refusal
    — pre-fix it returned a normal CompletedProcess with rc=127 and
    only a stderr line, feeding returncode oracles a fabricated
    target result."""
    from core.sandbox import context as _ctx
    missing = tmp_path / "no-such-cwd"
    try:
        r = _ctx.run(["/bin/true"], target=str(tmp_path),
                     output=str(tmp_path), cwd=str(missing), timeout=60)
    except SandboxSetupError as e:
        assert e.setup_category == "C", str(e)
        assert "cwd" in str(e)
        return
    except FileNotFoundError:
        # Subprocess-backed lane: Python validates cwd in the parent
        # and raises before exec — already loud; the spawn lane was
        # the silent one. Nothing to test on this host shape.
        pytest.skip("spawn lane not taken (subprocess cwd validation)")
    pytest.fail(
        f"bad cwd came back as a genuine result: rc={r.returncode} "
        f"(status-byte protocol regressed)")


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_rlimit_core_failure_raises_typed_error(tmp_path, monkeypatch):
    """Live: a mandatory RLIMIT_CORE failure in the spawn child aborts
    with category 'C' instead of a bare rc=99 result. Injected via a
    fork-inherited resource.setrlimit wrapper that refuses exactly
    RLIMIT_CORE."""
    import resource

    from core.sandbox import context as _ctx
    real = resource.setrlimit

    def refusing(res, limits):
        if res == resource.RLIMIT_CORE:
            raise OSError(1, "injected RLIMIT_CORE refusal")
        return real(res, limits)

    monkeypatch.setattr(resource, "setrlimit", refusing)
    try:
        r = _ctx.run(["/bin/true"], target=str(tmp_path),
                     output=str(tmp_path), timeout=60)
    except SandboxSetupError as e:
        assert e.setup_category == "C", str(e)
        assert "RLIMIT_CORE" in str(e)
        return
    except (pytest.skip.Exception, pytest.fail.Exception):
        raise
    except Exception as e:  # noqa: BLE001 — host can't reach the lane
        pytest.skip(f"spawn lane unavailable: {e}")
    # Subprocess lanes apply rlimits in preexec (different mechanism,
    # out of this protocol's scope) — only the spawn lane must raise.
    if r.sandbox_info.get("mount_ns_active") or (
            r.sandbox_info.get("backend") == "landlock-pidns"):
        pytest.fail(
            f"spawn-lane RLIMIT_CORE failure came back as a genuine "
            f"result: rc={r.returncode}")
    pytest.skip("spawn lane not taken on this host")


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_involuntary_child_death_raises_typed_error(tmp_path, monkeypatch):
    """Live: SIGKILL landing on the spawn child mid-setup (injected at
    the rlimits step via a fork-inherited resource.setrlimit wrapper)
    leaves NO status byte and NO exec confirmation — the parent must
    raise the typed '!' refusal instead of returning the setup child's
    rc=-9 as a genuine target result (which fed crash oracles a
    fabricated target crash)."""
    import resource
    import signal as _signal

    from core.sandbox import context as _ctx
    parent_pid = os.getpid()

    def killer(res, limits):
        if os.getpid() != parent_pid:
            os.kill(os.getpid(), _signal.SIGKILL)

    monkeypatch.setattr(resource, "setrlimit", killer)
    try:
        r = _ctx.run(["/bin/true"], target=str(tmp_path),
                     output=str(tmp_path), timeout=60)
    except SandboxSetupError as e:
        assert e.setup_category == "!", str(e)
        assert "died during setup" in str(e)
        return
    except (pytest.skip.Exception, pytest.fail.Exception):
        raise
    except Exception as e:  # noqa: BLE001 — host can't reach the lane
        pytest.skip(f"spawn lane unavailable: {e}")
    # Subprocess lanes apply rlimits in preexec_fn; a killed preexec
    # child surfaces through subprocess's own machinery, out of this
    # protocol's scope — only the spawn lane must raise.
    if r.sandbox_info.get("mount_ns_active") or (
            r.sandbox_info.get("backend") == "landlock-pidns"):
        pytest.fail(
            f"involuntary spawn-child death came back as a genuine "
            f"result: rc={r.returncode}")
    pytest.skip("spawn lane not taken on this host")


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_callback_kill_before_exec_is_a_result_not_a_refusal(
        tmp_path, monkeypatch):
    """Live: a SIGKILL sent by the caller's own exec_pid_callback that
    lands BEFORE the exec confirmation is caller-initiated termination
    — the documented callback contract ("SIGKILL is fine") — and must
    come back as the pre-existing CompletedProcess shape (rc=-9),
    never the involuntary-death '!' refusal. The pre-exec landing is
    made deterministic by stalling the 'G' confirmation write in the
    fork-inherited child, so the callback's kill always wins the race.
    Two-direction twin of test_involuntary_child_death_raises_typed_
    error: same signal, no callback there → still typed."""
    import signal as _signal
    import time as _time

    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx

    real_write = _spawn_mod._write_setup_status

    def stall_confirmation(fd, category, reason=""):
        if category == b"G":
            _time.sleep(1.0)
        real_write(fd, category, reason)

    monkeypatch.setattr(_spawn_mod, "_write_setup_status",
                        stall_confirmation)
    killed = {}

    def kill_it(pid):
        killed["pid"] = pid
        os.kill(pid, _signal.SIGKILL)

    try:
        r = _ctx.run(["/bin/sleep", "30"], target=str(tmp_path),
                     output=str(tmp_path), timeout=30,
                     capture_output=True, text=True,
                     exec_pid_callback=kill_it)
    except SandboxSetupError as e:
        pytest.fail(
            f"caller-initiated callback kill came back as a refusal: "
            f"{e} (setup_category={e.setup_category!r})")
    except (pytest.skip.Exception, pytest.fail.Exception):
        raise
    except Exception as e:  # noqa: BLE001 — host can't reach the lane
        pytest.skip(f"spawn lane unavailable: {e}")
    if not killed:
        pytest.skip("exec pid never delivered on this host shape")
    assert r.returncode == -_signal.SIGKILL, (
        f"expected the caller-visible rc=-9 contract, got "
        f"rc={r.returncode}")


def test_child_failure_diagnostic_escapes_at_site():
    """Source pin: the child-failure stderr diagnostic must escape the
    traceback at the site (escape_nonprintable, preserve_newlines).
    The writer gate CANNOT hold this site: the fix's own
    `except BaseException: _tb = ""` fallback re-binds the name, and
    the audit's flow-insensitive Assign semantics clear the taint —
    so a semantic revert (dropping only the _enp() wrap while keeping
    the try/except shape) reads clean to the gate. This pin (and the
    behavioural twin below) is the member's oracle."""
    spawn_src = (_REPO_ROOT / "core/sandbox/_spawn.py").read_text(
        encoding="utf-8")
    at = spawn_src.index("sandbox child failure:")
    region = spawn_src[at - 1600:at]
    assert "_tb = _enp(traceback.format_exc()" in region, (
        "the child-failure diagnostic no longer escapes the traceback "
        "at construction — raw target-influenced bytes would reach "
        "the operator's inherited stderr, and the writer gate is "
        "structurally blind to this site (except-rebind taint clear)"
    )
    assert "escape_nonprintable as _enp" in region


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_child_failure_diagnostic_escapes_hostile_bytes(
        tmp_path, monkeypatch, capfd):
    """Live: hostile bytes in the setup-failure exception text must
    reach the operator's inherited stderr ESCAPED. Injected via a
    fork-inherited resource.setrlimit wrapper whose message carries
    ESC/BEL (setup-failure text embeds target-influenced strings —
    bind paths, mount args — by the same derivation)."""
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx

    hostile = "pwned-\x1b]0;title\x07-\x1b[2J-end"

    def raising(limits, status_fd=None):
        # Generic (not specially-categorised) setup failure — flows to
        # the child's `except BaseException` diagnostic, the lane under
        # test. Fork-inherited monkeypatch, same seam family as the
        # RLIMIT_CORE / SIGKILL siblings above.
        raise ValueError(f"injected setup failure {hostile}")

    monkeypatch.setattr(_spawn_mod, "_set_rlimits", raising)
    try:
        _ctx.run(["/bin/true"], target=str(tmp_path),
                 output=str(tmp_path), timeout=60)
    except SandboxSetupError:
        pass  # fail-loud parent outcome — diagnostic already on fd 2
    except (pytest.skip.Exception, pytest.fail.Exception):
        raise
    except Exception as e:  # noqa: BLE001 — host can't reach the lane
        pytest.skip(f"spawn lane unavailable: {e}")
    # Whether the parent failed loud or degraded to a non-ns lane,
    # the child wrote its last-chance diagnostic to the inherited
    # stderr BEFORE the parent decided — the escape contract is on
    # that write itself.
    err = capfd.readouterr().err
    if "sandbox child failure" not in err:
        pytest.skip("spawn child-failure lane not exercised on this "
                    "host (no diagnostic on stderr)")
    assert "\x1b" not in err and "\x07" not in err, (
        "raw control bytes from setup-failure exception text reached "
        "the inherited stderr"
    )
    assert "pwned-" in err  # escaped, content preserved
