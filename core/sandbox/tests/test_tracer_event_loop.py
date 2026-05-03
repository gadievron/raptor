"""Mocked tests for the tracer event-loop dispatch.

`_handle_waitpid_event` takes one waitpid status + the active tracee
set + arch info, and decides what to do (record syscall, attach new
tracee, drop exited PID, pass through signal). All ptrace side-
effects are dependency-injected so tests construct synthetic statuses
and observe the resulting actions WITHOUT needing real ptrace.

These tests run in CI everywhere (no kernel feature requirements,
no permissions). They complement — but don't replace — the real
end-to-end tests in test_spawn_audit.py that exercise actual ptrace.

Status encoding cheatsheet (see man waitpid):
- exited(rc): status = (rc << 8)
- signalled(sig): status = sig
- stopped(sig): status = (sig << 8) | 0x7f
- ptrace event(ev, sig=SIGTRAP): status = (ev << 16) | (SIGTRAP << 8) | 0x7f
"""

from __future__ import annotations

import platform
import signal
import struct
from pathlib import Path

import pytest

from core.sandbox import tracer


pytestmark = pytest.mark.skipif(
    not tracer._is_supported_arch(),
    reason=f"tracer doesn't support {platform.machine()}",
)


# Status constructors — make tests readable.

def _exit_status(rc: int) -> int:
    return rc << 8

def _signal_death_status(sig: int) -> int:
    # WIFSIGNALED: low 7 bits = sig, no 0x7f marker
    return sig

def _stop_status(sig: int) -> int:
    # WIFSTOPPED: low 8 bits = 0x7f, next 8 = sig
    return (sig << 8) | 0x7f

def _ptrace_event_status(event: int) -> int:
    # ptrace events are SIGTRAP stops with the event code in upper 16
    return (event << 16) | (signal.SIGTRAP << 8) | 0x7f


@pytest.fixture
def arch_info():
    """Return a real arch_info table for the current arch — the
    syscall_table inside is referenced by the dispatch function."""
    return tracer._ARCH_INFO[tracer._ARCH]


@pytest.fixture
def fake_helpers():
    """Recording mocks for the side-effect helpers. Each entry is
    a callable that records its invocation and returns a sentinel."""
    calls = {
        "ptrace_cont": [],
        "read_regs": [],
        "decode_syscall": [],
        "read_tracee_string": [],
        "get_event_msg": [],
        "write_record": [],
    }

    def fake_ptrace_cont(pid, sig=0):
        calls["ptrace_cont"].append((pid, sig))
        return True

    def fake_read_regs(pid, ai):
        calls["read_regs"].append(pid)
        # Return non-None so dispatch goes into the decode path.
        return b"\x00" * ai["user_regs_size"]

    def fake_decode_syscall(regs, ai):
        calls["decode_syscall"].append(len(regs))
        # Return openat=257 on x86_64, openat=56 on aarch64
        nr = 257 if tracer._ARCH == "x86_64" else 56
        return nr, [0xdeadbeef, 0xcafef00d, 0, 0, 0, 0]

    def fake_read_tracee_string(pid, addr, max_bytes=4096):
        calls["read_tracee_string"].append((pid, addr))
        return "/etc/test"

    def fake_get_event_msg(pid):
        calls["get_event_msg"].append(pid)
        # Return a fake new-child PID; tests can assert it lands in `traced`.
        return 99999

    def fake_write_record(run_dir, name, nr, args, target_pid, path=None):
        calls["write_record"].append({
            "name": name, "nr": nr, "args": list(args),
            "target_pid": target_pid, "path": path,
        })
        return True

    helpers = {
        "ptrace_cont": fake_ptrace_cont,
        "read_regs": fake_read_regs,
        "decode_syscall": fake_decode_syscall,
        "read_tracee_string": fake_read_tracee_string,
        "get_event_msg": fake_get_event_msg,
        "write_record": fake_write_record,
    }
    helpers["calls"] = calls
    return helpers


def _dispatch(wpid, status, traced, target_pid, arch_info, helpers,
              record_count=0, cap_warned=False, run_dir=Path("/tmp")):
    """Convenience wrapper to call _handle_waitpid_event with the
    fake helpers from the fixture."""
    return tracer._handle_waitpid_event(
        wpid, status, traced, target_pid, arch_info,
        run_dir, record_count, cap_warned,
        ptrace_cont=helpers["ptrace_cont"],
        read_regs=helpers["read_regs"],
        decode_syscall=helpers["decode_syscall"],
        read_tracee_string=helpers["read_tracee_string"],
        get_event_msg=helpers["get_event_msg"],
        write_record=helpers["write_record"],
    )


class TestExitedTracees:
    """When a tracee exits (cleanly or by signal), it gets dropped
    from the traced set. The loop terminates when the set is empty."""

    def test_exited_tracee_removed_from_traced(self, arch_info, fake_helpers):
        traced = {1000, 1001, 1002}
        rc, _ = _dispatch(
            1001, _exit_status(0), traced, 1000, arch_info, fake_helpers,
        )
        assert traced == {1000, 1002}
        # No ptrace_cont needed — tracee already dead
        assert fake_helpers["calls"]["ptrace_cont"] == []

    def test_signalled_tracee_removed(self, arch_info, fake_helpers):
        traced = {1000}
        _dispatch(
            1000, _signal_death_status(signal.SIGKILL),
            traced, 1000, arch_info, fake_helpers,
        )
        assert traced == set()

    def test_unknown_pid_in_status_is_silent_noop(
            self, arch_info, fake_helpers):
        # M1 / N3 robustness: a wpid not in `traced` (could happen if
        # FORK_EVENT-add was missed) just gets silently discarded.
        # No exception, no resume call.
        traced = {1000}
        _dispatch(
            9999, _exit_status(0), traced, 1000, arch_info, fake_helpers,
        )
        assert traced == {1000}  # unchanged
        assert fake_helpers["calls"]["ptrace_cont"] == []


class TestSeccompTraceEvent:
    """SECCOMP_RET_TRACE event: read syscall, deref path if applicable,
    write record, resume tracee."""

    def test_seccomp_event_writes_record(self, arch_info, fake_helpers):
        traced = {1000}
        rc, cap = _dispatch(
            1000, _ptrace_event_status(tracer._PTRACE_EVENT_SECCOMP),
            traced, 1000, arch_info, fake_helpers,
        )
        assert rc == 1, "record_count should increment"
        assert cap is False
        # write_record was called with openat
        records = fake_helpers["calls"]["write_record"]
        assert len(records) == 1
        nr_expected = 257 if tracer._ARCH == "x86_64" else 56
        assert records[0]["nr"] == nr_expected
        assert records[0]["name"] == "openat"
        assert records[0]["path"] == "/etc/test"
        # tracee resumed
        assert fake_helpers["calls"]["ptrace_cont"] == [(1000, 0)]

    def test_seccomp_event_path_deref_for_openat(
            self, arch_info, fake_helpers):
        # openat path is at arg[1] — tracer should call
        # read_tracee_string on args[1], not args[0].
        traced = {1000}
        _dispatch(
            1000, _ptrace_event_status(tracer._PTRACE_EVENT_SECCOMP),
            traced, 1000, arch_info, fake_helpers,
        )
        # fake_decode_syscall returns args = [0xdeadbeef, 0xcafef00d, 0, ...]
        # _path_arg_index("openat") = 1, so we should read addr 0xcafef00d.
        deref_calls = fake_helpers["calls"]["read_tracee_string"]
        assert len(deref_calls) == 1
        assert deref_calls[0] == (1000, 0xcafef00d)

    def test_record_cap_emits_one_warning(
            self, arch_info, fake_helpers, monkeypatch, capfd):
        # Lower the cap so the test runs fast.
        monkeypatch.setattr(tracer, "_MAX_RECORDS_PER_RUN", 2)
        traced = {1000}
        rc, cap = 0, False
        for _ in range(5):
            rc, cap = _dispatch(
                1000, _ptrace_event_status(tracer._PTRACE_EVENT_SECCOMP),
                traced, 1000, arch_info, fake_helpers,
                record_count=rc, cap_warned=cap,
            )
        # 2 records persisted (cap), but ptrace_cont fired all 5 times.
        assert len(fake_helpers["calls"]["write_record"]) == 2
        assert len(fake_helpers["calls"]["ptrace_cont"]) == 5
        assert cap is True

    def test_read_regs_failure_skips_record_but_resumes(
            self, arch_info):
        # If reading regs fails (returns None), no record but tracee
        # still resumes — otherwise it'd be stuck forever.
        calls = []
        def fail_read_regs(pid, ai):
            return None
        def cont(pid, sig=0):
            calls.append((pid, sig))
            return True
        traced = {1000}
        rc, cap = tracer._handle_waitpid_event(
            1000, _ptrace_event_status(tracer._PTRACE_EVENT_SECCOMP),
            traced, 1000, arch_info, Path("/tmp"), 0, False,
            read_regs=fail_read_regs, ptrace_cont=cont,
            decode_syscall=lambda *a: (0, [0]*6),
            read_tracee_string=lambda *a, **k: None,
            get_event_msg=lambda p: None,
            write_record=lambda *a, **k: True,
        )
        assert rc == 0  # no record written
        assert calls == [(1000, 0)]  # but tracee resumed


class TestNewTraceeEvents:
    """FORK / VFORK / CLONE: get new child PID, add to traced set,
    resume parent."""

    @pytest.mark.parametrize("event_name,event_code", [
        ("FORK", tracer._PTRACE_EVENT_FORK),
        ("VFORK", tracer._PTRACE_EVENT_VFORK),
        ("CLONE", tracer._PTRACE_EVENT_CLONE),
    ])
    def test_new_tracee_event_adds_to_set(
            self, arch_info, fake_helpers, event_name, event_code):
        traced = {1000}
        _dispatch(
            1000, _ptrace_event_status(event_code),
            traced, 1000, arch_info, fake_helpers,
        )
        # GETEVENTMSG returned 99999 (the fake new-child PID)
        assert traced == {1000, 99999}, f"{event_name}: traced {traced}"
        assert fake_helpers["calls"]["get_event_msg"] == [1000]
        assert fake_helpers["calls"]["ptrace_cont"] == [(1000, 0)]

    def test_get_event_msg_failure_does_not_grow_set(self, arch_info):
        # If GETEVENTMSG returns None, we don't add a bogus PID.
        # M1's defensive SIGSTOP-side add covers this case later.
        calls = []
        def cont(pid, sig=0):
            calls.append((pid, sig))
            return True

        traced = {1000}
        tracer._handle_waitpid_event(
            1000, _ptrace_event_status(tracer._PTRACE_EVENT_FORK),
            traced, 1000, arch_info, Path("/tmp"), 0, False,
            ptrace_cont=cont,
            read_regs=lambda *a: None,
            decode_syscall=lambda *a: (0, [0]*6),
            read_tracee_string=lambda *a, **k: None,
            get_event_msg=lambda p: None,  # failure path
            write_record=lambda *a, **k: True,
        )
        assert traced == {1000}
        assert calls == [(1000, 0)]


class TestSigstopFromAutoAttachedTracee:
    """When a new tracee is auto-attached via TRACEFORK, the kernel
    delivers a SIGSTOP to it. Tracer must consume the SIGSTOP (NOT
    forward it via PTRACE_CONT signal arg) — otherwise the new
    tracee stays paused forever."""

    def test_sigstop_from_new_tracee_is_consumed(
            self, arch_info, fake_helpers):
        traced = {1000}  # target_pid=1000; 99999 is a new tracee
        _dispatch(
            99999, _stop_status(signal.SIGSTOP),
            traced, 1000, arch_info, fake_helpers,
        )
        # PTRACE_CONT with sig=0 (NOT signal.SIGSTOP)
        assert fake_helpers["calls"]["ptrace_cont"] == [(99999, 0)]
        # M1 defensive: traced grows even if FORK_EVENT-add path missed it
        assert 99999 in traced

    def test_sigstop_to_target_pid_is_passed_through(
            self, arch_info, fake_helpers):
        # SIGSTOP from somewhere external (not auto-attach) to the
        # ORIGINAL target — pass through so target sees it.
        # ... documented as a known caveat (O1 in commit-3 review):
        # the resume action will resume the target; SIGSTOP semantics
        # aren't preserved. But the dispatch path doesn't intercept.
        traced = {1000}
        _dispatch(
            1000, _stop_status(signal.SIGSTOP),
            traced, 1000, arch_info, fake_helpers,
        )
        # sig forwarded (SIGSTOP, not 0) — target sees the original signal
        assert fake_helpers["calls"]["ptrace_cont"] == [(1000, signal.SIGSTOP)]


class TestPtraceEventExit:
    """PTRACE_EVENT_EXIT: tracee about to die. Continue, let kernel
    finish the exit. The actual WIFEXITED/SIGNALED status arrives
    on the next waitpid."""

    def test_exit_event_resumes_tracee(self, arch_info, fake_helpers):
        traced = {1000}
        _dispatch(
            1000, _ptrace_event_status(tracer._PTRACE_EVENT_EXIT),
            traced, 1000, arch_info, fake_helpers,
        )
        # PID stays in traced — actual removal happens on the
        # subsequent WIFEXITED status.
        assert traced == {1000}
        assert fake_helpers["calls"]["ptrace_cont"] == [(1000, 0)]


class TestSignalPassthrough:
    """Signals other than SIGSTOP/SIGTRAP are passed through to the
    tracee so the original signal semantics are preserved (e.g.
    SIGTERM, SIGINT, SIGUSR1)."""

    @pytest.mark.parametrize("sig", [
        signal.SIGTERM, signal.SIGINT, signal.SIGUSR1, signal.SIGHUP,
    ])
    def test_signal_passthrough(self, arch_info, fake_helpers, sig):
        traced = {1000}
        _dispatch(
            1000, _stop_status(sig),
            traced, 1000, arch_info, fake_helpers,
        )
        # sig forwarded as-is
        assert fake_helpers["calls"]["ptrace_cont"] == [(1000, sig)]

    def test_sigtrap_swallowed(self, arch_info, fake_helpers):
        # SIGTRAP from non-event stops (rare) shouldn't be forwarded
        # — would confuse the tracee. The trace loop replaces it with 0.
        traced = {1000}
        _dispatch(
            1000, _stop_status(signal.SIGTRAP),
            traced, 1000, arch_info, fake_helpers,
        )
        assert fake_helpers["calls"]["ptrace_cont"] == [(1000, 0)]


class TestNonStoppedStatus:
    """waitpid can return statuses that aren't WIFSTOPPED, WIFEXITED,
    or WIFSIGNALED in some edge cases — the dispatch should silently
    no-op, not crash."""

    def test_continued_status_is_silent_noop(self, arch_info, fake_helpers):
        # WIFCONTINUED status (rare; happens after SIGCONT). Mock it
        # by feeding a status that's not stopped/exited/signalled.
        traced = {1000}
        # 0xffff = WIFCONTINUED on Linux
        rc, cap = _dispatch(
            1000, 0xffff, traced, 1000, arch_info, fake_helpers,
        )
        # No record, no resume, no set mutation
        assert traced == {1000}
        assert rc == 0
        assert fake_helpers["calls"]["ptrace_cont"] == []
