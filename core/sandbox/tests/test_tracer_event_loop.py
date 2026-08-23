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

import sys as _sys
import pytest as _pytest
pytestmark = _pytest.mark.skipif(
    _sys.platform != "linux",
    reason="Linux-only sandbox internals (mount-ns / Landlock / seccomp / ptrace tracer / pid1 shim) — see core/sandbox/_macos_spawn.py for the macOS path",
)


import platform  # noqa: E402
import signal  # noqa: E402
from pathlib import Path  # noqa: E402

import pytest  # noqa: E402

from core.sandbox import tracer  # noqa: E402


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

    def fake_write_record(run_dir, name, nr, args, target_pid, path=None,
                          *, filename=None, mode_field=None,
                          nonce=None):
        calls["write_record"].append({
            "name": name, "nr": nr, "args": list(args),
            "target_pid": target_pid, "path": path,
            "filename": filename, "mode_field": mode_field,
            "nonce": nonce,
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
              budget=None, run_dir=Path("/tmp"), escalated_syscalls=None):
    """Convenience wrapper to call _handle_waitpid_event with the
    fake helpers from the fixture.

    Returns the budget so tests can assert on its state
    (total_records, dropped_by_category, etc.). Constructs a fresh
    budget per dispatch unless one is passed in for state-carrying
    multi-event sequences.

    `escalated_syscalls` defaults to None (not a fresh set()) so
    existing callers of this helper keep exercising the same
    escalation-disabled path `_handle_waitpid_event` used before live
    escalation existed — only tests that explicitly pass a set opt
    into observing the new stderr-banner behaviour.
    """
    from core.sandbox import audit_budget
    if budget is None:
        budget = audit_budget.AuditBudget()
    tracer._handle_waitpid_event(
        wpid, status, traced, target_pid, arch_info,
        run_dir, budget,
        ptrace_cont=helpers["ptrace_cont"],
        read_regs=helpers["read_regs"],
        decode_syscall=helpers["decode_syscall"],
        read_tracee_string=helpers["read_tracee_string"],
        get_event_msg=helpers["get_event_msg"],
        write_record=helpers["write_record"],
        escalated_syscalls=escalated_syscalls,
    )
    return budget


class TestExitedTracees:
    """When a tracee exits (cleanly or by signal), it gets dropped
    from the traced set. The loop terminates when the set is empty."""

    def test_exited_tracee_removed_from_traced(self, arch_info, fake_helpers):
        traced = {1000, 1001, 1002}
        _dispatch(
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
        # Robustness: a wpid not in `traced` (could happen if
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
        budget = _dispatch(
            1000, _ptrace_event_status(tracer._PTRACE_EVENT_SECCOMP),
            traced, 1000, arch_info, fake_helpers,
        )
        assert budget.total_records == 1, "budget should record one event"
        assert not budget.dropped_by_category
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
            self, arch_info, fake_helpers, tmp_path):
        """Budget cap drops further records but still resumes the
        tracee on every event. Uses a small AuditBudget for speed."""
        from core.sandbox import audit_budget
        # openat → file-open category. Cap that category at
        # 2 with no refill so the third dispatch drops.
        budget = audit_budget.AuditBudget(
            category_caps={"file-open": 2},
            refill_rates={"file-open": 0.0},
            sampling_rates={},
        )
        traced = {1000}
        for _ in range(5):
            _dispatch(
                1000, _ptrace_event_status(tracer._PTRACE_EVENT_SECCOMP),
                traced, 1000, arch_info, fake_helpers,
                budget=budget, run_dir=tmp_path,
            )
        # 2 records persisted (cap), but ptrace_cont fired all 5 times.
        assert len(fake_helpers["calls"]["write_record"]) == 2
        assert len(fake_helpers["calls"]["ptrace_cont"]) == 5
        assert budget.dropped_by_category["file-open"] == 3

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
        from core.sandbox import audit_budget
        budget = audit_budget.AuditBudget()
        traced = {1000}
        tracer._handle_waitpid_event(
            1000, _ptrace_event_status(tracer._PTRACE_EVENT_SECCOMP),
            traced, 1000, arch_info, Path("/tmp"), budget,
            read_regs=fail_read_regs, ptrace_cont=cont,
            decode_syscall=lambda *a: (0, [0]*6),
            read_tracee_string=lambda *a, **k: None,
            get_event_msg=lambda p: None,
            write_record=lambda *a, **k: True,
        )
        assert budget.total_records == 0  # no record written
        assert calls == [(1000, 0)]  # but tracee resumed


def _ptrace_syscall_nr(arch_info):
    """Reverse-lookup the syscall number for 'ptrace' on the current
    arch's syscall table — used to make fake_decode_syscall return an
    escape-primitive syscall instead of the fixture's default openat."""
    for nr, name in arch_info["syscall_table"].items():
        if name == "ptrace":
            return nr
    raise AssertionError("ptrace not in syscall table for this arch")


class TestLiveEscalation:
    """Live stderr escalation banner for escape-primitive syscalls —
    fires the moment tracer.py sees one denied, ahead of the run-end
    sandbox-triage.json classification. See tracer.py's
    _LIVE_ESCALATE_SYSCALLS / _announce_escape_primitive."""

    def test_escape_primitive_escalates_once(
            self, arch_info, fake_helpers, monkeypatch):
        writes = []
        monkeypatch.setattr(tracer.os, "write",
                            lambda fd, data: writes.append((fd, data)))
        ptrace_nr = _ptrace_syscall_nr(arch_info)
        fake_helpers["decode_syscall"] = (
            lambda regs, ai: (ptrace_nr, [0, 0, 0, 0, 0, 0]))

        traced = {1000}
        escalated: set = set()
        budget = _dispatch(
            1000, _ptrace_event_status(tracer._PTRACE_EVENT_SECCOMP),
            traced, 1000, arch_info, fake_helpers,
            escalated_syscalls=escalated,
        )
        assert budget.total_records == 1  # record still written normally
        assert len(writes) == 1
        assert writes[0][0] == 2  # stderr fd
        assert b"ptrace" in writes[0][1]
        assert escalated == {"ptrace"}

        # Second denial of the SAME syscall this run: no second banner.
        _dispatch(
            1000, _ptrace_event_status(tracer._PTRACE_EVENT_SECCOMP),
            traced, 1000, arch_info, fake_helpers,
            budget=budget, escalated_syscalls=escalated,
        )
        assert len(writes) == 1, "dedup: one banner per syscall name per run"

    def test_non_escape_primitive_syscall_does_not_escalate(
            self, arch_info, fake_helpers, monkeypatch):
        # Default fake_decode_syscall returns openat — not in
        # _LIVE_ESCALATE_SYSCALLS.
        writes = []
        monkeypatch.setattr(tracer.os, "write",
                            lambda fd, data: writes.append((fd, data)))
        traced = {1000}
        _dispatch(
            1000, _ptrace_event_status(tracer._PTRACE_EVENT_SECCOMP),
            traced, 1000, arch_info, fake_helpers,
            escalated_syscalls=set(),
        )
        assert writes == []

    def test_escalation_disabled_by_env_var(
            self, arch_info, fake_helpers, monkeypatch):
        monkeypatch.setenv("RAPTOR_SANDBOX_LIVE_ESCALATION_DISABLED", "1")
        writes = []
        monkeypatch.setattr(tracer.os, "write",
                            lambda fd, data: writes.append((fd, data)))
        ptrace_nr = _ptrace_syscall_nr(arch_info)
        fake_helpers["decode_syscall"] = (
            lambda regs, ai: (ptrace_nr, [0, 0, 0, 0, 0, 0]))
        traced = {1000}
        _dispatch(
            1000, _ptrace_event_status(tracer._PTRACE_EVENT_SECCOMP),
            traced, 1000, arch_info, fake_helpers,
            escalated_syscalls=set(),
        )
        assert writes == []

    def test_no_escalation_when_set_not_provided(
            self, arch_info, fake_helpers, monkeypatch):
        # escalated_syscalls defaults to None — callers that haven't
        # opted in (e.g. every other test in this file, via _dispatch's
        # own default) see no behaviour change at all.
        writes = []
        monkeypatch.setattr(tracer.os, "write",
                            lambda fd, data: writes.append((fd, data)))
        ptrace_nr = _ptrace_syscall_nr(arch_info)
        fake_helpers["decode_syscall"] = (
            lambda regs, ai: (ptrace_nr, [0, 0, 0, 0, 0, 0]))
        traced = {1000}
        _dispatch(
            1000, _ptrace_event_status(tracer._PTRACE_EVENT_SECCOMP),
            traced, 1000, arch_info, fake_helpers,
        )
        assert writes == []

    def test_escalation_never_raises_out_of_hot_path(
            self, arch_info, fake_helpers, monkeypatch):
        # os.write raising OSError (e.g. closed/redirected stderr)
        # must not propagate — the tracer's event loop must keep
        # running regardless of whether the banner could be printed.
        def raising_write(fd, data):
            raise OSError("stderr closed")
        monkeypatch.setattr(tracer.os, "write", raising_write)
        ptrace_nr = _ptrace_syscall_nr(arch_info)
        fake_helpers["decode_syscall"] = (
            lambda regs, ai: (ptrace_nr, [0, 0, 0, 0, 0, 0]))
        traced = {1000}
        budget = _dispatch(
            1000, _ptrace_event_status(tracer._PTRACE_EVENT_SECCOMP),
            traced, 1000, arch_info, fake_helpers,
            escalated_syscalls=set(),
        )
        # Record write + tracee resume still happened despite the
        # failed banner.
        assert budget.total_records == 1
        assert fake_helpers["calls"]["ptrace_cont"] == [(1000, 0)]


class TestBudgetMarkerNonce:
    """Budget marker records carry the per-run nonce like sibling
    data records and the end-of-run summary, so a nonce-validating
    parser attributes them to the run."""

    def _dispatch_over_cap(self, tmp_path, nonce):
        """Drive two seccomp-trace events through a cap-1 budget so
        the second emits a category-exhaust marker."""
        from unittest import mock

        from core.sandbox import audit_budget
        arch_info = tracer._ARCH_INFO[tracer._ARCH]
        markers = []

        def fake_write_record_dict(run_dir, record, *, filename=None):
            markers.append(dict(record))

        openat_nr = 257 if tracer._ARCH == "x86_64" else 56
        status = _ptrace_event_status(tracer._PTRACE_EVENT_SECCOMP)
        budget = audit_budget.AuditBudget(
            category_caps={"file-open": 1},
            refill_rates={"file-open": 0.0},
            sampling_rates={},
        )
        with mock.patch.object(
                tracer, "_write_record_dict", fake_write_record_dict):
            for _ in range(2):
                tracer._handle_waitpid_event(
                    1000, status, {1000}, 1000, arch_info,
                    Path(tmp_path), budget,
                    observe_nonce=nonce,
                    ptrace_cont=lambda pid, sig=0: True,
                    read_regs=lambda pid, ai: b"\x00" * ai["user_regs_size"],
                    decode_syscall=lambda regs, ai: (
                        openat_nr, [0, 0, 0, 0, 0, 0]),
                    read_tracee_string=lambda pid, addr, max_bytes=4096: (
                        "/etc/test"),
                    get_event_msg=lambda pid: 0,
                    write_record=lambda *a, **k: True,
                )
        return markers

    def test_marker_carries_nonce(self, tmp_path):
        markers = self._dispatch_over_cap(tmp_path, nonce="run-nonce-1")
        assert markers, "cap-1 budget should have emitted a marker"
        for marker in markers:
            assert marker.get("nonce") == "run-nonce-1"

    def test_no_nonce_leaves_marker_unstamped(self, tmp_path):
        # Audit mode (no nonce): markers must not gain a None field.
        markers = self._dispatch_over_cap(tmp_path, nonce=None)
        assert markers
        for marker in markers:
            assert "nonce" not in marker


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

        from core.sandbox import audit_budget
        budget = audit_budget.AuditBudget()
        traced = {1000}
        tracer._handle_waitpid_event(
            1000, _ptrace_event_status(tracer._PTRACE_EVENT_FORK),
            traced, 1000, arch_info, Path("/tmp"), budget,
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
        # In production, the kernel always delivers the parent's
        # PTRACE_EVENT_FORK before the child's auto-attached SIGSTOP,
        # so by the time SIGSTOP fires the new tracee is already in
        # `traced` from the FORK-event branch. Set up that precondition
        # explicitly here.
        traced = {1000, 99999}  # 99999 already added by FORK event
        _dispatch(
            99999, _stop_status(signal.SIGSTOP),
            traced, 1000, arch_info, fake_helpers,
        )
        # PTRACE_CONT with sig=0 (NOT signal.SIGSTOP) — the SIGSTOP
        # is consumed, not forwarded.
        assert fake_helpers["calls"]["ptrace_cont"] == [(99999, 0)]
        # 99999 stays in traced (we don't remove on SIGSTOP).
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
        budget = _dispatch(
            1000, 0xffff, traced, 1000, arch_info, fake_helpers,
        )
        # No record, no resume, no set mutation
        assert traced == {1000}
        assert budget.total_records == 0
        assert fake_helpers["calls"]["ptrace_cont"] == []


class TestHostileArgEscalation:
    """socket()/ioctl() live escalation keys on the DECODED argument
    (tty-hijack ioctls, AF_PACKET/SOCK_RAW) — a plain AF_UNIX denial
    must stay silent."""

    def _dispatch_syscall(self, arch_info, fake_helpers, nr, args,
                          escalated, monkeypatch, writes):
        monkeypatch.setattr(
            tracer, "_announce_escape_primitive",
            lambda name, pid: writes.append(name))
        helpers = dict(fake_helpers)
        helpers["decode_syscall"] = lambda regs, ai: (nr, list(args))
        traced = {1234}
        _dispatch(1234, _ptrace_event_status(tracer._PTRACE_EVENT_SECCOMP),
                  traced, 1234,
                  arch_info, helpers, escalated_syscalls=escalated)

    def _nr(self, arch_info, name):
        return next(nr for nr, n in arch_info["syscall_table"].items()
                    if n == name)

    def test_tiocsti_ioctl_escalates_with_decoded_label(
            self, arch_info, fake_helpers, monkeypatch):
        writes, escalated = [], set()
        nr = self._nr(arch_info, "ioctl")
        self._dispatch_syscall(arch_info, fake_helpers, nr,
                               [0, 0x5412, 0, 0, 0, 0],
                               escalated, monkeypatch, writes)
        assert writes == ["ioctl(TIOCSTI)"]
        assert "ioctl(TIOCSTI)" in escalated

    def test_raw_socket_escalates_and_dedups_per_label(
            self, arch_info, fake_helpers, monkeypatch):
        writes, escalated = [], set()
        nr = self._nr(arch_info, "socket")
        for _ in range(3):
            self._dispatch_syscall(arch_info, fake_helpers, nr,
                                   [2, 3, 0, 0, 0, 0],
                                   escalated, monkeypatch, writes)
        assert writes == ["socket(SOCK_RAW)"]

    def test_af_unix_socket_denial_stays_silent(
            self, arch_info, fake_helpers, monkeypatch):
        writes, escalated = [], set()
        nr = self._nr(arch_info, "socket")
        self._dispatch_syscall(arch_info, fake_helpers, nr,
                               [1, 1, 0, 0, 0, 0],
                               escalated, monkeypatch, writes)
        assert writes == []

    def test_benign_ioctl_stays_silent(
            self, arch_info, fake_helpers, monkeypatch):
        writes, escalated = [], set()
        nr = self._nr(arch_info, "ioctl")
        self._dispatch_syscall(arch_info, fake_helpers, nr,
                               [0, 0x5413, 0, 0, 0, 0],  # TIOCGWINSZ
                               escalated, monkeypatch, writes)
        assert writes == []


class TestSymlinkAwareSuppression:
    """Filtered audit mode decides should_log from a path string read
    out of tracee memory. A symlink under an allowlisted/writable
    prefix that aliases a file OUTSIDE the allowlist
    (``<writable>/x -> <secrets>``) must NOT have its record
    suppressed: the kernel resolves the real target while the lexical
    match would hide the access (and with it the
    credential_path_touch signal)."""

    def _alias_layout(self, tmp_path):
        allowed = tmp_path / "writable"
        allowed.mkdir()
        secrets = tmp_path / "secrets"
        secrets.mkdir()
        (secrets / "id_rsa").write_text("KEY MATERIAL")
        (allowed / "x").symlink_to(secrets)
        return allowed, str(allowed / "x" / "id_rsa")

    def test_symlink_alias_out_of_allowlist_not_suppressed(self, tmp_path):
        allowed, alias = self._alias_layout(tmp_path)
        allowlist = [str(allowed)]
        # The lexical layer alone matches — that was the pre-fix
        # suppression condition.
        assert tracer._path_in_allowlist(alias, allowlist) is True
        # The suppression decision must refuse it.
        assert tracer._suppress_allowlisted_path(alias, allowlist) is False

    def test_real_file_under_allowlist_suppressed(self, tmp_path):
        allowed = tmp_path / "writable"
        allowed.mkdir()
        p = allowed / "scratch.txt"
        p.write_text("ok")
        assert tracer._suppress_allowlisted_path(
            str(p), [str(allowed)]) is True

    def test_symlink_within_allowlist_still_suppressed(self, tmp_path):
        """A symlink whose REAL target is also allowlisted is the
        benign case — keep dropping it, or filtered mode regresses to
        verbose for every in-tree symlink."""
        allowed = tmp_path / "writable"
        allowed.mkdir()
        (allowed / "real.txt").write_text("ok")
        (allowed / "link.txt").symlink_to(allowed / "real.txt")
        assert tracer._suppress_allowlisted_path(
            str(allowed / "link.txt"), [str(allowed)]) is True

    def test_nonexistent_path_under_allowlist_suppressed(self, tmp_path):
        """O_CREAT of a not-yet-existing file under a writable prefix:
        realpath is the identity, the drop decision stands."""
        allowed = tmp_path / "writable"
        allowed.mkdir()
        assert tracer._suppress_allowlisted_path(
            str(allowed / "new-file"), [str(allowed)]) is True

    def _dispatch_openat(self, arch_info, fake_helpers, tmp_path,
                         abs_path, audit_filter):
        from core.sandbox import audit_budget
        budget = audit_budget.AuditBudget()
        nr_openat = 257 if tracer._ARCH == "x86_64" else 56
        tracer._handle_waitpid_event(
            1000, _ptrace_event_status(tracer._PTRACE_EVENT_SECCOMP),
            {1000}, 1000, arch_info,
            tmp_path, budget,
            audit_filter=audit_filter,
            ptrace_cont=fake_helpers["ptrace_cont"],
            read_regs=fake_helpers["read_regs"],
            # openat(dirfd=AT_FDCWD-as-unsigned, path, O_RDONLY, ...)
            decode_syscall=lambda regs, ai: (
                nr_openat, [(1 << 64) - 100, 0xcafef00d, 0, 0, 0, 0]
            ),
            read_tracee_string=lambda pid, addr, max_bytes=4096: abs_path,
            get_event_msg=fake_helpers["get_event_msg"],
            write_record=fake_helpers["write_record"],
            resolve_path=lambda pid, path, dirfd: abs_path,
        )
        return fake_helpers["calls"]["write_record"]

    def test_event_loop_logs_symlink_aliased_read(
            self, arch_info, fake_helpers, tmp_path):
        """End-to-end through _handle_waitpid_event: the aliased open
        must produce a record in filtered mode (pre-fix: dropped)."""
        allowed, alias = self._alias_layout(tmp_path)
        audit_filter = {
            "verbose": False,
            "read_allowlist": [str(allowed)],
            "writable_paths": [str(allowed)],
        }
        records = self._dispatch_openat(
            arch_info, fake_helpers, tmp_path, alias, audit_filter)
        assert len(records) == 1
        assert records[0]["path"] == alias

    def test_event_loop_still_drops_genuine_allowlisted_read(
            self, arch_info, fake_helpers, tmp_path):
        allowed = tmp_path / "writable"
        allowed.mkdir()
        genuine = allowed / "notes.txt"
        genuine.write_text("ok")
        audit_filter = {
            "verbose": False,
            "read_allowlist": [str(allowed)],
            "writable_paths": [str(allowed)],
        }
        records = self._dispatch_openat(
            arch_info, fake_helpers, tmp_path, str(genuine), audit_filter)
        assert records == []


class TestRecordArgEnrichment:
    def test_write_record_decodes_socket_and_ioctl(self, tmp_path):
        import json as _json
        tracer._write_record(tmp_path, "socket", 41,
                             [17, 3, 768, 0, 0, 0], 4242)
        tracer._write_record(tmp_path, "ioctl", 16,
                             [0, 0x5412, 0, 0, 0, 0], 4242)
        tracer._write_record(tmp_path, "ptrace", 101,
                             [0, 0, 0, 0, 0, 0], 4242)
        jsonl = tmp_path / ".audit" / ".sandbox-denials.jsonl"
        records = [_json.loads(line)
                   for line in jsonl.read_text().splitlines()]
        by_name = {r["syscall"]: r for r in records}
        assert by_name["socket"]["socket_family"] == "AF_PACKET"
        assert by_name["socket"]["socket_type"] == "SOCK_RAW"
        assert by_name["ioctl"]["ioctl_cmd"] == "TIOCSTI"
        assert "ioctl_cmd" not in by_name["ptrace"]


class TestOpenat2StructReadInjectable:
    """The openat2 ``struct open_how`` deref goes through the injected
    ``read_tracee_bytes`` helper — like every other ptrace side-effect
    in the dispatch, tests can exercise the branch without a real
    tracee."""

    _OPENAT2_NR = 437  # same number on x86_64 and aarch64

    def _dispatch_openat2(self, arch_info, fake_helpers, how_flags,
                          audit_filter=None):
        import struct as _struct

        from core.sandbox import audit_budget

        bytes_calls = []

        def fake_read_tracee_bytes(pid, addr, n_bytes):
            bytes_calls.append((pid, addr, n_bytes))
            return _struct.pack("<Q", how_flags)

        budget = audit_budget.AuditBudget()
        tracer._handle_waitpid_event(
            1000, _ptrace_event_status(tracer._PTRACE_EVENT_SECCOMP),
            {1000}, 1000, arch_info,
            Path("/tmp"), budget,
            audit_filter=audit_filter,
            ptrace_cont=fake_helpers["ptrace_cont"],
            read_regs=fake_helpers["read_regs"],
            decode_syscall=lambda regs, ai: (
                self._OPENAT2_NR, [0, 0xcafef00d, 0xfeed0000, 24, 0, 0]
            ),
            read_tracee_string=fake_helpers["read_tracee_string"],
            read_tracee_bytes=fake_read_tracee_bytes,
            get_event_msg=fake_helpers["get_event_msg"],
            write_record=fake_helpers["write_record"],
            resolve_path=lambda pid, path, dirfd: "/etc/test",
        )
        return bytes_calls, budget

    def test_injected_helper_reads_open_how_struct(
            self, arch_info, fake_helpers):
        bytes_calls, _ = self._dispatch_openat2(
            arch_info, fake_helpers, how_flags=0,  # O_RDONLY
        )
        # First 8 bytes of *args[2] = struct open_how.flags.
        assert bytes_calls == [(1000, 0xfeed0000, 8)]
        records = fake_helpers["calls"]["write_record"]
        assert len(records) == 1
        assert records[0]["name"] == "openat2"

    def test_injected_flags_drive_write_intent_filtering(
            self, arch_info, fake_helpers):
        # Filtered mode with reads unrestricted: an O_RDONLY openat2
        # (flags decoded through the injected helper) is dropped; an
        # O_WRONLY one outside writable_paths is kept.
        audit_filter = {
            "verbose": False,
            "read_allowlist": None,
            "writable_paths": ["/nowhere"],
        }
        self._dispatch_openat2(
            arch_info, fake_helpers, how_flags=0,  # O_RDONLY → dropped
            audit_filter=audit_filter,
        )
        assert fake_helpers["calls"]["write_record"] == []
        self._dispatch_openat2(
            arch_info, fake_helpers, how_flags=1,  # O_WRONLY → kept
            audit_filter=audit_filter,
        )
        records = fake_helpers["calls"]["write_record"]
        assert len(records) == 1
        assert records[0]["name"] == "openat2"
