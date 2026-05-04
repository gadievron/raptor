"""Tests for core.sandbox.tracer — the audit-mode ptrace subprocess.

Commit 3 scope: building blocks of the tracer (ctypes plumbing, syscall
name lookup, register decoding, JSONL writes, attach/detach handshake).
The full event-loop integration (catching real SECCOMP_RET_TRACE events)
requires the seccomp.audit_mode changes that land in commit 4 — that's
where the end-to-end test will live.
"""

from __future__ import annotations

import sys as _sys
import pytest as _pytest
pytestmark = _pytest.mark.skipif(
    _sys.platform != "linux",
    reason="Linux-only sandbox internals (mount-ns / Landlock / seccomp / ptrace tracer / pid1 shim) — see core/sandbox/_macos_spawn.py for the macOS path",
)


import ctypes
import json
import os
import platform
import struct
import subprocess
import sys
import time
from pathlib import Path

import pytest

from core.sandbox import tracer


# Skip the whole module on archs the tracer doesn't support (currently
# x86_64 + aarch64). On supported archs the SeizeAndDetach test runs
# real ptrace; on unsupported archs the module-level skip avoids
# pulling in code paths that need _arch_info().
pytestmark = pytest.mark.skipif(
    not tracer._is_supported_arch(),
    reason=f"tracer doesn't support {platform.machine()} (x86_64/aarch64 only)",
)


class TestLibcCacheSentinel:
    """N1: _get_libc caches BOTH success and failure to avoid repeated
    find_library calls on systems where libc isn't usable. Tests pin
    the negative-cache behaviour."""

    def test_failure_is_cached(self, monkeypatch):
        # Reset cache, force find_library to return None, call twice,
        # assert find_library was only called ONCE.
        monkeypatch.setattr(tracer, "_libc", None)
        call_count = [0]
        def fake_find(name):
            call_count[0] += 1
            return None
        monkeypatch.setattr("ctypes.util.find_library", fake_find)

        first = tracer._get_libc()
        second = tracer._get_libc()
        assert first is None
        assert second is None
        # Exactly one find_library call — second was satisfied from cache.
        assert call_count[0] == 1, (
            f"expected find_library called once (cache hit on second), "
            f"got {call_count[0]} calls"
        )

    def test_failure_sentinel_is_distinct_from_unprobed(self):
        # The cache uses None for "unprobed" and _LIBC_UNAVAILABLE for
        # "tried, failed." Distinct sentinels are required so the
        # negative-cache path can be detected.
        assert tracer._LIBC_UNAVAILABLE is not None
        # Sentinel must NOT be a CDLL handle (would conflict with
        # success-cache check).
        assert not isinstance(tracer._LIBC_UNAVAILABLE, ctypes.CDLL)


class TestArchSupport:
    def test_supported_archs_include_x86_64_and_aarch64(self):
        assert "x86_64" in tracer._ARCH_INFO
        assert "aarch64" in tracer._ARCH_INFO

    def test_current_arch_is_supported_or_skip(self):
        # Module-level pytestmark would have skipped if not supported.
        assert tracer._is_supported_arch() is True
        assert tracer._arch_info() is not None

    @pytest.mark.parametrize("arch", ["x86_64", "aarch64"])
    def test_arch_info_entry_is_well_formed(self, arch):
        """Every supported arch's _ARCH_INFO entry must be structurally
        valid: positive regs size, six args slots, syscall_nr offset
        within bounds, non-empty syscall table.

        Catches transcription bugs the unit tests above would miss
        (e.g., 5 args instead of 6, regs_size=0, syscall_nr offset
        beyond regs region) without needing to actually run on the
        target arch — which is the whole point: aarch64 lives in CI
        only on dev's x86_64 box if at all, so structural validation
        on x86_64 protects future aarch64 deployments.
        """
        info = tracer._ARCH_INFO[arch]
        # Six syscall args is the Linux ABI on all supported archs.
        assert len(info["arg_offsets"]) == 6, (
            f"{arch}: expected 6 arg offsets, got {len(info["arg_offsets"])}")
        # All offsets land within the regs region.
        assert info["user_regs_size"] > 0, (
            f"{arch}: user_regs_size must be > 0")
        assert 0 <= info["syscall_nr_offset"] < info["user_regs_size"], (
            f"{arch}: syscall_nr_offset {info["syscall_nr_offset"]} out of "
            f"range [0, {info["user_regs_size"]})")
        for i, off in enumerate(info["arg_offsets"]):
            assert 0 <= off < info["user_regs_size"], (
                f"{arch}: arg[{i}] offset {off} out of range "
                f"[0, {info["user_regs_size"]})")
        # Syscall table must cover the union of b2 (blocklist) + b3
        # (file/network) syscalls — emptiness would mean the audit
        # tracer reports `unknown_<nr>` for everything.
        assert len(info["syscall_table"]) > 0, (
            f"{arch}: empty syscall_table")

    @pytest.mark.parametrize("arch", ["x86_64", "aarch64"])
    def test_arch_syscall_numbers_are_unique(self, arch):
        """No two syscall names map from the same number — an accidental
        duplicate (typo) would silently mask one of them. Distinct
        numbers means the dict size equals the value-set size.
        """
        info = tracer._ARCH_INFO[arch]
        assert len(set(info["syscall_table"].values())) == \
            len(info["syscall_table"]), (
                f"{arch}: duplicate syscall name in table — "
                f"check for transcription error")

    @pytest.mark.parametrize("arch", ["x86_64", "aarch64"])
    def test_arch_syscall_numbers_are_positive(self, arch):
        """Linux syscall numbers are positive small ints. A negative
        or zero key would be a transcription error (and would never
        match a real syscall_nr from regs).
        """
        info = tracer._ARCH_INFO[arch]
        for nr in info["syscall_table"]:
            assert nr > 0, (
                f"{arch}: syscall_nr {nr} non-positive")
            # Sanity upper bound — current Linux syscall nrs are well
            # under 1000; anything past 10000 is almost certainly a
            # typo (e.g., a hex value pasted as decimal).
            assert nr < 10000, (
                f"{arch}: syscall_nr {nr} suspiciously large "
                f"(name={info["syscall_table"][nr]!r})")


class TestSyscallNameLookup:
    """The hardcoded per-arch syscall tables cover the union of the
    seccomp blocklist + the b3 path syscalls. Pin the entries each
    arch's audit-mode consumers downstream will rely on."""

    # x86_64
    def test_x86_64_b3_path_syscalls_present(self):
        assert tracer._X86_64_SYSCALL_NAMES[2] == "open"
        assert tracer._X86_64_SYSCALL_NAMES[257] == "openat"

    def test_x86_64_b3_network_syscall_present(self):
        assert tracer._X86_64_SYSCALL_NAMES[42] == "connect"

    def test_x86_64_b2_blocklist_syscalls_present(self):
        assert tracer._X86_64_SYSCALL_NAMES[101] == "ptrace"
        assert tracer._X86_64_SYSCALL_NAMES[321] == "bpf"
        assert tracer._X86_64_SYSCALL_NAMES[323] == "userfaultfd"
        assert tracer._X86_64_SYSCALL_NAMES[425] == "io_uring_setup"

    # aarch64 — different syscall numbers from x86_64; pin the values
    # so a transcription error from asm-generic/unistd.h gets caught.
    def test_aarch64_b3_path_syscalls_present(self):
        # NOTE: aarch64 has no `open` syscall — only openat exists.
        assert tracer._AARCH64_SYSCALL_NAMES[56] == "openat"
        assert 2 not in tracer._AARCH64_SYSCALL_NAMES, \
            "aarch64 has no `open` syscall; entry 2 must not be present"

    def test_aarch64_b3_network_syscall_present(self):
        assert tracer._AARCH64_SYSCALL_NAMES[203] == "connect"

    def test_aarch64_b2_blocklist_syscalls_present(self):
        assert tracer._AARCH64_SYSCALL_NAMES[117] == "ptrace"
        assert tracer._AARCH64_SYSCALL_NAMES[280] == "bpf"
        assert tracer._AARCH64_SYSCALL_NAMES[282] == "userfaultfd"
        # io_uring_setup is the same number on both archs (425) — sanity
        # check that the architecturally-stable syscalls match.
        assert tracer._AARCH64_SYSCALL_NAMES[425] == "io_uring_setup"

    def test_io_uring_set_matches_across_archs(self):
        # io_uring_setup/enter/register were added unified across archs
        # (425/426/427). Pin that consistency so a future re-numbering
        # mistake gets caught.
        for nr in (425, 426, 427):
            assert (tracer._X86_64_SYSCALL_NAMES[nr]
                    == tracer._AARCH64_SYSCALL_NAMES[nr])

    def test_openat2_present_both_archs(self):
        """openat2 is Linux 5.6+. It uses the unified syscall number
        (437) on both x86_64 and aarch64. Without coverage here, code
        that uses openat2 directly (glibc on newer kernels, io_uring
        users, modern curl) is invisible to the audit tracer."""
        assert tracer._X86_64_SYSCALL_NAMES[437] == "openat2"
        assert tracer._AARCH64_SYSCALL_NAMES[437] == "openat2"

    def test_openat2_path_arg_index_matches_openat(self):
        """openat2 signature is (dirfd, pathname, &how, size). The path
        argument is at the same position as openat — index 1. If this
        ever drifts, the tracer will deref the wrong arg."""
        assert tracer._path_arg_index("openat2") == 1
        assert tracer._path_arg_index("openat2") == \
            tracer._path_arg_index("openat")

    def test_openat2_in_seccomp_audit_extras(self):
        """The seccomp filter swap to SCMP_ACT_TRACE for openat2 is what
        makes the kernel notify the tracer on openat2 calls. Without
        this, the tracer never sees them. Cross-module structural pin
        — keeps tracer table + seccomp filter in agreement."""
        from core.sandbox import seccomp
        assert "openat2" in seccomp._AUDIT_EXTRA_TRACE_SYSCALLS

    def test_io_uring_setup_has_visibility_gap_note(self):
        """io_uring SQEs (file/network ops submitted to the ring after
        setup) bypass the syscall layer entirely — seccomp tracing
        cannot see them. The audit record for io_uring_setup must
        carry an explicit `note` so an operator reading the JSONL
        knows subsequent activity by the same process is dark.
        Without this, an operator might see "io_uring_setup" once
        and assume the rest of the workload was traced normally."""
        note = tracer._VISIBILITY_GAP_NOTES.get("io_uring_setup")
        assert note is not None, (
            "io_uring_setup must have a visibility-gap note so "
            "operators don't miss the SQE-level audit blind spot"
        )
        # Note text must mention the specific bypass mechanism so
        # the operator can correlate it with what they observe.
        for required in ("io_uring", "untraceable"):
            assert required in note.lower(), (
                f"io_uring note must mention {required!r}: {note!r}"
            )


class TestDenialTypeMapping:
    """Tracer writes to the same JSONL as record_denial. The `type`
    field has to match the existing taxonomy (seccomp / write / network)
    so the summary aggregator interprets correctly."""

    def test_open_maps_to_write(self):
        assert tracer._denial_type("open") == "write"
        assert tracer._denial_type("openat") == "write"

    def test_connect_maps_to_network(self):
        assert tracer._denial_type("connect") == "network"

    def test_blocklist_syscall_maps_to_seccomp(self):
        # Anything not explicitly mapped → seccomp (the default for
        # blocklist syscalls)
        assert tracer._denial_type("ptrace") == "seccomp"
        assert tracer._denial_type("bpf") == "seccomp"
        assert tracer._denial_type("perf_event_open") == "seccomp"

    def test_unknown_syscall_defaults_to_seccomp(self):
        assert tracer._denial_type("unknown_99999") == "seccomp"


class TestRegisterDecode:
    """Decoder is arch-agnostic: takes a raw user_regs_struct buffer +
    the active arch's info dict. Build synthetic buffers per arch and
    verify the decoder extracts the right fields."""

    def _build_regs(self, arch: str, syscall_nr: int,
                    args: tuple = ()) -> bytes:
        """Pack a user_regs_struct for `arch` with a syscall nr and
        up to 6 arg values, others zero."""
        info = tracer._ARCH_INFO[arch]
        buf = bytearray(info["user_regs_size"])
        struct.pack_into("<Q", buf, info["syscall_nr_offset"], syscall_nr)
        for i, value in enumerate(args):
            if i >= len(info["arg_offsets"]):
                break
            struct.pack_into("<Q", buf, info["arg_offsets"][i], value)
        return bytes(buf)

    def test_x86_64_decodes_orig_rax_as_syscall_number(self):
        regs = self._build_regs("x86_64", syscall_nr=257)
        nr, args = tracer._decode_syscall(regs, tracer._ARCH_INFO["x86_64"])
        assert nr == 257
        assert args == [0, 0, 0, 0, 0, 0]

    def test_x86_64_decodes_six_args_in_correct_order(self):
        # Linux x86_64 syscall ABI: rdi, rsi, rdx, r10, r8, r9
        regs = self._build_regs("x86_64", 42, (10, 20, 30, 40, 50, 60))
        nr, args = tracer._decode_syscall(regs, tracer._ARCH_INFO["x86_64"])
        assert nr == 42
        assert args == [10, 20, 30, 40, 50, 60]

    def test_aarch64_decodes_x8_as_syscall_number(self):
        # openat on aarch64 = 56
        regs = self._build_regs("aarch64", syscall_nr=56)
        nr, args = tracer._decode_syscall(regs, tracer._ARCH_INFO["aarch64"])
        assert nr == 56
        assert args == [0, 0, 0, 0, 0, 0]

    def test_aarch64_decodes_six_args_in_correct_order(self):
        # Linux aarch64 syscall ABI: x0..x5
        regs = self._build_regs("aarch64", 203, (11, 22, 33, 44, 55, 66))
        nr, args = tracer._decode_syscall(regs, tracer._ARCH_INFO["aarch64"])
        assert nr == 203
        assert args == [11, 22, 33, 44, 55, 66]

    def test_aarch64_buffer_size_differs_from_x86_64(self):
        # Sanity: aarch64's user_regs_struct (272 bytes) is larger than
        # x86_64's (216 bytes). A common copy-paste bug would re-use the
        # x86_64 size for aarch64; this catches it.
        assert (tracer._ARCH_INFO["x86_64"]["user_regs_size"]
                != tracer._ARCH_INFO["aarch64"]["user_regs_size"])
        assert tracer._ARCH_INFO["aarch64"]["user_regs_size"] == 272

    def test_decodes_max_uint64_args(self):
        # Confirm uint64 (not signed) — arg values close to 2**64 must
        # decode without sign-extension. Run on x86_64 since that's the
        # CI host; aarch64 path is exercised via the synthetic buffer.
        max_val = (1 << 64) - 1
        regs = self._build_regs("x86_64", 257, (max_val, max_val))
        nr, args = tracer._decode_syscall(regs, tracer._ARCH_INFO["x86_64"])
        assert nr == 257
        assert args[0] == max_val
        assert args[1] == max_val


class TestJsonlRecordWrite:
    """Tracer writes records directly to the run's JSONL with the
    same shape as record_denial, so summary.summarize_and_write
    aggregates both sources transparently."""

    def test_writes_record_with_expected_fields(self, tmp_path):
        ok = tracer._write_record(
            tmp_path, "openat", 257,
            [0xdeadbeef, 0x1000, 0o644, 0, 0, 0],
            target_pid=12345,
        )
        assert ok is True

        path = tmp_path / tracer._DENIALS_FILENAME
        assert path.exists()
        records = [json.loads(line) for line in path.read_text().splitlines() if line]
        assert len(records) == 1
        r = records[0]
        # Match the record_denial output shape so summary aggregator works.
        assert r["type"] == "write"
        assert r["audit"] is True
        assert r["syscall"] == "openat"
        assert r["syscall_nr"] == 257
        # All six args logged — consumer interprets per-syscall meaning.
        assert r["args"] == [0xdeadbeef, 0x1000, 0o644, 0, 0, 0]
        assert r["returncode"] == 0
        assert "ts" in r
        assert "12345" in r["cmd"]

    def test_appends_multiple_records(self, tmp_path):
        # Multiple writes should append, not overwrite.
        for i in range(3):
            tracer._write_record(tmp_path, "openat", 257,
                                 [i, 0, 0, 0, 0, 0], target_pid=1)

        path = tmp_path / tracer._DENIALS_FILENAME
        records = [json.loads(line) for line in path.read_text().splitlines() if line]
        assert len(records) == 3
        # First arg differs per record; assert against args[0] specifically.
        assert [r["args"][0] for r in records] == [0, 1, 2]

    def test_write_to_unwritable_dir_returns_false_silently(self, tmp_path):
        # Tracer must NEVER raise — failed writes return False.
        bad = tmp_path / "does-not-exist-and-cant-be-created"
        bad.touch()  # Make it a FILE, not a dir, so mkdir fails silently
        ok = tracer._write_record(bad, "openat", 257,
                                  [0, 0, 0, 0, 0, 0], target_pid=1)
        assert ok is False

    def test_o_nofollow_refuses_symlink(self, tmp_path):
        # Mirror the same defense record_denial uses — symlink at the
        # JSONL path must NOT be followed.
        target = tmp_path / "evil-target"
        target.write_text("ATTACKER OWNED\n")
        link = tmp_path / tracer._DENIALS_FILENAME
        os.symlink(target, link)

        ok = tracer._write_record(tmp_path, "openat", 257,
                                  [0, 0, 0, 0, 0, 0], target_pid=1)
        # O_NOFOLLOW refuses; tracer reports failure but doesn't crash.
        assert ok is False
        # Target is unmodified.
        assert target.read_text() == "ATTACKER OWNED\n"


class TestReadRegsContract:
    """K1 / K4 contract checks via direct attribute access. The
    partial-regset rejection (`if iov.iov_len < size: return None`) is
    inspected here at the structural level — exercising it via a real
    libc.ptrace mock requires kernel-side iov mutation that's awkward
    to fake from Python. Integration tests in commit 4 (real seccomp
    filter + traced child) cover the live behaviour."""

    def test_iovec_iov_len_is_int_comparable(self):
        # The K1 check relies on `iov.iov_len < size` (int comparison
        # against the requested size). Pin that ctypes exposes iov_len
        # as something that compares to int correctly — otherwise
        # the guard is silently a no-op.
        iov = tracer._Iovec()
        iov.iov_len = 100
        assert iov.iov_len < 200
        assert iov.iov_len == 100
        assert iov.iov_len > 0

    def test_read_regs_rejects_unsupported_arch(self, monkeypatch):
        # K4 contract: arch_info is REQUIRED. Passing an arch_info dict
        # whose user_regs_size is 0 (the unsupported-arch sentinel) is
        # not a thing — we'd never construct one. But we CAN verify
        # that libc-missing → None.
        monkeypatch.setattr(tracer, "_get_libc", lambda: None)
        result = tracer._read_regs(
            12345, tracer._ARCH_INFO[tracer._ARCH],
        )
        assert result is None
    """`python -m core.sandbox.tracer <pid> <run_dir> [<sync_fd>]`
    argument parsing — the parent's spawn code invokes this form."""

    def test_no_args_returns_2(self, capsys):
        rc = tracer._cli_main([])
        assert rc == 2
        err = capsys.readouterr().err
        assert "Usage" in err

    def test_too_many_args_returns_2(self, capsys):
        # 4 args is now valid (config_path); 5 is too many.
        rc = tracer._cli_main(["1", "/tmp", "3", "/tmp/cfg", "extra"])
        assert rc == 2

    def test_non_integer_pid_returns_2(self, capsys):
        rc = tracer._cli_main(["not-a-pid", "/tmp"])
        assert rc == 2
        err = capsys.readouterr().err
        assert "integer" in err

    def test_non_integer_sync_fd_returns_2(self, capsys):
        rc = tracer._cli_main(["1", "/tmp", "not-a-fd"])
        assert rc == 2

    def test_negative_pid_rejected_at_parse_time(self, tmp_path, capsys):
        # L2: PID 0 / negative PIDs are rejected before any ptrace call.
        rc = tracer._cli_main(["-1", str(tmp_path)])
        assert rc == 1
        err = capsys.readouterr().err
        assert "must be positive" in err

    def test_zero_pid_rejected_at_parse_time(self, tmp_path, capsys):
        # PID 0 means "current process group" in some contexts;
        # explicit footgun-rejection.
        rc = tracer._cli_main(["0", str(tmp_path)])
        assert rc == 1
        err = capsys.readouterr().err
        assert "must be positive" in err

    def test_negative_sync_fd_rejected(self, tmp_path, capsys):
        rc = tracer._cli_main(["123", str(tmp_path), "-1"])
        assert rc == 1
        err = capsys.readouterr().err
        assert "non-negative" in err

    def test_nonexistent_run_dir_rejected_at_startup(self, tmp_path, capsys):
        # L1: bad run_dir is caught at CLI entry, before SEIZE.
        bogus = tmp_path / "does-not-exist"
        rc = tracer._cli_main(["123", str(bogus)])
        assert rc == 1
        err = capsys.readouterr().err
        assert "not a directory" in err

    def test_run_dir_that_is_a_file_rejected(self, tmp_path, capsys):
        f = tmp_path / "a-file"
        f.write_text("")
        rc = tracer._cli_main(["123", str(f)])
        assert rc == 1
        err = capsys.readouterr().err
        assert "not a directory" in err

    def test_unwritable_run_dir_rejected(self, tmp_path, capsys):
        # Skip if running as root (root bypasses POSIX permission checks).
        if os.geteuid() == 0:
            pytest.skip("running as root bypasses W_OK check")
        readonly = tmp_path / "readonly"
        readonly.mkdir()
        # 0o500 = read+execute, no write. Owner cannot write into it.
        readonly.chmod(0o500)
        try:
            rc = tracer._cli_main(["123", str(readonly)])
            assert rc == 1
            err = capsys.readouterr().err
            assert "not writable" in err
        finally:
            # Restore permissions so tmp_path cleanup can remove it.
            readonly.chmod(0o700)


class TestSeizeAndDetachLifecycle:
    """End-to-end sanity test of the ptrace handshake against a real
    child. Forks a sleep process, attaches via PTRACE_SEIZE, verifies
    the attach succeeded, then detaches cleanly. Doesn't drive the
    full event loop — that needs seccomp integration (commit 4)."""

    def test_seize_interrupt_detach_against_sleeping_child(self):
        # Fork a sleeper, SEIZE it, INTERRUPT to bring to a group-stop,
        # waitpid for the stop, then DETACH. This is the minimal full
        # ptrace handshake — proves our ctypes plumbing is correct
        # against a real running process. Spawned via subprocess (not
        # os.fork) to avoid fork-after-threads in pytest.
        # NOTE: subprocess.Popen ITSELF is the parent of the sleeper —
        # but for ptrace purposes the test process is treated as the
        # eventual ptracer via SEIZE, which works regardless of who
        # forked the target (Yama scope 1 permits tracing descendants;
        # subprocess-spawned processes are descendants).
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
        )
        try:
            # Brief settle so the child is actually running.
            time.sleep(0.05)

            seized = tracer._ptrace_seize(child.pid)
            assert seized is True, "PTRACE_SEIZE failed — Yama scope 3?"

            # Bring the running tracee to a group-stop so DETACH has
            # a stop state to consume.
            interrupted = tracer._ptrace_interrupt(child.pid)
            assert interrupted is True

            # Reap the stop event.
            wpid, status = os.waitpid(child.pid, 0)
            assert os.WIFSTOPPED(status), \
                f"expected stop after INTERRUPT, got status={status:#x}"

            detached = tracer._ptrace_detach(child.pid)
            assert detached is True
        finally:
            child.kill()
            child.wait(timeout=5)

    def test_seize_nonexistent_pid_returns_false(self):
        # Use 2**31-1 which is well above /proc/sys/kernel/pid_max
        # (default 4194304 = 2**22). Kernel rejects with ESRCH at
        # pid > pid_max, no chance of accidentally targeting a real
        # process. (The earlier 2**22 - 1 = 4194303 was at the
        # boundary and could occasionally be a valid PID.)
        bogus = 2 ** 31 - 1
        result = tracer._ptrace_seize(bogus)
        assert result is False

    def test_trace_returns_3_on_seize_failure(self, tmp_path):
        # M3: pin the trace() exit code 3 contract that commit-4 spawn
        # integration will read. Bogus PID → SEIZE fails → trace
        # returns 3 (not 0, not 4).
        bogus = 2 ** 31 - 1
        rc = tracer.trace(bogus, tmp_path)
        assert rc == 3, f"expected exit 3 on SEIZE failure, got {rc}"


class TestMultiProcessSupport:
    """L5 fix: TRACEFORK / TRACEVFORK / TRACECLONE options ensure
    multi-process and multi-threaded targets produce audit records
    for every subprocess and thread, not just the root. Tests at this
    layer pin the option bitfield + event-code constants + helper
    semantics; full multi-process E2E lands in commit 4 once spawn
    integration can run a real `make -j N`-style target."""

    def test_seize_options_include_fork_vfork_clone(self):
        # The bitfield in _ptrace_seize is computed at call time, so
        # we can't read it post-hoc without intercepting the libc call.
        # Pin via the constants instead — if a future change drops
        # one of these, the test fails AND the comment in _ptrace_seize
        # needs updating.
        from core.sandbox.tracer import (
            _PTRACE_O_TRACEFORK, _PTRACE_O_TRACEVFORK, _PTRACE_O_TRACECLONE,
        )
        assert _PTRACE_O_TRACEFORK == 0x00000002
        assert _PTRACE_O_TRACEVFORK == 0x00000004
        assert _PTRACE_O_TRACECLONE == 0x00000008

    def test_seize_options_include_exitkill(self):
        # M2: PTRACE_O_EXITKILL ensures clean teardown of all tracees
        # if the tracer dies. Without it, surviving tracees would
        # SIGSYS-die on their next traced syscall — same outcome,
        # noisier. Pin the constant value so a future re-numbering
        # gets caught.
        from core.sandbox.tracer import _PTRACE_O_EXITKILL
        assert _PTRACE_O_EXITKILL == 0x00100000

    def test_event_codes_match_kernel_uapi(self):
        # PTRACE_EVENT_FORK/VFORK/CLONE values from <linux/ptrace.h>.
        # These are stable kernel UAPI; if they ever change the
        # tracer dispatch is silently broken.
        from core.sandbox.tracer import (
            _PTRACE_EVENT_FORK, _PTRACE_EVENT_VFORK, _PTRACE_EVENT_CLONE,
            _PTRACE_EVENT_EXIT, _PTRACE_EVENT_SECCOMP,
        )
        assert _PTRACE_EVENT_FORK == 1
        assert _PTRACE_EVENT_VFORK == 2
        assert _PTRACE_EVENT_CLONE == 3
        assert _PTRACE_EVENT_EXIT == 6
        assert _PTRACE_EVENT_SECCOMP == 7

    def test_new_tracee_event_set_groups_fork_vfork_clone(self):
        # Dispatch in the trace loop relies on this set membership
        # check to route fork/vfork/clone identically.
        assert (tracer._NEW_TRACEE_EVENTS
                == frozenset((1, 2, 3)))

    def test_get_event_msg_returns_none_without_libc(self, monkeypatch):
        # GETEVENTMSG is the helper that extracts new-child PIDs from
        # fork/vfork/clone events. Verify the no-libc path (defense:
        # tracer must not crash on libc-load failure mid-run).
        monkeypatch.setattr(tracer, "_get_libc", lambda: None)
        result = tracer._ptrace_get_event_msg(12345)
        assert result is None


class TestPathDereference:
    """`_read_tracee_string` reads NUL-terminated strings from a
    tracee's address space via process_vm_readv. Tests run against
    our OWN PID — process_vm_readv on self is always permitted (no
    ptrace_attach needed)."""

    def test_reads_self_string(self):
        # Construct a known string in our address space, hand its
        # pointer to _read_tracee_string, expect the bytes back.
        marker = b"raptor-audit-test-marker\0"
        buf = ctypes.create_string_buffer(marker)
        addr = ctypes.addressof(buf)
        result = tracer._read_tracee_string(os.getpid(), addr)
        # NUL terminator is stripped.
        assert result == "raptor-audit-test-marker"

    def test_reads_path_like_string(self):
        # Real-world shape: a path the operator would care about.
        marker = b"/etc/hostname\0"
        buf = ctypes.create_string_buffer(marker)
        result = tracer._read_tracee_string(
            os.getpid(), ctypes.addressof(buf),
        )
        assert result == "/etc/hostname"

    def test_null_pointer_returns_none(self):
        # Common: targets sometimes pass NULL as a path pointer
        # (errors out at openat-time but we still want the trace).
        result = tracer._read_tracee_string(os.getpid(), 0)
        assert result is None

    def test_reads_long_string_truncates_at_max(self):
        # Bound: max_bytes prevents pathological never-NUL'd
        # buffers from making us read forever.
        marker = b"A" * 100 + b"\0"
        buf = ctypes.create_string_buffer(marker)
        result = tracer._read_tracee_string(
            os.getpid(), ctypes.addressof(buf), max_bytes=50,
        )
        # 50 bytes capped, no NUL inside the read window
        assert len(result) == 50
        assert result == "A" * 50

    def test_handles_non_utf8_bytes(self):
        # Filename can contain arbitrary bytes (Linux filesystems
        # don't enforce encoding). errors='replace' keeps the
        # record JSON-serialisable.
        marker = b"\xff\xfe-bad-utf8\0"
        buf = ctypes.create_string_buffer(marker)
        result = tracer._read_tracee_string(
            os.getpid(), ctypes.addressof(buf),
        )
        assert result is not None
        # Replacement character for the invalid bytes.
        assert "bad-utf8" in result


class TestPathArgIndex:
    """`_path_arg_index` maps syscall name → index of the path arg
    in the syscall's ABI. Used by the trace loop to know which arg
    to feed into _read_tracee_string."""

    def test_open_uses_arg_0(self):
        assert tracer._path_arg_index("open") == 0

    def test_openat_uses_arg_1(self):
        # openat(dirfd, path, flags, mode) — path is at index 1.
        assert tracer._path_arg_index("openat") == 1

    def test_connect_returns_none(self):
        # connect's "path" is actually a sockaddr struct, not a
        # string. Decoding sockaddr is a separate concern; the
        # tracer doesn't try.
        assert tracer._path_arg_index("connect") is None

    def test_unknown_syscall_returns_none(self):
        assert tracer._path_arg_index("ptrace") is None
        assert tracer._path_arg_index("bpf") is None
        assert tracer._path_arg_index("not-a-syscall") is None


class TestRecordWithPath:
    """When the trace loop derefs a path successfully, the JSONL
    record gets a `path` field AND the `cmd` reflects the path.
    Operators see something actionable instead of "traced PID N"."""

    def test_record_with_path_field(self, tmp_path):
        ok = tracer._write_record(
            tmp_path, "openat", 257,
            [0xdeadbeef, 0x1000, 0o644, 0, 0, 0],
            target_pid=12345,
            path="/etc/hostname",
        )
        assert ok is True

        records = [
            json.loads(line) for line in
            (tmp_path / tracer._DENIALS_FILENAME).read_text().splitlines()
            if line
        ]
        r = records[0]
        assert r["path"] == "/etc/hostname"
        # cmd reflects the actual path, not the generic "traced PID"
        assert "openat" in r["cmd"]
        assert "/etc/hostname" in r["cmd"]

    def test_record_without_path_falls_back_to_pid_cmd(self, tmp_path):
        # Some syscalls (ptrace, bpf, etc.) have no path; operator
        # sees the syscall name + traced PID.
        ok = tracer._write_record(
            tmp_path, "ptrace", 101,
            [0, 0, 0, 0, 0, 0],
            target_pid=99,
            path=None,
        )
        assert ok is True
        records = [
            json.loads(line) for line in
            (tmp_path / tracer._DENIALS_FILENAME).read_text().splitlines()
            if line
        ]
        r = records[0]
        assert "path" not in r  # absent when None
        assert "traced PID 99" in r["cmd"]


class TestSignalReadyHandshake:
    """The optional sync_fd lets the parent unblock the traced child
    only after we've fully attached. Ensures correct ordering."""

    def test_writes_byte_to_sync_fd(self, tmp_path):
        rd, wr = os.pipe()
        try:
            tracer._signal_ready(wr)
            # The pipe should now contain exactly one byte.
            data = os.read(rd, 16)
            assert data == b"\x01"
        finally:
            try:
                os.close(rd)
            except OSError:
                pass
            # _signal_ready closes wr on success; closing again is OK.
            try:
                os.close(wr)
            except OSError:
                pass

    def test_no_sync_fd_is_noop(self):
        # Must not raise / hang when sync_fd is None (testing path).
        tracer._signal_ready(None)

    def test_closes_fd_even_when_write_fails(self, monkeypatch):
        # K2 regression: if os.write raises, the fd must STILL be
        # closed via the finally clause. Without it, a transient
        # broken-pipe / disk-full would leak the fd in the tracer
        # process for the rest of its lifetime.
        rd, wr = os.pipe()
        try:
            def boom(*a, **k):
                raise OSError("simulated write failure")
            monkeypatch.setattr(os, "write", boom)

            # Must not raise; must close wr.
            tracer._signal_ready(wr)

            # Verify wr is closed: re-closing it should raise
            # OSError(EBADF). Don't catch — let pytest report.
            with pytest.raises(OSError):
                os.close(wr)
        finally:
            try:
                os.close(rd)
            except OSError:
                pass
