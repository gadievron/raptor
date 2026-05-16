"""Tests for core.sandbox.observe_profile.

Two layers:
  1. Parser unit tests against synthetic JSONL fixtures (no real
     sandbox needed — the file format is the contract).
  2. Tracer-routing tests that verify sandbox(observe=True) writes to
     the expected filename with the expected mode stamp. Built atop
     the same _handle_waitpid_event injection points the audit-filter
     tests use, so they don't depend on a working ptrace tracer.
  3. Cross-module pinning: the OBSERVE_FILENAME constant in the parser
     must match _OBSERVE_FILENAME in the tracer; the open(2) flag
     constants in the parser must match the tracer's. Drift would
     cause silent profile-extraction failures.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.sandbox.observe_profile import (
    OBSERVE_FILENAME,
    ConnectTarget,
    ObserveProfile,
    parse_observe_log,
)


def _write_jsonl(path: Path, records: list) -> None:
    """Materialise a JSONL fixture exactly as the tracer would."""
    with path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")


def _open_record(path: str, *, write_intent: bool = False) -> dict:
    """Build an `openat` record matching tracer._write_record output."""
    flags = 0o0000001 if write_intent else 0  # O_WRONLY=1, O_RDONLY=0
    return {
        "ts": "2026-05-04T00:00:00Z",
        "cmd": f"<sandbox audit: openat {path}>",
        "returncode": 0,
        "type": "write",
        "observe": True,
        "syscall": "openat",
        "syscall_nr": 257,
        "target_pid": 1234,
        "args": [-100, 0, flags, 0, 0, 0],  # AT_FDCWD, ptr, flags, ...
        "path": path,
    }


def _stat_record(path: str, syscall: str = "newfstatat") -> dict:
    """Build a stat-family record (newfstatat)."""
    return {
        "ts": "2026-05-04T00:00:00Z",
        "cmd": f"<sandbox audit: {syscall} {path}>",
        "returncode": 0,
        "type": "write",
        "observe": True,
        "syscall": syscall,
        "syscall_nr": 262,
        "target_pid": 1234,
        "args": [-100, 0, 0, 0, 0, 0],
        "path": path,
    }


def _connect_record(ip: str, port: int,
                    family: str = "AF_INET") -> dict:
    """Build a connect record with the tracer's path field shape."""
    return {
        "ts": "2026-05-04T00:00:00Z",
        "cmd": f"<sandbox audit: connect {ip}:{port} ({family})>",
        "returncode": 0,
        "type": "network",
        "observe": True,
        "syscall": "connect",
        "syscall_nr": 42,
        "target_pid": 1234,
        "args": [3, 0, 16, 0, 0, 0],
        "path": f"{ip}:{port} ({family})",
    }


# ---------------------------------------------------------------------------
# Parser — happy paths
# ---------------------------------------------------------------------------


class TestParseEmpty:

    def test_missing_file_returns_empty_profile(self, tmp_path):
        profile = parse_observe_log(tmp_path)
        assert profile == ObserveProfile()

    def test_empty_file_returns_empty_profile(self, tmp_path):
        (tmp_path / OBSERVE_FILENAME).write_text("")
        profile = parse_observe_log(tmp_path)
        assert profile == ObserveProfile()


class TestParsePaths:

    def test_read_open_classified_as_read(self, tmp_path):
        _write_jsonl(tmp_path / OBSERVE_FILENAME, [
            _open_record("/etc/passwd", write_intent=False),
        ])
        profile = parse_observe_log(tmp_path)
        assert profile.paths_read == ["/etc/passwd"]
        assert profile.paths_written == []

    def test_write_open_classified_as_written(self, tmp_path):
        _write_jsonl(tmp_path / OBSERVE_FILENAME, [
            _open_record("/tmp/scratch", write_intent=True),
        ])
        profile = parse_observe_log(tmp_path)
        assert profile.paths_written == ["/tmp/scratch"]
        assert profile.paths_read == []

    def test_stat_recorded_separately_from_open(self, tmp_path):
        # Common pattern: binary stat()s a path it never opens.
        _write_jsonl(tmp_path / OBSERVE_FILENAME, [
            _stat_record("/etc/ld.so.cache"),
            _open_record("/etc/passwd"),
        ])
        profile = parse_observe_log(tmp_path)
        assert profile.paths_stat == ["/etc/ld.so.cache"]
        assert profile.paths_read == ["/etc/passwd"]

    def test_dedup_preserves_first_seen_order(self, tmp_path):
        _write_jsonl(tmp_path / OBSERVE_FILENAME, [
            _open_record("/a"),
            _open_record("/b"),
            _open_record("/a"),  # dup
            _open_record("/c"),
        ])
        profile = parse_observe_log(tmp_path)
        assert profile.paths_read == ["/a", "/b", "/c"]

    def test_open_without_path_field_skipped(self, tmp_path):
        rec = _open_record("/some/path")
        del rec["path"]
        _write_jsonl(tmp_path / OBSERVE_FILENAME, [rec])
        profile = parse_observe_log(tmp_path)
        assert profile.paths_read == []


class TestParseConnect:

    def test_ipv4_connect_decoded(self, tmp_path):
        _write_jsonl(tmp_path / OBSERVE_FILENAME, [
            _connect_record("1.2.3.4", 443),
        ])
        profile = parse_observe_log(tmp_path)
        assert profile.connect_targets == [
            ConnectTarget(ip="1.2.3.4", port=443, family="AF_INET"),
        ]

    def test_ipv6_connect_decoded(self, tmp_path):
        _write_jsonl(tmp_path / OBSERVE_FILENAME, [
            _connect_record("::1", 443, family="AF_INET6"),
        ])
        profile = parse_observe_log(tmp_path)
        assert profile.connect_targets == [
            ConnectTarget(ip="::1", port=443, family="AF_INET6"),
        ]

    def test_dedup_connects(self, tmp_path):
        _write_jsonl(tmp_path / OBSERVE_FILENAME, [
            _connect_record("1.2.3.4", 443),
            _connect_record("1.2.3.4", 443),  # dup
            _connect_record("1.2.3.4", 80),   # different port
        ])
        profile = parse_observe_log(tmp_path)
        assert len(profile.connect_targets) == 2

    def test_connect_without_path_skipped(self, tmp_path):
        # sockaddr decode failure → path absent → record skipped.
        rec = _connect_record("1.2.3.4", 443)
        del rec["path"]
        _write_jsonl(tmp_path / OBSERVE_FILENAME, [rec])
        profile = parse_observe_log(tmp_path)
        assert profile.connect_targets == []

    def test_connect_unparseable_path_skipped(self, tmp_path):
        rec = _connect_record("1.2.3.4", 443)
        rec["path"] = "garbage"
        _write_jsonl(tmp_path / OBSERVE_FILENAME, [rec])
        profile = parse_observe_log(tmp_path)
        assert profile.connect_targets == []


class TestMacOSKextActionClassification:
    """The macOS log streamer stamps kext action names verbatim into
    the record's ``syscall`` field (``file-read-data``,
    ``file-write-create``, ``file-read-metadata``, ``network-outbound``
    rather than ``openat`` / ``connect``). The parser must classify
    them into the same buckets the Linux syscall vocabulary does.

    These tests use synthetic kext-shaped records so they run on
    Linux CI; the same code path executes when fed real records on
    macOS."""

    def _kext_rec(self, syscall: str, path: str) -> dict:
        return {
            "ts": "2026-05-08T00:00:00Z",
            "type": "read",
            "observe": True,
            "syscall": syscall,
            "path": path,
            "target_pid": 1234,
        }

    def test_file_read_data_classified_as_read(self, tmp_path):
        _write_jsonl(tmp_path / OBSERVE_FILENAME, [
            self._kext_rec("file-read-data", "/usr/lib/libSystem.B.dylib"),
        ])
        p = parse_observe_log(tmp_path)
        assert p.paths_read == ["/usr/lib/libSystem.B.dylib"]
        assert p.paths_written == []
        assert p.paths_stat == []

    def test_file_read_metadata_classified_as_stat(self, tmp_path):
        _write_jsonl(tmp_path / OBSERVE_FILENAME, [
            self._kext_rec("file-read-metadata",
                           "/Library/Frameworks/X.framework/Info.plist"),
        ])
        p = parse_observe_log(tmp_path)
        assert p.paths_stat == [
            "/Library/Frameworks/X.framework/Info.plist"
        ]
        assert p.paths_read == []

    def test_file_write_create_classified_as_write(self, tmp_path):
        _write_jsonl(tmp_path / OBSERVE_FILENAME, [
            self._kext_rec("file-write-create", "/tmp/scratch"),
        ])
        p = parse_observe_log(tmp_path)
        assert p.paths_written == ["/tmp/scratch"]

    def test_file_write_data_classified_as_write(self, tmp_path):
        _write_jsonl(tmp_path / OBSERVE_FILENAME, [
            self._kext_rec("file-write-data", "/tmp/log.txt"),
        ])
        p = parse_observe_log(tmp_path)
        assert p.paths_written == ["/tmp/log.txt"]

    def test_file_mknod_classified_as_write(self, tmp_path):
        _write_jsonl(tmp_path / OBSERVE_FILENAME, [
            self._kext_rec("file-mknod", "/tmp/fifo"),
        ])
        p = parse_observe_log(tmp_path)
        assert p.paths_written == ["/tmp/fifo"]

    def test_unknown_kext_action_dropped(self, tmp_path):
        # SBPL emits many other actions (process-info-pidinfo,
        # mach-lookup, sysctl-read) that don't fit any bucket. The
        # parser drops them silently — they're noise, not signal.
        _write_jsonl(tmp_path / OBSERVE_FILENAME, [
            self._kext_rec("mach-lookup", "com.apple.distributed_notifications"),
            self._kext_rec("file-read-data", "/etc/hosts"),
        ])
        p = parse_observe_log(tmp_path)
        assert p.paths_read == ["/etc/hosts"]


class TestParseSymlinkRefusal:
    """The audit run dir is bind-mounted writable inside the sandbox;
    a hostile target binary could replace .sandbox-observe.jsonl with
    a symlink before audit engages, and a vanilla open() would follow
    it. The parser opens with O_NOFOLLOW; this test confirms a
    symlinked log is refused (ELOOP → empty profile)."""

    def test_symlinked_log_refused(self, tmp_path):
        # Create the real (would-be-spoofed) data somewhere else.
        sentinel = tmp_path / "real-data.jsonl"
        sentinel.write_text(
            json.dumps(_open_record("/etc/spoofed")) + "\n"
        )
        # Plant the symlink at the expected log path — simulates the
        # target binary swapping the log file before the parser runs.
        log_path = tmp_path / OBSERVE_FILENAME
        log_path.symlink_to(sentinel)

        profile = parse_observe_log(tmp_path)
        # Without O_NOFOLLOW the parser would follow the symlink,
        # parse real-data.jsonl, and surface "/etc/spoofed" in
        # paths_read. With O_NOFOLLOW the open fails with ELOOP and
        # an empty profile lands.
        assert profile.paths_read == [], (
            "parser must refuse symlinked observe log to defeat "
            "TOCTOU swap by a hostile target binary"
        )


class TestParseRobustness:

    def test_malformed_line_skipped_continues(self, tmp_path):
        # Tracer SIGKILL'd mid-write — last line truncated. Parser
        # must still surface the well-formed records before it.
        path = tmp_path / OBSERVE_FILENAME
        with path.open("w", encoding="utf-8") as f:
            f.write(json.dumps(_open_record("/a")) + "\n")
            f.write('{"syscall": "openat", "path": "/b", "args"\n')  # truncated
            f.write(json.dumps(_open_record("/c")) + "\n")
        profile = parse_observe_log(tmp_path)
        assert profile.paths_read == ["/a", "/c"]

    def test_record_without_syscall_field_skipped(self, tmp_path):
        # The end-of-run audit_summary marker has no syscall field —
        # must not be parsed as a path.
        _write_jsonl(tmp_path / OBSERVE_FILENAME, [
            {"ts": "...", "type": "audit_summary",
             "totals": {"open": 5}},
            _open_record("/a"),
        ])
        profile = parse_observe_log(tmp_path)
        assert profile.paths_read == ["/a"]

    def test_observe_false_records_filtered(self, tmp_path):
        # Defensive: if a fixture mixes audit-mode records (observe=False)
        # into the file, the parser drops them.
        rec = _open_record("/skipme")
        rec["observe"] = False
        rec["audit"] = True
        _write_jsonl(tmp_path / OBSERVE_FILENAME, [
            rec,
            _open_record("/keep"),
        ])
        profile = parse_observe_log(tmp_path)
        assert profile.paths_read == ["/keep"]


# ---------------------------------------------------------------------------
# ObserveProfile.merge
# ---------------------------------------------------------------------------


class TestMerge:

    def test_merge_unions_paths_and_connects(self):
        a = ObserveProfile(paths_read=["/a"], paths_written=["/w1"],
                           paths_stat=["/s1"],
                           connect_targets=[
                               ConnectTarget("1.1.1.1", 443, "AF_INET"),
                           ])
        b = ObserveProfile(paths_read=["/b", "/a"], paths_written=["/w2"],
                           paths_stat=["/s1", "/s2"],
                           connect_targets=[
                               ConnectTarget("2.2.2.2", 443, "AF_INET"),
                           ])
        a.merge(b)
        assert a.paths_read == ["/a", "/b"]
        assert a.paths_written == ["/w1", "/w2"]
        assert a.paths_stat == ["/s1", "/s2"]
        assert len(a.connect_targets) == 2


# ---------------------------------------------------------------------------
# Cross-module pinning
# ---------------------------------------------------------------------------


class TestCrossModulePinning:
    """Drift between parser constants and tracer constants would
    silently produce empty profiles. Pin both ends here."""

    def test_observe_filename_matches_tracer(self):
        from core.sandbox import tracer
        assert OBSERVE_FILENAME == tracer._OBSERVE_FILENAME

    def test_open_flag_constants_match_tracer(self):
        from core.sandbox import observe_profile, tracer
        assert observe_profile._O_WRONLY == tracer._O_WRONLY
        assert observe_profile._O_RDWR == tracer._O_RDWR
        assert observe_profile._O_CREAT == tracer._O_CREAT
        assert observe_profile._O_TRUNC == tracer._O_TRUNC
        assert observe_profile._O_APPEND == tracer._O_APPEND

    def test_open_syscalls_match_tracer_path_arg_index(self):
        # Every syscall the parser classifies as "open-family" must
        # have a path arg the tracer can dereference. Otherwise the
        # parser's `path` field would never be populated for that
        # syscall and the parser would silently skip those records.
        # Pinning excludes macOS kext action names (file-read-data
        # etc.) — those don't go through ptrace, so _path_arg_index
        # has no entry for them. The kext records carry `path`
        # populated by the log streamer's regex parse instead.
        from core.sandbox import observe_profile, tracer
        for sc in observe_profile._OPEN_SYSCALLS:
            if sc.startswith("file-"):
                continue  # macOS kext action — not a Linux syscall
            assert tracer._path_arg_index(sc) is not None, (
                f"observe_profile classifies {sc!r} as open-family "
                f"but tracer._path_arg_index returns None — "
                f"records would lack `path`."
            )

    def test_stat_syscalls_match_tracer_path_arg_index(self):
        from core.sandbox import observe_profile, tracer
        for sc in observe_profile._STAT_SYSCALLS:
            if sc.startswith("file-"):
                continue  # macOS kext action — not a Linux syscall
            # Some stat-family syscalls may be unsupported on the
            # current arch (e.g., aarch64 has no `stat`/`lstat`) —
            # tracer._path_arg_index still returns a sensible index
            # because the table is arch-independent for the parser
            # contract; the seccomp install-time resolve is what
            # actually filters by arch.
            assert tracer._path_arg_index(sc) is not None, (
                f"observe_profile classifies {sc!r} as stat-family "
                f"but tracer._path_arg_index returns None."
            )


# ---------------------------------------------------------------------------
# Tracer-routing — does observe_mode actually swap the output filename?
# ---------------------------------------------------------------------------


class TestTracerRoutesToObserveFilename:
    """End-to-end check at the tracer write_record level: when
    audit_filter has observe_mode=True, records land in
    .sandbox-observe.jsonl with `"observe": True`; otherwise they
    land in .sandbox-denials.jsonl with `"audit": True`."""

    def test_observe_mode_routes_to_observe_filename(self, tmp_path):
        from core.sandbox.tracer import _write_record, _OBSERVE_FILENAME
        ok = _write_record(
            tmp_path, "openat", 257, [0, 0, 0, 0, 0, 0], 1234,
            path="/etc/passwd",
            filename=_OBSERVE_FILENAME,
            mode_field="observe",
        )
        assert ok is True
        observe_file = tmp_path / _OBSERVE_FILENAME
        assert observe_file.exists()
        # Denials file should NOT exist — observe-mode never writes
        # there.
        denials_file = tmp_path / ".sandbox-denials.jsonl"
        assert not denials_file.exists()
        rec = json.loads(observe_file.read_text().strip())
        assert rec["observe"] is True
        assert "audit" not in rec
        assert rec["syscall"] == "openat"
        assert rec["path"] == "/etc/passwd"

    def test_default_routes_to_denials_filename(self, tmp_path):
        from core.sandbox.tracer import _write_record, _DENIALS_FILENAME
        ok = _write_record(
            tmp_path, "openat", 257, [0, 0, 0, 0, 0, 0], 1234,
            path="/etc/passwd",
        )
        assert ok is True
        denials_file = tmp_path / _DENIALS_FILENAME
        assert denials_file.exists()
        observe_file = tmp_path / ".sandbox-observe.jsonl"
        assert not observe_file.exists()
        rec = json.loads(denials_file.read_text().strip())
        assert rec["audit"] is True
        assert "observe" not in rec

    def test_resolve_helpers_pin_observe_mode_choices(self):
        """Helpers used inside trace() to bind filename + mode-field
        once at startup. Pin behaviour so a refactor that flips the
        signs (e.g., observe_mode=True returning the denials
        filename) is caught immediately."""
        from core.sandbox.tracer import (
            _resolve_output_filename,
            _resolve_record_mode_field,
            _DENIALS_FILENAME,
            _OBSERVE_FILENAME,
        )
        assert _resolve_output_filename(True) == _OBSERVE_FILENAME
        assert _resolve_output_filename(False) == _DENIALS_FILENAME
        assert _resolve_record_mode_field(True) == "observe"
        assert _resolve_record_mode_field(False) == "audit"


# ---------------------------------------------------------------------------
# Public API surface — sandbox(observe=True)
# ---------------------------------------------------------------------------


class TestPublicObserveKwarg:
    """sandbox(observe=True) must:
      1. force audit_mode (TRACE action requires a tracer),
      2. force audit_verbose (we want every traced syscall),
      3. flow observe_mode=True down to _spawn.run_sandboxed.
    Verified at the audit_mode-resolution layer (no real spawn
    needed — that's the E2E test)."""

    @pytest.mark.skipif(
        __import__("sys").platform == "darwin",
        reason="Linux mount-ns spawn path; macOS variant is signature-parity only",
    )
    def test_observe_implies_audit(self):
        # The audit_mode/audit_verbose_active resolution lives at
        # the top of sandbox(); we check the variables by entering
        # the context manager and asserting the spawn path receives
        # observe_mode=True. Cheap probe: monkeypatch the spy on
        # the _spawn entry point and trigger a no-op run().
        from unittest.mock import patch
        from core.sandbox import context as ctx_mod

        seen_kwargs = {}

        def fake_run_sandboxed(cmd, **kwargs):
            seen_kwargs.update(kwargs)
            import subprocess
            return subprocess.CompletedProcess(args=cmd, returncode=0,
                                               stdout=b"", stderr=b"")

        # Force spawn-eligible path with mount-ns "available" so
        # _spawn.run_sandboxed gets called (rather than the
        # Landlock-only subprocess fallback). Two gates need
        # patching: ``context.check_mount_available`` controls
        # ``use_mount`` upstream of the spawn dispatch; the
        # ``_spawn.mount_ns_available`` re-check is the second
        # gate inside _spawn itself. Hosts where the OS blocks
        # unprivileged user-ns (Ubuntu 24.04+ default) return
        # False from both, so the test must override both.
        with patch("core.sandbox._spawn.run_sandboxed",
                   side_effect=fake_run_sandboxed) as spy, \
             patch("core.sandbox._spawn.mount_ns_available",
                   return_value=True), \
             patch("core.sandbox.context.check_mount_available",
                   return_value=True):
            with ctx_mod.sandbox(target=str(Path("/tmp")),
                                 output=str(Path("/tmp")),
                                 observe=True) as run:
                run(["true"])
        assert spy.called
        assert seen_kwargs.get("audit_mode") is True, (
            "observe=True must force audit_mode upstream"
        )
        assert seen_kwargs.get("audit_verbose") is True, (
            "observe=True must force audit_verbose upstream"
        )
        assert seen_kwargs.get("observe_mode") is True, (
            "observe=True must reach _spawn.run_sandboxed as observe_mode=True"
        )

    @pytest.mark.skipif(
        __import__("sys").platform == "darwin",
        reason="Linux mount-ns spawn path; macOS variant is signature-parity only",
    )
    def test_observe_off_by_default(self):
        from unittest.mock import patch
        from core.sandbox import context as ctx_mod

        seen_kwargs = {}

        def fake_run_sandboxed(cmd, **kwargs):
            seen_kwargs.update(kwargs)
            import subprocess
            return subprocess.CompletedProcess(args=cmd, returncode=0,
                                               stdout=b"", stderr=b"")

        with patch("core.sandbox._spawn.run_sandboxed",
                   side_effect=fake_run_sandboxed), \
             patch("core.sandbox._spawn.mount_ns_available",
                   return_value=True), \
             patch("core.sandbox.context.check_mount_available",
                   return_value=True):
            with ctx_mod.sandbox(target=str(Path("/tmp")),
                                 output=str(Path("/tmp"))) as run:
                run(["true"])
        # observe_mode kwarg should default to False so non-observe
        # callers don't accidentally engage the trace-set extension.
        assert seen_kwargs.get("observe_mode") in (False, None), (
            f"non-observe sandbox leaked observe_mode={seen_kwargs.get('observe_mode')!r}"
        )


# ---------------------------------------------------------------------------
# seccomp install — observe_mode extends the trace set
# ---------------------------------------------------------------------------


class TestSeccompTraceSetExtension:
    """seccomp installation in observe_mode adds stat-family
    syscalls on top of the audit-mode set. Verified at the
    pure-construct level by reading the module's lists; a separate
    e2e test would have to fork a tracer."""

    def test_observe_extra_set_disjoint_from_audit_extra(self):
        from core.sandbox.seccomp import (
            _AUDIT_EXTRA_TRACE_SYSCALLS,
            _OBSERVE_EXTRA_TRACE_SYSCALLS,
        )
        audit = set(_AUDIT_EXTRA_TRACE_SYSCALLS)
        observe = set(_OBSERVE_EXTRA_TRACE_SYSCALLS)
        # If they overlapped, the install loop would add the syscall
        # twice — libseccomp tolerates this but it's a bug indicator.
        assert audit.isdisjoint(observe), (
            f"audit and observe extra-trace sets overlap: "
            f"{audit & observe}"
        )

    def test_observe_extra_includes_stat_family(self):
        from core.sandbox.seccomp import _OBSERVE_EXTRA_TRACE_SYSCALLS
        for sc in ("newfstatat", "access"):
            assert sc in _OBSERVE_EXTRA_TRACE_SYSCALLS, (
                f"observe extra-trace set must include {sc!r} so "
                f"profile-extraction sees stat-family hits"
            )
