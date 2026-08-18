"""Robustness tests for core.sandbox.evidence — tamper-resistant
placement of sandbox enforcement evidence (F11) and anonymous-fd
config/nonce delivery (F31).

Backend-level tamper enforcement (mount-ns shadow tmpfs, Landlock
non-grant + REMOVE denial) is exercised in test_e2e_sandbox.py's
integration classes; this module covers the substrate mechanics that
run on any host: O_EXCL creation, held-fd appends, inode
verification, anonymous fds, fd-path spelling, parser back-compat and
the nonce-trust refusal backstop.
"""

from __future__ import annotations

import glob
import json
import logging
import os
import sys as _sys
import tempfile

import pytest

from core.sandbox import evidence as ev

pytestmark = pytest.mark.skipif(
    not _sys.platform.startswith(("linux", "darwin")),
    reason="POSIX fd semantics required",
)

# For tests that drive tracer.trace() itself: the ptrace/seccomp
# tracer only runs on Linux (its startup arch check rejects Darwin
# machine names before the evidence-fd plumbing is reached). macOS
# audit evidence is produced by the seatbelt log streamer instead —
# covered in test_macos_spawn.py / seatbelt_audit tests.
linux_only = pytest.mark.skipif(
    not _sys.platform.startswith("linux"),
    reason="tracer.trace() is the Linux ptrace tracer",
)


# ---------------------------------------------------------------------------
# Path helpers + back-compat resolution
# ---------------------------------------------------------------------------


class TestPaths:
    def test_write_path_is_under_audit_subdir(self, tmp_path):
        p = ev.evidence_write_path(tmp_path, "x.jsonl")
        assert p == tmp_path / ".audit" / "x.jsonl"

    def test_resolve_prefers_new_location(self, tmp_path):
        new = ev.evidence_write_path(tmp_path, "x.jsonl")
        new.parent.mkdir()
        new.write_text("new\n")
        (tmp_path / "x.jsonl").write_text("old\n")
        assert ev.resolve_read_path(tmp_path, "x.jsonl") == new

    def test_resolve_falls_back_to_legacy(self, tmp_path):
        old = tmp_path / "x.jsonl"
        old.write_text("old\n")
        assert ev.resolve_read_path(tmp_path, "x.jsonl") == old

    def test_resolve_defaults_to_new_when_neither_exists(self, tmp_path):
        assert ev.resolve_read_path(tmp_path, "x.jsonl") == (
            tmp_path / ".audit" / "x.jsonl"
        )

    def test_ensure_audit_dir_creates_0700(self, tmp_path):
        d = ev.ensure_audit_dir(tmp_path)
        assert d.is_dir()
        assert (d.stat().st_mode & 0o777) == 0o700

    def test_ensure_audit_dir_refuses_symlink(self, tmp_path):
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        os.symlink(elsewhere, tmp_path / ".audit")
        with pytest.raises(OSError, match="refusing"):
            ev.ensure_audit_dir(tmp_path)


# ---------------------------------------------------------------------------
# EvidenceFile — O_EXCL create, held-fd appends, inode verification
# ---------------------------------------------------------------------------


class TestEvidenceFile:
    def test_create_append_and_clean_close(self, tmp_path):
        f = ev.EvidenceFile.open(tmp_path, "d.jsonl")
        assert f.write_record({"a": 1}) is True
        assert f.write_line('{"b": 2}\n') is True
        assert f.close() is True  # verification clean
        lines = f.path.read_text().splitlines()
        assert [json.loads(x) for x in lines] == [{"a": 1}, {"b": 2}]
        # File mode is owner-only.
        assert (f.path.stat().st_mode & 0o777) == 0o600

    def test_second_open_appends_to_existing(self, tmp_path):
        f1 = ev.EvidenceFile.open(tmp_path, "d.jsonl")
        f1.write_record({"n": 1})
        f1.close()
        f2 = ev.EvidenceFile.open(tmp_path, "d.jsonl")
        f2.write_record({"n": 2})
        assert f2.close() is True
        recs = [json.loads(x)
                for x in f2.path.read_text().splitlines()]
        assert recs == [{"n": 1}, {"n": 2}]

    def test_preplanted_symlink_refused(self, tmp_path):
        target = tmp_path / "victim"
        target.write_text("")
        d = ev.ensure_audit_dir(tmp_path)
        os.symlink(target, d / "d.jsonl")
        with pytest.raises(OSError):
            ev.EvidenceFile.open(tmp_path, "d.jsonl")
        assert target.read_text() == ""

    def test_existing_file_with_loose_mode_refused(self, tmp_path):
        d = ev.ensure_audit_dir(tmp_path)
        p = d / "d.jsonl"
        p.write_text("attacker seeded\n")
        os.chmod(p, 0o666)
        with pytest.raises(OSError, match="failed validation"):
            ev.EvidenceFile.open(tmp_path, "d.jsonl")

    def test_existing_hardlinked_file_refused(self, tmp_path):
        d = ev.ensure_audit_dir(tmp_path)
        p = d / "d.jsonl"
        p.write_text("")
        os.chmod(p, 0o600)
        os.link(p, tmp_path / "alias")
        with pytest.raises(OSError, match="failed validation"):
            ev.EvidenceFile.open(tmp_path, "d.jsonl")

    def test_swapped_file_fires_loud_warning(self, tmp_path, caplog):
        f = ev.EvidenceFile.open(tmp_path, "d.jsonl")
        f.write_record({"real": True})
        # Simulate the tamper: replace the file at the path with a
        # different inode carrying forged content.
        forged = tmp_path / "forged"
        forged.write_text('{"forged": true}\n')
        os.replace(forged, f.path)
        with caplog.at_level(logging.WARNING,
                             logger="core.sandbox.evidence"):
            ok = f.close()
        assert ok is False
        assert any("TAMPER" in r.getMessage() for r in caplog.records)
        assert any("swapped" in r.getMessage() for r in caplog.records)

    def test_vanished_file_fires_loud_warning(self, tmp_path, caplog):
        f = ev.EvidenceFile.open(tmp_path, "d.jsonl")
        f.write_record({"real": True})
        os.unlink(f.path)
        with caplog.at_level(logging.WARNING,
                             logger="core.sandbox.evidence"):
            ok = f.close()
        assert ok is False
        assert any("vanished" in r.getMessage() for r in caplog.records)

    def test_appends_survive_path_swap(self, tmp_path):
        # The held fd pins the original inode: appends made AFTER a
        # path-level swap still land in the original file, not the
        # attacker's replacement.
        f = ev.EvidenceFile.open(tmp_path, "d.jsonl")
        f.write_record({"seq": 1})
        # Pin the ORIGINAL inode read-side BEFORE the swap. The held
        # fd is write-only, so it cannot be re-opened for reading
        # portably: /proc/self/fd/N (Linux) re-opens the inode fresh,
        # but /dev/fd/N (macOS) is a dup that keeps the write-only
        # access mode and fails an O_RDONLY open with EPERM.
        read_fd = os.open(f.path, os.O_RDONLY)
        hijack = tmp_path / "hijack"
        hijack.write_text("")
        os.replace(hijack, f.path)
        f.write_record({"seq": 2})
        with open(read_fd) as fh:
            recs = [json.loads(x) for x in fh.read().splitlines()]
        assert recs == [{"seq": 1}, {"seq": 2}]
        # The attacker's replacement at the PATH got neither record.
        assert f.path.read_text() == ""
        f.close(verify=False)

    def test_close_is_idempotent(self, tmp_path):
        f = ev.EvidenceFile.open(tmp_path, "d.jsonl")
        assert f.close() is True
        assert f.close() is True
        assert f.write_line("late\n") is False

    def test_fd_is_cloexec_by_default(self, tmp_path):
        # The evidence fd must not leak across any exec except the
        # tracer's (which flips inheritable explicitly post-fork).
        f = ev.EvidenceFile.open(tmp_path, "d.jsonl")
        assert os.get_inheritable(f.fd) is False
        f.close()


# ---------------------------------------------------------------------------
# anonymous_fd + fd_path (F31)
# ---------------------------------------------------------------------------


class TestAnonymousFd:
    def test_content_round_trips_and_no_tmp_file(self):
        before = set(glob.glob(
            os.path.join(tempfile.gettempdir(), "raptor-audit-cfg*"),
        ))
        fd = ev.anonymous_fd(b'{"nonce": "s3cret"}')
        try:
            after = set(glob.glob(
                os.path.join(tempfile.gettempdir(), "raptor-audit-cfg*"),
            ))
            # No filesystem name appeared anywhere a target could glob.
            assert after == before
            with open(ev.fd_path(fd)) as fh:
                assert json.load(fh) == {"nonce": "s3cret"}
        finally:
            os.close(fd)

    def test_fd_is_cloexec(self):
        fd = ev.anonymous_fd(b"x")
        try:
            assert os.get_inheritable(fd) is False
        finally:
            os.close(fd)

    def test_offset_rewound_for_shared_description_readers(self):
        # /dev/fd/N on macOS is a dup sharing the offset; the helper
        # must hand back an fd positioned at 0.
        fd = ev.anonymous_fd(b"hello")
        try:
            assert os.lseek(fd, 0, os.SEEK_CUR) == 0
            assert os.read(fd, 5) == b"hello"
        finally:
            os.close(fd)

    def test_unlinked_tempfile_branch(self, monkeypatch, tmp_path):
        # Force the non-memfd branch (the macOS implementation) and
        # verify it behaves identically: readable content, no
        # discoverable path left behind. tempfile is pointed at a
        # PRIVATE directory for the duration — a before/after listing
        # of the shared tmpdir is not hermetic under parallel workers
        # (any concurrent test's scratch file lands in the diff), and
        # the private dir also strengthens the positive property: the
        # unlinked file provably went to the observed directory.
        monkeypatch.setattr(ev.sys, "platform", "darwin")
        monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
        fd = ev.anonymous_fd(b"macos-branch")
        monkeypatch.undo()
        try:
            assert set(os.listdir(tmp_path)) == set(), (
                "unlinked-tempfile branch left a discoverable path"
            )
            assert os.read(fd, 64) == b"macos-branch"
        finally:
            os.close(fd)

    def test_fd_path_spelling_per_platform(self):
        assert ev.fd_path(7, platform="linux") == "/proc/self/fd/7"
        assert ev.fd_path(7, platform="darwin") == "/dev/fd/7"

    def test_parse_fd_path_round_trip(self):
        assert ev.parse_fd_path("/proc/self/fd/12") == 12
        assert ev.parse_fd_path("/dev/fd/3") == 3
        assert ev.parse_fd_path("/tmp/raptor-audit-cfg-x.json") is None
        assert ev.parse_fd_path("/proc/self/fd/abc") is None
        assert ev.parse_fd_path("") is None


# ---------------------------------------------------------------------------
# _write_audit_config (Landlock-only path) — no /tmp footprint
# ---------------------------------------------------------------------------


class TestLandlockAuditConfigDelivery:
    def test_config_serialised_into_anonymous_fd(self):
        from core.sandbox._landlock_audit import (
            _build_audit_config,
            _write_audit_config,
        )
        cfg = _build_audit_config(
            audit_verbose=True, observe_mode=True,
            observe_nonce="deadbeef", writable_paths=["/w"],
            readable_paths=None, allowed_tcp_ports=None,
            output="/out", target=None, restrict_reads=False,
            evidence_fd=42,
        )
        before = set(glob.glob(
            os.path.join(tempfile.gettempdir(), "raptor-audit-cfg*"),
        ))
        fd = _write_audit_config(cfg)
        try:
            after = set(glob.glob(
                os.path.join(tempfile.gettempdir(), "raptor-audit-cfg*"),
            ))
            assert after == before, (
                "config (carrying the nonce) must not exist at a "
                "filesystem path"
            )
            with open(ev.fd_path(fd)) as fh:
                loaded = json.load(fh)
            assert loaded["observe_nonce"] == "deadbeef"
            assert loaded["evidence_fd"] == 42
        finally:
            os.close(fd)


# ---------------------------------------------------------------------------
# Tracer consumes the fd-path config and releases the fd post-parse
# ---------------------------------------------------------------------------


class TestTracerFdConfigConsumption:
    def test_cli_reads_fd_path_config_and_closes_fd(
            self, tmp_path, monkeypatch):
        from core.sandbox import tracer as tracer_mod
        captured = {}

        def fake_trace(pid, run_dir, sync_fd=None, audit_filter=None):
            captured["filter"] = audit_filter
            return 0

        monkeypatch.setattr(tracer_mod, "trace", fake_trace)
        cfg_fd = ev.anonymous_fd(
            json.dumps({"verbose": True, "observe_mode": False}).encode(),
        )
        rc = tracer_mod._cli_main(
            ["1", str(tmp_path), "3", ev.fd_path(cfg_fd)],
        )
        assert rc == 0
        assert captured["filter"] == {
            "verbose": True, "observe_mode": False,
        }
        # The inherited config fd must be closed right after parsing
        # (before the target would be unblocked) so its
        # /proc/<pid>/fd reflection disappears.
        with pytest.raises(OSError):
            os.fstat(cfg_fd)

    @linux_only
    def test_trace_falls_back_when_evidence_fd_invalid(
            self, tmp_path, caplog, monkeypatch):
        # A stale/bad evidence_fd number must degrade to per-record
        # path appends (with a warning), never write into an
        # unrelated fd. Drive trace() far enough to hit the startup
        # fd validation: seize stubbed to succeed, waitpid stubbed to
        # report "no tracees" so the loop exits immediately.
        from core.sandbox import tracer as tracer_mod
        monkeypatch.setattr(tracer_mod, "_evidence_out_fd", None)
        monkeypatch.setattr(tracer_mod, "_ptrace_seize",
                            lambda pid: True)

        def no_children(*a, **k):
            raise ChildProcessError

        monkeypatch.setattr(tracer_mod.os, "waitpid", no_children)
        # An fd number that is definitely not open in this process.
        probe = os.open(os.devnull, os.O_RDONLY)
        os.close(probe)
        with caplog.at_level(logging.WARNING,
                             logger="core.sandbox.tracer"):
            rc = tracer_mod.trace(
                12345, tmp_path,
                audit_filter={"evidence_fd": probe},
            )
        assert rc == 0
        assert tracer_mod._evidence_out_fd is None
        assert any("evidence_fd" in r.getMessage()
                   for r in caplog.records)

    @linux_only
    def test_trace_adopts_valid_evidence_fd(self, tmp_path, monkeypatch):
        from core.sandbox import tracer as tracer_mod
        monkeypatch.setattr(tracer_mod, "_evidence_out_fd", None)
        monkeypatch.setattr(tracer_mod, "_ptrace_seize",
                            lambda pid: True)

        def no_children(*a, **k):
            raise ChildProcessError

        monkeypatch.setattr(tracer_mod.os, "waitpid", no_children)
        f = ev.EvidenceFile.open(tmp_path, ".sandbox-denials.jsonl")
        try:
            rc = tracer_mod.trace(
                12345, tmp_path,
                audit_filter={"evidence_fd": f.fd},
            )
            assert rc == 0
            assert tracer_mod._evidence_out_fd == f.fd
        finally:
            monkeypatch.setattr(tracer_mod, "_evidence_out_fd", None)
            f.close()


class TestTracerEvidenceFdAppend:
    def test_write_record_routes_through_evidence_fd(
            self, tmp_path, monkeypatch):
        from core.sandbox import tracer as tracer_mod
        f = ev.EvidenceFile.open(tmp_path, ".sandbox-denials.jsonl")
        monkeypatch.setattr(tracer_mod, "_evidence_out_fd", f.fd)
        ok = tracer_mod._write_record(
            tmp_path, "openat", 257, [0] * 6, target_pid=7,
            path="/etc/hosts",
        )
        assert ok is True
        # Landed in the held-fd file, not a fresh per-record open.
        recs = [json.loads(x)
                for x in f.path.read_text().splitlines()]
        assert recs[0]["path"] == "/etc/hosts"
        f.close()


# ---------------------------------------------------------------------------
# parse_observe_log — back-compat read + nonce-trust refusal backstop
# ---------------------------------------------------------------------------


def _observe_record(path="/etc/hosts", nonce=None):
    rec = {
        "ts": "2026-08-15T00:00:00+00:00",
        "cmd": f"<sandbox audit: openat {path}>",
        "returncode": 0,
        "type": "write",
        "observe": True,
        "syscall": "openat",
        "syscall_nr": 257,
        "target_pid": 1,
        "args": [0, 0, 0, 0, 0, 0],
        "path": path,
    }
    if nonce is not None:
        rec["nonce"] = nonce
    return rec


class TestParseObserveLogPlacement:
    def test_reads_new_audit_location(self, tmp_path):
        from core.sandbox.observe_profile import parse_observe_log
        p = ev.evidence_write_path(tmp_path, ".sandbox-observe.jsonl")
        p.parent.mkdir()
        p.write_text(json.dumps(_observe_record()) + "\n")
        profile = parse_observe_log(tmp_path)
        assert profile.paths_read == ["/etc/hosts"]

    def test_back_compat_reads_legacy_location(self, tmp_path):
        from core.sandbox.observe_profile import parse_observe_log
        legacy = tmp_path / ".sandbox-observe.jsonl"
        legacy.write_text(json.dumps(_observe_record()) + "\n")
        profile = parse_observe_log(tmp_path)
        assert profile.paths_read == ["/etc/hosts"]

    def test_new_location_wins_over_legacy(self, tmp_path):
        from core.sandbox.observe_profile import parse_observe_log
        new = ev.evidence_write_path(tmp_path, ".sandbox-observe.jsonl")
        new.parent.mkdir()
        new.write_text(json.dumps(_observe_record(path="/new")) + "\n")
        (tmp_path / ".sandbox-observe.jsonl").write_text(
            json.dumps(_observe_record(path="/legacy")) + "\n",
        )
        profile = parse_observe_log(tmp_path)
        assert profile.paths_read == ["/new"]


class TestNonceTrustRefusal:
    def _write_log(self, tmp_path, nonce):
        p = ev.evidence_write_path(tmp_path, ".sandbox-observe.jsonl")
        p.parent.mkdir(exist_ok=True)
        p.write_text(json.dumps(_observe_record(nonce=nonce)) + "\n")

    def test_trusted_on_isolated_backend(self, tmp_path):
        from core.sandbox.observe_profile import parse_observe_log
        self._write_log(tmp_path, "n1")
        profile = parse_observe_log(
            tmp_path, expected_nonce="n1",
            sandbox_info={"mount_ns_active": True},
        )
        assert profile.nonce_trusted is True
        assert profile.paths_read == ["/etc/hosts"]

    def test_trusted_on_namespaceless_with_protected_delivery(
            self, tmp_path):
        from core.sandbox.observe_profile import parse_observe_log
        self._write_log(tmp_path, "n1")
        profile = parse_observe_log(
            tmp_path, expected_nonce="n1",
            sandbox_info={"mount_ns_active": False,
                          "nonce_delivery": "anonymous_fd"},
        )
        assert profile.nonce_trusted is True

    def test_refused_on_namespaceless_without_delivery_record(
            self, tmp_path, caplog):
        # Fail-safe: a run that predates fd-based delivery (or a
        # future regression that drops the delivery stamp) must not
        # be granted nonce-based trust on a namespace-less backend.
        from core.sandbox.observe_profile import parse_observe_log
        self._write_log(tmp_path, "n1")
        with caplog.at_level(logging.WARNING,
                             logger="core.sandbox.observe_profile"):
            profile = parse_observe_log(
                tmp_path, expected_nonce="n1",
                sandbox_info={"mount_ns_active": False},
            )
        assert profile.nonce_trusted is False
        assert any("refusing nonce-based trust" in r.getMessage()
                   for r in caplog.records)
        # Records are still parsed — unauthenticated signal remains
        # available to the operator.
        assert profile.paths_read == ["/etc/hosts"]

    def test_refused_on_namespaceless_with_file_delivery(self, tmp_path):
        from core.sandbox.observe_profile import parse_observe_log
        self._write_log(tmp_path, "n1")
        profile = parse_observe_log(
            tmp_path, expected_nonce="n1",
            sandbox_info={"mount_ns_active": False,
                          "nonce_delivery": "file"},
        )
        assert profile.nonce_trusted is False

    def test_seatbelt_backend_counts_as_isolated(self, tmp_path):
        from core.sandbox.observe_profile import parse_observe_log
        self._write_log(tmp_path, "n1")
        profile = parse_observe_log(
            tmp_path, expected_nonce="n1",
            sandbox_info={"backend": "macos-seatbelt",
                          "nonce_delivery": "in_process"},
        )
        assert profile.nonce_trusted is True

    def test_no_sandbox_info_preserves_legacy_behaviour(self, tmp_path):
        from core.sandbox.observe_profile import parse_observe_log
        self._write_log(tmp_path, "n1")
        profile = parse_observe_log(tmp_path, expected_nonce="n1")
        assert profile.nonce_trusted is True

    def test_merge_trust_is_conjunctive(self):
        from core.sandbox.observe_profile import ObserveProfile
        a = ObserveProfile(nonce_trusted=True)
        b = ObserveProfile(nonce_trusted=False)
        a.merge(b)
        assert a.nonce_trusted is False


# ---------------------------------------------------------------------------
# summarize_and_write — back-compat read of the legacy denials spot
# ---------------------------------------------------------------------------


class TestSummaryBackCompat:
    def test_summarize_reads_legacy_jsonl(self, tmp_path):
        from core.sandbox import summary as summary_mod
        legacy = tmp_path / summary_mod.DENIALS_FILE
        legacy.write_text(json.dumps({
            "ts": "x", "cmd": "c", "returncode": 1, "type": "network",
        }) + "\n")
        result = summary_mod.summarize_and_write(tmp_path)
        assert result is not None
        assert result["total_denials"] == 1
        assert not legacy.exists()

    def test_summarize_prefers_new_location(self, tmp_path):
        from core.sandbox import summary as summary_mod
        new = ev.evidence_write_path(tmp_path, summary_mod.DENIALS_FILE)
        new.parent.mkdir()
        new.write_text(json.dumps({
            "ts": "x", "cmd": "new", "returncode": 1, "type": "write",
        }) + "\n")
        (tmp_path / summary_mod.DENIALS_FILE).write_text(
            json.dumps({
                "ts": "x", "cmd": "old", "returncode": 1,
                "type": "network",
            }) + "\n",
        )
        result = summary_mod.summarize_and_write(tmp_path)
        assert result["denials"][0]["cmd"] == "new"


# ---------------------------------------------------------------------------
# macOS seatbelt profile — evidence-dir deny clause
# ---------------------------------------------------------------------------


class TestSeatbeltEvidenceDeny:
    """Profile-string generation is platform-independent; only the
    sandbox-exec ENFORCEMENT needs a Darwin host (covered by the
    skip-on-non-darwin e2e in test_macos_spawn.py)."""

    def test_enforcement_profile_denies_evidence_dir(self, tmp_path):
        from core.sandbox.seatbelt import build_profile
        evdir = str(tmp_path / ".audit")
        profile = build_profile(
            output=str(tmp_path), audit_evidence_dir=evdir,
        )
        real = os.path.realpath(evdir)
        assert f'(deny file-write* (subpath "{real}"))' in profile

    def test_audit_mode_profile_still_denies_evidence_dir(self, tmp_path):
        # Audit mode replaces the write-deny with allow-with-report;
        # the evidence deny must survive (SBPL: explicit deny
        # outranks allow regardless of order).
        from core.sandbox.seatbelt import build_profile
        evdir = str(tmp_path / ".audit")
        profile = build_profile(
            output=str(tmp_path), audit_mode=True,
            audit_evidence_dir=evdir,
        )
        assert "(allow file-write* (with report))" in profile
        real = os.path.realpath(evdir)
        assert f'(deny file-write* (subpath "{real}"))' in profile

    def test_no_evidence_dir_no_clause(self, tmp_path):
        from core.sandbox.seatbelt import build_profile
        profile = build_profile(output=str(tmp_path))
        assert ".audit" not in profile
