"""Tests for core.run.tmp_reaper — stale temp-artifact sweep.

All tests point the reaper at a private tmp_path via a monkeypatched
``tempfile.gettempdir`` so nothing touches the real system temp dir.
"""

import os
import socket
import subprocess
import time
from pathlib import Path

import pytest

from core.run.tmp_reaper import reap_stale_logs, reap_stale_runs, reap_stale_tmp

_OLD = time.time() - 25 * 3600  # past the 24h default age floor


@pytest.fixture
def tmp_root(tmp_path, monkeypatch):
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
    monkeypatch.delenv("RAPTOR_TMP_REAP_MAX_AGE_H", raising=False)
    return tmp_path


def _make_old_dir(root, name, contents=()):
    d = root / name
    d.mkdir()
    for fname in contents:
        (d / fname).write_text("x")
    os.utime(d, (_OLD, _OLD))
    return d


class TestDirReaping:

    def test_stale_prefixed_dirs_reaped(self, tmp_root):
        dirs = [
            _make_old_dir(tmp_root, "raptor-llm-raptor-cafe0001-abc123"),
            _make_old_dir(tmp_root, "raptor-cc-cwd-abc123"),
            _make_old_dir(tmp_root, "raptor-joern-ws-abc123"),
            _make_old_dir(tmp_root, "raptor-calibrate-abc123"),
            _make_old_dir(tmp_root, "raptor_auto_abc123"),
            _make_old_dir(tmp_root, "raptor_git_frk_abc1"),
            _make_old_dir(tmp_root, "raptor_decomp_abc123"),
            _make_old_dir(tmp_root, "raptor-cocci-tmp-abc123"),
            _make_old_dir(tmp_root, "trust-synth-work-abc123"),
            _make_old_dir(tmp_root, "raptor-iris-codeql-abc123"),
            _make_old_dir(tmp_root, "raptor_recon_abc123"),
        ]
        reaped = reap_stale_tmp()
        assert sorted(reaped) == sorted(dirs)
        for d in dirs:
            assert not d.exists()

    def test_fresh_dir_kept(self, tmp_root):
        d = tmp_root / "raptor-llm-raptor-cafe0002-fresh1"
        d.mkdir()
        assert reap_stale_tmp() == []
        assert d.is_dir()

    def test_foreign_prefix_kept(self, tmp_root):
        d = _make_old_dir(tmp_root, "someone-elses-dir")
        assert reap_stale_tmp() == []
        assert d.is_dir()

    def test_observe_keep_dirs_not_reaped(self, tmp_root):
        # --keep / --out observe dirs are operator-preserved on purpose.
        d = _make_old_dir(
            tmp_root, "raptor-observe-abc123", [".sandbox-observe.jsonl"],
        )
        assert reap_stale_tmp() == []
        assert d.is_dir()

    def test_symlink_squatting_on_prefix_kept(self, tmp_root):
        target = tmp_root / "victim"
        target.mkdir()
        (target / "data.txt").write_text("precious")
        link = tmp_root / "raptor-llm-raptor-cafe0003-planted"
        link.symlink_to(target)
        os.utime(link, (_OLD, _OLD), follow_symlinks=False)
        assert reap_stale_tmp() == []
        assert link.is_symlink()
        assert (target / "data.txt").read_text() == "precious"

    def test_dir_with_answering_socket_kept_then_reaped(self, monkeypatch):
        # Own short root instead of the tmp_root fixture: AF_UNIX paths
        # cap at ~108 chars and a nested pytest basetemp (custom TMPDIR)
        # blows past it. Same workaround as test_proxy_netns_enforcement.
        import shutil
        import tempfile
        short_root = tempfile.mkdtemp(prefix="rpt_", dir="/tmp")
        monkeypatch.setattr("tempfile.gettempdir", lambda: short_root)
        monkeypatch.delenv("RAPTOR_TMP_REAP_MAX_AGE_H", raising=False)
        try:
            d = _make_old_dir(Path(short_root),
                              "raptor-llm-raptor-cafe0004-livesk")
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                srv.bind(str(d / "llm.sock"))
                srv.listen(1)
                os.utime(d, (_OLD, _OLD))
                assert reap_stale_tmp() == []
                assert d.is_dir()
            finally:
                srv.close()
            # Listener gone → ECONNREFUSED → dead → reaped.
            assert reap_stale_tmp() == [d]
            assert not d.exists()
        finally:
            shutil.rmtree(short_root, ignore_errors=True)

    def test_dir_serving_as_live_cwd_kept(self, tmp_root):
        d = _make_old_dir(tmp_root, "raptor-cc-cwd-livecwd")
        proc = subprocess.Popen(
            ["sleep", "30"], cwd=str(d),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            os.utime(d, (_OLD, _OLD))
            assert reap_stale_tmp() == []
            assert d.is_dir()
        finally:
            proc.terminate()
            proc.wait()


class TestFileReaping:

    def test_stale_sweep_yaml_and_joern_script_reaped(self, tmp_root):
        files = []
        for name in ("audit_sweep_ab12cd34.yaml", "wrapped-script42.sc",
                     "raptor-audit-cfg-ab12cd34.json",
                     "raptor-cocci-ab12cd34.cocci",
                     "cocci-output-3-abc123-file.c",
                     "cocci_small_output-3-abc123-file.c"):
            f = tmp_root / name
            f.write_text("rules: []\n")
            os.utime(f, (_OLD, _OLD))
            files.append(f)
        reaped = reap_stale_tmp()
        assert sorted(reaped) == sorted(files)

    def test_fresh_sweep_yaml_kept(self, tmp_root):
        f = tmp_root / "audit_sweep_ab12cd34.yaml"
        f.write_text("rules: []\n")
        assert reap_stale_tmp() == []
        assert f.is_file()

    def test_prefix_without_suffix_kept(self, tmp_root):
        f = tmp_root / "audit_sweep_notes.txt"
        f.write_text("keep me")
        os.utime(f, (_OLD, _OLD))
        assert reap_stale_tmp() == []
        assert f.is_file()


class TestConfigAndSafety:

    def test_env_zero_disables_sweep(self, tmp_root, monkeypatch):
        d = _make_old_dir(tmp_root, "raptor-llm-raptor-cafe0005-nosweep")
        monkeypatch.setenv("RAPTOR_TMP_REAP_MAX_AGE_H", "0")
        assert reap_stale_tmp() == []
        assert d.is_dir()

    def test_env_shrinks_age_floor(self, tmp_root, monkeypatch):
        d = tmp_root / "raptor-llm-raptor-cafe0006-young1"
        d.mkdir()
        two_h = time.time() - 2 * 3600
        os.utime(d, (two_h, two_h))
        assert reap_stale_tmp() == []
        monkeypatch.setenv("RAPTOR_TMP_REAP_MAX_AGE_H", "1")
        assert reap_stale_tmp() == [d]

    def test_non_numeric_env_falls_back_to_default(self, tmp_root,
                                                   monkeypatch):
        d = _make_old_dir(tmp_root, "raptor-llm-raptor-cafe0007-badenv")
        monkeypatch.setenv("RAPTOR_TMP_REAP_MAX_AGE_H", "soon")
        assert reap_stale_tmp() == [d]

    def test_never_raises(self, tmp_root, monkeypatch):
        _make_old_dir(tmp_root, "raptor-llm-raptor-cafe0008-boom")

        def _boom(*a, **kw):
            raise RuntimeError("listdir exploded")

        monkeypatch.setattr(os, "listdir", _boom)
        assert reap_stale_tmp() == []


class TestLogReaping:
    """Log reaping is OPT-IN: audit-trail files are never deleted
    unless the operator sets RAPTOR_LOG_REAP_MAX_AGE_D."""

    @pytest.fixture
    def log_dir(self, tmp_path, monkeypatch):
        from core.config import RaptorConfig
        monkeypatch.setattr(RaptorConfig, "LOG_DIR", tmp_path)
        monkeypatch.delenv("RAPTOR_LOG_REAP_MAX_AGE_D", raising=False)
        return tmp_path

    @staticmethod
    def _log(root, name, age_s):
        f = root / name
        f.write_text("{}\n")
        t = time.time() - age_s
        os.utime(f, (t, t))
        return f

    def test_default_deletes_nothing(self, log_dir):
        # No env set → audit data untouched no matter how old.
        ancient = self._log(log_dir, "raptor_1_pid1_1.jsonl", 400 * 86400)
        assert reap_stale_logs() == []
        assert ancient.is_file()

    def test_opt_in_reaps_old_keeps_fresh(self, log_dir, monkeypatch):
        monkeypatch.setenv("RAPTOR_LOG_REAP_MAX_AGE_D", "14")
        old = self._log(log_dir, "raptor_1_pid1_1.jsonl", 15 * 86400)
        fresh = self._log(log_dir, "raptor_2_pid2_2.jsonl", 86400)
        assert reap_stale_logs() == [old]
        assert not old.exists()
        assert fresh.is_file()

    def test_non_log_files_kept(self, log_dir, monkeypatch):
        monkeypatch.setenv("RAPTOR_LOG_REAP_MAX_AGE_D", "14")
        other = self._log(log_dir, "notes.txt", 30 * 86400)
        assert reap_stale_logs() == []
        assert other.is_file()

    def test_env_zero_stays_disabled(self, log_dir, monkeypatch):
        old = self._log(log_dir, "raptor_1_pid1_1.jsonl", 30 * 86400)
        monkeypatch.setenv("RAPTOR_LOG_REAP_MAX_AGE_D", "0")
        assert reap_stale_logs() == []
        assert old.is_file()

    def test_non_numeric_env_deletes_nothing(self, log_dir, monkeypatch):
        # Unlike the tmp sweep (worthless artifacts → fall back to the
        # default), a garbled opt-in for AUDIT DATA must not delete.
        old = self._log(log_dir, "raptor_1_pid1_1.jsonl", 400 * 86400)
        monkeypatch.setenv("RAPTOR_LOG_REAP_MAX_AGE_D", "fortnight")
        assert reap_stale_logs() == []
        assert old.is_file()

    def test_missing_log_dir_is_noop(self, tmp_path, monkeypatch):
        from core.config import RaptorConfig
        monkeypatch.setattr(RaptorConfig, "LOG_DIR", tmp_path / "absent")
        monkeypatch.setenv("RAPTOR_LOG_REAP_MAX_AGE_D", "14")
        assert reap_stale_logs() == []


class TestRunReaping:

    @pytest.fixture
    def out_root(self, tmp_path, monkeypatch):
        monkeypatch.delenv("RAPTOR_RUN_REAP_MAX_AGE_D", raising=False)
        return tmp_path

    @staticmethod
    def _run_dir(root, name, status, age_d=45.0, *, with_meta=True):
        import json
        from datetime import datetime, timedelta, timezone
        d = root / name
        d.mkdir()
        if with_meta:
            ts = datetime.now(timezone.utc) - timedelta(days=age_d)
            (d / ".raptor-run.json").write_text(json.dumps({
                "version": 2, "command": "scan", "status": status,
                "timestamp": ts.isoformat(), "extra": {},
            }))
        return d

    def test_old_failed_and_cancelled_reaped(self, out_root):
        failed = self._run_dir(out_root, "scan-001", "failed")
        cancelled = self._run_dir(out_root, "fuzz-001", "cancelled")
        reaped = reap_stale_runs(out_root)
        assert sorted(reaped) == sorted([failed, cancelled])
        assert not failed.exists() and not cancelled.exists()

    def test_completed_and_running_never_reaped(self, out_root):
        done = self._run_dir(out_root, "scan-001", "completed")
        live = self._run_dir(out_root, "scan-002", "running")
        assert reap_stale_runs(out_root) == []
        assert done.is_dir() and live.is_dir()

    def test_fresh_failed_kept(self, out_root):
        fresh = self._run_dir(out_root, "scan-001", "failed", age_d=2.0)
        assert reap_stale_runs(out_root) == []
        assert fresh.is_dir()

    def test_non_run_dirs_untouched(self, out_root):
        logs = self._run_dir(out_root, "logs", "failed", with_meta=False)
        (logs / "raptor_1.jsonl").write_text("{}")
        assert reap_stale_runs(out_root) == []
        assert logs.is_dir()

    def test_env_zero_disables(self, out_root, monkeypatch):
        failed = self._run_dir(out_root, "scan-001", "failed")
        monkeypatch.setenv("RAPTOR_RUN_REAP_MAX_AGE_D", "0")
        assert reap_stale_runs(out_root) == []
        assert failed.is_dir()

    def test_mtime_fallback_when_timestamp_malformed(self, out_root):
        import json
        d = out_root / "scan-001"
        d.mkdir()
        (d / ".raptor-run.json").write_text(json.dumps({
            "status": "failed", "timestamp": "not-a-date", "extra": {},
        }))
        os.utime(d, (_OLD, _OLD))  # only ~25h — under the 30d floor
        assert reap_stale_runs(out_root) == []
        old = time.time() - 45 * 86400
        os.utime(d, (old, old))
        assert reap_stale_runs(out_root) == [d]

    def test_missing_parent_is_noop(self, tmp_path):
        assert reap_stale_runs(tmp_path / "absent") == []


class TestStartRunHook:

    def test_start_run_invokes_sweeps(self, tmp_path, monkeypatch):
        import core.run.tmp_reaper as reaper_mod
        from core.run.metadata import start_run

        calls = []
        monkeypatch.setattr(
            reaper_mod, "reap_stale_tmp", lambda: calls.append("tmp") or [],
        )
        monkeypatch.setattr(
            reaper_mod, "reap_stale_logs", lambda: calls.append("logs") or [],
        )
        monkeypatch.setattr(
            reaper_mod, "reap_stale_runs",
            lambda parent: calls.append(("runs", parent)) or [],
        )
        out = tmp_path / "run"
        start_run(out, "scan")
        assert calls == ["tmp", "logs", ("runs", out.parent)]
