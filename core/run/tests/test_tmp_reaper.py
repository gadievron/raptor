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

    def test_stale_pytest_session_dir_reaped(self, tmp_root):
        # The root conftest's session-tmp containment leaks exactly one
        # ``raptor-pytest-*`` dir when a test session is SIGKILLed; the
        # static prefix entry is the cross-process reclamation contract
        # (runtime registration would die with the killed session).
        d = _make_old_dir(
            tmp_root, "raptor-pytest-abc123", ["tmpxyz", "litter.txt"],
        )
        assert reap_stale_tmp() == [d]
        assert not d.exists()

    def test_stale_coord_isolation_probe_dir_reaped(self, tmp_root):
        # Coordinator-isolation probe dirs are atexit-cleaned, but the
        # first ones are minted at collection time — before the
        # conftest TMPDIR containment exists — so a SIGKILLed run
        # strands them directly under the system tmp.
        d = _make_old_dir(tmp_root, "raptor-coord-isolation-abc123")
        assert reap_stale_tmp() == [d]
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

    def test_oversize_metadata_skipped_unread(self, out_root):
        # A metadata file over the byte budget must not be parsed
        # (bounded load) — the dir is skipped, not reaped, even
        # though the padded JSON is valid and says failed+stale.
        import json
        from datetime import datetime, timedelta, timezone
        d = out_root / "scan-001"
        d.mkdir()
        ts = datetime.now(timezone.utc) - timedelta(days=45)
        (d / ".raptor-run.json").write_text(json.dumps({
            "version": 2, "command": "scan", "status": "failed",
            "timestamp": ts.isoformat(), "extra": {},
            "padding": "x" * (2 << 20),
        }))
        assert reap_stale_runs(out_root) == []
        assert d.is_dir()

    def test_metadata_at_budget_still_reaped(self, out_root):
        failed = self._run_dir(out_root, "scan-001", "failed")
        assert (failed / ".raptor-run.json").stat().st_size <= (1 << 20)
        assert reap_stale_runs(out_root) == [failed]

    def test_swapped_dir_not_deleted(self, out_root, tmp_path, monkeypatch):
        # Validation happens against an lstat snapshot; deletion is by
        # pathname. If another writer swaps a different directory into
        # the validated name in between (e.g. renames a completed
        # sibling there), the reaper must notice the identity change
        # and skip — not delete the swapped-in victim.
        import shutil as _shutil

        import core.run.tmp_reaper as reaper_mod

        stale = self._run_dir(out_root, "scan-001", "failed")
        victim = tmp_path / "victim-results"
        victim.mkdir()
        (victim / "findings.json").write_text("{}")

        real_age = reaper_mod._run_age_seconds

        def swap_then_age(meta, st, now):
            # Runs after validation, before the delete: replace the
            # validated dir with the victim under the same name.
            _shutil.rmtree(stale)
            os.rename(victim, stale)
            return real_age(meta, st, now)

        monkeypatch.setattr(reaper_mod, "_run_age_seconds", swap_then_age)
        assert reaper_mod.reap_stale_runs(out_root) == []
        assert (stale / "findings.json").is_file()


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


# Production scratch sites whose cleanup is exit-path-only (rmtree in a
# finally, an atexit hook, or an owner object's teardown). SIGKILL and
# OOM skip every exit path, and a runtime register_dir_prefix() call
# dies with the process that made it — cross-process reclamation of
# these strays requires a static _DIR_PREFIXES entry.
_PRODUCTION_SCRATCH_PREFIXES = (
    "r2-sandbox-",             # packages/binary_analysis/radare2_understand.py
    "raptor-cocci-hunt-",      # packages/code_understanding/dispatch/hunt_cocci_dispatch.py
    "raptor-oracle-envbuild-", # core/analysis/binary_oracle_cli.py
    "corpus-excerpt-",         # core/audit/corpus/run_corpus.py
    "raptor-compose-",         # core/container/compose.py
    "raptor-env-",             # core/env/provision.py (+ raptor-env-build-)
    "cve-env-source-",         # packages/cve_env .../tools/source_build.py
    "cve-env-dfgbuild-",       # packages/cve_env .../agent/tools.py
    "joern-matrix-",           # packages/joern/scripts/compat_matrix.py
    "raptor-sca-stress-",      # packages/sca/calibration/stress.py
)


class TestProductionScratchPrefixContract:

    @pytest.mark.parametrize("prefix", _PRODUCTION_SCRATCH_PREFIXES)
    def test_prefix_listed_static(self, prefix):
        from core.run import tmp_reaper
        assert prefix in tmp_reaper._DIR_PREFIXES, (
            f"{prefix!r} scratch dirs are cleaned on exit paths only; "
            "without a static _DIR_PREFIXES entry a SIGKILLed run "
            "strands them in the system tmp forever"
        )

    def test_stale_production_scratch_reaped(self, tmp_root):
        dirs = [
            _make_old_dir(tmp_root, p + "stray01")
            for p in _PRODUCTION_SCRATCH_PREFIXES
        ]
        reaped = reap_stale_tmp()
        assert sorted(reaped) == sorted(dirs)
        for d in dirs:
            assert not d.exists()


class TestSigkilledProcessStrays:
    """Own-pgid SIGKILL drill: a child process creates one scratch dir
    per production prefix and kills its own process group — no
    interpreter exit path (finally / atexit / __exit__) ever runs,
    mirroring an OOM-kill or an operator ``kill -9`` of a pipeline.
    A FRESH interpreter then sweeps: only the static prefix tuple is
    visible cross-process, so this proves end-to-end reclamation."""

    def test_strays_reaped_by_fresh_process_sweep(self, tmp_path):
        import sys

        repo_root = Path(__file__).resolve().parents[3]
        child_code = (
            "import os, sys, tempfile\n"
            "for prefix in sys.argv[1:]:\n"
            "    tempfile.mkdtemp(prefix=prefix, dir=os.environ['TMPDIR'])\n"
            "os.kill(0, 9)\n"  # SIGKILL own pgid: no exit path runs
        )
        env = {k: v for k, v in os.environ.items()
               if k != "RAPTOR_TMP_REAP_MAX_AGE_H"}
        env["TMPDIR"] = str(tmp_path)
        proc = subprocess.run(
            [sys.executable, "-c", child_code,
             *_PRODUCTION_SCRATCH_PREFIXES],
            env=env, start_new_session=True, capture_output=True,
            timeout=60,
        )
        assert proc.returncode == -9, proc.stderr.decode()
        strays = list(tmp_path.iterdir())
        assert len(strays) == len(_PRODUCTION_SCRATCH_PREFIXES)
        for d in strays:
            os.utime(d, (_OLD, _OLD))

        env["PYTHONPATH"] = str(repo_root)
        sweeper = subprocess.run(
            [sys.executable, "-c",
             "from core.run.tmp_reaper import reap_stale_tmp;"
             "print(len(reap_stale_tmp()))"],
            env=env, capture_output=True, text=True, timeout=60,
        )
        assert sweeper.returncode == 0, sweeper.stderr
        assert sweeper.stdout.strip() == str(len(strays))
        assert list(tmp_path.iterdir()) == []


class TestLiveOwnerKeepalive:
    """The ownership-transfer prefixes whose dirs can legitimately sit
    mtime-quiet past the age floor WHILE ALIVE (env work dirs: sandbox
    rootfs mtime froze at export; compose staging: bind-mount sources;
    corpus excerpts: read-only for multi-day runs). Their owners hold a
    scratch keepalive from creation to cleanup — that pairing is what
    makes the static listing safe, and its absence (dead owner) is what
    makes the dir reapable."""

    _QUIET_LIVE_PREFIXES = ("raptor-env-", "raptor-compose-",
                            "corpus-excerpt-")

    @pytest.fixture(autouse=True)
    def _isolated_keepalive(self, monkeypatch):
        from core.run import scratch as scratch_mod
        monkeypatch.setattr(scratch_mod, "_keepalive_paths", set())

    def test_live_owner_survives_dead_owner_reaped(self, tmp_root):
        from core.run import scratch as scratch_mod
        from core.run.scratch import keepalive_register, keepalive_unregister
        for prefix in self._QUIET_LIVE_PREFIXES:
            d = _make_old_dir(tmp_root, prefix + "live01")
            keepalive_register(d)
            # >24h quiet, owner alive: the ticker's refresh protects it.
            scratch_mod._keepalive_tick()
            assert reap_stale_tmp() == [], prefix
            assert d.is_dir(), prefix
            # Owner cleaned up (or died — no more refresh): reclaimable.
            keepalive_unregister(d)
            os.utime(d, (_OLD, _OLD))
            assert reap_stale_tmp() == [d], prefix
            assert not d.exists(), prefix
