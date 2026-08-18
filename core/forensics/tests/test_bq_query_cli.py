"""Subprocess tests for libexec/raptor-bq-query.

Contract under test:
  - exit 2: trust-marker refusal / argparse usage errors
  - exit 3: query-shape validation rejections (structured stderr JSON)
  - exit 4: unreadable query file
  - exit 5: google-cloud-bigquery missing (--no-sandbox, real env)
  - exit 6: sandboxed mode without GOOGLE_APPLICATION_CREDENTIALS
  - exit 0 + JSON envelope pass-through with a stubbed client tree on
    PYTHONPATH (--no-sandbox — the sandboxed path needs kernel
    features and live egress, which CI hosts don't guarantee)

Live BigQuery is never contacted.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
WRAPPER = REPO_ROOT / "libexec" / "raptor-bq-query"

_TRUST_MARKERS = ("CLAUDECODE", "_RAPTOR_TRUSTED")


def _base_env(**extra) -> dict:
    env = {k: v for k, v in os.environ.items() if k not in _TRUST_MARKERS}
    env["_RAPTOR_TRUSTED"] = "1"
    env.pop("GOOGLE_APPLICATION_CREDENTIALS", None)
    env.update(extra)
    return env


def _run(args, env=None, stdin=None, timeout=60):
    return subprocess.run(
        [sys.executable, str(WRAPPER), *args],
        env=env if env is not None else _base_env(),
        input=stdin,
        capture_output=True, text=True, timeout=timeout,
        check=False,
    )


def _stderr_error(proc) -> dict:
    lines = [ln for ln in proc.stderr.splitlines() if ln.startswith("{")]
    assert lines, f"no structured error on stderr: {proc.stderr!r}"
    return json.loads(lines[-1])


class TestTrustGate:
    def test_refused_without_markers(self):
        env = {k: v for k, v in os.environ.items()
               if k not in _TRUST_MARKERS}
        proc = _run(["--query", "SELECT 1"], env=env)
        assert proc.returncode == 2
        assert "bin/raptor" in proc.stderr

    def test_raptor_trusted_passes_gate(self):
        # Reaches argparse (validation error is post-gate proof).
        proc = _run(["--query", "DROP TABLE t", "--no-sandbox"])
        assert proc.returncode == 3


class TestUsage:
    def test_no_query_source_is_usage_error(self):
        proc = _run([])
        assert proc.returncode == 2

    def test_query_and_query_file_conflict(self):
        proc = _run(["--query", "SELECT 1", "--query-file", "x.sql"])
        assert proc.returncode == 2

    def test_nonpositive_cap_rejected(self):
        proc = _run(["--query", "SELECT 1", "--max-bytes-billed", "0"])
        assert proc.returncode == 2

    def test_nonpositive_timeout_rejected(self):
        proc = _run(["--query", "SELECT 1", "--timeout", "-5"])
        assert proc.returncode == 2

    def test_unknown_format_rejected(self):
        proc = _run(["--query", "SELECT 1", "--format", "csv"])
        assert proc.returncode == 2


class TestValidationExitCodes:
    @pytest.mark.parametrize("sql", [
        "DELETE FROM t WHERE TRUE",
        "SELECT 1; DROP TABLE t",
        "/* smuggled */ INSERT INTO t VALUES (1)",
        "-- nothing here",
    ])
    def test_rejected_shapes_exit_3(self, sql):
        proc = _run(["--query", sql])
        assert proc.returncode == 3
        err = _stderr_error(proc)
        assert err["error"] == "validation"
        assert err["exit_code"] == 3
        assert proc.stdout == ""

    def test_query_file_validation(self, tmp_path):
        qfile = tmp_path / "q.sql"
        qfile.write_text("TRUNCATE TABLE t")
        proc = _run(["--query-file", str(qfile)])
        assert proc.returncode == 3

    def test_stdin_query_file(self):
        proc = _run(["--query-file", "-"], stdin="MERGE t USING s ON 1=1")
        assert proc.returncode == 3

    def test_missing_query_file_exit_4(self, tmp_path):
        proc = _run(["--query-file", str(tmp_path / "absent.sql")])
        assert proc.returncode == 4
        assert _stderr_error(proc)["error"] == "input"


class TestSandboxCredentialPreflight:
    def test_sandboxed_mode_requires_explicit_credentials(self):
        proc = _run(["--query", "SELECT 1"])
        assert proc.returncode == 6
        err = _stderr_error(proc)
        assert err["error"] == "credentials"
        assert "--no-sandbox" in err["message"]


@pytest.fixture
def fake_google_tree(tmp_path):
    """A stub google-cloud-bigquery package tree for PYTHONPATH."""
    root = tmp_path / "stub-packages"
    pkg = root / "google"
    (pkg / "auth").mkdir(parents=True)
    (pkg / "oauth2").mkdir()
    (pkg / "cloud" / "bigquery").mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    (pkg / "auth" / "__init__.py").write_text(textwrap.dedent("""
        from . import exceptions

        def default(scopes=None):
            return object(), "stub-project"
    """))
    (pkg / "auth" / "exceptions.py").write_text(textwrap.dedent("""
        class GoogleAuthError(Exception):
            pass

        class DefaultCredentialsError(GoogleAuthError):
            pass
    """))
    (pkg / "oauth2" / "__init__.py").write_text("")
    (pkg / "oauth2" / "service_account.py").write_text(textwrap.dedent("""
        class Credentials:
            @staticmethod
            def from_service_account_info(info, scopes=None):
                return object()
    """))
    (pkg / "cloud" / "__init__.py").write_text("")
    (pkg / "cloud" / "bigquery" / "__init__.py").write_text(
        textwrap.dedent("""
        import datetime


        class QueryJobConfig:
            def __init__(self, **kw):
                self.dry_run = False
                self.use_query_cache = True
                self.maximum_bytes_billed = None
                for k, v in kw.items():
                    setattr(self, k, v)


        class _Job:
            job_id = "stub-job"
            total_bytes_processed = 2048
            total_bytes_billed = 4096
            cache_hit = True

            def result(self, timeout=None):
                return iter([
                    {"actor_login": "stub-user",
                     "created_at": datetime.datetime(2025, 7, 13)},
                ])


        class Client:
            def __init__(self, credentials=None, project=None):
                self.project = project or "stub-project"

            def query(self, sql, job_config=None):
                return _Job()
    """))
    return root


class TestJsonPassThrough:
    def test_envelope_on_stdout(self, fake_google_tree):
        env = _base_env(PYTHONPATH=str(fake_google_tree))
        proc = _run(["--query", "SELECT 1", "--no-sandbox"], env=env)
        assert proc.returncode == 0, proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["row_count"] == 1
        assert payload["rows"][0]["actor_login"] == "stub-user"
        # datetime serialized via default=str
        assert payload["rows"][0]["created_at"].startswith("2025-07-13")
        assert payload["job"]["job_id"] == "stub-job"

    def test_no_sandbox_prints_posture_notice(self, fake_google_tree):
        env = _base_env(PYTHONPATH=str(fake_google_tree))
        proc = _run(["--query", "SELECT 1", "--no-sandbox"], env=env)
        assert "egress is NOT pinned" in proc.stderr

    def test_output_file(self, fake_google_tree, tmp_path):
        env = _base_env(PYTHONPATH=str(fake_google_tree))
        out_file = tmp_path / "rows.json"
        proc = _run(
            ["--query", "SELECT 1", "--no-sandbox",
             "--output", str(out_file)],
            env=env)
        assert proc.returncode == 0, proc.stderr
        summary = json.loads(proc.stdout)
        assert summary["row_count"] == 1
        assert summary["output"] == str(out_file)
        envelope = json.loads(out_file.read_text())
        assert envelope["rows"][0]["actor_login"] == "stub-user"

    def test_dry_run_envelope(self, fake_google_tree):
        env = _base_env(PYTHONPATH=str(fake_google_tree))
        proc = _run(
            ["--query", "SELECT 1", "--no-sandbox", "--dry-run"], env=env)
        assert proc.returncode == 0, proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["dry_run"] is True
        assert payload["total_bytes_processed"] == 2048
        assert "estimated_cost_usd" in payload


class TestDependencyExit:
    def test_missing_client_exits_5(self):
        try:
            import google.cloud.bigquery  # noqa: F401
            pytest.skip("google-cloud-bigquery installed on this host")
        except ImportError:
            pass
        proc = _run(["--query", "SELECT 1", "--no-sandbox"])
        assert proc.returncode == 5
        assert _stderr_error(proc)["error"] == "dependency"
