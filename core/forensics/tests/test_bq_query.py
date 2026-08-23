"""Robustness tests for core/forensics/bq_query.py.

Live BigQuery cannot be exercised here (no GOOGLE_APPLICATION_
CREDENTIALS on CI hosts), so execution paths run against a stubbed
``google`` module tree injected via ``sys.modules``. Everything else —
the query-shape validation matrix, proxy-host resolution, error
taxonomy, and the child-process protocol — is fully mockable and
covered.
"""

from __future__ import annotations

import io
import json
import sys
import types

import pytest

from core.forensics import bq_query as bq

# =========================================================================
# validation matrix
# =========================================================================


class TestValidateQueryAccepts:
    @pytest.mark.parametrize("sql", [
        "SELECT 1",
        "select created_at FROM `githubarchive.day.20250713`",
        "  \n\tSELECT 1",
        "WITH x AS (SELECT 1) SELECT * FROM x",
        "with x as (select 1) select * from x",
        "SELECT 1;",
        "SELECT 1 ;\n\n",
        "-- leading comment\nSELECT 1",
        "# hash comment\nSELECT 1",
        "/* block\ncomment */ SELECT 1",
        "SELECT ';' AS tricky",
        'SELECT ";" AS tricky',
        "SELECT '''multi;line\nDELETE''' AS s",
        'SELECT """x; DROP TABLE t""" AS s',
        "SELECT `weird;column` FROM t",
        "SELECT 'it\\'s; fine'",
        "SELECT 1 -- trailing comment with ; DELETE",
        "﻿SELECT 1",  # BOM-prefixed
    ])
    def test_accepted(self, sql):
        assert bq.validate_query(sql) is not None


class TestValidateQueryRejects:
    @pytest.mark.parametrize("sql", [
        "DELETE FROM `dataset.t` WHERE TRUE",
        "INSERT INTO t VALUES (1)",
        "UPDATE t SET a = 1 WHERE TRUE",
        "MERGE t USING s ON t.id = s.id WHEN MATCHED THEN DELETE",
        "DROP TABLE t",
        "CREATE TABLE t (a INT64)",
        "ALTER TABLE t ADD COLUMN b INT64",
        "TRUNCATE TABLE t",
        "GRANT `roles/bigquery.admin` ON SCHEMA d TO 'user:x'",
        "DECLARE x INT64",
        "BEGIN SELECT 1; END",
        "CALL d.proc()",
        "EXPORT DATA OPTIONS(uri='gs://x/*') AS SELECT 1",
    ])
    def test_dml_ddl_scripting_rejected(self, sql):
        with pytest.raises(bq.QueryValidationError):
            bq.validate_query(sql)

    @pytest.mark.parametrize("sql", [
        "SELECT 1; DELETE FROM t WHERE TRUE",
        "SELECT 1; SELECT 2",
        "SELECT 1;;",
        "SELECT 1; -- ok\nDROP TABLE t",
    ])
    def test_multi_statement_rejected(self, sql):
        with pytest.raises(bq.QueryValidationError, match="multiple"):
            bq.validate_query(sql)

    @pytest.mark.parametrize("sql", [
        "/* smuggle */ DELETE FROM t WHERE TRUE",
        "-- innocuous\nDELETE FROM t WHERE TRUE",
        "# innocuous\nDROP TABLE t",
        "/* SELECT */ INSERT INTO t VALUES (1)",
    ])
    def test_comment_smuggled_dml_rejected(self, sql):
        with pytest.raises(bq.QueryValidationError, match="keyword"):
            bq.validate_query(sql)

    @pytest.mark.parametrize("sql", [
        "",
        "   \n\t  ",
        "-- only a comment",
        "/* only a block comment */",
        "# only a hash comment\n-- and another",
    ])
    def test_empty_rejected(self, sql):
        with pytest.raises(bq.QueryValidationError, match="empty"):
            bq.validate_query(sql)

    def test_oversized_rejected(self):
        sql = "SELECT '" + "a" * bq.MAX_QUERY_BYTES + "'"
        with pytest.raises(bq.QueryValidationError, match="exceeds"):
            bq.validate_query(sql)

    def test_non_string_rejected(self):
        with pytest.raises(bq.QueryValidationError):
            bq.validate_query(None)

    def test_leading_punctuation_rejected(self):
        with pytest.raises(bq.QueryValidationError):
            bq.validate_query("(SELECT 1)")


class TestStripSqlNoise:
    def test_line_comment_removed(self):
        assert "DELETE" not in bq.strip_sql_noise("SELECT 1 -- DELETE")

    def test_block_comment_removed(self):
        assert "DROP" not in bq.strip_sql_noise("SELECT /* DROP */ 1")

    def test_unterminated_block_comment_swallows_rest(self):
        out = bq.strip_sql_noise("SELECT 1 /* never closed DELETE")
        assert "DELETE" not in out

    def test_string_bodies_blanked(self):
        out = bq.strip_sql_noise("SELECT 'a;b' AS x")
        assert ";" not in out

    def test_escaped_quote_inside_string(self):
        out = bq.strip_sql_noise(r"SELECT 'a\'b;' AS x")
        assert ";" not in out

    def test_code_outside_literals_kept(self):
        out = bq.strip_sql_noise("SELECT a FROM t WHERE b > 1")
        assert "WHERE b > 1" in out


# =========================================================================
# proxy-host resolution
# =========================================================================


class TestProxyHosts:
    @pytest.fixture(autouse=True)
    def _no_override(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            bq, "_OVERRIDE_CONFIG_PATH", tmp_path / "absent.json")
        monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)

    def test_default_hosts(self):
        hosts = bq.proxy_hosts_for_bq()
        assert "bigquery.googleapis.com" in hosts
        assert "oauth2.googleapis.com" in hosts
        assert "www.googleapis.com" in hosts

    def test_token_uri_host_from_key_file(self, tmp_path, monkeypatch):
        key = tmp_path / "key.json"
        key.write_text(json.dumps({
            "type": "service_account",
            "token_uri": "https://accounts.google.com/o/oauth2/token",
        }))
        monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(key))
        assert "accounts.google.com" in bq.proxy_hosts_for_bq()

    def test_token_uri_host_from_inline_json(self, monkeypatch):
        monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", json.dumps({
            "type": "service_account",
            "token_uri": "https://legacy.example.test/token",
        }))
        assert "legacy.example.test" in bq.proxy_hosts_for_bq()

    def test_default_token_uri_not_duplicated(self, tmp_path, monkeypatch):
        key = tmp_path / "key.json"
        key.write_text(json.dumps(
            {"token_uri": "https://oauth2.googleapis.com/token"}))
        monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(key))
        hosts = bq.proxy_hosts_for_bq()
        assert hosts.count("oauth2.googleapis.com") == 1

    def test_malformed_creds_tolerated(self, tmp_path, monkeypatch):
        key = tmp_path / "key.json"
        key.write_text("{not json")
        monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(key))
        assert bq.proxy_hosts_for_bq() == list(bq._DEFAULT_BQ_HOSTS)

    def test_override_replaces_default(self, tmp_path, monkeypatch):
        override = tmp_path / "bq-proxy-hosts.json"
        override.write_text(json.dumps({"hosts": ["bq.mirror.test"]}))
        monkeypatch.setattr(bq, "_OVERRIDE_CONFIG_PATH", override)
        assert bq.proxy_hosts_for_bq() == ["bq.mirror.test"]

    def test_malformed_override_falls_back(self, tmp_path, monkeypatch):
        override = tmp_path / "bq-proxy-hosts.json"
        override.write_text("[]")
        monkeypatch.setattr(bq, "_OVERRIDE_CONFIG_PATH", override)
        assert bq.proxy_hosts_for_bq() == list(bq._DEFAULT_BQ_HOSTS)


# =========================================================================
# execution against a stubbed google client
# =========================================================================


class _FakeJob:
    def __init__(self, rows=None, *, dry_bytes=None, raise_on_result=None):
        self._rows = rows if rows is not None else []
        self.total_bytes_processed = (
            dry_bytes if dry_bytes is not None else 4096)
        self.total_bytes_billed = 8192
        self.job_id = "job-123"
        self.cache_hit = False
        self._raise = raise_on_result

    def result(self, timeout=None):
        if self._raise is not None:
            raise self._raise
        return iter(self._rows)


class _FakeClient:
    def __init__(self, credentials=None, project=None):
        self.project = project or "stub-project"
        self.last_sql = None
        self.last_job_config = None
        self.next_job = _FakeJob(rows=[{"a": 1}])

    def query(self, sql, job_config=None):
        self.last_sql = sql
        self.last_job_config = job_config
        return self.next_job


def _install_google_stub(monkeypatch, client_holder):
    """Inject a minimal ``google`` module tree into sys.modules."""
    google = types.ModuleType("google")
    auth = types.ModuleType("google.auth")
    auth_exceptions = types.ModuleType("google.auth.exceptions")

    class GoogleAuthError(Exception):
        pass

    class DefaultCredentialsError(GoogleAuthError):
        pass

    auth_exceptions.GoogleAuthError = GoogleAuthError
    auth_exceptions.DefaultCredentialsError = DefaultCredentialsError
    auth.exceptions = auth_exceptions
    auth.default = lambda scopes=None: (object(), "adc-project")

    oauth2 = types.ModuleType("google.oauth2")
    service_account = types.ModuleType("google.oauth2.service_account")

    class _FakeSACreds:
        @staticmethod
        def from_service_account_info(info, scopes=None):
            return object()

    service_account.Credentials = _FakeSACreds
    oauth2.service_account = service_account

    cloud = types.ModuleType("google.cloud")
    bigquery_mod = types.ModuleType("google.cloud.bigquery")

    class QueryJobConfig:
        def __init__(self, **kw):
            self.dry_run = False
            self.use_query_cache = True
            self.maximum_bytes_billed = None
            for k, v in kw.items():
                setattr(self, k, v)

    def _client_factory(credentials=None, project=None):
        client = _FakeClient(credentials=credentials, project=project)
        client_holder.append(client)
        return client

    bigquery_mod.Client = _client_factory
    bigquery_mod.QueryJobConfig = QueryJobConfig
    cloud.bigquery = bigquery_mod
    google.auth = auth
    google.oauth2 = oauth2
    google.cloud = cloud

    for name, mod in {
        "google": google,
        "google.auth": auth,
        "google.auth.exceptions": auth_exceptions,
        "google.oauth2": oauth2,
        "google.oauth2.service_account": service_account,
        "google.cloud": cloud,
        "google.cloud.bigquery": bigquery_mod,
    }.items():
        monkeypatch.setitem(sys.modules, name, mod)
    return auth_exceptions


class TestExecute:
    @pytest.fixture
    def clients(self, monkeypatch):
        holder: list = []
        self._auth_exceptions = _install_google_stub(monkeypatch, holder)
        monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
        return holder

    def test_envelope_shape(self, clients):
        result = bq.execute("SELECT 1")
        assert result["dry_run"] is False
        assert result["rows"] == [{"a": 1}]
        assert result["row_count"] == 1
        assert result["job"]["job_id"] == "job-123"
        assert result["job"]["total_bytes_billed"] == 8192

    def test_bytes_billed_cap_applied(self, clients):
        bq.execute("SELECT 1", max_bytes_billed=12345)
        assert clients[0].last_job_config.maximum_bytes_billed == 12345

    def test_default_cap_applied(self, clients):
        bq.execute("SELECT 1")
        assert (clients[0].last_job_config.maximum_bytes_billed
                == bq.DEFAULT_MAX_BYTES_BILLED)

    def test_dry_run_envelope(self, clients, monkeypatch):
        def factory(credentials=None, project=None):
            client = _FakeClient(project=project)
            client.next_job = _FakeJob(dry_bytes=1024**4)
            clients.append(client)
            return client
        monkeypatch.setattr(
            sys.modules["google.cloud.bigquery"], "Client", factory)
        result = bq.execute("SELECT 1", dry_run=True)
        assert result["dry_run"] is True
        assert result["total_bytes_processed"] == 1024**4
        assert result["estimated_cost_usd"] == pytest.approx(6.25)
        assert clients[0].last_job_config.dry_run is True

    def test_validation_precedes_execution(self, clients):
        with pytest.raises(bq.QueryValidationError):
            bq.execute("DELETE FROM t WHERE TRUE")
        assert not clients  # no client was ever constructed

    def test_inline_json_credentials_project(self, clients, monkeypatch):
        monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", json.dumps(
            {"type": "service_account", "project_id": "inline-proj"}))
        result = bq.execute("SELECT 1")
        assert result["job"]["project"] == "inline-proj"

    def test_oversized_inline_credentials_rejected(self, clients,
                                                   monkeypatch):
        monkeypatch.setenv(
            "GOOGLE_APPLICATION_CREDENTIALS",
            "{" + " " * bq._CREDS_INLINE_MAX + "}")
        with pytest.raises(bq.CredentialsError):
            bq.execute("SELECT 1")

    def test_auth_error_classified_as_credentials(self, clients,
                                                  monkeypatch):
        exceptions = self._auth_exceptions

        def failing_default(scopes=None):
            raise exceptions.DefaultCredentialsError("no ADC here")
        monkeypatch.setattr(
            sys.modules["google.auth"], "default", failing_default)
        with pytest.raises(bq.CredentialsError):
            bq.execute("SELECT 1")

    def test_api_error_classified_as_query(self, clients, monkeypatch):
        def factory(credentials=None, project=None):
            client = _FakeClient(project=project)
            client.next_job = _FakeJob(
                raise_on_result=RuntimeError("quota exceeded"))
            clients.append(client)
            return client
        monkeypatch.setattr(
            sys.modules["google.cloud.bigquery"], "Client", factory)
        with pytest.raises(bq.QueryExecutionError):
            bq.execute("SELECT 1")

    def test_timeout_classified(self, clients, monkeypatch):
        def factory(credentials=None, project=None):
            client = _FakeClient(project=project)
            client.next_job = _FakeJob(raise_on_result=TimeoutError())
            clients.append(client)
            return client
        monkeypatch.setattr(
            sys.modules["google.cloud.bigquery"], "Client", factory)
        with pytest.raises(bq.QueryTimeoutError):
            bq.execute("SELECT 1", timeout_s=0.01)


class TestDependencyError:
    def test_missing_client_library(self):
        try:
            import google.cloud.bigquery  # noqa: F401
            pytest.skip("google-cloud-bigquery installed on this host")
        except ImportError:
            pass
        with pytest.raises(bq.DependencyError):
            bq.execute("SELECT 1")


# =========================================================================
# structured errors + child protocol
# =========================================================================


class TestWriteErrorJson:
    def test_typed_exception(self):
        buf = io.StringIO()
        code = bq.write_error_json(
            buf, bq.QueryValidationError("bad shape"))
        assert code == bq.EXIT_VALIDATION
        payload = json.loads(buf.getvalue())
        assert payload == {
            "error": "validation",
            "message": "bad shape",
            "exit_code": bq.EXIT_VALIDATION,
        }

    def test_ad_hoc_kind(self):
        buf = io.StringIO()
        code = bq.write_error_json(buf, "sandbox", "boom", bq.EXIT_SANDBOX)
        assert code == bq.EXIT_SANDBOX
        assert json.loads(buf.getvalue())["error"] == "sandbox"

    def test_single_line(self):
        buf = io.StringIO()
        bq.write_error_json(buf, bq.RequestInputError("x\ny"))
        assert buf.getvalue().count("\n") == 1


class TestChildMain:
    def _run_child(self, monkeypatch, stdin_text):
        monkeypatch.setattr(sys, "stdin", io.StringIO(stdin_text))
        out, err = io.StringIO(), io.StringIO()
        monkeypatch.setattr(sys, "stdout", out)
        monkeypatch.setattr(sys, "stderr", err)
        code = bq._child_main()
        return code, out.getvalue(), err.getvalue()

    def test_malformed_request(self, monkeypatch):
        code, _, err = self._run_child(monkeypatch, "{not json")
        assert code == bq.EXIT_INPUT
        assert json.loads(err)["error"] == "input"

    def test_non_object_request(self, monkeypatch):
        code, _, _err = self._run_child(monkeypatch, "[1, 2]")
        assert code == bq.EXIT_INPUT

    def test_missing_sql_key(self, monkeypatch):
        code, _, _err = self._run_child(monkeypatch, "{}")
        assert code == bq.EXIT_INPUT

    def test_validation_error_via_child(self, monkeypatch):
        code, _, err = self._run_child(
            monkeypatch, json.dumps({"sql": "DROP TABLE t"}))
        assert code == bq.EXIT_VALIDATION
        assert json.loads(err)["error"] == "validation"

    def test_success_roundtrip(self, monkeypatch):
        holder: list = []
        _install_google_stub(monkeypatch, holder)
        monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
        code, out, _ = self._run_child(
            monkeypatch,
            json.dumps({"sql": "SELECT 1", "max_bytes_billed": 999}))
        assert code == bq.EXIT_OK
        payload = json.loads(out)
        assert payload["rows"] == [{"a": 1}]
        assert holder[0].last_job_config.maximum_bytes_billed == 999


class TestJsonDefault:
    def test_bytes_base64(self):
        assert bq._json_default(b"\x00\xff") == "AP8="

    def test_fallback_str(self):
        import datetime
        stamp = datetime.datetime(
            2025, 7, 13, 20, 30, 24, tzinfo=datetime.timezone.utc)
        assert "2025-07-13" in bq._json_default(stamp)
