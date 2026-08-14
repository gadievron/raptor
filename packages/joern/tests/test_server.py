"""Tests for packages.joern.server."""

from __future__ import annotations

from unittest.mock import patch

from packages.joern.server import (
    JoernServer,
    _find_free_port,
    _repl_bridge_path,
)
from packages.joern.tunables import JoernTunables


class TestFindFreePort:
    def test_returns_nonzero_port(self):
        port = _find_free_port()
        assert isinstance(port, int)
        assert port > 0


class TestReplBridgePath:
    @patch("packages.joern.server._joern_path", return_value=None)
    def test_returns_none_when_joern_missing(self, _):
        assert _repl_bridge_path() is None

    @patch("packages.joern.server._joern_path")
    def test_finds_bridge_next_to_joern(self, mock_joern, tmp_path):
        joern_bin = tmp_path / "joern"
        joern_bin.write_text("#!/bin/bash\n", encoding="utf-8")
        bridge = tmp_path / "repl-bridge"
        bridge.write_text("#!/bin/bash\n", encoding="utf-8")
        mock_joern.return_value = str(joern_bin)
        result = _repl_bridge_path()
        assert result == str(bridge)


class TestJoernServerInit:
    def test_default_values(self):
        srv = JoernServer()
        assert srv._heap_mb is None
        assert srv._proc is None
        assert srv._port is None
        assert srv._cpg_loaded is False

    def test_custom_heap(self):
        srv = JoernServer(heap_mb=2048)
        assert srv._heap_mb == 2048

    def test_from_tunables(self):
        t = JoernTunables(heap_mb=1024, cpg_timeout_s=60, query_timeout_s=60)
        srv = JoernServer.from_tunables(t)
        assert srv._heap_mb == 1024
        assert srv._query_timeout_s == 60

    def test_from_tunables_none_heap(self):
        t = JoernTunables(heap_mb=None)
        srv = JoernServer.from_tunables(t)
        assert srv._heap_mb is None

    def test_from_tunables_default(self):
        srv = JoernServer.from_tunables()
        assert srv._heap_mb is None
        assert srv._query_timeout_s == 300


class TestJoernServerProperties:
    def test_port_none_before_start(self):
        srv = JoernServer()
        assert srv.port is None

    def test_pid_none_before_start(self):
        srv = JoernServer()
        assert srv.pid is None


class TestJoernServerIsAlive:
    def test_not_alive_before_start(self):
        srv = JoernServer()
        assert srv.is_alive() is False


class TestJoernServerQuery:
    def test_query_without_cpg(self):
        srv = JoernServer()
        srv._cpg_loaded = False
        result = srv.query("cpg.method.l")
        assert result.errors
        assert "no CPG loaded" in result.errors[0]

    def test_query_validation_blocks_dangerous(self):
        srv = JoernServer()
        srv._cpg_loaded = True
        result = srv.query('java.io.File("/etc/passwd")')
        assert result.errors
        assert "blocked" in result.errors[0]

    def test_query_fails_fast_when_server_process_dead(self):
        """If the server process has exited, query() returns an error
        immediately rather than blocking on a stale HTTP connection."""
        from unittest.mock import MagicMock

        srv = JoernServer()
        srv._cpg_loaded = True
        srv._base_url = "http://127.0.0.1:9999"

        mock_proc = MagicMock()
        mock_proc.poll.return_value = 1  # process exited
        srv._proc = mock_proc

        result = srv.query("cpg.method.l")
        assert result.errors
        assert "server process exited" in result.errors[0]


class TestJoernServerQueryScript:
    def test_script_not_found(self, tmp_path):
        srv = JoernServer()
        result = srv.query_script(tmp_path / "nonexistent.sc")
        assert result.errors
        assert "not found" in result.errors[0]


class TestJoernServerImportCpg:
    def test_cpg_file_not_found(self, tmp_path):
        srv = JoernServer()
        srv._base_url = "http://127.0.0.1:9999"
        ok = srv.import_cpg(tmp_path / "nonexistent.bin")
        assert ok is False


class TestJoernServerImportCode:
    def test_target_not_directory(self, tmp_path):
        srv = JoernServer()
        srv._base_url = "http://127.0.0.1:9999"
        f = tmp_path / "file.c"
        f.write_text("int main(){}", encoding="utf-8")
        ok = srv.import_code(f)
        assert ok is False


class TestJoernServerCloseWorkspace:
    @patch.object(JoernServer, "_post_sync", return_value={"success": True})
    def test_close_workspace_resets_flag(self, mock_post):
        srv = JoernServer()
        srv._cpg_loaded = True
        srv.close_workspace()
        assert srv._cpg_loaded is False
        mock_post.assert_called_once()


class TestJoernServerRunTaintQuery:
    def test_rejects_invalid_source(self):
        srv = JoernServer()
        srv._cpg_loaded = True
        flows = srv.run_taint_query("not valid!", "memcpy")
        assert flows == []

    def test_rejects_invalid_sink(self):
        srv = JoernServer()
        srv._cpg_loaded = True
        flows = srv.run_taint_query("parse_header", "not valid!")
        assert flows == []


class TestJoernServerContextManager:
    @patch.object(JoernServer, "start")
    @patch.object(JoernServer, "stop")
    def test_context_manager(self, mock_stop, mock_start):
        with JoernServer():
            mock_start.assert_called_once()
        assert mock_stop.call_count >= 1


class TestJoernServerStopIdempotent:
    def test_stop_before_start(self):
        srv = JoernServer()
        srv.stop()  # should not raise
        assert srv._proc is None


class TestJoernServerRunTieredSweep:
    def test_script_not_found(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "packages.joern.server.Path",
            lambda *a, **kw: tmp_path / "nonexistent",
        )
        srv = JoernServer()
        srv._cpg_loaded = True
        result = srv.run_tiered_sweep()
        assert result.errors
        assert "not found" in result.errors[0]

    def test_substitutes_lang_profile_sinks(self, tmp_path):
        from packages.joern.lang_config import PYTHON, C_CPP
        script_path = (
            __import__("pathlib").Path(__file__).resolve().parent.parent
            / "queries" / "tiered_taint.sc"
        )
        content = script_path.read_text(encoding="utf-8")

        for profile in (PYTHON, C_CPP):
            for sink in profile.sinks[:3]:
                assert sink in " ".join(profile.sinks)

            sink_items = ", ".join(f'"{s}"' for s in profile.sinks)
            expected = f"List({sink_items})"
            substituted = content.replace("__DANGEROUS_SINKS__", expected)
            assert "__DANGEROUS_SINKS__" not in substituted
            assert expected in substituted

    def test_substitutes_depth_and_args(self):
        from packages.joern.lang_config import C_CPP
        script_path = (
            __import__("pathlib").Path(__file__).resolve().parent.parent
            / "queries" / "tiered_taint.sc"
        )
        content = script_path.read_text(encoding="utf-8")
        sink_items = ", ".join(f'"{s}"' for s in C_CPP.sinks)
        content = content.replace("__DANGEROUS_SINKS__", f"List({sink_items})")
        content = content.replace("__EFFECTIVE_DEPTH__", str(C_CPP.max_call_depth))
        content = content.replace("__MAX_ARGS__", str(C_CPP.max_args_to_allow))
        content = content.replace("__MAX_OUTPUT_ARGS__", str(C_CPP.max_output_args_expansion))

        assert "__EFFECTIVE_DEPTH__" not in content
        assert "__MAX_ARGS__" not in content
        assert "__MAX_OUTPUT_ARGS__" not in content
        assert "val effectiveDepth = 4" in content
        assert "maxArgsToAllow = 200" in content
        assert "maxOutputArgsExpansion = 200" in content

    def test_without_cpg(self):
        srv = JoernServer()
        srv._cpg_loaded = False
        result = srv.run_tiered_sweep()
        assert result.errors
        assert "no CPG loaded" in result.errors[0]


class TestJoernServerZGCFlags:
    @staticmethod
    def _safe_stop(srv):
        # The mocked Popen carries a fake pid — stop() must never reach the
        # real os.killpg, or it signals whatever live process group owns
        # that pgid (this killed operator screen sessions).
        with patch("packages.joern.server.os.killpg",
                   side_effect=ProcessLookupError):
            srv.stop()

    @staticmethod
    def _start_and_capture(srv):
        from unittest.mock import MagicMock

        captured_cmd = []

        def fake_popen(cmd, **kwargs):
            captured_cmd.extend(cmd)
            mock_proc = MagicMock()
            mock_proc.pid = 12345
            mock_proc.poll.return_value = None
            mock_proc.stderr = MagicMock()
            mock_proc.wait = MagicMock()
            return mock_proc

        with patch("packages.joern.server.os.killpg",
                   side_effect=ProcessLookupError):
            with patch("packages.joern.server.subprocess.Popen",
                       side_effect=fake_popen):
                with patch.object(srv, "_wait_for_ready", return_value=True):
                    with patch.object(srv, "_warmup_imports"):
                        srv.start()
        return captured_cmd

    def test_start_cmd_includes_zgc_jdk21(self):
        """JDK 21-23: ZGC selected, G1 disabled, ZGenerational passed."""
        srv = JoernServer(heap_mb=8192)
        with patch("packages.joern.prereqs._java_version", return_value=21):
            captured_cmd = self._start_and_capture(srv)

        assert "-J-XX:-UseG1GC" in captured_cmd
        assert "-J-XX:+UseZGC" in captured_cmd
        assert "-J-XX:+ZGenerational" in captured_cmd
        assert "-J-XX:+UseStringDeduplication" in captured_cmd
        assert "-J-Djava.util.concurrent.ForkJoinPool.common.parallelism=6" in captured_cmd
        assert "-J-Xms8192m" in captured_cmd
        assert "-J-Xmx8192m" in captured_cmd

        self._safe_stop(srv)

    def test_start_cmd_omits_zgenerational_jdk24_plus(self):
        """JDK >= 24 removed ZGenerational — must not be passed."""
        srv = JoernServer()
        with patch("packages.joern.prereqs._java_version", return_value=25):
            captured_cmd = self._start_and_capture(srv)

        assert "-J-XX:+UseZGC" in captured_cmd
        assert "-J-XX:+ZGenerational" not in captured_cmd

        self._safe_stop(srv)

    def test_boot_retries_without_gc_flags_when_jvm_dies(self):
        """First boot dies (e.g. GC flag conflict) → retry with defaults."""
        from unittest.mock import MagicMock

        srv = JoernServer()
        launches = []

        def fake_popen(cmd, **kwargs):
            launches.append(list(cmd))
            mock_proc = MagicMock()
            mock_proc.pid = 12345
            # First launch: dead process; second: alive.
            mock_proc.poll.return_value = 1 if len(launches) == 1 else None
            mock_proc.stderr = MagicMock()
            mock_proc.wait = MagicMock()
            return mock_proc

        ready_results = iter([False, True])

        with patch("packages.joern.prereqs._java_version", return_value=25):
            with patch("packages.joern.server.os.killpg",
                       side_effect=ProcessLookupError):
                with patch("packages.joern.server.subprocess.Popen",
                           side_effect=fake_popen):
                    with patch.object(srv, "_wait_for_ready",
                                      side_effect=lambda: next(ready_results)):
                        with patch.object(srv, "_warmup_imports"):
                            srv.start()

        assert len(launches) == 2
        assert any(a.startswith("-J-XX:") for a in launches[0])
        assert not any(a.startswith("-J-XX:") for a in launches[1])

        self._safe_stop(srv)


class TestQueryCancellable:
    def test_cancel_before_result(self):
        srv = JoernServer()
        srv._cpg_loaded = True
        srv._base_url = "http://127.0.0.1:9999"

        call_count = 0

        def fake_post_async(query_str):
            return "test-uuid-123"

        def fake_get_result(uuid):
            return None

        def cancel_immediately():
            nonlocal call_count
            call_count += 1
            return call_count >= 1

        with patch.object(srv, "_post_async", side_effect=fake_post_async), \
             patch.object(srv, "_get_result", side_effect=fake_get_result):
            result = srv.query_cancellable(
                "cpg.method.l",
                cancel_check=cancel_immediately,
                poll_interval=0.01,
            )
        assert result.errors
        assert "cancelled" in result.errors[0]

    def test_result_returned_when_ready(self):
        srv = JoernServer()
        srv._cpg_loaded = True
        srv._base_url = "http://127.0.0.1:9999"

        def fake_post_async(query_str):
            return "test-uuid-456"

        def fake_get_result(uuid):
            return {"stdout": "", "stderr": "", "success": True}

        with patch.object(srv, "_post_async", side_effect=fake_post_async), \
             patch.object(srv, "_get_result", side_effect=fake_get_result):
            result = srv.query_cancellable("cpg.method.l", poll_interval=0.01)
        assert not result.errors
        assert result.ok

    def test_falls_back_to_sync_when_async_unavailable(self):
        srv = JoernServer()
        srv._cpg_loaded = True
        srv._base_url = "http://127.0.0.1:9999"

        def fake_post_async(query_str):
            return None

        sync_resp = {"stdout": "", "stderr": "", "success": True}

        with patch.object(srv, "_post_async", side_effect=fake_post_async), \
             patch.object(srv, "_post_sync", return_value=sync_resp):
            result = srv.query_cancellable("cpg.method.l")
        assert result.ok

    def test_no_cpg_returns_error(self):
        srv = JoernServer()
        srv._cpg_loaded = False
        result = srv.query_cancellable("cpg.method.l")
        assert result.errors
        assert "no CPG loaded" in result.errors[0]

    def test_timeout_returns_error(self):
        srv = JoernServer(query_timeout_s=1)
        srv._cpg_loaded = True
        srv._base_url = "http://127.0.0.1:9999"

        with patch.object(srv, "_post_async", return_value="uuid-789"), \
             patch.object(srv, "_get_result", return_value=None), \
             patch.object(srv, "restart", return_value=False):
            result = srv.query_cancellable(
                "cpg.method.l", timeout=1, poll_interval=0.1,
            )
        assert result.errors
        assert "timeout" in result.errors[0]

    def test_post_async_returns_none_without_base_url(self):
        srv = JoernServer()
        srv._base_url = None
        assert srv._post_async("1+1") is None

    def test_get_result_returns_none_without_base_url(self):
        srv = JoernServer()
        srv._base_url = None
        assert srv._get_result("some-uuid") is None


class TestRestart:
    def test_restart_after_query_timeout(self):
        """When query() gets a timeout, it restarts the server so
        subsequent queries don't queue behind the stuck one."""
        srv = JoernServer()
        srv._cpg_loaded = True
        srv._base_url = "http://127.0.0.1:9999"

        with patch.object(srv, "_post_sync", return_value=None), \
             patch.object(srv, "restart", return_value=True) as mock_restart:
            srv._last_post_error = "query timed out after 300s"
            result = srv.query("cpg.method.l")
        assert result.errors
        mock_restart.assert_called_once()

    def test_no_restart_on_non_timeout_error(self):
        """Non-timeout errors should not trigger a restart."""
        srv = JoernServer()
        srv._cpg_loaded = True
        srv._base_url = "http://127.0.0.1:9999"

        with patch.object(srv, "_post_sync", return_value=None), \
             patch.object(srv, "restart") as mock_restart:
            srv._last_post_error = "connection failed: refused"
            result = srv.query("cpg.method.l")
        assert result.errors
        mock_restart.assert_not_called()

    def test_restart_preserves_cpg_path(self, tmp_path):
        """restart() should reload the CPG from the stored path."""
        cpg_file = tmp_path / "cpg.bin"
        cpg_file.write_bytes(b"")

        srv = JoernServer()
        srv._cpg_path = cpg_file

        with patch.object(srv, "stop"), \
             patch.object(srv, "start"), \
             patch.object(srv, "import_cpg", return_value=True) as mock_import:
            result = srv.restart()
        assert result is True
        mock_import.assert_called_once_with(cpg_file)


class TestRunTaintExistsQuery:
    def test_exists_true(self):
        srv = JoernServer()
        srv._cpg_loaded = True
        srv._base_url = "http://127.0.0.1:9999"

        resp = {"stdout": "JOERN_EXISTS:true\n", "stderr": "", "success": True}
        with patch.object(srv, "_post_sync", return_value=resp):
            assert srv.run_taint_exists_query("foo", "bar") is True

    def test_exists_false(self):
        srv = JoernServer()
        srv._cpg_loaded = True
        srv._base_url = "http://127.0.0.1:9999"

        resp = {"stdout": "JOERN_EXISTS:false\n", "stderr": "", "success": True}
        with patch.object(srv, "_post_sync", return_value=resp):
            assert srv.run_taint_exists_query("foo", "bar") is False

    def test_invalid_source_returns_false(self):
        srv = JoernServer()
        srv._cpg_loaded = True
        assert srv.run_taint_exists_query("foo;bar", "baz") is False


class TestRunSummaryBatch:
    def test_empty_methods_returns_empty(self):
        srv = JoernServer()
        srv._cpg_loaded = True
        assert srv.run_summary_batch([]) == {}

    def test_no_cpg_returns_empty(self):
        srv = JoernServer()
        srv._cpg_loaded = False
        assert srv.run_summary_batch(["foo"]) == {}

    def test_invalid_method_returns_empty(self):
        srv = JoernServer()
        srv._cpg_loaded = True
        assert srv.run_summary_batch(["not valid!"]) == {}

    def test_parses_summary_output(self):
        srv = JoernServer()
        srv._cpg_loaded = True
        srv._base_url = "http://127.0.0.1:9999"

        raw = 'METHOD:foo|TAINTS:buf|PRE:assert(buf != NULL)|RET:int\n'
        resp = {"stdout": raw, "stderr": "", "success": True}
        with patch.object(srv, "_post_sync", return_value=resp):
            result = srv.run_summary_batch(["foo"])
        assert "foo" in result
        assert result["foo"].taint_rules == ["buf"]
        assert result["foo"].preconditions == ["assert(buf != NULL)"]
        assert result["foo"].returns == ["int"]

    def test_uses_cancellable_when_cancel_check_provided(self):
        srv = JoernServer()
        srv._cpg_loaded = True
        srv._base_url = "http://127.0.0.1:9999"

        raw = 'METHOD:bar|TAINTS:|PRE:|RET:void\n'

        def fake_post_async(query_str):
            return "uuid-summary"

        def fake_get_result(uuid):
            return {"stdout": raw, "stderr": "", "success": True}

        with patch.object(srv, "_post_async", side_effect=fake_post_async), \
             patch.object(srv, "_get_result", side_effect=fake_get_result):
            result = srv.run_summary_batch(
                ["bar"], cancel_check=lambda: False, timeout=30,
            )
        assert "bar" in result
        assert result["bar"].returns == ["void"]


class TestWarmupDataflow:
    @patch.object(JoernServer, "_post_sync", return_value={"stdout": "List()", "success": True})
    def test_warmup_fires_reachable_by(self, mock_post):
        srv = JoernServer()
        srv._warmup_dataflow()
        assert mock_post.called
        query = mock_post.call_args[0][0]
        assert "reachableBy" in query
        assert "__RAPTOR_WARMUP_NONEXISTENT__" in query
        assert "dataflowengineoss" in query
