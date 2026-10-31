"""A REPL runtime exception must not become a successful empty-flow result."""

from unittest.mock import patch

from packages.joern.server import JoernServer, _has_scala_error


def test_runtime_exception_is_an_error_even_when_http_reports_success():
    server = JoernServer()
    server._cpg_loaded = True
    trace = "java.nio.file.AccessDeniedException: /installation/source.py\n  at java.base/java.nio.file.Files.writeString(Files.java:1)"
    with patch.object(server, "_post_sync", return_value={"success": True, "stdout": trace}):
        result = server.query("query")
    assert not result.ok and result.errors


def test_record_name_in_exception_message_cannot_hide_failure():
    assert _has_scala_error("java.lang.IllegalStateException: JOERN_FLOW: message")
    assert _has_scala_error("-- [E006] Not Found Error: JOERN_FLOW: message")


def test_exception_text_inside_source_record_is_data():
    assert not _has_scala_error("JOERN_FLOW:{\"code\":\"java.lang.IllegalStateException: text\"}")


def test_cli_runtime_exception_is_not_empty_success(tmp_path):
    from types import SimpleNamespace
    from packages.joern.models import JoernCPG
    from packages.joern.runner import run_query
    graph = tmp_path / "cpg.bin"
    graph.write_bytes(b"graph")
    result = run_query(JoernCPG(graph, tmp_path), "cpg.method.l",
                       subprocess_runner=lambda *a, **kw: SimpleNamespace(
                           stdout="java.lang.IllegalStateException: failed query",
                           stderr="", returncode=0))
    assert not result.ok and result.errors


def test_managed_query_scope_preserves_result_and_does_not_publish_local_values():
    server = JoernServer()
    server._cpg_loaded = True
    with patch.object(server, "_post_sync", return_value={"success": True, "stdout": "7"}) as post:
        result = server.query("val privateName = 7; privateName", isolate_scope=True)
    assert result.query == "val privateName = 7; privateName"
    assert result.ok
    assert post.call_args.args[0] == "locally {\nval privateName = 7; privateName\n}"


def test_missing_success_is_unknown_execution_not_empty_success():
    server = JoernServer()
    server._cpg_loaded = True
    with patch.object(server, "_post_sync", return_value={"stdout": ""}):
        result = server.query("query")
    assert not result.ok and result.execution_incomplete and result.errors
    assert result.to_dict()["execution_incomplete"] is True


def test_lost_transport_marks_execution_as_incomplete():
    server = JoernServer()
    server._cpg_loaded = True
    with patch.object(server, "_post_sync", return_value=None):
        result = server.query("query", no_restart=True)
    assert not result.ok and result.execution_incomplete
