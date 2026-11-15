"""Malformed query sequences cannot retire output or invoke a runner."""

import subprocess

import pytest

from core.dataflow import codeql_augmented_run as module


def test_query_sequence_domain_precedes_output_and_dispatch(tmp_path, monkeypatch):
    monkeypatch.setattr(module.CodeQLTunables, "from_tuning",
                        lambda: module.CodeQLTunables(threads=1, ram_mb=512))
    output = tmp_path / "owned.sarif"
    calls = []

    def runner(argv, **kwargs):
        calls.append(argv)
        output.write_text("new owned report")
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    for queries in (["owned query.ql"], ("scope/queries:owned",)):
        output.write_text("prior owned report")
        calls.clear()
        result = module.analyze(tmp_path / "db", queries, output, runner=runner)
        assert len(calls) == 1
        assert calls[0][4:4 + len(queries)] == list(queries)
        assert result.queries == tuple(queries)
        assert output.read_text() == "new owned report"
    for queries in ("owned.ql", b"owned.ql", {"owned.ql": True}, 7, None,
                    [""], ["  "], [None], [True], [1], ["owned.ql", []]):
        calls.clear()
        output.write_text("prior owned report")
        with pytest.raises(ValueError, match="quer"):
            module.analyze(tmp_path / "db", queries, output, runner=runner)
        assert calls == []
        assert output.read_text() == "prior owned report"
