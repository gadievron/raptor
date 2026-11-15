"""Extra argument shape errors cannot retire a previous analysis report."""

import subprocess

import pytest

from core.dataflow import codeql_augmented_run as module


def test_extra_argument_sequence_precedes_output_and_dispatch(tmp_path, monkeypatch):
    monkeypatch.setattr(module.CodeQLTunables, "from_tuning",
                        lambda: module.CodeQLTunables(threads=1, ram_mb=512))
    output = tmp_path / "owned.sarif"
    calls = []

    def runner(argv, **kwargs):
        calls.append(argv)
        output.write_text("new owned report")
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    for extra in ((), ["--threads=8"], ("--owned-option", ""), ["--owned-option", "a b"]):
        calls.clear()
        output.write_text("prior owned report")
        before = tuple(extra)
        module.analyze(tmp_path / "db", ["owned.ql"], output, extra_args=extra, runner=runner)
        assert len(calls) == 1
        if extra:
            assert calls[0][-len(extra):] == list(extra)
        assert tuple(extra) == before
        assert output.read_text() == "new owned report"
    for extra in ("--threads=8", b"--threads=8", {"--threads=8": True}, 7, None,
                  [None], [True], [1], ["--threads=8", []]):
        calls.clear()
        output.write_text("prior owned report")
        with pytest.raises(ValueError, match="extra_args"):
            module.analyze(tmp_path / "db", ["owned.ql"], output, extra_args=extra, runner=runner)
        assert calls == []
        assert output.read_text() == "prior owned report"
