import json
import subprocess

import pytest

from core.dataflow.barrier_synth import adjudicate


def test_adjudication_refuses_previous_output_when_runner_writes_nothing(tmp_path):
    pack = tmp_path / "owned-pack"
    pack.mkdir()
    output = pack / "out.sarif"
    output.write_text(json.dumps({"runs": [{"results": []}]}))
    calls = []

    def runner(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    with pytest.raises(ValueError, match="SARIF document must be an object"):
        adjudicate("owned query", tmp_path / "db", work_dir=pack, runner=runner)
    assert len(calls) == 1
    assert (pack / "SynthBarrier.ql").read_text() == "owned query"


def test_adjudication_counts_fresh_output_after_previous_artifact(tmp_path):
    pack = tmp_path / "owned-pack"
    pack.mkdir()
    output = pack / "out.sarif"
    output.write_text(json.dumps({"runs": [{"results": []}]}))
    calls = []

    def runner(argv, **kwargs):
        calls.append(argv)
        assert not output.exists()
        output.write_text(json.dumps({"runs": [{"results": [{}]}]}))
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    assert adjudicate("owned query", tmp_path / "db", work_dir=pack, runner=runner) == 1
    assert len(calls) == 1
