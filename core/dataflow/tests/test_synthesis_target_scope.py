"""Invalid target scopes refuse synthesis before proposing or reading."""

import json

import pytest

from core.dataflow import barrier_synth


@pytest.mark.parametrize("line", [0, -1, False, True, 1.0, "1"])
def test_invalid_target_line_cannot_establish_zero_count(tmp_path, line):
    path = tmp_path / "owned.sarif"
    path.write_text(json.dumps({"runs": [{"results": [{"locations": [{
        "physicalLocation": {"artifactLocation": {"uri": "a.py"},
                             "region": {"startLine": 1}},
    }]}]}]}))
    with pytest.raises(ValueError, match="target_line"):
        barrier_synth._count_results_for_target(path, "a.py", line)


@pytest.mark.parametrize("scope", [
    {"target_uri": "a.py", "target_line": 0},
    {"target_line": 1}, {"target_uri": ""}, {"target_uri": False},
])
def test_invalid_scope_refuses_before_proposer(tmp_path, scope):
    def proposer(*args, **kwargs):
        pytest.fail("invalid scope must not reach proposer")

    proposal = barrier_synth.BarrierProposal("cmdi", "owned", "sink(value)", "fixture")
    with pytest.raises(ValueError, match="target_"):
        barrier_synth.run_synthesis_loop(
            proposal, tmp_path / "after", tmp_path / "before",
            proposer=proposer, work_dir=tmp_path / "work", **scope,
        )
    assert not (tmp_path / "work").exists()


def test_target_line_requires_uri_before_reading(tmp_path):
    with pytest.raises(ValueError, match="target_line.*target_uri"):
        barrier_synth._count_results_for_target(tmp_path / "absent.sarif", target_line=1)


def test_direct_adjudication_refuses_before_writing_or_running(tmp_path):
    def runner(*args, **kwargs):
        pytest.fail("invalid scope must not reach runner")

    work = tmp_path / "work"
    with pytest.raises(ValueError, match="target_line"):
        barrier_synth.adjudicate(
            "owned inert query", tmp_path / "db", work_dir=work,
            target_uri="a.py", target_line=0, runner=runner,
        )
    assert not work.exists()
