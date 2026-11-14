"""Synthesis retry-budget refusal happens before proposing or iterating."""

import pytest

from core.dataflow.barrier_synth import (
    BarrierProposal, run_synthesis_loop, synthesize_over_corpus,
)


def _no_proposal(*args, **kwargs):
    pytest.fail("proposer must not run")


@pytest.mark.parametrize("field", ["max_attempts", "max_refine_attempts"])
@pytest.mark.parametrize("value", [-1, False, True, 1.5, "1", None])
def test_loop_refuses_invalid_retry_budget_before_proposing(tmp_path, field, value):
    proposal = BarrierProposal("cmdi", "owned", "sink(value)", "owned fixture")
    with pytest.raises(ValueError, match=field):
        run_synthesis_loop(
            proposal, tmp_path / "after", tmp_path / "before",
            proposer=_no_proposal, work_dir=tmp_path / "work",
            **{field: value},
        )


def test_zero_attempts_preserves_no_proposal_result(tmp_path):
    proposal = BarrierProposal("cmdi", "owned", "sink(value)", "owned fixture")
    diag = {}
    result = run_synthesis_loop(
        proposal, tmp_path / "after", tmp_path / "before",
        proposer=_no_proposal, work_dir=tmp_path / "work",
        max_attempts=0, diag=diag,
    )
    assert result is None
    assert diag == {"last_error": None, "attempts": 0, "refine_attempts": 0}


def test_corpus_refuses_negative_budget_before_consuming_items(tmp_path):
    def items():
        pytest.fail("items must not be consumed")
        yield

    with pytest.raises(ValueError, match="max_attempts"):
        synthesize_over_corpus(
            items(), proposer=_no_proposal, work_dir=tmp_path, max_attempts=-1,
        )
