"""Keep value-epoch witnesses separate from unverified sink interpretation."""
from core.dataflow import smt_barrier as sb


def assert_epoch_character_model(result, retained):
    """A retained epoch proves a conditional character model, never a sink."""
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    assert result.artifact is None
    model = result.extras.get("smt_character_model")
    if retained:
        assert model is not None, result.reasoning
        assert model["sound"] is True
        assert model["source_bound"] is False
        assert "sink interpretation" in result.reasoning
    else:
        assert model is None, result.reasoning
