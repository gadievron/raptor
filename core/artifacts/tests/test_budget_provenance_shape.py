"""Unknown provenance never grants permission to shed narrative records."""
from copy import deepcopy

import pytest

from core.artifacts import context_map_budget as mod


@pytest.fixture(autouse=True)
def no_artifact_write(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("in-memory budget test attempted artifact write")
    monkeypatch.setattr(mod, "write_bytes_atomically", forbidden)
    monkeypatch.setattr(mod, "save_context_map", forbidden)


@pytest.mark.parametrize("unknown", [[], {}], ids=["array", "object"])
@pytest.mark.parametrize("slot,field,stamp", [
    ("entry_points", "origin", "inventory-entry"),
    ("sinks", "source", "mechanical"),
    ("sink_details", "source", "heuristic"),
], ids=["entry", "sink", "sink-detail"])
def test_unknown_provenance_survives_budget_degradation(slot, field, stamp, unknown):
    narrative = {"id": "owned narrative", field: unknown, "ast_view": "retain me"}
    machine = {"id": "owned machine", field: stamp, "ast_view": "x" * 512}
    before = deepcopy(narrative)
    data = {slot: [narrative, machine]}
    applied = mod.enforce_context_map_budget(data, budget_bytes=1)
    assert applied
    assert data[slot] == [before]
    assert narrative == before


@pytest.mark.parametrize("value", [None, "unknown", 7, False], ids=["null", "text", "integer", "boolean"])
def test_unknown_scalar_stamps_stay_unclassified(value):
    assert not mod._is_synthesized({"origin": value})
    assert not mod._is_machine_sink({"source": value})


def test_known_provenance_vocabulary_is_unchanged():
    assert mod._is_synthesized({"origin": "inventory-entry"})
    assert mod._is_machine_sink({"source": "mechanical"})
    assert mod._is_machine_sink({"source": "heuristic"})
    assert not mod._is_synthesized({"origin": "mechanical"})
    assert not mod._is_machine_sink({"source": "inventory-entry"})
