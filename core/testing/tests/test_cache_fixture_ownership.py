"""Cache fixtures borrow their caller's state without clearing it."""

import importlib
import inspect

import pytest


CASES = [
    (
        "core.audit.tests.test_vocab_packs",
        "_clear_caches",
        [("vocab_packs", "_pack_cache"), ("vocab_packs", "_kernel_tree_cache")],
    ),
    (
        "packages.llm_analysis.tests.test_iris_specs_in_predicates",
        "_clear_note_cache",
        [("dv", "_IRIS_NOTE_CACHE")],
    ),
    (
        "core.audit.tests.test_context_type_cache",
        "clear_type_caches",
        [("context", "_type_definition_cache"), ("context", "_header_cache")],
    ),
    (
        "core.llm.tests.test_raptor_config_schema_guard",
        "_fresh_warn_latch",
        [("detection", "_schema_mismatch_warned")],
    ),
    (
        "core.audit.tests.test_call_edge_store_consumers",
        "_hermetic_ambient_state",
        [("orch_mod", "_GRAPH_STORE_MEMO"), ("pc", "_STORE_LANE_MEMO")],
    ),
]


@pytest.mark.parametrize("module_name,fixture_name,fields", CASES)
@pytest.mark.parametrize("interrupt", [False, True])
def test_cache_fixture_preserves_borrowed_state(
    module_name,
    fixture_name,
    fields,
    interrupt,
    tmp_path,
    monkeypatch,
):
    module = importlib.import_module(module_name)
    borrowed = []
    for owner_name, field in fields:
        if owner_name == "orch_mod":
            owner = importlib.import_module("core.audit.orchestrator")
        else:
            owner = getattr(module, owner_name)
        original = (
            {"borrowed"}
            if field == "_schema_mismatch_warned"
            else {"borrowed": object()}
        )
        monkeypatch.setattr(owner, field, original)
        borrowed.append((owner, field, original, original.copy()))
    function = getattr(module, fixture_name).__wrapped__
    patch = pytest.MonkeyPatch()
    generator = None
    try:
        kwargs = {"monkeypatch": patch, "tmp_path": tmp_path}
        result = function(
            **{
                key: value
                for key, value in kwargs.items()
                if key in inspect.signature(function).parameters
            }
        )
        if inspect.isgenerator(result):
            generator = result
            next(generator)
        for owner, field, original, contents in borrowed:
            assert getattr(owner, field) is not original
            assert original == contents
        if interrupt:
            raise KeyboardInterrupt
    except KeyboardInterrupt:
        pass
    finally:
        if generator is not None:
            try:
                next(generator)
            except StopIteration:
                pass
            finally:
                generator.close()
        patch.undo()
    for owner, field, original, contents in borrowed:
        assert getattr(owner, field) is original
        assert original == contents
