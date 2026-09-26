"""Content pins for the recall-domain sink packs (second-order
stores, secrets flow, template engines).

These packs are pure data on the sealed pack format: every pin here
loads them through the UNCHANGED loader and matches them through the
UNCHANGED extractor — the assertions are about the data (pairing
closure, vocabulary membership, per-entry claims), never about new
code paths."""

from __future__ import annotations

import pytest

from core.taint.learned_intake import intake_learned_specs
from core.taint.mad_matrix import emissibility_report
from core.taint.packs import (
    PackSet,
    default_pack_names,
    load_packs,
)
from core.taint.summaries import (
    SpecIndex,
    build_spec_index,
    extract_summary,
    index_module_text,
)


@pytest.fixture(scope="module")
def seed_packs() -> PackSet:
    return load_packs(default_pack_names("python"))


@pytest.fixture(scope="module")
def specs(seed_packs: PackSet) -> SpecIndex:
    return build_spec_index(seed_packs)


def summarize(source: str, specs: SpecIndex, qualname: str):
    idx = index_module_text(source, "app.py", module_name="app")
    entry = idx.function_named(qualname)
    assert entry is not None, f"fixture must define {qualname}"
    return extract_summary(idx, entry, specs)


def pack_named(seed_packs: PackSet, name: str):
    matches = [p for p in seed_packs.packs if p.name == name]
    assert len(matches) == 1, f"{name} must ship exactly once"
    return matches[0]


# ── second-order-stores ──────────────────────────────────────────────


def test_second_order_pack_ships_as_pure_data(seed_packs: PackSet):
    """The pack rides the default name glob — shipping it changed no
    loader, matcher, or intake code."""
    assert "python/second-order-stores" in default_pack_names("python")
    pack = pack_named(seed_packs, "second-order-stores")
    assert all(s.kind == "stored_read" for s in pack.sources)
    kinds = {s.kind for s in pack.sinks}
    assert kinds == {"stored_write", "dotted_callee"}


def test_second_order_classes_enter_the_vocabulary(seed_packs: PackSet):
    vocab = seed_packs.taint_class_vocabulary()
    assert {"stored-user-input", "stored-taint", "deserialize"} <= vocab


def test_store_key_pairing_closes_within_the_pack(seed_packs: PackSet):
    """Every declared store has BOTH halves: a read source and a write
    sink sharing the store_key label. An unpaired half would declare a
    store the cross-request join can never close."""
    pack = pack_named(seed_packs, "second-order-stores")
    read_keys = {s.store_key for s in pack.sources if s.kind == "stored_read"}
    write_keys = {s.store_key for s in pack.sinks if s.kind == "stored_write"}
    assert read_keys and read_keys == write_keys


def test_stored_kinds_refuse_in_the_matrix_with_reasons(
    seed_packs: PackSet,
):
    """Models-as-data cannot express the store pairing — every
    stored_* row from this pack must land in the counted refusals with
    a per-kind reason, while the pack's plain dotted deserialization
    sink emits."""
    report = emissibility_report(seed_packs, language="python")
    reasons = {r.row: r.reason for r in report.rejected}
    pack = pack_named(seed_packs, "second-order-stores")
    for source in pack.sources:
        row = f"source:stored_read:{source.match}"
        assert "stored_read" in reasons[row]
    for sink in pack.sinks:
        if sink.kind != "stored_write":
            continue
        row = f"sink:stored_write:{sink.match}"
        assert "stored_write" in reasons[row]
    assert "sink:dotted_callee:pickle.loads" not in reasons


def test_pickle_loads_is_both_deser_sink_and_stored_source(
    specs: SpecIndex,
):
    """One callee, two independent claims: tainted INPUT fires the
    CWE-502 sink; the OUTPUT carries the stored-read taint either
    way."""
    src = """
import pickle

def f(blob):
    data = pickle.loads(blob)
    return data
"""
    s = summarize(src, specs, "f")
    deser = [ev for ev in s.sink_events if ev.match == "pickle.loads"]
    assert [ev.sink_class for ev in deser] == ["deserialize"]
    assert deser[0].cwe == "CWE-502"
    assert {f.origin for ev in deser for f in ev.flows} == {"param:0"}
    assert "stored_read" in {e.kind for e in s.source_events}
    assert any(
        f.origin == "source:stored_read:pickle.loads" for f in s.returns
    )


def test_deserialize_label_joins_the_learned_channel(seed_packs: PackSet):
    """The store's raw ``deserialize`` spelling used to refuse counted
    (no pack declared the class); the second-order pack declaring it
    is the pure-data unlock."""
    result = intake_learned_specs(
        [{
            "role": "sink", "function": "app.codec.load_state",
            "taint_classes": ["deserialize"], "confidence": 0.8,
        }],
        vocabulary=seed_packs.taint_class_vocabulary(),
    )
    assert [s.taint_classes for s in result.sinks] == [("deserialize",)]


def test_execute_storage_claim_is_disjoint_from_the_sqli_claim(
    seed_packs: PackSet,
):
    """cursor.execute carries two claims in the shipped set: the
    web-injection-core sqli claim on the STATEMENT (argument 0 of the
    bound method_name spelling) and this pack's storage claim on the
    PARAMETERS (argument 2 of the unbound dotted spelling, past the
    cursor and the statement). They must not restate each other."""
    stored = [
        s for s in seed_packs.sinks
        if s.kind == "stored_write" and s.match.endswith(".execute")
    ]
    assert stored
    for sink in stored:
        assert sink.args == (2,)
        assert sink.sink_class == "stored-taint"
    sqli = [
        s for s in seed_packs.sinks
        if s.kind == "method_name" and s.match == "execute"
    ]
    assert sqli
    for sink in sqli:
        assert sink.args == (0,)
        assert sink.sink_class == "sql-injection"
