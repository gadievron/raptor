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


# ── secrets-flow ─────────────────────────────────────────────────────


def test_secrets_pack_ships_as_pure_data(seed_packs: PackSet):
    assert "python/secrets-flow" in default_pack_names("python")
    vocab = seed_packs.taint_class_vocabulary()
    assert {"secret", "secret-exposure"} <= vocab


def test_env_secret_reaches_the_logging_sink(specs: SpecIndex):
    """End-to-end through the unchanged extractor: a credential read
    seeds the secret class and the printf-style logging argument
    (position 1, not just the message) fires the sink."""
    src = """
import os
import logging

def f():
    token = os.environ.get("API_TOKEN")
    logging.info("using token %s", token)
"""
    s = summarize(src, specs, "f")
    hits = [ev for ev in s.sink_events if ev.match == "logging.info"]
    assert [ev.sink_class for ev in hits] == ["secret-exposure"]
    assert hits[0].cwe == "CWE-532"
    origins = {f.origin for ev in hits for f in ev.flows}
    assert origins == {"source:call_return:os.environ.get"}


def test_logger_instance_spelling_fires_heuristically(specs: SpecIndex):
    """logger.debug has no import binding — the method_name entry
    gated on the receiver named logger is what catches it."""
    src = """
import logging

logger = logging.getLogger(__name__)

def f(secret):
    logger.debug("key=%s", secret)
"""
    s = summarize(src, specs, "f")
    hits = [ev for ev in s.sink_events if ev.match == "debug"]
    assert [ev.sink_class for ev in hits] == ["secret-exposure"]
    assert {f.origin for ev in hits for f in ev.flows} == {"param:0"}


def test_warning_tier_secrets_sinks_declare_heuristic_confidence(
    seed_packs: PackSet,
):
    """print and Exception fire on ubiquitous calls — the entries must
    carry the weaker confidence so consumers can weigh them."""
    pack = pack_named(seed_packs, "secrets-flow")
    by_match = {s.match: s for s in pack.sinks}
    assert by_match["print"].confidence == "heuristic"
    assert by_match["Exception"].confidence == "heuristic"
    assert by_match["logging.info"].confidence == "exact"


def test_argv_claim_carries_no_shell_suppression(seed_packs: PackSet):
    """Both subprocess.run claims ship: the command-injection entry is
    suppressed by a literal shell=False, the argv-visibility entry is
    not — shell mode changes interpretation, not process-table
    visibility."""
    runs = {
        s.sink_class: s for s in seed_packs.sinks
        if s.match == "subprocess.run"
    }
    assert set(runs) == {"command-injection", "secret-exposure"}
    assert ("shell", "False") in runs["command-injection"].unless_kwargs
    assert runs["secret-exposure"].unless_kwargs == ()
    assert runs["secret-exposure"].cwe == "CWE-214"


def test_redaction_sanitizers_are_tag_only(seed_packs: PackSet):
    """Redaction completeness is a call-site property — the pack may
    record the hop but never kill the flow."""
    pack = pack_named(seed_packs, "secrets-flow")
    assert pack.sanitizers
    for sanitizer in pack.sanitizers:
        assert sanitizer.semantics == "tag"
        assert sanitizer.sink_classes == ("secret-exposure",)


def test_secrets_rows_emit_or_refuse_accountably(seed_packs: PackSet):
    """Dotted secrets rows emit models-as-data rows; the method_name
    logger entries land in the counted refusals with the per-kind
    reason."""
    report = emissibility_report(seed_packs, language="python")
    reasons = {r.row: r.reason for r in report.rejected}
    assert "method_name" in reasons["sink:method_name:info"]
    assert "method_name" in reasons["sink:method_name:debug"]
    emitted_ok = {
        "sink:dotted_callee:logging.info",
        "sink:dotted_callee:urllib.parse.urlencode",
        "source:call_return:os.environ.get",
    }
    assert not (emitted_ok & set(reasons))


# ── template-engines ─────────────────────────────────────────────────


def test_template_pack_ships_as_pure_data(seed_packs: PackSet):
    assert "python/template-engines" in default_pack_names("python")
    pack = pack_named(seed_packs, "template-engines")
    assert pack.sinks and not pack.sources
    assert {s.sink_class for s in pack.sinks} == {"template-injection"}
    assert {s.cwe for s in pack.sinks} == {"CWE-1336", "CWE-94"}


def test_no_shipped_pack_restates_another_packs_sink(
    seed_packs: PackSet,
):
    """De-dup census over the whole shipped set: the same claim —
    (kind, match, sink class) — may ship once. Deliberate same-callee
    overlaps (subprocess.run argv vs shell, execute statement vs
    parameters, pickle.loads input vs output) differ in class or kind
    and pass; a restated row would be pure noise."""
    seen: dict[tuple[str, str, str], str] = {}
    for sink in seed_packs.sinks:
        claim = (sink.kind, sink.match, sink.sink_class)
        assert claim not in seen, (
            f"{sink.pack} restates {claim} from {seen[claim]}"
        )
        seen[claim] = sink.pack


def test_constructor_level_ssti_fires_via_the_env_hint(
    specs: SpecIndex,
):
    """env.from_string(user) has no import binding — the
    receiver-hinted method_name entry is what catches the dominant
    spelling."""
    src = """
import jinja2

def f(user):
    env = jinja2.Environment()
    return env.from_string(user)
"""
    s = summarize(src, specs, "f")
    hits = [ev for ev in s.sink_events if ev.match == "from_string"]
    assert [ev.sink_class for ev in hits] == ["template-injection"]
    assert hits[0].confidence == "heuristic"
    assert {f.origin for ev in hits for f in ev.flows} == {"param:0"}


def test_unbound_from_string_spelling_carries_self_offset(
    seed_packs: PackSet,
):
    """The dotted from_string entries describe the unbound spelling
    Environment.from_string(env, source) — the tainted source is
    position 1, and the keyword spelling is declared beside it so
    from_string(source=...) is not a miss."""
    pack = pack_named(seed_packs, "template-engines")
    for sink in pack.sinks:
        if sink.kind != "dotted_callee":
            continue
        if sink.match.endswith(".from_string"):
            assert sink.args == (1,)
            assert sink.kwargs
        else:
            # Constructor calls have no explicit self.
            assert sink.args == (0,)
