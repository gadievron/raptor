"""Acceptance test of the format's extension story: a NEW pack that
introduces a new sink class and uses the reserved stored-taint kinds
loads as pure data — same loader, same validators, zero code changes.

The fixture pack (``fixtures/packs/python/stored-taint-demo.json``)
is deliberately NOT shipped under ``core/taint/data/packs/`` — it
plays the role of tomorrow's pack drop, loaded through the operator
config-dir channel."""

from __future__ import annotations

from pathlib import Path

from core.taint.learned_intake import intake_learned_specs
from core.taint.mad_matrix import emissibility_report
from core.taint.packs import default_pack_names, load_packs

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "packs"


def load_with_fixture():
    names = [*default_pack_names("python"), "python/stored-taint-demo"]
    return load_packs(names, extra_dirs=[FIXTURE_DIR])


def test_new_pack_loads_as_pure_data():
    ps = load_with_fixture()
    demo = [p for p in ps.packs if p.name == "stored-taint-demo"]
    assert len(demo) == 1
    (pack,) = demo
    assert pack.sources[0].kind == "stored_read"
    assert pack.sinks[0].kind == "stored_write"
    # the store_key pairing survives into the typed model
    assert pack.sources[0].store_key == pack.sinks[0].store_key


def test_new_sink_classes_enter_the_vocabulary_without_code():
    baseline = load_packs(default_pack_names("python"))
    extended = load_with_fixture()
    new_classes = (extended.taint_class_vocabulary()
                   - baseline.taint_class_vocabulary())
    assert {"stored-taint", "secret-exposure", "stored-user-input"} <= new_classes


def test_new_vocabulary_immediately_governs_the_learned_channel():
    """The closed learned-channel vocabulary follows the pack data: a
    learned spec naming the new class is refused before the pack drop
    and admitted after it — no code changed in between."""
    learned = [{
        "role": "sink", "function": "app.store.persist",
        "taint_classes": ["stored-taint"], "confidence": 0.8,
    }]
    before = intake_learned_specs(
        learned,
        vocabulary=load_packs(default_pack_names("python")).taint_class_vocabulary(),
    )
    after = intake_learned_specs(
        learned, vocabulary=load_with_fixture().taint_class_vocabulary(),
    )
    assert before.sinks == () and before.refusal_count(
        "taint_class_outside_vocabulary") == 1
    assert len(after.sinks) == 1


def test_reserved_kinds_are_loud_not_silent_in_the_matrix():
    report = emissibility_report(load_with_fixture(), language="python")
    reasons = {r.row: r.reason for r in report.rejected}
    assert any("stored_read" in row for row in reasons)
    assert any("stored_write" in row for row in reasons)
    # the plain dotted_callee sink in the same pack emits fine — the
    # refusals are per-kind, not per-pack
    counts = dict(report.counts)
    assert counts.get("sinkModel", 0) > 0
