"""Preserve capped receipts, snapshot semantics, and bounded temporary data."""

import tracemalloc

import pytest

from core.analysis.summaries import FunctionSummary, Precondition
from core.audit import mechanical_gates, postcondition_verify
from core.audit.cross_entry.model import AccessIndex
from core.audit.cross_entry.slices import entry_paths
from core.audit.cross_function_verify import _extract_sinks_from_hypothesis
from core.audit.field_census import FieldCensus, FieldRead, FieldRecord, FieldWrite
from core.audit.hypothesis_intake import _load_one_record
from core.audit.promotion_alarm import G2_BYPASS_KEY, build_alarm_record
from core.audit.ptr_lifecycle import detect_field_parity_deviations


def _census(reads, extra=False):
    fields = {f"copied{i}": FieldRecord(f"copied{i}", writes=[
        FieldWrite("a.c", 10 + i, "replace", "new", f"from_field:old.copied{i}")])
        for i in range(3)}
    fields["missed"] = FieldRecord("missed", reads=reads)
    if extra:
        fields["other_missed"] = FieldRecord("other_missed", reads=reads)
    return FieldCensus(fields=fields)


def test_parity_keeps_owner_link_and_first_outside_read_independent():
    reads = [FieldRead("a.c", 1, "replace", "unrelated"),
             FieldRead("b.c", 20, "read", "unrelated"),
             FieldRead("c.c", 30, "other", "old")]
    deviations = detect_field_parity_deviations(_census(reads, extra=True), min_cluster=3)
    assert [d.field for d in deviations] == ["missed", "other_missed"]
    assert all((d.peer_evidence.deviant.file, d.peer_evidence.deviant.line) == ("b.c", 20)
               for d in deviations)
    first, second = [d.peer_evidence.exhibits for d in deviations]
    assert len(first) == len(second) == 3
    assert all(a is not b for a, b in zip(first, second, strict=True))
    first.clear()
    assert len(second) == 3


def test_parity_does_not_materialize_linked_or_outside_read_lists():
    if tracemalloc.is_tracing():
        pytest.skip("requires ownership of allocation tracing")
    read = FieldRead("b.c", 20, "read", "old")
    census = _census([read] * 50000)
    tracemalloc.start()
    try:
        result = detect_field_parity_deviations(census, min_cluster=3)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert [d.field for d in result] == ["missed"]
    assert peak < 128 * 1024


def _alarm(review_result):
    return build_alarm_record(stage="test", file="a.c", function="f", verdict="finding",
                              evidence_tool="", review_result=review_result)


def test_alarm_tiers_are_snapshotted_before_value_conversion():
    tiers = {}

    class MutatingValue:
        def __str__(self):
            tiers.clear()
            return "xref_backed"

    tiers.update({"first": MutatingValue(), "second": "llm_summarized"})
    record = _alarm({G2_BYPASS_KEY: ["inv"], "g2_invariant_bypass_tiers": tiers})
    assert record["bypass_claimed_tiers"] == {
        "first": "xref_backed", "second": "llm_summarized"}
    assert tiers == {}


def test_alarm_dict_subclass_retains_items_iteration():
    seen = []

    class Tiers(dict):
        def items(self):
            for key, value in super().items():
                seen.append(key)
                yield key, value

    tiers = Tiers({str(i): "xref_backed" for i in range(30)})
    record = _alarm({G2_BYPASS_KEY: ["inv"], "g2_invariant_bypass_tiers": tiers})
    assert list(record["bypass_claimed_tiers"]) == [str(i) for i in range(16)]
    assert seen == [str(i) for i in range(30)]


def test_alarm_preserves_conversion_errors_for_nonstring_bypass_values():
    class BadValue:
        def __str__(self):
            raise ValueError("cannot format claim")

    with pytest.raises(ValueError, match="cannot format claim"):
        _alarm({G2_BYPASS_KEY: ["inv"] * 16 + [BadValue()]})


def test_alarm_does_not_copy_unused_native_tier_items():
    if tracemalloc.is_tracing():
        pytest.skip("requires ownership of allocation tracing")
    review = {G2_BYPASS_KEY: ["inv"],
              "g2_invariant_bypass_tiers": {str(i): "xref_backed" for i in range(50000)}}
    _alarm({G2_BYPASS_KEY: ["warm"]})
    tracemalloc.start()
    try:
        record = _alarm(review)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert len(record["bypass_claimed_tiers"]) == 16
    assert peak < 128 * 1024


def test_seed_flags_are_snapshotted_before_bool_conversion():
    flags = {}

    class MutatingValue:
        def __bool__(self):
            flags.clear()
            return True

    flags.update({"first": MutatingValue(), "second": False, "third": True})
    raw = {"file": "a.c", "claim": "a claim", "disproof": "a disproof",
           "evidence_tier": "xref_backed", "derived_from_target": flags}
    record = _load_one_record(raw, 0, "test", {})
    assert record.derived_from_target == {"first": True, "second": False, "third": True}
    assert flags == {}


def test_summary_conversions_beyond_visible_cap_still_raise():
    class BadValue:
        def __str__(self):
            raise ValueError("cannot render condition")

    summary = FunctionSummary("f", "a.c", preconditions=[
        Precondition("param", 0, ["valid"] * 10 + [BadValue()])])
    with pytest.raises(ValueError, match="cannot render condition"):
        postcondition_verify._extract_consumer_preconditions(
            {"name": "f", "file": "a.c"}, {"a.c:f": summary})
    summary.preconditions = [Precondition("param", 0, ["valid"])] * 10 + [
        Precondition("param", 0, [BadValue()])]
    with pytest.raises(ValueError, match="cannot render condition"):
        mechanical_gates.format_callee_defenses([summary])


def test_hypothesis_sink_prefix_keeps_explicit_priority_dedup_and_case():
    hypothesis = "execute_first `the` `AB` `pkg.ab` 'cd' \"ef\" `gh` `ij` write_later"
    assert _extract_sinks_from_hypothesis(hypothesis) == ["AB", "cd", "ef", "gh", "ij"]


def test_entry_queue_prefix_keeps_original_bfs_order_and_path_cap():
    parents = {"target": {f"parent{i:04d}" for i in range(2000)}}
    parents.update({name: set() for name in parents["target"]})
    index = AccessIndex(entries={name: [] for name in parents["target"]})
    assert entry_paths(index, "target", 1, parents) == [
        [f"parent{i:04d}", "target"] for i in range(16)]


def test_custom_field_mapping_keeps_per_cluster_iteration():
    class Fields(dict):
        calls = 0

        def items(self):
            self.calls += 1
            return super().items()

    census = _census([FieldRead("b.c", 20, "read", "old")])
    for record in census.fields.values():
        if record.writes:
            write = record.writes[0]
            record.writes.append(FieldWrite(
                "a.c", write.line + 10, "replace_other", "new", write.rhs_class))
    census.fields = Fields(census.fields)
    result = detect_field_parity_deviations(census, min_cluster=3)
    assert len(result) == 2
    assert census.fields.calls == 2
