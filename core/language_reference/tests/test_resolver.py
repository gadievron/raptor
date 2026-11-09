"""Language lookup supplies conditional reading, never target conclusions."""

import pytest

from core.language_reference import ReferenceContext, lookup


def test_unsigned_narrowing_request_gets_full_destination_distinctions():
    answer = lookup("owned-request", "conversion from uint32_t to uint16_t",
                    ReferenceContext("c", "c11"))
    assert answer.status == "answered"
    assert answer.request_id == "owned-request"
    assert len(answer.entries) == 1
    core = answer.entries[0].render_core()
    assert "unsigned" in core and "modulo" in core
    assert "implementation-defined signal" in core
    assert "_Bool" in core
    assert "floating-to-integer" in core
    assert "destination range" in core
    assert "6.3.1.3" in core


def test_unknown_edition_supplies_conditional_rule_without_guessing_host():
    answer = lookup("r", "conversion", ReferenceContext("c"),
                    entry_id="c.integer-conversion")
    assert answer.status == "needs_target_facts"
    assert answer.missing_facts == ("language edition",)
    assert answer.entries


@pytest.mark.parametrize("context", [ReferenceContext("cpp", "c++11"),
                                     ReferenceContext("c", "c23"),
                                     ReferenceContext("rust")])
def test_exact_id_does_not_bypass_applicability(context):
    answer = lookup("r", "conversion", context, entry_id="c.integer-conversion")
    assert answer.status == "unsupported"
    assert not answer.entries


def test_usual_conversions_include_promotion_prerequisite():
    answer = lookup("r", "", ReferenceContext("c", "c11"),
                    entry_id="c.integer-usual-conversions")
    assert answer.status == "answered"
    assert [e.entry_id for e in answer.entries] == [
        "c.integer-promotion", "c.integer-usual-conversions"]
    core = "\n".join(e.render_core() for e in answer.entries)
    assert "represents every value" in core
    assert "Comparison operators produce int" in core
    assert "Shifts, casts and assignments" in core


@pytest.mark.parametrize("topic", ["does the caller enforce a bound", "", "x" * 513])
def test_unavailable_topic_is_explicit_without_generic_word_matches(topic):
    answer = lookup("r", topic, ReferenceContext("c", "c11"))
    assert answer.status == "unsupported"
    assert not answer.entries


def test_ambiguous_topic_retains_conditions_and_candidate_status():
    answer = lookup("r", "integer", ReferenceContext("c", "c11"))
    assert answer.status == "ambiguous"
    assert len(answer.entries) > 1
    assert all(entry.conditions and entry.citations for entry in answer.entries)
