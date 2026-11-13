"""Measured initial omission stays tied to original binary invocation material."""
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace

import pytest

from core.audit.binary_initial_type_delivery import (
    capture_initial_type_delivery, capture_initial_type_inventory, initial_type_delivery_rows,
)
from core.audit.binary_review_scope import BinaryInputIdentity, BinaryKnowledgeOrigin


def _case():
    ctx = {"is_binary": True, "file": "binary:owned", "function": "f", "line_start": 0,
           "type_definitions": [{"name": "Packet", "file": "ghidra-types", "line": 0,
                                 "source": "struct Packet { unsigned length; };"}]}
    identity = BinaryInputIdentity("1" * 64, (1, 2, 3, 4, 5), 4096, 32,
                                   "decompilation", "2" * 64, analysis_sha256="3" * 64)
    origin = BinaryKnowledgeOrigin(pass_id="owned-pass", file="binary:owned", function="f",
        line_start=0, line_end=0, source_identity=None, binary_identity=identity)
    return ctx, origin


def test_owned_measured_omission_survives_fresh_equal_context_and_does_not_lend_rows():
    ctx, origin = _case()
    rows = initial_type_delivery_rows(ctx, [], omission_reason="glance_packet")
    assert rows[0]["status"] == "omitted" and rows[0]["reason"] == "glance_packet"
    proof = capture_initial_type_delivery(rows, origin=origin, ctx=ctx)
    assert proof is not None and proof.permits_omission("Packet", deepcopy(ctx), origin)
    rows[0]["status"] = "delivered"
    returned = proof.records()
    returned[0]["status"] = "delivered"
    assert proof.records()[0]["status"] == "omitted"
    assert proof.permits_omission("Packet", ctx, origin)
    assert not proof.permits_omission("Other", ctx, origin)
    assert not proof.permits_omission("Packet", ctx, replace(origin, pass_id="other-pass"))


def test_visible_unknown_and_forged_compatibility_fields_do_not_permit_requery():
    ctx, origin = _case()
    # A caller-populated compatibility key supplies no formatter observation.
    ctx["binary_initial_type_delivery"] = initial_type_delivery_rows(ctx, [])
    assert capture_initial_type_delivery(None, origin=origin, ctx=ctx) is None
    rows = initial_type_delivery_rows(ctx, [SimpleNamespace(label="type_definitions")])
    assert rows[0]["status"] == "delivered" and rows[0]["reason"] == "rendered"
    proof = capture_initial_type_delivery(rows, origin=origin, ctx=ctx)
    assert proof is not None and not proof.permits_omission("Packet", ctx, origin)
    assert initial_type_delivery_rows(ctx, None) == []
    assert initial_type_delivery_rows(ctx, [object()]) == []
    assert initial_type_delivery_rows(ctx, "type_definitions") == []
    assert initial_type_delivery_rows({**ctx, "is_binary": False}, []) == []


def test_receipt_describes_rendered_material_before_a_late_fit_callback(monkeypatch):
    from core.audit import context as formatter
    from core.llm import prompt_budget
    from core.testing.module_views import scoped_function_imports

    ctx, _ = _case()
    ctx.update(address=4096, representation="decompilation", source="int f(void) { return 1; }",
               metadata={}, callers=[], callees=[], sinks=[], trust_surface={})
    expected = initial_type_delivery_rows(ctx, [SimpleNamespace(label="type_definitions")])
    original_fit = prompt_budget.fit_to_budget_report

    def mutate_after_fitting(*args, **kwargs):
        report = original_fit(*args, **kwargs)
        ctx["type_definitions"][0]["source"] = "struct Packet { unsigned changed; };"
        return report

    receipts = []
    with scoped_function_imports(formatter, ("format_context_for_prompt",),
                                 {"core.llm.prompt_budget": prompt_budget}) as imports:
        with monkeypatch.context() as patch:
            patch.setattr(getattr(imports, "core.llm.prompt_budget"),
                          "fit_to_budget_report", mutate_after_fitting)
            prompt = formatter.format_context_for_prompt(ctx, budget_limit=100000,
                                                        knowledge_delivery_sink=receipts.append)
    assert "unsigned length" in prompt and "unsigned changed" not in prompt
    assert receipts[0]["binary_initial_type_delivery"] == expected


def test_original_subject_inventory_survives_compatibility_removal():
    ctx, origin = _case()
    inventory = capture_initial_type_inventory(ctx, origin=origin)
    rows = initial_type_delivery_rows(ctx, [SimpleNamespace(label="type_definitions")])
    del ctx["type_definitions"]
    assert inventory is not None and inventory.contains("Packet")
    proof = capture_initial_type_delivery(rows, origin=origin, ctx=ctx, inventory=inventory)
    assert proof is not None and proof.records()[0]["status"] == "delivered"
    assert not proof.permits_omission("Packet", ctx, origin)


def test_mixed_round_answers_do_not_borrow_another_requests_omission():
    from core.audit.binary_subjects import _answers
    from packages.ghidra.model import REDatabase, REType

    ctx, first_origin = _case()
    ctx["type_definitions"].append({"name": "Other", "file": "ghidra-types", "line": 0,
                                    "source": "struct Other { unsigned value; };"})
    ctx["_binary_analysis_database"] = REDatabase(source_tool="fixture", binary_path="owned.bin",
        types=[REType(name=name, kind="struct", source_tool="fixture") for name in ("Packet", "Other", "Third")])
    first_inventory = capture_initial_type_inventory(ctx, origin=first_origin)
    first_delivery = capture_initial_type_delivery(initial_type_delivery_rows(ctx, []),
        origin=first_origin, ctx=ctx, inventory=first_inventory)
    later_origin = replace(first_origin, pass_id="later-owned-pass")
    later_inventory = capture_initial_type_inventory(ctx, origin=later_origin)
    later_delivery = capture_initial_type_delivery(
        initial_type_delivery_rows(ctx, [SimpleNamespace(label="type_definitions")]),
        origin=later_origin, ctx=ctx, inventory=later_inventory)
    prior_observation = (("packet-request", first_inventory, first_delivery),)
    later_observations = (("other-request", later_inventory, later_delivery),
                          ("third-request", later_inventory, later_delivery))
    prior = _answers((("packet-request", "Packet"),), ctx, initial_observations=prior_observation)
    later = _answers((("other-request", "Other"), ("third-request", "Third")), ctx,
                     initial_observations=later_observations)
    combined = _answers((("packet-request", "Packet"), ("other-request", "Other"), ("third-request", "Third")),
                        ctx, initial_observations=(*prior_observation, *later_observations))
    assert [answer.status for answer in combined] == ["partial", "unavailable", "partial"]
    assert combined == (*prior, *later)


@pytest.mark.parametrize("change", ["name", "file", "line", "source", "replace", "append", "occurrence"])
def test_original_omission_cannot_adopt_late_material_or_occurrence(change):
    ctx, origin = _case()
    proof = capture_initial_type_delivery(initial_type_delivery_rows(ctx, []), origin=origin, ctx=ctx)
    assert proof is not None
    if change in ("name", "file", "source"):
        ctx["type_definitions"][0][change] += " changed"
    elif change == "line":
        ctx["type_definitions"][0]["line"] = 1
    elif change == "replace":
        ctx["type_definitions"] = [{**ctx["type_definitions"][0], "source": "struct Packet {};"}]
    elif change == "append":
        ctx["type_definitions"].append({"name": "Other", "file": "ghidra-types", "line": 0, "source": "other"})
    else:
        ctx["function"] = "other"
    assert not proof.permits_omission("Packet", ctx, origin)


@pytest.mark.parametrize("change", ["bool_version", "str_version", "role", "subject", "digest",
                                    "status", "reason", "extra", "missing", "duplicate"])
def test_malformed_or_ambiguous_rows_have_no_valid_winner(change):
    ctx, origin = _case()
    rows = initial_type_delivery_rows(ctx, [])
    row, = rows
    if change == "bool_version":
        row["schema_version"] = True
    elif change == "str_version":
        row["schema_version"] = "1"
    elif change == "role":
        row["role"] = "model-claim"
    elif change == "subject":
        row["subject"] = "Other"
    elif change == "digest":
        row["definition_sha256"] = "0" * 64
    elif change == "status":
        row["status"] = "unknown"
    elif change == "reason":
        row["reason"] = "rendered"
    elif change == "extra":
        row["authoritative"] = True
    elif change == "missing":
        del row["reason"]
    else:
        rows.append(dict(row))
    assert capture_initial_type_delivery(rows, origin=origin, ctx=ctx) is None


@pytest.mark.parametrize("change", ["bool_line", "bad_source", "duplicate_subject"])
def test_malformed_compatibility_descriptors_do_not_acquire_omission(change):
    ctx, origin = _case()
    if change == "bool_line":
        ctx["type_definitions"][0]["line"] = False
    elif change == "bad_source":
        ctx["type_definitions"][0]["source"] = object()
    else:
        ctx["type_definitions"].append(dict(ctx["type_definitions"][0]))
    assert initial_type_delivery_rows(ctx, []) == []
    assert capture_initial_type_delivery([], origin=origin, ctx=ctx) is None
