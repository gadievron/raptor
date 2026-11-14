"""Only the exact supplied synthesis section earns delivery credit."""
from copy import deepcopy

from core.audit import context as actual_context, continuation_context as continuation, synthesis_review_context as synthesis
from core.llm.prompt_budget import PromptSection

import pytest


@pytest.fixture(autouse=True)
def _owned_formatter_catalog(monkeypatch):
    from core.audit import context as context_module

    # Retain the borrowed slot and restore its original identity on every exit.
    monkeypatch.setattr(context_module, "_tool_catalog_cache", context_module._tool_catalog_cache)
    monkeypatch.setattr(context_module, "_get_tool_catalog", lambda: "")

    def forbidden_catalog():
        raise AssertionError("owned formatter control must not discover host tools or import a solver")

    monkeypatch.setattr(context_module, "_build_tool_catalog", forbidden_catalog)


def test_actual_formatter_supplies_the_frozen_section_for_stable_context_id():
    formatter = actual_context.format_context_for_prompt
    gap = {"file": "unit.c", "name": "f", "line_start": 1, "line_end": 1,
           "synthesis_hit_line": 1, "synthesis_rule_id": "owned-rule",
           "synthesis_snippet": "return value;"}
    payload = synthesis.build_synthesis_review_context(gap)
    ctx = {"file": "unit.c", "function": "f", "source": "int f(int value) { return value; }\n",
           "language": "c", "line_start": 1, "line_end": 1, "synthesis_review_context": payload}
    spec = continuation.context_spec(ctx, kind="synthesis_match", version=payload.version)
    assert spec is not None and spec["context_id"] == "context:synthesis_match:" + payload.version
    assert continuation.context_spec(ctx, kind="synthesis_match", version="forged") is None
    ctx["continuation_context_inputs"] = [spec]
    deliveries = []
    prompt = formatter(ctx, external_delivery_sink=deliveries.append)
    section = synthesis.render_synthesis_review_context(payload)
    assert section in prompt
    assert deliveries == [[{**spec, "delivered": True, "reason": "complete_prompt_section"}]]
    copied = deepcopy(ctx)
    assert continuation.context_spec(copied, kind="synthesis_match", version=payload.version) == spec
    original = [PromptSection("synthesis_match", section, 0)]
    assert not continuation.context_delivery(ctx, original, [])[0]["delivered"]
    another = synthesis.build_synthesis_review_context(gap)
    assert another.version == payload.version
    other_section = [PromptSection("synthesis_match", synthesis.render_synthesis_review_context(another), 0)]
    assert not continuation.context_delivery(ctx, original, other_section)[0]["delivered"]
    assert continuation.context_spec({**ctx, "synthesis_review_context": {"rule_id": "forged"}},
                                     kind="synthesis_match", version=payload.version) is None

    glance_deliveries = []
    glance_prompt = formatter({**ctx, "triage_bucket": "glance"},
                             external_delivery_sink=glance_deliveries.append)
    assert section in glance_prompt
    assert glance_deliveries == [[{**spec, "delivered": True, "reason": "complete_prompt_section"}]]
    assert continuation.context_spec({**ctx, "line_end": 2},
                                     kind="synthesis_match", version=payload.version) is None
