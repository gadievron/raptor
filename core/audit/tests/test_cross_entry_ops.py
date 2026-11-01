"""Ops-table retrieval must retain the call, binding, and downstream effects."""
from dataclasses import replace

import pytest

from core.audit.cross_entry import Limits, build_access_index, build_slices
from core.audit.cross_entry.study import _payload, _validate
from core.audit.tests.test_cross_entry import fn, semantic
from core.audit.tests.test_cross_entry import grammar as grammar

HEADER = '''
struct request { int *data; int length; };
struct ops { int (*run)(struct request *r); int (*stop)(struct request *r); };
'''


def fixture(installation, invocation="return ops->run(r);", helper=False):
    implementation = ('int impl(struct request *r) { return helper(r); }' if helper else
                      'int impl(struct request *r) { int *p = r->data; touch(p + 1,r->length + 4); return 0; }')
    return {"api.h":HEADER,
            "impl.c":'#include "api.h"\n'+
                ('int helper(struct request *q) { int *p = q->data; touch(p + 1,q->length + 4); return 0; }\n' if helper else '')+
                implementation+'\nint stop(struct request *r) { return 0; }\n'+installation,
            "consumer.c":'#include "api.h"\nint consume(struct ops *ops, struct request *r) { '+invocation+' }'}


@pytest.mark.parametrize("installation",[
    'static struct ops table = {impl, stop};',
    'static struct ops table = {.run=impl, stop};',
    'static struct ops tables[] = {{impl,stop}, {.run=impl}};',
    'static struct ops tables[4] = {[2]={impl,stop}};',
    'void setup(struct ops **p) { *p = &(struct ops){.run=impl}; }',
    'void setup(struct ops **p) { *p = &(struct ops){impl,stop}; }',
])
def test_static_positional_array_and_compound_ops_tables(installation):
    index = build_access_index(fixture(installation))
    call = next(c for c in index.calls if c.name == "ops->run")
    assert call.dispatch_candidates == [fn(index,"impl")]
    assert not call.targets
    unit = build_slices(index,["consumer.c:consume"])[0][0]
    assert "touch(p + 1,r->length + 4)" in unit.source
    assert call.dispatch_bindings[0]["parameter_bindings"] == {"r":"r"}
    assert any("ops->run(r)" in d["source"] for d in index.declarations.values())


@pytest.mark.parametrize("invocation",[
    'int (*callback)(struct request *) = ops->run; return callback(r);',
    'int (*callback)(struct request *); callback = ops->run; return (*callback)(r);',
    'int (*callback)(struct request *) = ops->run; int (*alias)(struct request *)=callback; return alias(r);',
    'return (*ops->run)(r);',
])
def test_callback_loaded_from_ops_slot_retains_handoff_evidence(invocation):
    index = build_access_index(fixture('static struct ops table = {.run=impl};',invocation))
    call = next(c for c in index.calls if c.caller == fn(index,"consume"))
    assert call.dispatch_candidates == [fn(index,"impl")]
    assert not call.targets
    unit = build_slices(index,["consumer.c:consume"])[0][0]
    prompt,allowed,_ = _payload(index,unit,unit.functions,Limits())
    row = call.dispatch_bindings[0]
    assert row["invocation_evidence"] in allowed
    assert all(e in allowed for e in row["alias_evidence"])
    assert "ops->run" in prompt


def test_alias_assignment_after_call_does_not_create_candidate():
    src = fixture('static struct ops table = {.run=impl};',
                  'int (*callback)(struct request *); int value = callback(r); callback = ops->run; return value;')
    index = build_access_index(src)
    assert not next(c for c in index.calls if c.name == "callback").dispatch_candidates


def test_shadowed_alias_does_not_reuse_outer_binding():
    src = fixture('static struct ops table = {.run=impl};',
                  'int (*callback)(struct request *)=ops->run; { int (*callback)(struct request *); return callback(r); }')
    index = build_access_index(src)
    assert not next(c for c in index.calls if c.name == "callback").dispatch_candidates


def test_ambiguous_preprocessor_layout_does_not_guess_positional_slot():
    src = fixture('static struct ops table = {impl};')
    src["api.h"] = HEADER.replace('int (*run)(struct request *r);',
        '#if MODE\nint (*first)(struct request *r);\n#endif\nint (*run)(struct request *r);')
    index = build_access_index(src)
    assert not next(c for c in index.calls if c.name == "ops->run").dispatch_candidates
    assert any(r["reason"] == "positional_callback_layout_unresolved" for r in index.coverage["unresolved"])


def test_callback_helper_effects_and_argument_bindings_reach_prompt_and_queue():
    index = build_access_index(fixture('static struct ops table = {.run=impl};',helper=True))
    unit = build_slices(index,["consumer.c:consume"],limits=replace(Limits(),functions_per_slice=2))[0][0]
    helper = fn(index,"helper")
    row = next(r for r in unit.dispatch_candidates if r["target"] == helper)
    assert [s["kind"] for s in row["dispatch_path"]] == ["dispatch_candidate","direct_call"]
    assert row["dispatch_path"][1]["parameter_bindings"] == {"q":"r"}
    assert helper in unit.evidence_candidates
    assert helper not in unit.functions
    assert "touch(p + 1,q->length + 4)" in unit.source
    prompt,allowed,present = _payload(index,unit,unit.functions,Limits())
    assert helper in present and helper not in allowed
    assert '"q": "r"' in prompt
    assert row["dispatch_path"][1]["evidence_id"] in allowed
    raw = semantic(unit)
    raw["witnesses"][0]["sequence"].append(helper)
    result = _validate(raw,allowed,present,consumer=unit.consumer,conditional_targets={helper})
    assert f"callback_body_incomplete:{helper}" in result["witnesses"][0]["missing_dependencies"]
    assert f"callback_selection_unverified:{helper}" in result["witnesses"][0]["missing_dependencies"]
    focused = build_slices(index,["consumer.c:consume"],focus_functions=[helper])[0][0]
    _,focused_allowed,_ = _payload(index,focused,focused.functions,Limits())
    assert helper in focused_allowed


def test_dispatch_depth_ceiling_is_recorded():
    index = build_access_index(fixture('static struct ops table = {.run=impl};',helper=True))
    unit = build_slices(index,["consumer.c:consume"],limits=replace(Limits(),graph_depth=0))[0][0]
    assert any(t.startswith("dispatch_path_depth:") for t in unit.truncated)
    assert fn(index,"impl") in unit.evidence_candidates


def test_callback_installed_through_local_function_pointer_keeps_alias_evidence():
    src = fixture('void setup(struct ops *o) { int (*chosen)(struct request *)=impl; o->run=chosen; }')
    index = build_access_index(src)
    call = next(c for c in index.calls if c.name == "ops->run")
    assert call.dispatch_candidates == [fn(index,"impl")]
    unit = build_slices(index,["consumer.c:consume"])[0][0]
    prompt,allowed,_ = _payload(index,unit,unit.functions,Limits())
    assert "o->run=chosen" in prompt
    assert call.dispatch_bindings[0]["alias_evidence"]
    assert all(e in allowed for e in call.dispatch_bindings[0]["alias_evidence"])


def test_nested_ops_dispatch_reaches_effect_with_both_selection_obligations():
    src = fixture('static struct ops table = {.run=impl};')
    src["api.h"] += '\nstruct second_ops { int (*next)(struct request *r); };\nstruct second_ops *stage(struct request *r);'
    src["impl.c"] = '''#include "api.h"
int final(struct request *q) { int *p=q->data; touch(p + 1,q->length + 4); return 0; }
int impl(struct request *r) { return stage(r)->next(r); }
static struct ops table = {.run=impl};
static struct second_ops next_table = {.next=final};
'''
    index = build_access_index(src)
    unit = build_slices(index,["consumer.c:consume"])[0][0]
    row = next(r for r in unit.dispatch_candidates if r["target"] == fn(index,"final"))
    assert [s["kind"] for s in row["dispatch_path"]] == ["dispatch_candidate","dispatch_candidate"]
    assert [s["target"] for s in row["dispatch_path"]] == [fn(index,"impl"),fn(index,"final")]
    prompt,allowed,_ = _payload(index,unit,unit.functions,Limits())
    assert "stage(r)->next(r)" in prompt
    assert "touch(p + 1,q->length + 4)" in prompt
    assert all(s["evidence_id"] in allowed and s["invocation_evidence"] in allowed for s in row["dispatch_path"])


def test_dispatch_cycle_terminates_and_preserves_candidate_inventory():
    src = fixture('static struct ops table = {.run=impl};',helper=True)
    src["impl.c"] = src["impl.c"].replace('touch(p + 1,q->length + 4);','touch(p + 1,q->length + 4); impl(q);')
    index = build_access_index(src)
    unit = build_slices(index,["consumer.c:consume"])[0][0]
    assert len(unit.dispatch_candidates) == 2
    assert {r["target"] for r in unit.dispatch_candidates} == {fn(index,"impl"),fn(index,"helper")}


def test_dispatch_depth_loss_is_visible_in_durable_progress(tmp_path):
    from core.audit.cross_entry.integration import prepare_cross_entry
    from core.json import load_json
    root = tmp_path/"src"
    root.mkdir()
    out = tmp_path/"out"
    for fp,source in fixture('static struct ops table = {.run=impl};',helper=True).items():
        (root/fp).write_text(source)
    prepare_cross_entry(root,[{"file":"consumer.c","name":"consume"}],mode="context",out_dir=out,
                        drain_index=True,limits=replace(Limits(),graph_depth=0))
    progress = load_json(out/"cross-entry-progress.json")
    assert any(b["detail"]["reason"] == "dispatch_path_coverage" for b in progress["blocked_work"])
    assert progress["work_remaining"]


def test_small_traversal_budget_does_not_drop_initial_ops_candidates():
    from core.audit.cross_entry.dispatch import expand_dispatch_paths
    src = fixture('static struct ops table = {.run=impl}; static struct ops other = {.run=stop};',helper=True)
    index = build_access_index(src)
    call = next(c for c in index.calls if c.name == "ops->run")
    rows,deferred = expand_dispatch_paths(index,call.dispatch_bindings,replace(Limits(),max_sites=1))
    assert {r["target"] for r in rows} == {fn(index,"impl"),fn(index,"stop")}
    assert deferred


def test_callback_argument_mismatch_is_evidence_not_a_pruning_rule():
    src = fixture('static struct ops table = {.run=impl};')
    src["impl.c"] = src["impl.c"].replace('int impl(struct request *r)', 'int impl(struct request *r, int extra)')
    index = build_access_index(src)
    call = next(c for c in index.calls if c.name == "ops->run")
    assert fn(index,"impl") in call.dispatch_candidates
    assert not call.dispatch_bindings[0]["argument_count_matches"]
    assert any(r["reason"] == "callback_argument_count_unverified" for r in index.coverage["unresolved"])


def test_cast_callback_assignment_retains_target_for_signature_review():
    index = build_access_index(fixture('static struct ops table = {.run=(int (*)(struct request *))impl};'))
    assert next(c for c in index.calls if c.name == "ops->run").dispatch_candidates == [fn(index,"impl")]


def test_conditional_callback_installation_keeps_both_alternatives():
    index = build_access_index(fixture('void setup(struct ops *o,int condition) { o->run=condition ? impl : stop; }'))
    call = next(c for c in index.calls if c.name == "ops->run")
    assert set(call.dispatch_candidates) == {fn(index,"impl"),fn(index,"stop")}
    assert not call.targets
    assert all(r["status"] == "conditional_runtime_selection" for r in call.dispatch_bindings)
