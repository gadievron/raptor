"""Cross-entry retrieval and evidence safety, with real tree-sitter parsing.

No provider calls. Fake semantic responses exercise gates, not bug recall.
"""
from __future__ import annotations

import json
from dataclasses import replace

import pytest

from core.audit.cross_entry import Limits, build_access_index, build_slices
from core.audit.cross_entry.integration import collect_sources, prepare_cross_entry
from core.audit.cross_entry.study import _validate, run_studies


@pytest.fixture(autouse=True)
def grammar():
    from core.audit.callsite_consistency import parse_source_cached
    if parse_source_cached("a.c","int f(void) { return 0; }")[0] is None:
        pytest.skip("requires tree-sitter C")


def fn(index, name):
    return next(f.id for f in index.functions.values() if f.name == name)


def sources():
    return {"state.h":"struct state { int ready; int len; int refcount; };",
            "writer.c":'#include "state.h"\nvoid put(struct state *ctx) { ctx->ready++; ctx->len = 2; }',
            "reader.c":'#include "state.h"\nint get(struct state *other) { return other->len; }'}


def test_type_identity_cross_tu_and_names():
    index = build_access_index(sources())
    assert {a.type_id for a in index.accesses} == {"state.h:0:struct state"}
    assert {a.resolution for a in index.accesses} == {"resolved"}
    assert {a.member_path for a in index.accesses} == {"ready","len"}
    assert next(a for a in index.accesses if a.member_path == "ready").operation == "read_modify_write"


def test_different_types_same_owner_and_same_tag_tus_stay_separate():
    index = build_access_index({
        "a.c":"struct state { int ready; }; void a(struct state *ctx) { ctx->ready = 1; }",
        "b.c":"struct state { int ready; }; void b(struct state *ctx) { ctx->ready = 2; }"})
    assert len({a.type_id for a in index.accesses}) == 2
    units,_ = build_slices(index,["a.c:a"])
    assert units[0].functions == [fn(index,"a")]


def test_missing_declaration_identity_is_partial():
    index = build_access_index({"a.c":"void a(struct state *ctx) { ctx->ready = 1; }"})
    assert index.accesses[0].resolution == "partial"
    assert "partial_or_unresolved_type_identity" in build_slices(index)[0][0].unresolved


def test_typedef_shadowing_full_paths_and_lifecycle_fields():
    index = build_access_index({"a.c":"""
typedef struct state { int state; int len; int refcount; } state_t;
struct other { int state; };
void f(state_t *ctx) {
    ctx->state = 1; ctx->left.ready++; ctx->right.ready += 1;
    { struct other *ctx; ctx->state = 2; }
    ctx->len = 4; ctx->refcount--;
}
"""})
    assert {a.member_path for a in index.accesses} == {"state","left.ready","right.ready","len","refcount"}
    states = [a for a in index.accesses if a.member_path == "state"]
    assert len({a.type_id for a in states}) == 2
    outer = next(a for a in index.accesses if a.member_path == "len")
    assert outer.type_id == states[0].type_id
    assert next(a for a in index.accesses if a.member_path == "right.ready").operation == "read_modify_write"


def test_helper_and_whole_object_effects_survive_mixed_writes():
    index = build_access_index({"a.c":"struct state { int ready; int data; }; void f(struct state *ctx) { ctx->ready = 1; attach(&ctx->data); memset(ctx,0,4); }"})
    assert {a.operation for a in index.accesses} >= {"direct_write","address_escape","unresolved_effect"}
    unit = build_slices(index)[0][0]
    assert "unknown_helper_effects" in unit.reasons
    assert any("memset" in u for u in unit.unresolved)


def test_homogeneous_provenance_does_not_filter_and_single_entry_retained():
    index = build_access_index({"a.c":"struct state { int ready; }; void f(struct state *ctx) { ctx->ready = 1; ctx->ready = 2; }"})
    assert {a.provenance for a in index.accesses} == {"literal_const"}
    assert len(build_slices(index)[0]) == 1


def test_wrappers_and_cross_tu_registration_resolve_definitions():
    src = sources()
    src["wrapper.c"] = "int entry(struct state *p) { return get(p); }"
    src["ops.c"] = "static struct api ops = {\n.send = put,\n.recv = entry,\n};"
    index = build_access_index(src)
    assert fn(index,"put") in index.entries
    assert fn(index,"entry") in index.entries
    assert index.entries[fn(index,"put")][0]["file"] == "ops.c"
    unit = build_slices(index,["reader.c:get"])[0][0]
    assert [fn(index,"entry"),fn(index,"get")] in unit.entry_paths
    assert fn(index,"put") in unit.functions
    wrapper = build_slices(index,["wrapper.c:entry"])[0][0]
    assert fn(index,"get") in wrapper.functions
    assert fn(index,"put") in wrapper.functions


def test_static_symbols_do_not_resolve_across_tus():
    index = build_access_index({"a.c":"static void helper(void) {}",
                                "b.c":"void entry(void) { helper(); }"})
    assert not index.calls[0].targets
    assert not index.relations


def test_ambiguous_external_symbols_are_not_resolved():
    index = build_access_index({"a.c":"void helper(void) {}", "b.c":"void helper(void) {}",
                                "c.c":"void entry(void) { helper(); }"})
    assert len(index.calls[0].targets) == 2
    assert not index.relations


def test_cross_type_resource_assignment():
    index = build_access_index({"a.c":"""
struct producer { int *data; }; struct request { int *payload; };
void bridge(struct producer *p, struct request *r) { r->payload = p->data; }
void attach(struct producer *p, int *external) { p->data = external; }
void use(struct request *r) { write_to(r->payload); }
"""})
    assert any(r.kind == "resource_assignment" for r in index.relations)
    unit = build_slices(index,["a.c:use"])[0][0]
    assert fn(index,"attach") in unit.functions
    assert "cross_type_resource_assignment" in unit.reasons


@pytest.mark.parametrize("kwargs,reason", [({"max_files":0},"skipped"),({"max_bytes":1},"skipped"),
    ({"max_sites":0},"truncated"),({"max_functions":0},"truncated")])
def test_index_caps_are_visible(kwargs,reason):
    index = build_access_index(sources(),limits=replace(Limits(),**kwargs))
    assert index.coverage[reason]
    assert not index.coverage["complete"]


def test_parser_fallback_is_explicit_not_typed_regex(monkeypatch):
    monkeypatch.setattr("core.audit.callsite_consistency.parse_source_cached",lambda *a:(None,None))
    index = build_access_index(sources())
    assert not index.functions
    assert all(s["reason"] == "unsupported_parser" for s in index.coverage["skipped"])


def test_fingerprints_cover_new_writer_and_body_changes():
    src = sources()
    original = build_access_index(src)
    assert original.fingerprint == build_access_index(dict(reversed(list(src.items())))).fingerprint
    src["new.c"] = "void change(struct state *ctx) { ctx->ready = 2; }"
    assert original.fingerprint != build_access_index(src).fingerprint
    src = sources()
    src["writer.c"] += "\n/* new source */"
    assert original.fingerprint != build_access_index(src).fingerprint


def test_selection_budget_and_context_truncation():
    index = build_access_index(sources())
    units,deferred = build_slices(index,limits=replace(Limits(),max_slices=1,source_chars=20,functions_per_slice=1))
    assert len(units) == 1 and len(deferred) == 1
    assert len(units[0].source) <= 20
    assert units[0].truncated
    assert build_slices(index,limits=replace(Limits(),max_slices=0))[0] == []


def write_sources(root):
    for fp,source in sources().items():
        (root/fp).write_text(source)


def test_confined_collection_and_single_file_siblings(tmp_path):
    root = tmp_path/"repo"
    root.mkdir()
    write_sources(root)
    external = tmp_path/"secret.c"
    external.write_text("secret")
    (root/"escape.c").symlink_to(external)
    src,coverage = collect_sources(root/"reader.c",["reader.c","../secret.c"],Limits())
    assert "writer.c" in src and "state.h" in src
    assert "escape.c" not in src and "../secret.c" not in src
    assert not coverage["complete"]


def test_collection_rejects_fifo_and_records_byte_cap(tmp_path):
    import os
    (tmp_path/"a.c").write_text("a"*100)
    os.mkfifo(tmp_path/"b.c")
    src,coverage = collect_sources(tmp_path,["a.c"],replace(Limits(),max_bytes=5))
    assert not src
    assert {s["reason"] for s in coverage["skipped"]} >= {"byte_budget","unreadable_or_nonregular"}


def test_report_files_take_priority_at_file_cap(tmp_path):
    write_sources(tmp_path)
    src,cov = collect_sources(tmp_path,["writer.c"],replace(Limits(),max_files=1))
    assert list(src) == ["writer.c"]
    assert cov["truncated"]


class Client:
    def __init__(self,responses=()):
        self.responses = iter(responses)
        self.calls = []
    def is_budget_exhausted(self):
        return False
    def generate_structured(self,prompt,schema,**kwargs):
        self.calls.append((prompt,schema,kwargs))
        response = next(self.responses)
        if isinstance(response,Exception):
            raise response
        return response,""


def witness(unit):
    return {"statement":"conditional mismatch","consumer_requirement":"consistent state",
            "sequence":[unit.consumer,unit.consumer],"evidence_ids":[unit.consumer],
            "object_identity":"same handle, requires checking","conditions":["same object"],
            "consequence":"unauthorized operation","missing_dependencies":[],"falsifiers":["consumer rechecks"]}


def semantic(unit):
    return {"facts":[],"witnesses":[witness(unit)],"needed_symbols":[]}


def test_semantic_validation_rejects_invented_evidence_and_sequence():
    index = build_access_index(sources())
    unit = build_slices(index)[0][0]
    raw = semantic(unit)
    raw["witnesses"][0]["evidence_ids"] = ["invented"]
    assert not _validate(raw,{unit.consumer},{unit.consumer})["witnesses"]
    raw = semantic(unit)
    raw["witnesses"][0]["sequence"] = ["invented"]
    assert not _validate(raw,{unit.consumer},{unit.consumer})["witnesses"]


def test_study_refutation_cache_and_never_promotes_confidence(tmp_path):
    index = build_access_index(sources())
    unit = build_slices(index,["reader.c:get"])[0][0]
    client = Client([semantic(unit),{"verdict":"survives","reason":"conditional","evidence_ids":[unit.consumer]}])
    result = run_studies(index,[unit],client,out_dir=tmp_path)[unit.id]
    assert len(client.calls) == 2
    assert result["study"]["witnesses"][0]["confidence"] == "inferred"
    assert result["refutations"][0]["verdict"] == "survives"
    assert all(c[2]["call_class"] == "study" for c in client.calls)
    recalled = run_studies(index,[unit],Client(),out_dir=tmp_path)[unit.id]
    assert recalled["cache_hit"]
    changed = build_access_index({**sources(),"new.c":"void change(struct state *ctx) { ctx->len = 3; }"})
    new_unit = build_slices(changed,["reader.c:get"])[0][0]
    result = run_studies(changed,[new_unit],Client(),out_dir=tmp_path,limits=replace(Limits(),max_calls=0))[new_unit.id]
    assert result["status"] == "deferred"


def test_missing_refutation_evidence_does_not_discharge(tmp_path):
    index = build_access_index(sources())
    unit = build_slices(index,["reader.c:get"])[0][0]
    result = run_studies(index,[unit],Client([semantic(unit),{"verdict":"contradicted","reason":"trust me","evidence_ids":[]}]),out_dir=tmp_path)[unit.id]
    assert result["refutations"][0]["verdict"] == "unsupported"


def test_call_cap_covers_refutation_and_failures(tmp_path):
    index = build_access_index(sources())
    unit = build_slices(index,["reader.c:get"])[0][0]
    client = Client([semantic(unit)])
    result = run_studies(index,[unit],client,out_dir=tmp_path,limits=replace(Limits(),max_calls=1))[unit.id]
    assert len(client.calls) == 1
    assert result["refutations"][0]["reason"] == "refutation_budget"
    client = Client([RuntimeError("provider failed")])
    result = run_studies(index,[unit],client,out_dir=tmp_path/"error")[unit.id]
    assert result["status"] == "error"


def test_input_budget_and_cancellation_before_dispatch(tmp_path):
    index = build_access_index(sources())
    unit = build_slices(index)[0][0]
    client = Client()
    result = run_studies(index,[unit],client,out_dir=tmp_path,limits=replace(Limits(),input_tokens=1))[unit.id]
    assert result["status"] == "error" and not client.calls
    result = run_studies(index,[unit],client,out_dir=tmp_path,should_stop=lambda:True)[unit.id]
    assert result["status"] == "deferred" and not client.calls


def test_shadow_context_and_prompt_delivery(tmp_path):
    from core.audit.context import format_context_for_prompt
    root = tmp_path/"repo"
    root.mkdir()
    write_sources(root)
    gaps = [{"file":"reader.c","name":"get"}]
    assert prepare_cross_entry(root,gaps,mode="off",out_dir=tmp_path/"off") == {}
    assert not (tmp_path/"off").exists()
    assert prepare_cross_entry(root,gaps,mode="shadow",out_dir=tmp_path/"shadow") == {}
    contexts = prepare_cross_entry(root,gaps,mode="context",out_dir=tmp_path/"context")
    assert set(contexts) == {"reader.c:get"}
    assert "void put" in contexts["reader.c:get"]
    ctx = {"file":"reader.c","function":"get","line_start":1,"source":"return 0;","cross_entry_analysis":contexts["reader.c:get"]}
    rendered = format_context_for_prompt(ctx)
    assert "Shared-state protocol investigation" in rendered
    assert "void put" in rendered
    delivery = json.loads((tmp_path/"context"/"cross-entry-delivery.json").read_text())
    assert delivery["available_to_review"] == ["reader.c:get"]


def test_no_false_claim_of_object_identity_for_disjoint_instances():
    index = build_access_index({"a.c":"struct state { int len; }; void a(void) { struct state left; left.len = 1; } void b(void) { struct state right; right.len = 2; }"})
    origins = {a.object_origin for a in index.accesses}
    assert len(origins) == 2
    assert all("same_object_and_call_order_require_verification" in u.unresolved for u in build_slices(index)[0])


def test_invalid_modes_and_limits_rejected(tmp_path):
    with pytest.raises(ValueError):
        Limits(max_calls=-1)
    with pytest.raises(ValueError):
        prepare_cross_entry(tmp_path,[],mode="invalid",out_dir=tmp_path/"out")


def test_global_struct_accesses_and_parameter_shadowing():
    index = build_access_index({"a.c":"""
struct state { int ready; }; static struct state shared;
void set(void) { shared.ready = 1; }
int get(void) { return shared.ready; }
int shadow(struct state *shared) { return shared->ready; }
"""})
    globals_ = [a for a in index.accesses if a.function != fn(index,"shadow")]
    assert len({a.binding for a in globals_}) == 1
    assert globals_[0].binding.startswith("global:a.c:")
    assert next(a for a in index.accesses if a.function == fn(index,"shadow")).binding != globals_[0].binding


def test_header_closure_precedes_unrelated_sources(tmp_path):
    (tmp_path/"include").mkdir()
    (tmp_path/"reader.c").write_text('#include <state.h>\nint get(struct state *s) { return s->len; }')
    (tmp_path/"include"/"state.h").write_text('struct state { int len; };')
    (tmp_path/"aaa.c").write_text('int unrelated;')
    src,coverage = collect_sources(tmp_path,["reader.c"],replace(Limits(),max_files=2))
    assert set(src) == {"reader.c","include/state.h"}
    assert coverage["truncated"]


def test_larger_context_root_keeps_report_scope(tmp_path):
    (tmp_path/"component").mkdir()
    (tmp_path/"other").mkdir()
    (tmp_path/"shared.h").write_text("struct state { int len; };")
    (tmp_path/"component"/"reader.c").write_text("int get(struct state *s) { return s->len; }")
    (tmp_path/"other"/"writer.c").write_text("void put(struct state *s) { s->len = 4; }")
    contexts = prepare_cross_entry(tmp_path/"component",[{"file":"reader.c","name":"get"}],
        context_root=tmp_path,mode="context",out_dir=tmp_path/"out")
    assert set(contexts) == {"reader.c:get"}
    assert "void put" in contexts["reader.c:get"]


def test_demand_retrieval_uses_indexed_definitions_and_shared_budget(tmp_path):
    src = sources()
    src["helper.c"] = "int external_contract(void) { return 1; }"
    index = build_access_index(src)
    unit = build_slices(index,["reader.c:get"])[0][0]
    first = {"facts":[],"witnesses":[],"needed_symbols":["external_contract","../../secret"]}
    client = Client([first,semantic(unit),{"verdict":"unsupported","reason":"conditional","evidence_ids":[]}])
    result = run_studies(index,[unit],client,out_dir=tmp_path)[unit.id]
    assert result["retrieved_functions"] == [fn(index,"external_contract")]
    assert len(client.calls) == 3
    assert "int external_contract" in client.calls[1][0]
    assert "DECLARATION_ID state.h:0:struct state" in client.calls[1][0]
    assert run_studies(index,[unit],Client(),out_dir=tmp_path)[unit.id]["cache_hit"]


def test_malformed_cached_response_is_recomputed(tmp_path):
    index = build_access_index(sources())
    unit = build_slices(index,["reader.c:get"])[0][0]
    run_studies(index,[unit],Client([{"facts":[],"witnesses":[],"needed_symbols":[]}]),out_dir=tmp_path)
    cache = next((tmp_path/"cross-entry-cache").glob("*.json"))
    raw = json.loads(cache.read_text())
    raw["study"] = {"witnesses":"broken"}
    cache.write_text(json.dumps(raw))
    client = Client([{"facts":[],"witnesses":[],"needed_symbols":[]}])
    assert not run_studies(index,[unit],client,out_dir=tmp_path)[unit.id]["cache_hit"]
    assert len(client.calls) == 1


def test_semantic_mode_is_delivered_with_refutation(tmp_path):
    write_sources(tmp_path)
    units = build_slices(build_access_index(sources()),["reader.c:get"])[0]
    unit = units[0]
    client = Client([semantic(unit),{"verdict":"contradicted","reason":"consumer checks state","evidence_ids":[unit.consumer]}])
    contexts = prepare_cross_entry(tmp_path,[{"file":"reader.c","name":"get"}],mode="study",out_dir=tmp_path/"out",client=client)
    assert "conditional mismatch" in contexts["reader.c:get"]
    assert "contradicted" in contexts["reader.c:get"]
    assert '"confidence": "inferred"' in contexts["reader.c:get"]


def test_pipeline_options_forward_experimental_flags(tmp_path):
    from core.audit.pipeline import AuditPipelineOpts, ReviewMode, _build_orchestrator_config
    opts = AuditPipelineOpts(target_path=tmp_path,out_dir=tmp_path/"out",cross_entry="shadow",
                             cross_entry_max_calls=3,cross_entry_max_files=10,cross_entry_root=tmp_path)
    cfg = _build_orchestrator_config(opts,None,[],ReviewMode.SECURITY)
    assert (cfg.cross_entry,cfg.cross_entry_max_calls,cfg.cross_entry_max_files,cfg.cross_entry_root) == ("shadow",3,10,tmp_path)


def test_delivery_receipt_reaches_review_result(tmp_path):
    from core.audit.llm_review import make_review_fn
    from core.audit.orchestrator import OrchestratorConfig
    ctx = {"file":"a.c","function":"f","line_start":1,"source":"int f(void) { return 0; }",
           "cross_entry_analysis":"conditional shared-state context"}
    client = Client([{"status":"clean","body":"reviewed","hypothesis":""}])
    result = make_review_fn(client)(ctx,OrchestratorConfig(target_path=tmp_path,out_dir=tmp_path))
    assert result.review_result["cross_entry_rendered"] is True
    assert "conditional shared-state context" in client.calls[0][0]


@pytest.mark.parametrize("family,bodies", [
    ("stale_validation",["void validate(struct state *s) { s->checked = s->version; }",
                         "void change(struct state *s) { s->version++; }",
                         "int consume(struct state *s) { return s->checked; }"]),
    ("lifetime",["void submit(struct state *s) { queue(&s->payload); }",
                  "void close(struct state *s) { release(s->payload); }",
                  "void consume(struct state *s) { write_to(s->payload); }"]),
    ("rollback",["int failed_grant(struct state *s) { s->authorized = 1; return -1; }",
                  "int consume(struct state *s) { return s->authorized; }"]),
    ("bounds",["void grow(struct state *s) { s->len = 8; }",
                "int consume(struct state *s) { return s->capacity - s->len; }"]),
])
def test_protocol_families_retrieve_all_transitions(family,bodies):
    src = {"state.h":"struct state { int checked; int version; int *payload; int authorized; int len; int capacity; };"}
    src.update({f"step{i}.c":body for i,body in enumerate(bodies)})
    index = build_access_index(src)
    consumer = fn(index,"consume")
    units,_ = build_slices(index,[consumer])
    assert set(units[0].functions) == set(index.functions)
    assert "same_object_and_call_order_require_verification" in units[0].unresolved


def test_unincluded_type_definition_does_not_prove_identity():
    index = build_access_index({"unrelated.h":"struct state { int len; };",
                               "a.c":"int get(struct state *s) { return s->len; }"})
    assert index.accesses[0].resolution == "partial"
    assert not index.coverage["complete"]


def test_header_static_globals_have_per_tu_identity():
    index = build_access_index({"state.h":"struct state { int len; }; static struct state shared;",
        "a.c":'#include "state.h"\nvoid a(void) { shared.len = 1; }',
        "b.c":'#include "state.h"\nvoid b(void) { shared.len = 2; }'})
    assert len({a.binding for a in index.accesses}) == 2


def test_indirect_writes_through_member_storage():
    index = build_access_index({"a.c":"struct state { int *data; }; void f(struct state *s) { *s->data = 1; s->data[0] = 2; }"})
    assert {a.operation for a in index.accesses} == {"indirect_write"}


def test_near_cap_selection_has_no_duplicates_or_missing_work():
    src = {"a.c":"struct state { int len; };\n"+"\n".join(
        f"int f{i}(struct state *s) {{ return s->len; }}" for i in range(39))}
    units,deferred = build_slices(build_access_index(src))
    assert len(units) == len({u.id for u in units}) == 39
    assert not deferred


def test_graph_and_source_budget_do_not_dispatch_without_consumer(tmp_path):
    index = build_access_index(sources())
    units,deferred = build_slices(index,limits=replace(Limits(),graph_seconds=0))
    assert not units and all(d["reason"] == "graph_budget" for d in deferred)
    unit = build_slices(index)[0][0]
    client = Client()
    result = run_studies(index,[unit],client,out_dir=tmp_path,limits=replace(Limits(),source_chars=1))[unit.id]
    assert result["status"] == "context_incomplete" and not client.calls


def test_prompt_budget_shedding_receipt():
    from core.audit.context import format_context_for_prompt
    ctx = {"file":"a.c","function":"f","line_start":1,"source":"int f(void) { return 0; }",
           "cross_entry_analysis":"candidate "*5000}
    format_context_for_prompt(ctx,budget_limit=500)
    assert ctx["cross_entry_rendered"] is False


def test_scalar_arguments_do_not_imply_mutable_object_effects():
    index = build_access_index({"a.c":"void f(int size) { consume(size); } void g(int *p) { mutate(p); }"})
    assert {a.function for a in index.accesses} == {fn(index,"g")}


def test_cpp_class_name_resolution():
    from core.audit.callsite_consistency import parse_source_cached
    if parse_source_cached("probe.cpp","struct S { int x; };")[0] is None:
        pytest.skip("requires C++ grammar")
    index = build_access_index({"state.hpp":"struct State { int ready; };",
        "a.cpp":'#include "state.hpp"\nvoid put(State *s) { s->ready++; }',
        "b.cpp":'#include "state.hpp"\nint get(State *s) { return s->ready; }'})
    assert len(index.accesses) == 2
    assert len({a.type_id for a in index.accesses}) == 1
    assert {a.resolution for a in index.accesses} == {"resolved"}


def test_ambiguous_report_definition_does_not_deliver_wrong_consumer(tmp_path):
    (tmp_path/"a.c").write_text("struct state { int ready; };\n#if MODE\nint get(struct state *s) { return s->ready; }\n#else\nint get(struct state *s) { return 1 + s->ready; }\n#endif\n")
    contexts = prepare_cross_entry(tmp_path,[{"file":"a.c","name":"get"}],mode="context",out_dir=tmp_path/"out")
    assert not contexts
    index = json.loads((tmp_path/"out"/"cross-entry-index.json").read_text())
    assert any(u["reason"] == "ambiguous_or_missing_report_definition" for u in index["coverage"]["unresolved"])


@pytest.mark.slow
def test_full_orchestrator_delivers_sibling_not_in_checklist(tmp_path,monkeypatch):
    from core.audit.orchestrator import OrchestratorConfig, ReviewOutcome, run_orchestrator
    target = tmp_path/"target"
    target.mkdir()
    write_sources(target)
    out = tmp_path/"out"
    out.mkdir()
    (out/"checklist.json").write_text(json.dumps({"files":[{"path":"reader.c","items":[
        {"name":"get","line_start":2,"line_end":2}]}]}))
    captured = []
    # This test exercises shared-state prep and delivery, not the unrelated
    # detector import-closure census or external analysis installations.
    monkeypatch.setattr("core.audit.orchestrator._run_mechanical_detectors",lambda *a,**kw:({},set()))
    def review(ctx,cfg):
        captured.append(ctx)
        from core.audit.cross_entry.progress import acknowledge_delivery
        if ctx.get("cross_entry_receipt"):
            acknowledge_delivery(cfg.out_dir,ctx["cross_entry_receipt"])
        return ReviewOutcome(file=ctx["file"],function=ctx["function"],status="clean",body="reviewed")
    cfg = OrchestratorConfig(target_path=target,out_dir=out,cross_entry="context",resume=False,
        prefilter_skip=False,triage=False,vendored_triage=False,iris=False,sage_recall=False,
        domain_model_import=False,dynamic_validation=False,max_workers=1,
        joern_overrides={"enabled":False},no_binary_oracle=True,
        library_replay=False,cross_run_import=False,annotations_read=False)
    result = run_orchestrator(cfg,review)
    assert result.reviewed == 1
    assert captured and "void put" in captured[0]["cross_entry_analysis"]
    assert not (out/"cross-entry-error.json").exists()
    # A continuation can prepare new evidence after the ordinary review
    # finished. The next continuation must reopen that covered function.
    resumed = replace(cfg,resume=True)
    run_orchestrator(resumed,review)
    rerun = run_orchestrator(resumed,review)
    assert rerun.reviewed == 1
    assert len(captured) == 2
    assert captured[0]["cross_entry_receipt"]["job"] != captured[1]["cross_entry_receipt"]["job"]


def test_digest_uses_shared_canonical_json_bytes():
    import hashlib
    from core.audit.cross_entry.model import digest
    from core.json import dumps_canonical
    value = {"z": ["café", {"b": 2, "a": 1}], "a": "shared-state"}
    expected = hashlib.sha256(dumps_canonical(value).encode("utf-8")).hexdigest()
    assert digest(value) == expected
    assert digest(dict(reversed(list(value.items())))) == expected


def test_typed_consumer_state_beats_large_unrelated_setup_driver():
    # Repeated spelling overlap through a consumer helper used to outrank
    # the real producer. The producer's filename is intentionally test-like:
    # provenance filenames must not decide protocol relevance.
    index = build_access_index({
        "state.h":"struct session { int state; int size; }; struct scratch { int state; int size; };",
        "reader.c":'#include "state.h"\nvoid helper(struct scratch *t) { t->state = 1; t->size = 2; }\n'
                   'int consume(struct session *s, struct scratch *t) { helper(t); return s->state + s->size; }',
        "test_writer.c":'#include "state.h"\nvoid establish(struct session *s) { s->state = 1; s->size = 2; }',
        "driver.c":'#include "state.h"\nvoid setup(struct scratch *t) {'+'t->state = 1; t->size = 2; '*100+'}',
    })
    unit = build_slices(index,["reader.c:consume"],limits=replace(Limits(),functions_per_slice=2))[0][0]
    assert unit.functions == [fn(index,"consume"),fn(index,"establish")]
    assert "unique_typed_path_affinity" in unit.reasons


def test_repeated_touches_do_not_outweigh_unique_shared_paths():
    index = build_access_index({"a.c":"struct session { int state; int size; };\n"
        "int consume(struct session *s) { return s->state + s->size; }\n"
        "void establish(struct session *s) { s->state = 1; s->size = 2; }\n"
        "void noise(struct session *s) {"+'s->state = 1; '*100+'}'})
    unit = build_slices(index,["a.c:consume"],limits=replace(Limits(),functions_per_slice=2))[0][0]
    assert unit.functions == [fn(index,"consume"),fn(index,"establish")]


def test_recursive_headers_cannot_crowd_out_sibling_producer(tmp_path):
    (tmp_path/"src").mkdir()
    (tmp_path/"include").mkdir()
    (tmp_path/"src"/"reader.c").write_text('#include <h0.h>\nint consume(void) { return 0; }')
    (tmp_path/"src"/"writer.c").write_text('void establish(void) {}')
    for i in range(20):
        (tmp_path/"include"/f"h{i}.h").write_text(f'#include <h{i+1}.h>\n')
    src,coverage = collect_sources(tmp_path,["src/reader.c"],replace(Limits(),max_files=8))
    assert "src/reader.c" in src
    assert "include/h0.h" in src
    assert "src/writer.c" in src
    assert len(src) == 8
    assert "header_budget" in coverage["truncated"]


def dispatch_sources():
    return {"api.h":"""
struct request { int *data; int length; };
struct ops { int (*run)(struct request *r); };
struct instance { union { struct ops ops; }; };
struct session { struct instance *engine; struct request *request; };
struct ops *get_ops(struct instance *i);
""",
        "setup.c":'#include "api.h"\nint implementation(struct request *r) { int *view = r->data; touch(view, r->length + 4); return 0; }\n'
                  'void install(struct instance *i) { i->ops.run = &implementation; }',
        "invoke.c":'#include "api.h"\nint dispatch(struct instance *i, struct request *r) { return get_ops(i)->run(r); }',
        "consumer.c":'#include "api.h"\nint consume(struct session *s) { return dispatch(s->engine,s->request); }'}


def test_typed_callback_assignment_through_getter_and_anonymous_union():
    index = build_access_index(dispatch_sources())
    target = fn(index,"implementation")
    call = next(c for c in index.calls if c.name == "get_ops(i)->run")
    assert call.dispatch_candidates == [target]
    assert not call.targets  # A unique possibility is still conditional.
    assert target not in index.entries
    assert any(r.kind == "dispatch_candidate" and r.target == target and r.resolution == "conditional" for r in index.relations)
    assert any(r.kind == "dispatch_argument_binding" and r.source.endswith(":r") for r in index.relations)
    unit = build_slices(index,["consumer.c:consume"])[0][0]
    assert any(r["target"] == target and r["status"] == "conditional_runtime_selection" for r in unit.dispatch_candidates)
    assert "touch(view, r->length + 4)" in unit.source


def test_callback_slot_spelling_does_not_merge_unrelated_types():
    src = dispatch_sources()
    src["other.c"] = 'struct unrelated { int (*run)(int n); }; int wrong(int n) { return n; } void other_install(struct unrelated *o) { o->run = wrong; }'
    index = build_access_index(src)
    call = next(c for c in index.calls if c.name == "get_ops(i)->run")
    assert call.dispatch_candidates == [fn(index,"implementation")]
    assert fn(index,"wrong") not in call.dispatch_candidates


def test_array_and_nested_callback_initializers():
    src = dispatch_sources()
    src["setup.c"] = '#include "api.h"\nint implementation(struct request *r) { return r->length; }\nstatic struct instance instances[] = {{.ops = {.run = implementation}}};'
    index = build_access_index(src)
    assert any(r["target"] == fn(index,"implementation") for r in index.callbacks)
    assert next(c for c in index.calls if c.name == "get_ops(i)->run").dispatch_candidates == [fn(index,"implementation")]


def test_unknown_getter_return_type_does_not_invent_dispatch_edge():
    src = dispatch_sources()
    src["api.h"] = src["api.h"].replace('struct ops *get_ops(struct instance *i);','')
    index = build_access_index(src)
    assert not next(c for c in index.calls if c.name == "get_ops(i)->run").dispatch_candidates
    assert any(r["reason"] == "callback_owner_unresolved" for r in index.coverage["unresolved"])


def test_callback_fragments_are_citable_but_full_body_is_not_assumed():
    from core.audit.cross_entry.study import _payload
    index = build_access_index(dispatch_sources())
    target = fn(index,"implementation")
    unit = build_slices(index,["consumer.c:consume"])[0][0]
    # Force the implementation to be excerpt-only, regardless of peer ranking.
    unit = replace(unit,functions=[unit.consumer,fn(index,"dispatch")])
    prompt,allowed,functions = _payload(index,unit,unit.functions,Limits())
    assert target in functions and target not in allowed
    assert "touch(view, r->length + 4)" in prompt
    assert "fragment_only_functions" in prompt
    evidence = next(a.id for a in index.accesses if a.function == target and a.expression == "view")
    assert evidence in allowed
    raw = semantic(unit)
    raw["witnesses"][0]["sequence"].append(target)
    raw["witnesses"][0]["evidence_ids"].append(evidence)
    result = _validate(raw,allowed,functions,consumer=unit.consumer,conditional_targets={target})
    w = result["witnesses"][0]
    assert f"callback_body_incomplete:{target}" in w["missing_dependencies"]
    assert f"callback_selection_unverified:{target}" in w["missing_dependencies"]
    assert w["confidence"] == "inferred"
    raw["witnesses"][0]["evidence_ids"] = [unit.consumer,target]
    assert not _validate(raw,allowed,functions)["witnesses"]


def test_callback_catalogue_budget_preserves_target_inventory():
    from core.audit.cross_entry.dispatch import dispatch_catalogue
    index = build_access_index(dispatch_sources())
    unit = build_slices(index,["consumer.c:consume"])[0][0]
    emitted,omitted = dispatch_catalogue(index,unit.dispatch_candidates,1)
    assert not emitted and omitted > 0
    assert unit.dispatch_candidates
    assert index.callbacks


def test_computed_offset_site_is_not_hidden_by_earlier_generic_calls():
    from core.audit.cross_entry.dispatch import dispatch_catalogue
    src = dispatch_sources()
    src["setup.c"] = '#include "api.h"\nint implementation(struct request *r) {\nint *view = r->data;\ntouch(view, 0);\ntouch(view, 1);\ntouch(view, 2);\ntouch(view + 1, r->length + 4);\nreturn 0;\n}\nvoid install(struct instance *i) { i->ops.run = implementation; }'
    index = build_access_index(src)
    unit = build_slices(index,["consumer.c:consume"])[0][0]
    fragments,_ = dispatch_catalogue(index,unit.dispatch_candidates,8000)
    assert any("touch(view + 1, r->length + 4)" in f["source"] for f,_ in fragments)


def test_local_function_pointer_declaration_does_not_add_formal_parameters():
    src = dispatch_sources()
    src["setup.c"] = '#include "api.h"\nint implementation(struct request *r) { void (*local)(int n); return r->length; }\nvoid install(struct instance *i) { i->ops.run = implementation; }'
    index = build_access_index(src)
    assert index.functions[fn(index,"implementation")].params == ["r"]
    assert next(c for c in index.calls if c.name == "get_ops(i)->run").dispatch_candidates == [fn(index,"implementation")]


def test_callback_parameter_shadowing_a_function_is_not_a_fixed_binding():
    src = dispatch_sources()
    src["setup.c"] = '#include "api.h"\nint implementation(struct request *r) { return r->length; }\nvoid install(struct instance *i, int (*implementation)(struct request *r)) { i->ops.run = implementation; }'
    index = build_access_index(src)
    assert not next(c for c in index.calls if c.name == "get_ops(i)->run").dispatch_candidates
    assert any(r["reason"] == "callback_value_indirect" for r in index.coverage["unresolved"])


def test_local_function_pointer_call_does_not_resolve_to_shadowed_global():
    index = build_access_index({"a.c":"int handler(int n) { return n; } int invoke(int (*handler)(int n)) { return handler(1); }"})
    assert not next(c for c in index.calls if c.name == "handler").targets


def test_conditional_callback_validation_is_idempotent_on_cache_recall():
    from core.audit.cross_entry.study import _payload
    index = build_access_index(dispatch_sources())
    target = fn(index,"implementation")
    unit = build_slices(index,["consumer.c:consume"])[0][0]
    unit = replace(unit,functions=[unit.consumer,fn(index,"dispatch")])
    _,allowed,functions = _payload(index,unit,unit.functions,Limits())
    raw = semantic(unit)
    raw["witnesses"][0]["sequence"].append(target)
    once = _validate(raw,allowed,functions,consumer=unit.consumer,conditional_targets={target})
    twice = _validate(once,allowed,functions,consumer=unit.consumer,conditional_targets={target})
    assert once["witnesses"] == twice["witnesses"]
