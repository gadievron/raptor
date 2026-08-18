"""Field-access census substrate tests (five-channel programme §0).

Hermetic: in-memory source texts, no subprocesses, no LLM. The
tree-sitter tier is exercised when the grammar is installed; the
regex tier is exercised explicitly by disabling the parse cache.
"""

from __future__ import annotations

import json

import pytest

from core.audit import field_census as fc
from core.audit.field_census import (
    TIER_REGEX,
    TIER_TREE_SITTER,
    build_field_census,
    function_spans,
    priority_fields_from_study_list,
    seed_injected_hypotheses,
    write_census_artifact,
    written_never_read,
)


def _ts_available() -> bool:
    from core.audit.callsite_consistency import parse_source_cached
    tree, _ = parse_source_cached("probe.c", "int f(void) { return 0; }")
    return tree is not None


requires_ts = pytest.mark.skipif(
    not _ts_available(), reason="tree-sitter C grammar unavailable",
)


SRC = """
void retarget(struct ch *obj, struct ch *tmp) {
    obj->engine = tmp->engine;
    obj->handle = make_handle(tmp);
    obj->owner_ref = NULL;
    obj->limit = 42;
}
void ch_init(struct ch *obj, struct prt *p) {
    obj->port = p;
}
struct prt *ch_get_port(struct ch *c) {
    return c->port;
}
void reader(struct ch *o) {
    struct n *q = rcu_dereference(o->node);
    struct prt *direct = o->port;
    if (o->limit) {
        o->dispatch(1);
    }
}
"""


@requires_ts
class TestTreeSitterTier:
    @pytest.fixture()
    def census(self):
        return build_field_census({"src/ch.c": SRC})

    def test_tier(self, census):
        assert census.tier == TIER_TREE_SITTER
        assert not census.degraded

    def test_write_rhs_provenance_classes(self, census):
        by_field = {
            name: [w.rhs_class for w in rec.writes]
            for name, rec in census.fields.items() if rec.writes
        }
        assert by_field["engine"] == ["from_field:tmp.engine"]
        assert by_field["handle"] == ["from_call:make_handle"]
        assert by_field["owner_ref"] == ["literal_null"]
        assert by_field["limit"] == ["literal_const"]
        assert by_field["port"] == ["from_param:p"]

    def test_write_records_owner_function_lock(self, census):
        w = census.fields["engine"].writes[0]
        assert (w.owner, w.function, w.file) == (
            "obj", "retarget", "src/ch.c",
        )
        assert w.line == 3
        assert w.lock_held == ""

    def test_read_contexts(self, census):
        reads = {
            (r.function, r.context)
            for r in census.fields["port"].reads
        }
        assert ("ch_get_port", "return") in reads
        assert ("reader", "alias_assign:direct") in reads

    def test_derived_through_call_alias(self, census):
        # p = rcu_dereference(o->node): the value flows through the
        # passthrough call into the local — still an alias edge.
        contexts = [r.context for r in census.fields["node"].reads]
        assert contexts == ["alias_assign:q"]

    def test_condition_and_invoke_contexts(self, census):
        assert any(
            r.context == "condition"
            for r in census.fields["limit"].reads
        )
        assert any(
            r.context == "invoke"
            for r in census.fields["dispatch"].reads
        )

    def test_written_never_read(self, census):
        # "engine" is written AND read (its rhs is tmp->engine — a
        # read of the same field name on the source graph); "handle"
        # and "owner_ref" are written and never read target-wide.
        assert sorted(r.field for r in written_never_read(census)) == [
            "handle", "owner_ref",
        ]

    def test_function_spans(self, census):
        spans = {s.name: s for s in census.functions["src/ch.c"]}
        assert set(spans) == {
            "retarget", "ch_init", "ch_get_port", "reader",
        }
        assert spans["retarget"].start == 2
        assert set(spans["ch_init"].params) == {"obj", "p"}
        assert not spans["retarget"].is_static

    def test_static_and_function_pointer_params(self):
        src = (
            "static void set_cb(struct s *x, void (*cb)(int)) {\n"
            "    x->remove_cb = cb;\n"
            "}\n"
        )
        census = build_field_census({"a.c": src})
        span = census.functions["a.c"][0]
        assert span.is_static
        assert "cb" in span.params
        assert census.fields["remove_cb"].writes[0].rhs_class == \
            "from_param:cb"

    def test_artifact_write(self, census, tmp_path):
        path = write_census_artifact(census, tmp_path)
        assert path is not None
        payload = json.loads(path.read_text())
        assert payload["tier"] == TIER_TREE_SITTER
        assert "port" in payload["fields"]
        assert payload["fields"]["port"]["writes"]


class TestRegexTier:
    @pytest.fixture()
    def census(self, monkeypatch):
        import core.audit.callsite_consistency as cc
        monkeypatch.setattr(
            cc, "parse_source_cached", lambda *_a, **_k: (None, None),
        )
        return build_field_census({"src/ch.c": SRC})

    def test_degraded_tier(self, census):
        assert census.tier == TIER_REGEX
        assert census.degraded

    def test_regex_records_carry_tier(self, census):
        assert census.fields["engine"].tier == TIER_REGEX

    def test_regex_rhs_classes(self, census):
        classes = {
            name: rec.writes[0].rhs_class
            for name, rec in census.fields.items() if rec.writes
        }
        assert classes["engine"] == "from_field:tmp.engine"
        assert classes["owner_ref"] == "literal_null"
        assert classes["limit"] == "literal_const"
        assert classes["handle"].startswith("from_call:")


class TestCapsAndPriority:
    def test_noise_fields_dropped_unless_priority(self):
        src = "void f(struct s *x, int v) { x->len = v; x->seq = v; }\n"
        plain = build_field_census({"a.c": src})
        assert "len" not in plain.fields  # noise list
        prioritised = build_field_census(
            {"a.c": src}, priority_fields=frozenset({"len"}),
        )
        assert "len" in prioritised.fields

    def test_field_cap_keeps_priority_fields_first(self):
        src = "".join(
            f"void f{i}(struct s *x, int v) {{ x->field_{i} = v; }}\n"
            for i in range(6)
        )
        census = build_field_census(
            {"a.c": src},
            priority_fields=frozenset({"field_5"}),
            max_fields=2,
        )
        assert "field_5" in census.fields
        assert census.telemetry["fields_skipped"] == 4
        assert census.capped

    def test_sites_per_field_cap(self):
        body = "".join(
            f"    x->hot = {i};\n" for i in range(8)
        )
        src = f"void f(struct s *x) {{\n{body}}}\n"
        census = build_field_census(
            {"a.c": src}, max_sites_per_field=3,
        )
        rec = census.fields["hot"]
        assert len(rec.writes) == 3
        assert rec.sites_capped

    def test_budget_overrun_sets_telemetry(self):
        census = build_field_census(
            {"a.c": "void f(struct s *x) { x->fld = 1; }\n"},
            budget_s=0.0,
        )
        assert census.telemetry["budget_exceeded"]
        assert census.capped

    def test_non_c_files_skipped(self):
        census = build_field_census({"a.py": "x = 1\n"})
        assert census.telemetry["files_skipped_language"] == 1
        assert not census.fields


class TestPriorityFromStudyList:
    def test_items_with_lifecycle_seeds_contribute_fields(self):
        payload = {"items": [
            {"name": "s1", "fields": ["cached", "pool"],
             "resource_lifecycle": ["BIO_free"]},
            {"name": "s2", "fields": ["ignored"],
             "resource_lifecycle": [], "alloc_frees": [],
             "state_transitions": []},
            {"name": "s3", "fields": ["seq"],
             "state_transitions": ["INIT->READY"]},
        ]}
        assert priority_fields_from_study_list(payload) == frozenset(
            {"cached", "pool", "seq"},
        )

    def test_path_and_missing_file(self, tmp_path):
        assert priority_fields_from_study_list(tmp_path) == frozenset()
        p = tmp_path / "study-list.json"
        p.write_text(json.dumps({"items": [
            {"fields": ["fld"], "alloc_frees": ["kmalloc/kfree"]},
        ]}))
        assert priority_fields_from_study_list(tmp_path) == \
            frozenset({"fld"})
        assert priority_fields_from_study_list(None) == frozenset()

    def test_bare_list_shape(self):
        assert priority_fields_from_study_list(
            [{"fields": ["fld"], "resource_lifecycle": ["x_free"]}],
        ) == frozenset({"fld"})


class TestSeedInjectedHypotheses:
    def test_seeds_matching_gaps_only(self):
        gaps = [
            {"file": "a.c", "name": "f"},
            {"file": "b.c", "name": "g"},
        ]
        handoffs = [
            {"file": "a.c", "function": "f", "mechanism": "stale alias"},
        ]
        n = seed_injected_hypotheses(
            gaps, handoffs, source="ptr_lifecycle_census",
        )
        assert n == 1
        inj = gaps[0]["injected_hypotheses"][0]
        assert inj["mechanism"] == "stale alias"
        assert inj["source"] == "ptr_lifecycle_census"
        assert "injected_hypotheses" not in gaps[1]


class TestFunctionSpansFallback:
    def test_regex_spans(self):
        spans = fc.function_spans_regex(
            "static int helper(struct s *x, int v) {\n"
            "    return v;\n"
            "}\n"
            "void top(void) {\n"
            "    helper(0, 1);\n"
            "}\n",
        )
        by_name = {s.name: s for s in spans}
        assert by_name["helper"].is_static
        assert not by_name["top"].is_static
        assert by_name["helper"].start == 1
        assert by_name["helper"].end == 3
        assert "v" in by_name["helper"].params

    def test_function_spans_dispatches(self, monkeypatch):
        import core.audit.callsite_consistency as cc
        monkeypatch.setattr(
            cc, "parse_source_cached", lambda *_a, **_k: (None, None),
        )
        spans = function_spans("void f(int a) {\n}\n", "x.c")
        assert [s.name for s in spans] == ["f"]
