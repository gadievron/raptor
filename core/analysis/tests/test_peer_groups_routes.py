"""Tests for the L10 route-family peer-group layer.

Synthetic ``RouteModels`` artifacts (``from_dict`` — the exact disk
shape) pin the join contract: family keys, claim floor, CBV
exclusion, truncated-chain exclusion, the two-valued auth-decoration
property, minority-preserving caps, escaping. One end-to-end fixture
builds the models with the REAL route extractor so the
decorator-position contract (decoration facts only) is pinned
against the whole facts → recognition → family chain.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from core.analysis.peer_groups import (
    GROUP_TYPE_ROUTE_FAMILY,
    MAX_ROUTE_FAMILIES,
    MAX_ROUTE_FAMILY_MEMBERS,
    MIN_ROUTE_FAMILY_MEMBERS,
    ROUTE_AUTH_PROPERTY,
    _route_family_groups,
    resolve_peer_groups,
    route_models_for_prep,
)
from core.analysis.route_models import RouteModels, build_route_models
from core.inventory.call_graph import extract_call_graph_python
from core.inventory.extractors import PythonExtractor


# ── fixtures ──────────────────────────────────────────────────────────


def _func(name, file="src/app.py", line=1):
    return {"name": name, "file": file, "line": line}


def _route(pattern, handler, *, framework="flask", style="decorator",
           chain=(), truncated=False, kind=None, methods=("GET",)):
    d = {
        "framework": framework,
        "route_pattern": pattern,
        "http_methods": list(methods),
        "handler": handler,
        "params": [],
        "middleware_chain": [
            {"name": n, "tier": "resolved_static"} for n in chain
        ],
        "registration": {"file": "src/app.py", "line": 1, "style": style},
    }
    if truncated:
        d["middleware_truncated"] = True
    if kind:
        d["handler_kind"] = kind
    return d


def _models(routes):
    return RouteModels.from_dict({"routes": routes})


def _groups(routes, functions):
    groups, _note = _route_family_groups(_models(routes), functions)
    return groups


@dataclass
class FakeDispatchTable:
    function: str = "dispatch"
    file: str = "src/app.py"
    handlers: dict = field(default_factory=dict)


def _record_for(rel_path: str, content: str) -> dict:
    items = [i.to_dict()
             for i in PythonExtractor().extract(rel_path, content)]
    return {
        "path": rel_path,
        "language": "python",
        "items": items,
        "call_graph": extract_call_graph_python(content).to_dict(),
    }


def _inventory(sources: dict[str, str]) -> dict:
    return {"files": [_record_for(p, s)
                      for p, s in sorted(sources.items())]}


# ── family formation ─────────────────────────────────────────────────


class TestFamilyFormation:
    def test_group_by_framework_style_and_prefix(self):
        routes = [
            _route("/admin/users", "src/app.py::admin_users@10"),
            _route("/admin/keys", "src/app.py::admin_keys@20"),
            _route("/admin/audit", "src/app.py::admin_audit@25"),
            _route("/api/items", "src/app.py::api_items@30"),
            _route("/api/orders", "src/app.py::api_orders@40"),
            _route("/api/carts", "src/app.py::api_carts@45"),
            # Same prefix, different style — separate family (below
            # the claim floor, so refused).
            _route("/admin/legacy", "src/app.py::admin_legacy@50",
                   style="method_call"),
        ]
        funcs = [_func(n, line=i) for i, n in enumerate(
            ["admin_users", "admin_keys", "admin_audit", "api_items",
             "api_orders", "api_carts", "admin_legacy"])]
        groups = _groups(routes, funcs)
        assert [g.group_id for g in groups] == [
            "route_family:flask:decorator:admin",
            "route_family:flask:decorator:api",
        ]
        assert all(g.sibling_type == GROUP_TYPE_ROUTE_FAMILY
                   for g in groups)
        assert {s.function for s in groups[0].siblings} \
            == {"admin_users", "admin_keys", "admin_audit"}
        assert {s.function for s in groups[1].siblings} \
            == {"api_items", "api_orders", "api_carts"}

    def test_django_unconstrained_methods_group_fine(self):
        """``http_methods: []`` on Django FBVs means "not constrained
        at registration" — methods are never a grouping fact, so
        empty-method routes family like any other."""
        routes = [
            _route("items/<int:pk>/", "src/views.py::detail@5",
                   framework="django", style="urlconf", methods=()),
            _route("items/all/", "src/views.py::listing@15",
                   framework="django", style="urlconf", methods=()),
            _route("items/new/", "src/views.py::creator@25",
                   framework="django", style="urlconf", methods=()),
        ]
        funcs = [_func("detail", file="src/views.py", line=5),
                 _func("listing", file="src/views.py", line=15),
                 _func("creator", file="src/views.py", line=25)]
        groups = _groups(routes, funcs)
        assert [g.group_id for g in groups] \
            == ["route_family:django:urlconf:items"]

    def test_dynamic_first_segment_families_together(self):
        routes = [
            _route("/<int:uid>/profile", "src/app.py::profile@1"),
            _route("/{uid}/settings", "src/app.py::settings_page@2"),
            _route("/<int:uid>/billing", "src/app.py::billing@3"),
        ]
        funcs = [_func("profile"), _func("settings_page"),
                 _func("billing")]
        groups = _groups(routes, funcs)
        assert [g.group_id for g in groups] \
            == ["route_family:flask:decorator:<dynamic>"]

    def test_same_handler_two_routes_one_member(self):
        routes = [
            _route("/api/a", "src/app.py::multi@1"),
            _route("/api/b", "src/app.py::multi@1",
                   chain=("login_required",)),
            _route("/api/c", "src/app.py::other@2"),
            _route("/api/d", "src/app.py::third@3"),
        ]
        funcs = [_func("multi"), _func("other"), _func("third")]
        groups = _groups(routes, funcs)
        assert len(groups) == 1
        members = {s.function: s.properties for s in groups[0].siblings}
        # Decoration ORs across the member's routes.
        assert members["multi"] == {ROUTE_AUTH_PROPERTY: True}
        assert members["other"] == {ROUTE_AUTH_PROPERTY: False}

    def test_unjoined_and_unparsable_handlers_skipped(self):
        routes = [
            _route("/api/a", "not-a-handler-id"),
            _route("/api/b", "src/app.py::ghost@7"),   # not in queue
            _route("/api/c", "src/app.py::real_a@1"),
            _route("/api/d", "src/app.py::real_b@2"),
            _route("/api/e", "src/app.py::real_c@3"),
        ]
        funcs = [_func("real_a"), _func("real_b"), _func("real_c")]
        groups = _groups(routes, funcs)
        assert len(groups) == 1
        assert {s.function for s in groups[0].siblings} \
            == {"real_a", "real_b", "real_c"}

    def test_bare_name_rescue_requires_matching_basename(self):
        """The bare-name fallback exists for path-ROOT normalization
        differences; a same-named function in an UNRELATED file must
        not be pulled into (and claimed out of) its real groups."""
        routes = [
            # Different root, same basename → rescued.
            _route("/api/a", "vendor/tree/src/app.py::real_a@1"),
            _route("/api/b", "src/app.py::real_b@2"),
            _route("/api/c", "src/app.py::real_c@3"),
            # Same bare name, unrelated file basename → refused.
            _route("/api/d", "vendor/other/lib.py::shared_helper@5"),
        ]
        funcs = [_func("real_a"), _func("real_b"), _func("real_c"),
                 _func("shared_helper", file="src/util.py")]
        groups = _groups(routes, funcs)
        assert len(groups) == 1
        assert {s.function for s in groups[0].siblings} \
            == {"real_a", "real_b", "real_c"}


# ── claim floor (comparator capability) ──────────────────────────────


class TestClaimFloor:
    def test_floor_matches_the_interface_comparator(self):
        from core.audit.consistency_dimensions import (
            INTERFACE_MIN_GROUP,
        )
        assert MIN_ROUTE_FAMILY_MEMBERS == INTERFACE_MIN_GROUP

    def test_below_floor_family_neither_claims_nor_emits(self):
        """A 2-member family cannot vote in the interface comparator;
        claiming it would only strip its handlers out of the later
        exclusive layers (pure lead suppression). It must leave them
        with their existing groups."""
        funcs = [_func(n) for n in ("h_a", "h_b", "h_c", "h_d")]
        table = FakeDispatchTable(
            handlers={f"CMD_{n}": n
                      for n in ("h_a", "h_b", "h_c", "h_d")})
        routes = [
            _route("/api/c", "src/app.py::h_c@1"),
            _route("/api/d", "src/app.py::h_d@1"),
        ]
        post = resolve_peer_groups(
            funcs, dispatch_tables=[table],
            route_models=_models(routes),
        )
        assert [str(g.sibling_type) for g in post] == ["dispatch_site"]
        assert {s.function for s in post[0].siblings} \
            == {"h_a", "h_b", "h_c", "h_d"}


# ── consumer-caveat enforcement ──────────────────────────────────────


class TestCaveatEnforcement:
    def test_cbv_records_excluded(self):
        """``handler_kind: class`` is skipped even when a same-named
        function record exists (hostile shape) — CBV chains are
        unwalked, never unprotected peers."""
        routes = [
            _route("cls/a/", "src/views.py::ItemView@5",
                   framework="django", style="urlconf", kind="class"),
            _route("cls/b/", "src/views.py::fbv_one@10",
                   framework="django", style="urlconf"),
            _route("cls/c/", "src/views.py::fbv_two@20",
                   framework="django", style="urlconf"),
            _route("cls/d/", "src/views.py::fbv_three@30",
                   framework="django", style="urlconf"),
        ]
        funcs = [
            _func("ItemView", file="src/views.py", line=5),  # decoy
            _func("fbv_one", file="src/views.py", line=10),
            _func("fbv_two", file="src/views.py", line=20),
            _func("fbv_three", file="src/views.py", line=30),
        ]
        groups = _groups(routes, funcs)
        assert len(groups) == 1
        assert {s.function for s in groups[0].siblings} \
            == {"fbv_one", "fbv_two", "fbv_three"}

    def test_truncated_chain_member_excluded_with_note(self):
        """A truncated chain must never be read as "no auth
        decorator": the member cannot vote either way, so it leaves
        the family — said in-band, never silently."""
        routes = [
            _route("/api/a", "src/app.py::a@1",
                   chain=("login_required",)),
            _route("/api/b", "src/app.py::b@2",
                   chain=("login_required",)),
            _route("/api/c", "src/app.py::c@3",
                   chain=("login_required",)),
            _route("/api/d", "src/app.py::d@4", truncated=True),
        ]
        funcs = [_func(n) for n in ("a", "b", "c", "d")]
        groups = _groups(routes, funcs)
        assert len(groups) == 1
        assert {s.function for s in groups[0].siblings} \
            == {"a", "b", "c"}
        assert "1 member(s) excluded" in groups[0].shared_context
        assert "truncated" in groups[0].shared_context

    def test_truncated_route_poisons_member_with_clean_route_too(self):
        routes = [
            _route("/api/a", "src/app.py::a@1"),
            _route("/api/a2", "src/app.py::a@1", truncated=True),
            _route("/api/b", "src/app.py::b@2"),
            _route("/api/c", "src/app.py::c@3"),
            _route("/api/d", "src/app.py::d@4"),
        ]
        funcs = [_func(n) for n in ("a", "b", "c", "d")]
        groups = _groups(routes, funcs)
        assert {s.function for s in groups[0].siblings} \
            == {"b", "c", "d"}

    def test_auth_property_two_valued_on_every_member(self):
        """Every member votes the decoration property: True when an
        auth-matching decorator is recorded, explicit False when not
        — a decoration fact for the interface comparator, never
        folded into the body-evidence auth_check vote."""
        routes = [
            _route("/api/a", "src/app.py::a@1",
                   chain=("login_required",)),
            _route("/api/b", "src/app.py::b@2",
                   chain=("cache.cached",)),
            _route("/api/c", "src/app.py::c@3"),
        ]
        funcs = [_func("a"), _func("b"), _func("c")]
        groups = _groups(routes, funcs)
        props = {s.function: dict(s.properties)
                 for s in groups[0].siblings}
        assert props["a"] == {ROUTE_AUTH_PROPERTY: True}
        assert props["b"] == {ROUTE_AUTH_PROPERTY: False}
        assert props["c"] == {ROUTE_AUTH_PROPERTY: False}


# ── decorator position: decoration facts only ────────────────────────


_POSITION_SRC = '''\
from flask import Flask

app = Flask(__name__)


def login_required(f):
    return f


@login_required
@app.route("/acct/above")
def above_handler():
    return "a"


@app.route("/acct/below")
@login_required
def below_handler():
    return "b"


@app.route("/acct/plain")
def plain_handler():
    return "c"
'''


class TestDecoratorPosition:
    def test_position_mints_no_protection_distinction(self):
        """An auth decorator ABOVE the registration decorator rebinds
        the module name without wrapping the registered callable;
        one BELOW does wrap it. The chain records presence only, so
        both members must come out byte-identical — the layer records
        that peers differ in decorator PRESENCE, never that a present
        decorator makes a member protected."""
        models = build_route_models(_inventory({"app.py": _POSITION_SRC}))
        funcs = [
            _func("above_handler", file="app.py"),
            _func("below_handler", file="app.py"),
            _func("plain_handler", file="app.py"),
        ]
        groups, _note = _route_family_groups(models, funcs)
        assert len(groups) == 1
        props = {s.function: dict(s.properties)
                 for s in groups[0].siblings}
        assert props["above_handler"] == props["below_handler"] \
            == {ROUTE_AUTH_PROPERTY: True}
        assert props["plain_handler"] == {ROUTE_AUTH_PROPERTY: False}
        # No property vocabulary beyond the decoration fact exists —
        # nothing here can encode "protected".
        all_keys = set().union(*(p.keys() for p in props.values()))
        assert all_keys == {ROUTE_AUTH_PROPERTY}


# ── caps / hostile shapes ────────────────────────────────────────────


class TestBounds:
    def test_family_flood_capped_with_in_band_note(self):
        routes = []
        funcs = []
        n_fams = MAX_ROUTE_FAMILIES + 20
        for i in range(n_fams):
            for j in (0, 1, 2):
                name = f"h_{i:03d}_{j}"
                routes.append(_route(
                    f"/p{i:03d}/x{j}", f"src/app.py::{name}@{i}{j}"))
                funcs.append(_func(name))
        groups, note = _route_family_groups(_models(routes), funcs)
        assert len(groups) == MAX_ROUTE_FAMILIES
        # Sorted family keys → the kept prefix set is deterministic.
        assert groups[0].group_id == "route_family:flask:decorator:p000"
        # Eviction is reported, never partial-silent.
        assert f"{n_fams} comparator-capable families" in note
        assert f"kept {MAX_ROUTE_FAMILIES}" in note

    def test_no_note_when_under_the_family_cap(self):
        routes = [
            _route("/api/a", "src/app.py::a@1"),
            _route("/api/b", "src/app.py::b@2"),
            _route("/api/c", "src/app.py::c@3"),
        ]
        funcs = [_func(n) for n in ("a", "b", "c")]
        _groups_out, note = _route_family_groups(
            _models(routes), funcs)
        assert note == ""

    def test_family_cap_note_reaches_resolver_notes(self):
        routes = []
        funcs = []
        for i in range(MAX_ROUTE_FAMILIES + 1):
            for j in (0, 1, 2):
                name = f"h_{i:03d}_{j}"
                routes.append(_route(
                    f"/p{i:03d}/x{j}", f"src/app.py::{name}@{i}{j}"))
                funcs.append(_func(name))
        notes: list[str] = []
        resolve_peer_groups(
            funcs, route_models=_models(routes), notes=notes)
        assert any(n.startswith("route-family: family cap")
                   for n in notes)

    def test_member_cap_truncates_with_note(self):
        routes = []
        funcs = []
        for i in range(MAX_ROUTE_FAMILY_MEMBERS + 8):
            name = f"h_{i:03d}"
            routes.append(_route(f"/api/x{i}", f"src/app.py::{name}@{i}"))
            funcs.append(_func(name))
        groups = _groups(routes, funcs)
        assert len(groups) == 1
        assert len(groups[0].siblings) == MAX_ROUTE_FAMILY_MEMBERS
        assert (f"capped at {MAX_ROUTE_FAMILY_MEMBERS} of "
                f"{MAX_ROUTE_FAMILY_MEMBERS + 8}") \
            in groups[0].shared_context

    def test_member_cap_preserves_property_minority(self):
        """Member names are attacker-chosen; deterministic first-N
        survivor selection would let a hostile repo name the
        undecorated deviant to sort past the cut. Minority-value
        members are retained first."""
        routes = []
        funcs = []
        for i in range(MAX_ROUTE_FAMILY_MEMBERS):
            # 32 decorated members whose names sort FIRST.
            name = f"aaa_{i:03d}"
            routes.append(_route(
                f"/api/x{i}", f"src/app.py::{name}@{i}",
                chain=("login_required",)))
            funcs.append(_func(name))
        # The undecorated deviant sorts LAST.
        routes.append(_route("/api/zzz",
                             "src/app.py::zzz_unprotected@999"))
        funcs.append(_func("zzz_unprotected"))
        groups = _groups(routes, funcs)
        assert len(groups) == 1
        kept = {s.function for s in groups[0].siblings}
        assert "zzz_unprotected" in kept
        assert len(kept) == MAX_ROUTE_FAMILY_MEMBERS
        props = {s.function: s.properties[ROUTE_AUTH_PROPERTY]
                 for s in groups[0].siblings}
        assert props["zzz_unprotected"] is False
        assert sum(1 for v in props.values() if v) \
            == MAX_ROUTE_FAMILY_MEMBERS - 1
        assert "minority-preserving" in groups[0].shared_context

    def test_hostile_pattern_text_escaped_everywhere(self):
        """Route patterns are attacker-authored bytes; ids,
        descriptions and contexts must carry the escaped form."""
        evil = "/\x1b[31mfake\x9b/x"
        routes = [
            _route(evil + "/a", "src/app.py::a@1"),
            _route(evil + "/b", "src/app.py::b@2"),
            _route(evil + "/c", "src/app.py::c@3"),
        ]
        funcs = [_func(n) for n in ("a", "b", "c")]
        groups = _groups(routes, funcs)
        assert len(groups) == 1
        rendered = (groups[0].group_id + groups[0].description
                    + groups[0].shared_context)
        assert "\x1b" not in rendered and "\x9b" not in rendered
        assert "\\x1b" in rendered

    def test_display_truncation_carries_elision_marker(self):
        long_seg = "a" * 400
        routes = [
            _route(f"/{long_seg}/x{i}", f"src/app.py::h{i}@{i}")
            for i in range(3)
        ]
        funcs = [_func(f"h{i}") for i in range(3)]
        groups = _groups(routes, funcs)
        assert len(groups) == 1
        assert "…[truncated]" in groups[0].description
        assert "…[truncated]" in groups[0].shared_context

    def test_no_routes_or_no_functions_empty(self):
        assert _groups([], [_func("a")]) == []
        assert _groups([_route("/a/b", "f.py::a@1")], []) == []


# ── resolver integration ─────────────────────────────────────────────


class TestResolverIntegration:
    def test_route_layer_claims_before_dispatch_site(self):
        """L10 is exclusive and first: handlers it claims never reach
        the (weaker) later exclusive layers."""
        routes = [
            _route("/api/a", "src/app.py::a@1"),
            _route("/api/b", "src/app.py::b@2"),
            _route("/api/c", "src/app.py::c@3"),
        ]
        funcs = [_func(n) for n in ("a", "b", "c")]
        table = FakeDispatchTable(
            handlers={"CMD_A": "a", "CMD_B": "b", "CMD_C": "c"})
        with_routes = resolve_peer_groups(
            funcs, route_models=_models(routes),
            dispatch_tables=[table],
        )
        assert [g.sibling_type for g in with_routes
                if g.sibling_type in (GROUP_TYPE_ROUTE_FAMILY,
                                      "dispatch_site")] \
            == [GROUP_TYPE_ROUTE_FAMILY]
        without = resolve_peer_groups(funcs, dispatch_tables=[table])
        assert [g.sibling_type for g in without] == ["dispatch_site"]

    def test_no_route_models_is_equivalent_to_before(self):
        funcs = [_func("get_a"), _func("get_b")]
        assert [g.to_dict() for g in resolve_peer_groups(funcs)] \
            == [g.to_dict() for g in resolve_peer_groups(
                funcs, route_models=None)]


# ── producer ─────────────────────────────────────────────────────────


class TestProducer:
    def test_loads_colocated_artifact_first(self, tmp_path):
        models = _models([
            _route("/api/a", "src/app.py::a@1"),
        ])
        models.save(tmp_path / "route-models.json")
        loaded = route_models_for_prep(out_dir=tmp_path)
        assert loaded is not None
        assert [r.route_pattern for r in loaded.all_routes()] == ["/api/a"]

    def test_builds_from_inventory_facts(self):
        inv = _inventory({"app.py": _POSITION_SRC})
        models = route_models_for_prep(inv)
        assert models is not None
        assert len(models.all_routes()) == 3

    def test_corrupt_artifact_falls_back_to_inventory(self, tmp_path):
        (tmp_path / "route-models.json").write_text("{not json", "utf-8")
        inv = _inventory({"app.py": _POSITION_SRC})
        models = route_models_for_prep(inv, out_dir=tmp_path)
        assert models is not None
        assert len(models.all_routes()) == 3

    def test_none_when_no_source_yields_routes(self, tmp_path):
        assert route_models_for_prep(out_dir=tmp_path) is None
        assert route_models_for_prep({"files": [{"path": "a.py"}]}) is None
        assert route_models_for_prep(None, 42, "x") is None

    def test_non_python_facts_never_trigger_a_build(self):
        """C records carry call_graph blocks too; only Python
        records populate registration facts, so a C-only inventory
        must short-circuit to None without a callgraph build."""
        assert route_models_for_prep({"files": [
            {"path": "a.c", "language": "c", "call_graph": {}},
        ]}) is None
