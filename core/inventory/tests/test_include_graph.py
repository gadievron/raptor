"""Layer-1 include-graph derivation: reverse index, two-component
census, roles-from-evidence, artifact discipline, consumer queries."""

from __future__ import annotations

import json
import re
from pathlib import Path

from core.inventory import include_graph
from core.inventory.include_graph import (
    ARTIFACT_NAME,
    REF_BASIS_VALUES,
    bootstrap_context_for_file,
    build_include_graph,
    census_qualifier,
    directly_requestable_library,
    executed_before,
    include_facts_for_file,
    load_include_graph,
    save_include_graph,
)


def _edge(line, keyword, shape, **kw):
    e = {"line": line, "keyword": keyword, "shape": shape,
         "conditional": False, "position": "file_scope",
         "span_hash": "0" * 12, "raw": kw.pop("raw", "")}
    e.update(kw)
    return e


def _php_file(path, includes=None, defines=None, guard=None):
    cg = {"imports": {}, "calls": [], "indirection": [],
          "includes": includes or [], "defines": defines or []}
    if guard is not None:
        cg["direct_access_guard"] = guard
    return {"path": path, "language": "php", "sha256": "x",
            "items": [], "call_graph": cg}


def _inventory_dict(files, excluded=(), target="/t"):
    return {
        "target_path": target,
        "parse_fingerprint": "fp-test",
        "files": files,
        "excluded_files": [{"path": p, "reason": "r"} for p in excluded],
    }


class TestDerivation:
    def _base_inventory_dict(self):
        return _inventory_dict([
            _php_file("entry_a.php", includes=[
                _edge(3, "require_once", "const_prefix",
                      const_name="APP_PATH", literal_tail="lib/shared.php",
                      raw="APP_PATH . 'lib/shared.php'"),
            ]),
            _php_file("entry_b.php", includes=[
                _edge(4, "include_once", "const_prefix",
                      const_name="APP_PATH", literal_tail="lib/shared.php",
                      conditional=True,
                      raw="APP_PATH . 'lib/shared.php'"),
            ]),
            _php_file("lib/shared.php",
                      guard={"line": 2, "constant": "IN_APP"}),
            _php_file("lib/orphan.php"),
        ])

    def test_reverse_index_and_roles(self):
        g = build_include_graph(self._base_inventory_dict())
        shared = g["files"]["lib/shared.php"]
        assert shared["role"] == "library"
        assert shared["includer_count"] == 2
        includers = {r["includer"] for r in shared["included_by"]}
        assert includers == {"entry_a.php", "entry_b.php"}
        for r in shared["included_by"]:
            assert r["basis"] == "tail_unique"
        assert g["files"]["entry_a.php"]["role"] == "designed_entry"
        assert g["files"]["lib/orphan.php"]["role"] == "designed_entry"

    def test_role_vocabulary_has_no_dual(self):
        # "dual" is a QUERY over includer-index + guard evidence,
        # never a stored label.
        g = build_include_graph(self._base_inventory_dict())
        assert {e["role"] for e in g["files"].values()} <= {
            "library", "designed_entry"}

    def test_dual_is_a_query(self):
        inv = self._base_inventory_dict()
        inv["files"].append(_php_file("lib/unguarded.php"))
        inv["files"][0]["call_graph"]["includes"].append(
            _edge(9, "require", "const_prefix", const_name="APP_PATH",
                  literal_tail="lib/unguarded.php"))
        g = build_include_graph(inv)
        assert directly_requestable_library(
            g["files"]["lib/unguarded.php"]) is True
        # guarded library: not directly requestable
        assert directly_requestable_library(
            g["files"]["lib/shared.php"]) is False
        # designed entry: role query is about libraries only
        assert directly_requestable_library(
            g["files"]["entry_a.php"]) is False

    def test_guard_evidence_carried(self):
        g = build_include_graph(self._base_inventory_dict())
        shared = g["files"]["lib/shared.php"]
        assert shared["direct_access_guard"] is True
        assert shared["direct_access_guard_line"] == 2
        assert shared["direct_access_guard_constant"] == "IN_APP"

    def test_ambiguous_tail_refuses_into_census(self):
        inv = _inventory_dict([
            _php_file("entry.php", includes=[
                _edge(3, "require", "const_prefix",
                      const_name="APP_PATH", literal_tail="dup.php"),
            ]),
            _php_file("a/dup.php"),
            _php_file("b/dup.php"),
        ])
        g = build_include_graph(inv)
        assert g["files"]["a/dup.php"]["role"] == "designed_entry"
        assert g["files"]["b/dup.php"]["role"] == "designed_entry"
        [rec] = g["unresolved_edges"]
        assert rec["reason"] == "tail_ambiguous"
        assert sorted(rec["candidates"]) == ["a/dup.php", "b/dup.php"]
        assert g["census"]["unresolved_edge_count"] == 1

    def test_literal_edges_resolve_via_anchored_target(self):
        inv = _inventory_dict([
            _php_file("src/entry.php", includes=[
                _edge(2, "include", "literal", literal_tail="other.php",
                      target="src/other.php"),
            ]),
            _php_file("src/other.php"),
        ])
        g = build_include_graph(inv)
        assert g["files"]["src/other.php"]["includer_count"] == 1
        assert (g["files"]["src/other.php"]["included_by"][0]["basis"]
                == "relative_literal")

    def test_missing_literal_target_joins_census(self):
        inv = _inventory_dict([
            _php_file("entry.php", includes=[
                _edge(2, "include", "literal", literal_tail="gone.php",
                      target="gone.php"),
            ]),
        ])
        g = build_include_graph(inv)
        [rec] = g["unresolved_edges"]
        assert rec["reason"] == "target_missing"

    def test_resolution_profile_counts(self):
        g = build_include_graph(self._base_inventory_dict())
        fs = g["resolution_profile"]["file_scope"]
        assert fs["const_prefix"] == 2
        assert fs["total"] == 2
        assert g["resolution_profile"]["outcomes"][
            "resolved_tail_unique"] == 2

    def test_artifact_stamps(self):
        g = build_include_graph(self._base_inventory_dict())
        assert g["tier"] == "hint"
        assert g["producer"]["module"] == (
            "core.inventory.include_graph")
        assert g["producer"]["parse_fingerprint"] == "fp-test"
        assert g["producer"]["version"] == 1
        assert "note" in g


class TestTwoComponentCensus:
    def _dispatcher_inventory_dict(self, tmp_path: Path):
        """A dynamic dispatcher whose candidates land on foreign-
        extension files the walker cannot parse — the census's
        second component."""
        target = tmp_path / "tree"
        (target / "modules").mkdir(parents=True)
        (target / "entry.php").write_text("<?php\n")
        (target / "modules" / "one.mod").write_text("plain text\n")
        (target / "modules" / "two.mod").write_text("plain text\n")
        inv = _inventory_dict([
            _php_file("entry.php", includes=[
                _edge(5, "require_once", "dynamic",
                      literal_stem="modules/", literal_tail=".mod",
                      raw='APP_PATH . $dir . "modules/$page.mod"'),
            ]),
        ], target=str(target))
        return inv, target

    def test_mod_shaped_unwalked_target_renders(self, tmp_path):
        inv, target = self._dispatcher_inventory_dict(tmp_path)
        g = build_include_graph(inv, target_root=target)
        paths = {t["path"]: t for t in g["unwalked_targets"]}
        assert "modules/one.mod" in paths
        assert "modules/two.mod" in paths
        entry = paths["modules/one.mod"]
        assert entry["reason"] == "not_in_language_map"
        assert entry["via"] == [{"file": "entry.php", "line": 5}]
        assert g["census"]["unwalked_target_count"] == 2
        assert g["census"]["unresolved_edge_count"] == 1
        [rec] = g["unresolved_edges"]
        assert rec["reason"] == "dynamic"
        assert sorted(rec["candidates"]) == [
            "modules/one.mod", "modules/two.mod"]

    def test_without_target_root_census_narrows_honestly(self, tmp_path):
        inv, _target = self._dispatcher_inventory_dict(tmp_path)
        g = build_include_graph(inv)  # inventory-only universe
        assert g["census"]["unwalked_target_count"] == 0
        assert g["census"]["unresolved_edge_count"] == 1

    def test_uninformative_tail_overflows_to_nothing(self, tmp_path):
        target = tmp_path / "tree"
        target.mkdir()
        for i in range(40):
            (target / f"f{i}.php").write_text("<?php\n")
        inv = _inventory_dict([
            _php_file("f0.php", includes=[
                _edge(2, "include", "dynamic", literal_tail=".php",
                      raw='"$page.php"'),
            ]),
        ], target=str(target))
        g = build_include_graph(inv, target_root=target)
        [rec] = g["unresolved_edges"]
        assert rec.get("candidates_overflow") is True
        assert "candidates" not in rec
        assert g["census"]["unwalked_target_count"] == 0

    def test_excluded_target_reason(self, tmp_path):
        target = tmp_path / "tree"
        (target / "skipped").mkdir(parents=True)
        (target / "entry.php").write_text("<?php\n")
        (target / "skipped" / "inner.php").write_text("<?php\n")
        inv = _inventory_dict([
            _php_file("entry.php", includes=[
                _edge(2, "require", "const_prefix",
                      const_name="APP_PATH",
                      literal_tail="skipped/inner.php"),
            ]),
        ], excluded=["skipped/"], target=str(target))
        g = build_include_graph(inv, target_root=target)
        [t] = g["unwalked_targets"]
        assert t["path"] == "skipped/inner.php"
        assert t["reason"] == "excluded"
        # the edge still resolved (reverse index widens attention)
        assert g["files"]["skipped/inner.php"]["includer_count"] == 1
        assert g["files"]["skipped/inner.php"]["unwalked"] is True


class TestArtifactIO:
    def test_save_load_roundtrip_with_lock(self, tmp_path):
        g = build_include_graph(_inventory_dict([_php_file("a.php")]))
        save_include_graph(tmp_path, g)
        assert (tmp_path / ARTIFACT_NAME).is_file()
        # checklist.lock discipline: the lock file is the checklist's
        assert (tmp_path / "checklist.lock").exists()
        loaded = load_include_graph(tmp_path)
        assert loaded == json.loads(
            (tmp_path / ARTIFACT_NAME).read_text())

    def test_load_missing_is_none(self, tmp_path):
        assert load_include_graph(tmp_path) is None

    def test_load_malformed_is_none(self, tmp_path):
        (tmp_path / ARTIFACT_NAME).write_text("[1, 2]")
        assert load_include_graph(tmp_path) is None
        (tmp_path / ARTIFACT_NAME).write_text("{not json")
        assert load_include_graph(tmp_path) is None


class TestTailAlignment:
    """Component alignment is the const_prefix lane's licence: an
    extension-fragment tail cannot align, so it never resolves."""

    def test_dot_tail_never_resolves_const_prefix(self):
        # unique bare-suffix match exists — and is exactly the wrong
        # thing to trust: '.conf.php' would "uniquely" hit a file
        # that merely ENDS with those bytes.
        inv = _inventory_dict([
            _php_file("entry.php", includes=[
                _edge(3, "require", "const_prefix", const_name="C",
                      literal_tail=".conf.php"),
            ]),
            _php_file("apps/main.conf.php"),
        ])
        g = build_include_graph(inv)
        assert g["files"]["apps/main.conf.php"]["includer_count"] == 0
        [rec] = g["unresolved_edges"]
        assert rec["reason"] == "tail_unaligned"
        assert g["resolution_profile"]["outcomes"][
            "unresolved_tail_unaligned"] == 1

    def test_aligned_tail_still_resolves(self):
        inv = _inventory_dict([
            _php_file("entry.php", includes=[
                _edge(3, "require", "const_prefix", const_name="C",
                      literal_tail="inc/boot.php"),
            ]),
            _php_file("inc/boot.php"),
        ])
        g = build_include_graph(inv)
        assert g["files"]["inc/boot.php"]["includer_count"] == 1


class TestTruncationCensus:
    """Edge-capped extraction joins the census (third component):
    a file whose edges were capped may be missing includer
    contributions entirely, and the qualifier must say so."""

    def _flood_inventory_dict(self, truncated: bool):
        cg_edges = [_edge(1, "include", "literal",
                          literal_tail="pad.php", target="pad.php")]
        f = _php_file("flood.php", includes=cg_edges)
        if truncated:
            f["call_graph"]["includes_truncated"] = True
        return _inventory_dict([f, _php_file("pad.php"),
                           _php_file("deep.php")])

    def test_truncated_file_joins_census_and_qualifier(self):
        g = build_include_graph(self._flood_inventory_dict(True))
        assert g["census"]["truncated_file_count"] == 1
        assert g["truncated_files"] == [
            {"path": "flood.php", "recorded_edges": 1}]
        q = census_qualifier(g)
        assert "truncated in 1 file(s)" in q
        facts = include_facts_for_file(g, "deep.php")
        assert facts["census"]["truncated_files"] == 1
        assert "truncated in 1 file(s)" in facts["qualifier"]

    def test_normal_tree_census_byte_identical(self):
        # The mechanism must not alter censuses on non-flood trees.
        g = build_include_graph(self._flood_inventory_dict(False))
        assert g["census"] == {"unresolved_edge_count": 0,
                               "unwalked_target_count": 0}
        assert "truncated_files" not in g
        q = census_qualifier(g)
        assert "truncated" not in q
        facts = include_facts_for_file(g, "deep.php")
        assert "truncated_files" not in facts["census"]


class TestDerivationCostBounds:
    """A flooded checklist must not grind the derivation: the
    const_prefix lane proves uniqueness with a two-match cap, and
    extension-fragment tails draw a run-level tree-scan budget."""

    def test_flooded_const_edges_stay_fast_and_nonvacuous(self):
        import time
        files = [
            _php_file(f"d{i % 100}/f{i}.php") for i in range(20000)
        ]
        # flooder: 4096 const edges with a heavily shared basename
        # (worst bucket) + 4096 extension-fragment edges (worst
        # scan route).
        flood_edges = [
            _edge(k, "include", "const_prefix", const_name="C",
                  literal_tail="f0.php")
            for k in range(4096)
        ] + [
            _edge(k, "include", "dynamic", literal_tail=".php")
            for k in range(4096)
        ]
        files.append(_php_file("flood.php", includes=flood_edges))
        # non-vacuity: one normal edge must still resolve
        files.append(_php_file("entry.php", includes=[
            _edge(1, "require", "const_prefix", const_name="C",
                  literal_tail="lib/only.php")]))
        files.append(_php_file("lib/only.php"))
        inv = _inventory_dict(files)
        t0 = time.monotonic()
        g = build_include_graph(inv)
        elapsed = time.monotonic() - t0
        # Pre-cap this took tens of seconds; generous CI bound.
        assert elapsed < 5.0
        assert g["files"]["lib/only.php"]["includer_count"] == 1

    def test_shared_basename_bucket_probes_bounded(self):
        # The match cap counts MATCHES; a never-matching needle
        # against a shared-basename bucket walked the whole bucket
        # per edge (tens of seconds at 100k x 4096). Probe budget
        # bounds iterations run-wide.
        import time
        files = [_php_file(f"d{i}/x.php") for i in range(20000)]
        files.append(_php_file("flood.php", includes=[
            _edge(k, "include", "const_prefix", const_name="C",
                  literal_tail="zz/x.php")
            for k in range(4096)
        ]))
        # non-vacuity: a normal edge resolves despite the flood
        files.append(_php_file("aaa.php", includes=[
            _edge(1, "require", "const_prefix", const_name="C",
                  literal_tail="lib/only.php")]))
        files.append(_php_file("lib/only.php"))
        inv = _inventory_dict(files)
        t0 = time.monotonic()
        g = build_include_graph(inv)
        elapsed = time.monotonic() - t0
        assert elapsed < 5.0
        assert g["files"]["lib/only.php"]["includer_count"] == 1
        # post-exhaustion edges refuse with the honest overflow shape
        assert any(r.get("candidates_overflow")
                   for r in g["unresolved_edges"])

    def test_scan_budget_overflow_records_marker(self):
        from core.inventory.include_graph import (
            MAX_TREE_SCAN_EDGES_PER_RUN,
        )
        files = [_php_file(f"m{i}.php") for i in range(10)]
        edges = [
            _edge(k, "include", "dynamic", literal_tail=".mod")
            for k in range(MAX_TREE_SCAN_EDGES_PER_RUN + 5)
        ]
        files.append(_php_file("dispatch.php", includes=edges))
        g = build_include_graph(_inventory_dict(files))
        overflowed = [r for r in g["unresolved_edges"]
                      if r.get("candidates_overflow")]
        assert len(overflowed) == 5  # past-budget edges refuse loudly


class TestWalkIntegration:
    """The environment walk riding the graph derivation: artifact
    section, basis supersede, and the 1b consumer queries."""

    def _inventory_dict(self):
        def cg(includes=(), defines=(), boundaries=(),
               parse_errors=False):
            d = {"imports": {}, "calls": [], "indirection": [],
                 "includes": list(includes), "defines": list(defines)}
            if boundaries:
                d["boundaries"] = list(boundaries)
            if parse_errors:
                d["parse_errors"] = True
            return d

        files = [
            {"path": "src/e1.php", "language": "php", "sha256": "x",
             "items": [], "call_graph": cg(
                 includes=[_edge(3, "require_once", "const_prefix",
                                 const_name="APP",
                                 literal_tail="inc/gate.php")],
                 defines=[{"line": 2, "name": "APP", "value": "../",
                           "conditional": False, "fallback": False,
                           "position": "file_scope"}])},
            {"path": "src/e2.php", "language": "php", "sha256": "x",
             "items": [], "call_graph": cg(
                 includes=[_edge(3, "require_once", "const_prefix",
                                 const_name="APP",
                                 literal_tail="inc/gate.php")],
                 defines=[{"line": 2, "name": "APP", "value": "../",
                           "conditional": False, "fallback": False,
                           "position": "file_scope"}])},
            # gate has NO define (inherits) + an edge whose tail is
            # AMBIGUOUS for the 1a suffix rule (two dup.php) but
            # exact under the environment.
            {"path": "inc/gate.php", "language": "php", "sha256": "x",
             "items": [], "call_graph": cg(
                 includes=[
                     _edge(2, "require", "const_prefix",
                           const_name="APP",
                           literal_tail="lib/shared.php"),
                     _edge(4, "require", "const_prefix",
                           const_name="APP", literal_tail="dup.php"),
                     _edge(6, "require", "const_prefix",
                           const_name="APP",
                           literal_tail="conf/.env.php"),
                 ],
                 boundaries=[{"line": 8,
                              "kind": "conditional_return"}])},
            {"path": "lib/shared.php", "language": "php",
             "sha256": "x", "items": [], "call_graph": cg()},
            {"path": "dup.php", "language": "php", "sha256": "x",
             "items": [], "call_graph": cg()},
            {"path": "a/dup.php", "language": "php", "sha256": "x",
             "items": [], "call_graph": cg()},
            {"path": "conf/.env.php", "language": "php",
             "sha256": "x", "items": [], "call_graph": cg()},
        ]
        return _inventory_dict(files)

    def test_walk_section_and_classes(self):
        g = build_include_graph(self._inventory_dict())
        w = g["walk"]
        # Pass-1 candidates include the ambiguity-orphaned files; the
        # env supersede flips them to library afterwards, so only the
        # real entries keep classes.
        assert w["entries_walked"] == 5
        [cls] = [c for c in w["entry_classes"]
                 if c["entry_count"] == 2]
        assert set(cls["guaranteed_prefix"]) >= {
            "inc/gate.php", "lib/shared.php", "dup.php",
            "conf/.env.php"}
        p = w["prefixes"]["src/e1.php"]
        assert p["class"] == cls["class"]
        members = {m["file"]: m for m in p["members"]}
        assert members["lib/shared.php"]["guaranteed"] is True
        # a file the supersede flipped to library is unclassed
        assert w["prefixes"]["dup.php"]["class"] is None
        assert g["files"]["dup.php"]["role"] == "library"

    def test_env_supersedes_ambiguous_tail(self):
        # 1a refused dup.php (two suffix candidates); the walk
        # grounds it — the ref joins with basis env_resolved and the
        # 1a census discharges that edge.
        g = build_include_graph(self._inventory_dict())
        refs = g["files"]["dup.php"]["included_by"]
        assert refs and all(r["basis"] == "env_resolved" for r in refs)
        assert g["files"]["dup.php"]["role"] == "library"
        assert not any(
            u.get("file") == "inc/gate.php" and u.get("line") == 4
            for u in g["unresolved_edges"])
        assert g["resolution_profile"]["outcomes"][
            "env_resolved_from_census"] >= 1
        assert g["resolution_profile"]["outcomes"][
            "env_census_discharged"] >= 1

    def test_env_resolves_dotfile_exactly(self):
        # Prerequisite (iv): the walk closes the dotfile residue the
        # 1a alignment rule refused.
        g = build_include_graph(self._inventory_dict())
        refs = g["files"]["conf/.env.php"]["included_by"]
        assert [r["basis"] for r in refs] == ["env_resolved"]

    def test_env_confirms_unique_tail_basis(self):
        g = build_include_graph(self._inventory_dict())
        [ref] = g["files"]["lib/shared.php"]["included_by"]
        assert ref["basis"] == "env_resolved"  # upgraded from tail_unique
        assert g["resolution_profile"]["outcomes"][
            "env_confirmed_tail_basis"] >= 1

    def test_executed_before_queries(self):
        g = build_include_graph(self._inventory_dict())
        assert executed_before(g, "src/e1.php", "lib/shared.php") is True
        assert executed_before(g, "src/e1.php", "nope.php") is False
        assert executed_before(g, "nope.php", "lib/shared.php") is None
        # line-aware: gate.php's own boundary at line 8
        assert executed_before(
            g, "src/e1.php", "inc/gate.php", line=5) is True
        assert executed_before(
            g, "src/e1.php", "inc/gate.php", line=9) is False

    def test_bootstrap_context_shape(self):
        g = build_include_graph(self._inventory_dict())
        ctx = bootstrap_context_for_file(g, "lib/shared.php")
        assert ctx["tier"] == "hint"
        [cls] = ctx["entry_classes"]
        assert cls["guaranteed"] is True
        assert cls["entry_count"] == 2
        assert "src/e1.php" in cls["receipt"]
        # ORDER-AWARE: dup.php is included at gate.php:4, AFTER
        # lib/shared.php (gate.php:2) — it must NOT render as having
        # run first. Only the gate file itself precedes.
        assert {r["file"] for r in ctx["guaranteed_prefix"]} == {
            "inc/gate.php"}
        # the MANDATORY census
        assert "unresolved_edges" in ctx["unresolved_census"]
        assert "unwalked_targets" in ctx["unresolved_census"]
        assert "qualifier" in ctx
        assert ctx["invariants"] == []

    def test_bootstrap_context_refuses_without_valid_census(self):
        g = build_include_graph(self._inventory_dict())
        g["census"] = {"unresolved_edge_count": "forged"}
        assert bootstrap_context_for_file(g, "lib/shared.php") is None

    def test_shared_prefix_intersects_ALL_classes_not_rendered_cap(self):
        # The guaranteed-prefix intersection must run over every
        # guaranteed-reaching class — intersecting only the rendered
        # (capped) subset would overclaim "on every stock path".
        g = build_include_graph(self._inventory_dict())
        walk = g["walk"]
        # synthesize 7 guaranteed-reaching classes; only the first
        # shares nothing beyond "common.php"
        walk["file_facts"]["lib/shared.php"] = {"classes": [
            {"class": f"ec{i:08d}", "guaranteed": True,
             "entries_reaching": 1, "receipt": f"e{i}.php -> x",
             "preceding": (["common.php", "extra.php"]
                           if i < 6 else ["common.php"])}
            for i in range(7)
        ]}
        walk["entry_classes"] = [
            {"class": f"ec{i:08d}", "entry_count": 1,
             "entries": [f"e{i}.php"],
             "guaranteed_prefix": ["common.php", "extra.php",
                                   "lib/shared.php"]}
            for i in range(7)
        ]
        ctx = bootstrap_context_for_file(g, "lib/shared.php",
                                         max_classes=5)
        assert ctx["entry_class_total"] == 7
        assert len(ctx["entry_classes"]) == 5  # rendering capped
        # extra.php is NOT shared by class 6 — must not be claimed
        assert [r["file"] for r in ctx["guaranteed_prefix"]] == [
            "common.php"]

    def test_executed_before_unknown_for_parse_errored_member(self):
        inv = self._inventory_dict()
        for f in inv["files"]:
            if f["path"] == "lib/shared.php":
                f["call_graph"]["parse_errors"] = True
        g = build_include_graph(inv)
        # membership guarantee would be True, but the member's own
        # line structure is not trustworthy — unknown, never a guess
        assert executed_before(
            g, "src/e1.php", "lib/shared.php") is None

    def test_backslash_disagreement_never_evicts_1a_ref(self):
        # On POSIX the literally-backslash-named file is what runs;
        # a separator-interpretation disagreement between the lanes
        # keeps the 1a base and censuses the disagreement.
        inv = _inventory_dict([
            {"path": "e.php", "language": "php", "sha256": "x",
             "items": [], "call_graph": {
                 "imports": {}, "calls": [], "indirection": [],
                 "includes": [_edge(3, "include", "const_prefix",
                                    const_name="SM",
                                    literal_tail="x\\gate.php")],
                 "defines": [{"line": 2, "name": "SM",
                              "value": "lib/", "conditional": False,
                              "fallback": False,
                              "position": "file_scope"}]}},
            {"path": "lib/x\\gate.php", "language": "php",
             "sha256": "x", "items": [],
             "call_graph": {"imports": {}, "calls": [],
                            "indirection": [], "includes": [],
                            "defines": []}},
            {"path": "lib/x/gate.php", "language": "php",
             "sha256": "x", "items": [],
             "call_graph": {"imports": {}, "calls": [],
                            "indirection": [], "includes": [],
                            "defines": []}},
        ])
        g = build_include_graph(inv)
        # env resolves the literal backslash file (no rewriting)
        refs = g["files"]["lib/x\\gate.php"]["included_by"]
        assert any(r["basis"] == "env_resolved" for r in refs)
        # and no eviction of any surviving 1a base ever plants the
        # forward-slash decoy
        assert g["files"]["lib/x/gate.php"]["includer_count"] == 0

    def test_bootstrap_context_census_carries_walk_truncation(self):
        g = build_include_graph(self._inventory_dict())
        w = g["walk"]
        w["budget_exhausted"] = True
        w["outcomes"]["entries_unclassed_truncated"] = 2
        ctx = bootstrap_context_for_file(g, "lib/shared.php")
        assert ctx["unresolved_census"]["walk_truncated_entries"] == 2
        assert ctx["unresolved_census"]["walk_budget_exhausted"] is True
        assert "TRUNCATED for 2 entries" in ctx["qualifier"]

    def _starved_inventory_dict(self, entry_count=6):
        # Many entries, one shared library — with a tiny statement
        # budget only the first entry's walk completes.
        def entry(path):
            return {
                "path": path, "language": "php", "sha256": "x",
                "items": [], "call_graph": {
                    "imports": {}, "calls": [], "indirection": [],
                    "includes": [_edge(3, "require_once",
                                       "const_prefix",
                                       const_name="APP",
                                       literal_tail="lib/shared.php")],
                    "defines": [{"line": 2, "name": "APP",
                                 "value": "./", "conditional": False,
                                 "fallback": False,
                                 "position": "file_scope"}]}}
        files = [entry(f"e{i}.php") for i in range(1, entry_count + 1)]
        files.append({"path": "lib/shared.php", "language": "php",
                      "sha256": "x", "items": [],
                      "call_graph": {"imports": {}, "calls": [],
                                     "indirection": [], "includes": [],
                                     "defines": []}})
        return _inventory_dict(files)

    def test_budget_exhaustion_reaches_bootstrap_via_render(
            self, monkeypatch):
        # THE RENDER PATH: budget_exhausted must survive the fold
        # into the artifact's walk section — bootstrap reads the
        # rendered section, so a hand-injected flag would not prove
        # the plumbing.
        import core.inventory.include_walk as iw
        monkeypatch.setattr(iw, "MAX_WALK_STMT_VISITS", 3)
        g = build_include_graph(self._starved_inventory_dict())
        assert g["walk"]["budget_exhausted"] is True
        ctx = bootstrap_context_for_file(g, "lib/shared.php")
        assert ctx["unresolved_census"]["walk_budget_exhausted"] is True
        assert ctx["unresolved_census"]["walk_truncated_entries"] == 5
        assert "TRUNCATED for 5 entries" in ctx["qualifier"]
        assert "(global walk budget exhausted)" in ctx["qualifier"]

    def test_unstarved_walk_carries_no_budget_flag(self):
        g = build_include_graph(self._starved_inventory_dict())
        assert g["walk"]["budget_exhausted"] is False
        ctx = bootstrap_context_for_file(g, "lib/shared.php")
        assert "walk_budget_exhausted" not in ctx["unresolved_census"]
        assert "TRUNCATED" not in ctx["qualifier"]

    def _gated_inventory_dict(self):
        # The gate-first idiom: e1 includes zz_gate FIRST, then the
        # a01..a04 helpers, then the target. Alphabetically the gate
        # sorts LAST — a capped alphabetical slice hides exactly it.
        def cg(includes=(), defines=()):
            return {"imports": {}, "calls": [], "indirection": [],
                    "includes": list(includes),
                    "defines": list(defines)}
        define = {"line": 2, "name": "APP", "value": "./",
                  "conditional": False, "fallback": False,
                  "position": "file_scope"}
        e1_includes = [
            _edge(3 + i, "require_once", "const_prefix",
                  const_name="APP", literal_tail=t)
            for i, t in enumerate(["zz_gate.php", "a01.php",
                                   "a02.php", "a03.php", "a04.php",
                                   "target.php"])]
        files = [
            {"path": "e1.php", "language": "php", "sha256": "x",
             "items": [],
             "call_graph": cg(e1_includes, [define])},
        ]
        for p in ("a01.php", "a02.php", "a03.php", "a04.php",
                  "zz_gate.php", "target.php"):
            files.append({"path": p, "language": "php", "sha256": "x",
                          "items": [], "call_graph": cg()})
        return _inventory_dict(files)

    def test_prefix_cap_renders_execution_order_total_and_marker(self):
        # An alphabetical slice would render a01..a03 and cut off
        # exactly the gate; witness-entry execution pre-order
        # surfaces it first, and the elision is explicit (true
        # total + marker).
        g = build_include_graph(self._gated_inventory_dict())
        ctx = bootstrap_context_for_file(g, "target.php",
                                         max_prefix=3)
        assert [r["file"] for r in ctx["guaranteed_prefix"]] == [
            "zz_gate.php", "a01.php", "a02.php"]
        assert ctx["guaranteed_prefix_total"] == 5
        assert ctx["guaranteed_prefix_truncated"] is True

    def test_prefix_under_cap_has_total_and_no_marker(self):
        g = build_include_graph(self._gated_inventory_dict())
        ctx = bootstrap_context_for_file(g, "target.php")
        assert ctx["guaranteed_prefix_total"] == 5
        assert len(ctx["guaranteed_prefix"]) == 5
        assert "guaranteed_prefix_truncated" not in ctx

    def test_bootstrap_context_none_for_unknown_file(self):
        g = build_include_graph(self._inventory_dict())
        assert bootstrap_context_for_file(g, "unknown.php") is None

    def test_entry_file_gets_own_class_with_note(self):
        g = build_include_graph(self._inventory_dict())
        ctx = bootstrap_context_for_file(g, "src/e1.php")
        assert ctx["entry_classes"][0]["guaranteed"] is True
        assert "is itself an entry" in ctx["entry_classes"][0]["receipt"]
        assert "verify include order" in ctx["note"]


class TestConsumerQueries:
    def _graph(self):
        inv = _inventory_dict([
            _php_file("entry.php", includes=[
                _edge(3, "require_once", "const_prefix",
                      const_name="APP_PATH", literal_tail="lib/x.php"),
                _edge(9, "include", "dynamic", raw="$page"),
            ]),
            _php_file("lib/x.php"),
        ])
        return build_include_graph(inv)

    def test_facts_carry_census_and_qualifier(self):
        facts = include_facts_for_file(self._graph(), "lib/x.php")
        assert facts["tier"] == "hint"
        assert facts["role"] == "library"
        assert facts["includer_total"] == 1
        [inc] = facts["includers"]
        assert inc["file"] == "entry.php"
        assert inc["line"] == 3
        assert inc["keyword"] == "require_once"
        # mandatory two-component census
        assert facts["census"]["unresolved_edges"] == 1
        assert facts["census"]["unwalked_targets"] == 0
        assert "1 unresolved include site(s)" in facts["qualifier"]
        assert "0 unwalked include target(s)" in facts["qualifier"]

    def test_census_present_even_without_includers(self):
        facts = include_facts_for_file(self._graph(), "entry.php")
        assert facts["role"] == "designed_entry"
        assert facts["includers"] == []
        assert "census" in facts and "qualifier" in facts

    def test_unknown_file_is_none(self):
        assert include_facts_for_file(self._graph(), "nope.php") is None
        assert include_facts_for_file({"files": "junk"}, "x") is None

    def test_invalid_census_renders_unknown_never_zero(self):
        # A failed census must never coerce to "modulo 0 and 0" —
        # zeros are a positive completeness claim.
        for census in (
            {"unresolved_edge_count": "many",
             "unwalked_target_count": True},
            {"unresolved_edge_count": -1, "unwalked_target_count": 0},
            None,
        ):
            g = dict(self._graph())
            if census is None:
                g.pop("census", None)
            else:
                g["census"] = census
            q = census_qualifier(g)
            assert "unknown" in q
            assert "0 unresolved include site(s)" not in q
            facts = include_facts_for_file(g, "lib/x.php")
            assert facts["census"] == {"valid": False}
            assert "unknown" in facts["qualifier"]

    def test_tampered_enums_and_bounds_sanitised(self):
        g = self._graph()
        ref = g["files"]["lib/x.php"]["included_by"][0]
        ref.update(keyword="`;rm -rf`", position="verdict:disproven",
                   basis="## forged", line=-5, includer="Z" * 100000)
        g["files"]["lib/x.php"]["role"] = "EXPLOITABLE_SKIP_REVIEW"
        facts = include_facts_for_file(g, "lib/x.php")
        [inc] = facts["includers"]
        assert inc["keyword"] == "include"
        assert inc["position"] == "file_scope"
        assert inc["basis"] == ""
        assert inc["line"] == 0
        assert len(inc["file"]) == 512
        assert facts["role"] == "unknown"

    def test_dotslash_prefix_normalised(self):
        facts = include_facts_for_file(self._graph(), "./lib/x.php")
        assert facts is not None


class TestBasisVocabulary:
    """Producer↔consumer basis-vocabulary contract.

    The build writes ``basis`` at literal write sites; the one query
    every consumer goes through (:func:`include_facts_for_file`)
    re-validates against ``REF_BASIS_VALUES``. Together these pins
    make a NEW producer basis fail HERE instead of silently rendering
    ``""`` (indistinguishable from a forged value) in every consumer:
    the write-site census forces the new value into the declared
    vocabulary, and the render pin proves declared values survive the
    consumer query verbatim.
    """

    _WRITE_SITE_PATTERNS = (
        # _resolve_to(target, "<basis>", includer, edge)
        re.compile(r"_resolve_to\(\s*[^,]+,\s*\"([^\"]+)\""),
        # ref["basis"] = "<basis>"  /  {"basis": "<basis>"}
        re.compile(r"[\"']basis[\"']\s*\]?\s*[:=]\s*[\"']([^\"']+)[\"']"),
    )

    @classmethod
    def _written_bases(cls, source: str) -> set[str]:
        found: set[str] = set()
        for pat in cls._WRITE_SITE_PATTERNS:
            found.update(pat.findall(source))
        return found

    def test_write_sites_match_declared_vocabulary(self):
        # Set-EQUALITY, both directions: a write site whose basis is
        # missing from the declared vocabulary would render "" through
        # every consumer; a declared value nothing writes is a stale
        # allowlist entry.
        source = Path(include_graph.__file__).read_text()
        assert self._written_bases(source) == set(REF_BASIS_VALUES)

    def test_write_site_census_sees_new_bases(self):
        # Tripwire direction: a hypothetical fourth producer basis, in
        # each write shape the module uses, is visible to the census —
        # so a new write site cannot hide from the set-equality pin.
        double = (
            "_resolve_to(target, \"walk_guessed\", path, e)\n"
            "old[1][\"basis\"] = \"sibling_probe\"\n"
            "ref = {\"basis\": \"manifest_pinned\"}\n"
        )
        assert self._written_bases(double) == {
            "walk_guessed", "sibling_probe", "manifest_pinned"}

    def test_every_declared_basis_renders_verbatim(self):
        # Producer ⊆ consumer, behaviourally: each declared basis
        # survives the consumer query; anything outside still blanks.
        for basis in (*REF_BASIS_VALUES, "forged_basis"):
            graph = {
                "census": {"unresolved_edge_count": 0,
                           "unwalked_target_count": 0},
                "files": {"lib/x.php": {
                    "role": "library", "includer_count": 1,
                    "included_by": [{
                        "includer": "entry.php", "line": 3,
                        "keyword": "require_once", "conditional": False,
                        "position": "file_scope", "basis": basis}],
                }},
                "unresolved_edges": [], "unwalked_targets": [],
            }
            facts = include_facts_for_file(graph, "lib/x.php")
            [inc] = facts["includers"]
            expected = basis if basis in REF_BASIS_VALUES else ""
            assert inc["basis"] == expected

    def test_env_resolved_basis_renders_end_to_end(self):
        # Walk-grounded resolution through the REAL producer: a
        # const-prefix edge whose tail is ambiguous for the 1a suffix
        # rule (two dup.php) resolves via the environment walk; the
        # strongest basis must reach consumers intact, not blank.
        inv = _inventory_dict([
            _php_file("src/e1.php", includes=[
                _edge(3, "require", "const_prefix",
                      const_name="APP", literal_tail="dup.php"),
            ], defines=[{"line": 2, "name": "APP", "value": "../",
                         "conditional": False, "fallback": False,
                         "position": "file_scope"}]),
            _php_file("dup.php"),
            _php_file("a/dup.php"),
        ])
        g = build_include_graph(inv)
        refs = g["files"]["dup.php"]["included_by"]
        assert [r["basis"] for r in refs] == ["env_resolved"]
        facts = include_facts_for_file(g, "dup.php")
        [inc] = facts["includers"]
        assert inc["basis"] == "env_resolved"
