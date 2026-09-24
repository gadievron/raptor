"""Layer-1 include-graph derivation: reverse index, two-component
census, roles-from-evidence, artifact discipline, consumer queries."""

from __future__ import annotations

import json
from pathlib import Path


from core.inventory.include_graph import (
    ARTIFACT_NAME,
    build_include_graph,
    census_qualifier,
    directly_requestable_library,
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


def _inventory(files, excluded=(), target="/t"):
    return {
        "target_path": target,
        "parse_fingerprint": "fp-test",
        "files": files,
        "excluded_files": [{"path": p, "reason": "r"} for p in excluded],
    }


class TestDerivation:
    def _base_inventory(self):
        return _inventory([
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
        g = build_include_graph(self._base_inventory())
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
        g = build_include_graph(self._base_inventory())
        assert {e["role"] for e in g["files"].values()} <= {
            "library", "designed_entry"}

    def test_dual_is_a_query(self):
        inv = self._base_inventory()
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
        g = build_include_graph(self._base_inventory())
        shared = g["files"]["lib/shared.php"]
        assert shared["direct_access_guard"] is True
        assert shared["direct_access_guard_line"] == 2
        assert shared["direct_access_guard_constant"] == "IN_APP"

    def test_ambiguous_tail_refuses_into_census(self):
        inv = _inventory([
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
        inv = _inventory([
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
        inv = _inventory([
            _php_file("entry.php", includes=[
                _edge(2, "include", "literal", literal_tail="gone.php",
                      target="gone.php"),
            ]),
        ])
        g = build_include_graph(inv)
        [rec] = g["unresolved_edges"]
        assert rec["reason"] == "target_missing"

    def test_resolution_profile_counts(self):
        g = build_include_graph(self._base_inventory())
        fs = g["resolution_profile"]["file_scope"]
        assert fs["const_prefix"] == 2
        assert fs["total"] == 2
        assert g["resolution_profile"]["outcomes"][
            "resolved_tail_unique"] == 2

    def test_artifact_stamps(self):
        g = build_include_graph(self._base_inventory())
        assert g["tier"] == "hint"
        assert g["producer"]["module"] == (
            "core.inventory.include_graph")
        assert g["producer"]["parse_fingerprint"] == "fp-test"
        assert g["producer"]["version"] == 1
        assert "note" in g


class TestTwoComponentCensus:
    def _dispatcher_inventory(self, tmp_path: Path):
        """A dynamic dispatcher whose candidates land on foreign-
        extension files the walker cannot parse — the census's
        second component."""
        target = tmp_path / "tree"
        (target / "modules").mkdir(parents=True)
        (target / "entry.php").write_text("<?php\n")
        (target / "modules" / "one.mod").write_text("plain text\n")
        (target / "modules" / "two.mod").write_text("plain text\n")
        inv = _inventory([
            _php_file("entry.php", includes=[
                _edge(5, "require_once", "dynamic",
                      literal_stem="modules/", literal_tail=".mod",
                      raw='APP_PATH . $dir . "modules/$page.mod"'),
            ]),
        ], target=str(target))
        return inv, target

    def test_mod_shaped_unwalked_target_renders(self, tmp_path):
        inv, target = self._dispatcher_inventory(tmp_path)
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
        inv, _target = self._dispatcher_inventory(tmp_path)
        g = build_include_graph(inv)  # inventory-only universe
        assert g["census"]["unwalked_target_count"] == 0
        assert g["census"]["unresolved_edge_count"] == 1

    def test_uninformative_tail_overflows_to_nothing(self, tmp_path):
        target = tmp_path / "tree"
        target.mkdir()
        for i in range(40):
            (target / f"f{i}.php").write_text("<?php\n")
        inv = _inventory([
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
        inv = _inventory([
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
        g = build_include_graph(_inventory([_php_file("a.php")]))
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
        inv = _inventory([
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
        inv = _inventory([
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

    def _flood_inventory(self, truncated: bool):
        cg_edges = [_edge(1, "include", "literal",
                          literal_tail="pad.php", target="pad.php")]
        f = _php_file("flood.php", includes=cg_edges)
        if truncated:
            f["call_graph"]["includes_truncated"] = True
        return _inventory([f, _php_file("pad.php"),
                           _php_file("deep.php")])

    def test_truncated_file_joins_census_and_qualifier(self):
        g = build_include_graph(self._flood_inventory(True))
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
        g = build_include_graph(self._flood_inventory(False))
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
        inv = _inventory(files)
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
        inv = _inventory(files)
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
        g = build_include_graph(_inventory(files))
        overflowed = [r for r in g["unresolved_edges"]
                      if r.get("candidates_overflow")]
        assert len(overflowed) == 5  # past-budget edges refuse loudly


class TestConsumerQueries:
    def _graph(self):
        inv = _inventory([
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
