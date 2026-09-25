"""Per-entry constant-environment walk: seeding/carry/no-op/refuse,
entry-anchored resolution, boundaries, guarantee direction,
memoisation, and the guarantee-direction prerequisites."""

from __future__ import annotations

from core.inventory.include_walk import walk_entries


def _edge(line, shape, cond=False, pos="file_scope", **kw):
    e = {"line": line, "keyword": "require_once", "shape": shape,
         "conditional": cond, "position": pos}
    e.update(kw)
    return e


def _const(line, const, tail, **kw):
    return _edge(line, "const_prefix", const_name=const,
                 literal_tail=tail, **kw)


def _define(line, name, value, cond=False, fb=False):
    return {"line": line, "name": name, "value": value,
            "conditional": cond, "fallback": fb,
            "position": "file_scope"}


def _walk(edges, defines=None, meta=None, entries=None, tree=None):
    edges = dict(edges)
    meta_all = {p: {"parse_errors": False, "boundaries": []}
                for p in edges}
    for p, m in (meta or {}).items():
        meta_all.setdefault(p, {})
        meta_all[p].update(m)
    return walk_entries(
        entries if entries is not None else sorted(edges),
        edges_by_file=edges,
        defines_by_file=defines or {},
        meta_by_file=meta_all,
        tree_set=tree if tree is not None else set(edges),
    )


def _prefix(out, entry):
    return {m["file"]: m for m in out["prefixes"][entry]["members"]}


class TestEnvironmentRules:
    def test_inherited_constant_library_resolves_under_entry_walk(self):
        # The A1 acceptance shape: a gate file with NO define of its
        # own resolves its edges under the entry's carried binding,
        # through conditional-fallback files, deriving the full
        # guaranteed bootstrap chain — and two entries with
        # different-valued bindings anchored at their own dirs land
        # in the same class.
        edges = {
            "src/a.php": [_const(3, "APP", "inc/gate.php")],
            "plug/two/b.php": [_const(3, "APP", "inc/gate.php")],
            "inc/gate.php": [_const(2, "APP", "lib/glob.php")],
            "lib/glob.php": [_const(5, "APP", "lib/intl.php")],
            "lib/intl.php": [_const(9, "APP", "class/m.class.php")],
            "class/m.class.php": [],
        }
        defines = {
            "src/a.php": [_define(2, "APP", "../")],
            "plug/two/b.php": [_define(2, "APP", "../../")],
            "lib/intl.php": [_define(2, "APP", "../", cond=True,
                                     fb=True)],
            "class/m.class.php": [_define(1, "APP", "./", cond=True,
                                          fb=True)],
        }
        out = _walk(edges, defines,
                    entries=["src/a.php", "plug/two/b.php"])
        for entry in ("src/a.php", "plug/two/b.php"):
            pref = _prefix(out, entry)
            for f in ("inc/gate.php", "lib/glob.php", "lib/intl.php",
                      "class/m.class.php"):
                assert pref[f]["guaranteed"] is True, (entry, f)
        [cls] = out["entry_classes"]
        assert cls["entry_count"] == 2
        assert "inc/gate.php" in cls["guaranteed_prefix"]
        assert out["outcomes"]["define_fallback_noop"] >= 2

    def test_fallback_define_supplies_binding_standalone(self):
        edges = {
            "lib/x.php": [_const(5, "APP", "lib/y.php")],
            "lib/y.php": [],
        }
        defines = {"lib/x.php": [_define(2, "APP", "../",
                                         cond=True, fb=True)]}
        out = _walk(edges, defines, entries=["lib/x.php"])
        assert _prefix(out, "lib/x.php")["lib/y.php"]["guaranteed"]

    def test_conflicting_redefine_refuses(self):
        # An unconditional re-define of a carried constant with a
        # different value poisons it: edges below resolve to
        # unresolved, never to either candidate.
        edges = {
            "a.php": [_const(4, "APP", "lib/t.php")],
            "evil.php": [],
            "lib/t.php": [],
        }
        defines = {"a.php": [_define(2, "APP", "./"),
                             _define(3, "APP", "lib/")]}
        out = _walk(edges, defines, entries=["a.php"])
        assert "lib/t.php" not in _prefix(out, "a.php")
        [u] = out["prefixes"]["a.php"]["unresolved"]
        assert u["reason"] == "env_conflict"
        assert out["outcomes"]["define_conflict_poisoned"] == 1

    def test_identical_redefine_is_noop(self):
        edges = {"a.php": [_const(4, "APP", "t.php")], "t.php": []}
        defines = {"a.php": [_define(2, "APP", "./"),
                             _define(3, "APP", "./")]}
        out = _walk(edges, defines, entries=["a.php"])
        assert _prefix(out, "a.php")["t.php"]["guaranteed"]

    def test_nonliteral_define_poisons_not_guesses(self):
        edges = {"a.php": [_const(4, "APP", "t.php")], "t.php": []}
        defines = {"a.php": [_define(2, "APP", None)]}
        out = _walk(edges, defines, entries=["a.php"])
        [u] = out["prefixes"]["a.php"]["unresolved"]
        assert u["reason"] == "env_conflict"

    def test_mid_walk_define_extends_environment(self):
        # Adjudicated: included files extend the environment in
        # execution order (bootstrap files defining constants for
        # later includes is the dominant honest idiom).
        edges = {
            "a.php": [_edge(2, "literal", literal_tail="conf.php",
                            target="conf.php"),
                      _const(3, "ROOT", "lib/t.php")],
            "conf.php": [],
            "lib/t.php": [],
        }
        defines = {"conf.php": [_define(1, "ROOT", "./")]}
        out = _walk(edges, defines, entries=["a.php"])
        assert _prefix(out, "a.php")["lib/t.php"]["guaranteed"]

    def test_dotfile_tail_resolves_exactly(self):
        # Prerequisite (iv): full-path resolution under the binding —
        # no suffix matching — closes the 1a dotfile residue.
        edges = {
            "a.php": [_const(3, "APP", "conf/.env.php")],
            "conf/.env.php": [],
            "x.env.php": [],
        }
        defines = {"a.php": [_define(2, "APP", "./")]}
        out = _walk(edges, defines, entries=["a.php"])
        pref = _prefix(out, "a.php")
        assert pref["conf/.env.php"]["guaranteed"]
        assert "x.env.php" not in pref

    def test_binding_escaping_tree_refuses(self):
        edges = {"a.php": [_const(3, "APP", "t.php")], "t.php": []}
        defines = {"a.php": [_define(2, "APP", "../../")]}
        out = _walk(edges, defines, entries=["a.php"])
        [u] = out["prefixes"]["a.php"]["unresolved"]
        assert u["reason"] == "env_escapes_tree"


class TestGuaranteeDirection:
    def test_conditional_edges_join_unguaranteed(self):
        edges = {
            "a.php": [_edge(2, "literal", literal_tail="c.php",
                            target="c.php", cond=True)],
            "c.php": [_edge(1, "literal", literal_tail="d.php",
                            target="d.php")],
            "d.php": [],
        }
        out = _walk(edges, entries=["a.php"])
        pref = _prefix(out, "a.php")
        assert pref["c.php"]["guaranteed"] is False
        # guarantee is chain-AND: below a conditional hop, never true
        assert pref["d.php"]["guaranteed"] is False

    def test_function_body_edges_never_join(self):
        edges = {
            "a.php": [_edge(2, "literal", literal_tail="c.php",
                            target="c.php", pos="function_body")],
            "c.php": [],
        }
        out = _walk(edges, entries=["a.php"])
        assert "c.php" not in _prefix(out, "a.php")
        assert out["outcomes"]["function_body_edges_skipped"] == 1

    def test_conditional_return_demotes_below_boundary(self):
        edges = {
            "a.php": [
                _edge(3, "literal", literal_tail="up.php",
                      target="up.php"),
                _edge(9, "literal", literal_tail="down.php",
                      target="down.php"),
            ],
            "up.php": [], "down.php": [],
        }
        meta = {"a.php": {"boundaries": [
            {"line": 5, "kind": "conditional_return"}]}}
        out = _walk(edges, meta=meta, entries=["a.php"])
        pref = _prefix(out, "a.php")
        assert pref["up.php"]["guaranteed"] is True
        assert pref["down.php"]["guaranteed"] is False
        assert pref["a.php"]["boundary_line"] == 5

    def test_notdefined_guard_boundary_noops_under_binding(self):
        # `if (!defined('IN_APP')) die();` demotes nothing under a
        # walk whose environment binds IN_APP; a positive
        # `defined(C)` return always applies.
        edges = {
            "e.php": [_edge(4, "literal", literal_tail="lib.php",
                            target="lib.php")],
            "lib.php": [_edge(9, "literal", literal_tail="deep.php",
                              target="deep.php")],
            "deep.php": [],
        }
        meta = {"lib.php": {"boundaries": [
            {"line": 2, "kind": "conditional_abort",
             "guard_constant": "IN_APP", "guard_negated": True}]}}
        defines = {"e.php": [_define(2, "IN_APP", "1")]}
        out = _walk(edges, defines, meta=meta, entries=["e.php"])
        assert _prefix(out, "e.php")["deep.php"]["guaranteed"] is True
        # without the binding the boundary applies
        out2 = _walk(edges, meta=meta, entries=["e.php"])
        assert _prefix(out2, "e.php")["deep.php"]["guaranteed"] is False

    def test_positive_defined_return_always_applies(self):
        edges = {
            "e.php": [_edge(4, "literal", literal_tail="lib.php",
                            target="lib.php")],
            "lib.php": [_edge(9, "literal", literal_tail="deep.php",
                              target="deep.php")],
            "deep.php": [],
        }
        meta = {"lib.php": {"boundaries": [
            {"line": 2, "kind": "conditional_return",
             "guard_constant": "DONE", "guard_negated": False}]}}
        defines = {"e.php": [_define(2, "DONE", "1")]}
        out = _walk(edges, defines, meta=meta, entries=["e.php"])
        assert _prefix(out, "e.php")["deep.php"]["guaranteed"] is False

    def test_halt_compiler_is_a_hard_terminator(self):
        # Prerequisite (ii): a planted "unconditional" edge after
        # __halt_compiler is data — it must never become a prefix
        # member at all.
        edges = {
            "a.php": [
                _edge(2, "literal", literal_tail="live.php",
                      target="live.php"),
                _edge(9, "literal", literal_tail="dead.php",
                      target="dead.php"),
            ],
            "live.php": [], "dead.php": [],
        }
        meta = {"a.php": {"boundaries": [{"line": 5, "kind": "halt"}]}}
        out = _walk(edges, meta=meta, entries=["a.php"])
        pref = _prefix(out, "a.php")
        assert "dead.php" not in pref  # post-halt bytes never walk
        assert pref["live.php"]["guaranteed"] is True  # above the halt
        assert out["outcomes"]["stmts_after_halt_skipped"] == 1

    def test_goto_refuses_guarantees_below(self):
        edges = {
            "a.php": [
                _edge(2, "literal", literal_tail="up.php",
                      target="up.php"),
                _edge(9, "literal", literal_tail="down.php",
                      target="down.php"),
            ],
            "up.php": [], "down.php": [],
        }
        meta = {"a.php": {"boundaries": [{"line": 5, "kind": "goto"}]}}
        out = _walk(edges, meta=meta, entries=["a.php"])
        pref = _prefix(out, "a.php")
        assert pref["up.php"]["guaranteed"] is True
        assert pref["down.php"]["guaranteed"] is False

    def test_parse_error_file_refuses_guarantees_censused(self):
        # Prerequisite (i): an ERROR-bearing tree's conditional flags
        # are not guarantee-grade; edges FROM it stay reachability
        # only, and the refusal is censused.
        edges = {
            "a.php": [_edge(2, "literal", literal_tail="err.php",
                            target="err.php")],
            "err.php": [_edge(1, "literal", literal_tail="deep.php",
                              target="deep.php")],
            "deep.php": [],
        }
        meta = {"err.php": {"parse_errors": True}}
        out = _walk(edges, meta=meta, entries=["a.php"])
        pref = _prefix(out, "a.php")
        assert pref["err.php"]["guaranteed"] is True  # inclusion happened
        assert pref["err.php"]["parse_errors"] is True
        assert pref["deep.php"]["guaranteed"] is False
        assert out["outcomes"]["walk_parse_error_refusals"] == 1

    def test_boundary_overflow_sentinel_applies(self):
        edges = {
            "a.php": [_edge(9, "literal", literal_tail="t.php",
                            target="t.php")],
            "t.php": [],
        }
        meta = {"a.php": {"boundaries": [
            {"line": 5, "kind": "overflow"}]}}
        out = _walk(edges, meta=meta, entries=["a.php"])
        assert _prefix(out, "a.php")["t.php"]["guaranteed"] is False


class TestEnvironmentTrust:
    """The environment's trust dimension: bindings acquired on
    non-guaranteed chains, or in parse-errored files, are
    poison-grade — they never skip guards and never ground
    resolutions."""

    def _gatekeeper(self):
        # checker returns unless AUTH is defined, then includes the
        # gate — the runtime-proven fabrication family's shared core.
        edges = {
            "checker.php": [_edge(5, "literal",
                                  literal_tail="gate.php",
                                  target="gate.php")],
            "gate.php": [],
        }
        meta = {"checker.php": {"boundaries": [
            {"line": 2, "kind": "conditional_return",
             "guard_constant": "AUTH", "guard_negated": True}]}}
        return edges, meta

    def test_define_on_conditional_chain_never_skips_guards(self):
        # entry conditionally includes the file that defines AUTH;
        # runtime with the condition false aborts at the checker —
        # the gate must NOT read as guaranteed.
        edges, meta = self._gatekeeper()
        edges["entry.php"] = [
            _edge(2, "literal", literal_tail="optional.php",
                  target="optional.php", cond=True),
            _edge(3, "literal", literal_tail="checker.php",
                  target="checker.php"),
        ]
        edges["optional.php"] = []
        defines = {"optional.php": [_define(1, "AUTH", "yes")]}
        out = _walk(edges, defines, meta=meta, entries=["entry.php"])
        assert _prefix(out, "entry.php")["gate.php"]["guaranteed"] is False
        assert out["outcomes"]["define_poisoned"] >= 1

    def test_define_on_guaranteed_chain_still_grounds(self):
        # Two-direction: the same shape with an UNCONDITIONAL include
        # of the defining file keeps the guard skip and the guarantee.
        edges, meta = self._gatekeeper()
        edges["entry.php"] = [
            _edge(2, "literal", literal_tail="setup.php",
                  target="setup.php"),
            _edge(3, "literal", literal_tail="checker.php",
                  target="checker.php"),
        ]
        edges["setup.php"] = []
        defines = {"setup.php": [_define(1, "AUTH", "yes")]}
        out = _walk(edges, defines, meta=meta, entries=["entry.php"])
        assert _prefix(out, "entry.php")["gate.php"]["guaranteed"] is True

    def test_define_in_parse_errored_file_never_grounds(self):
        # ERROR recovery can launder a branch-guarded define to
        # conditional=False — a parse-errored file's defines are
        # poison-grade even on a guaranteed chain.
        edges, meta = self._gatekeeper()
        edges["entry.php"] = [
            _edge(2, "literal", literal_tail="legacy.php",
                  target="legacy.php"),
            _edge(3, "literal", literal_tail="checker.php",
                  target="checker.php"),
        ]
        edges["legacy.php"] = []
        defines = {"legacy.php": [_define(1, "AUTH", "yes")]}
        meta["legacy.php"] = {"parse_errors": True}
        out = _walk(edges, defines, meta=meta, entries=["entry.php"])
        assert _prefix(out, "entry.php")["gate.php"]["guaranteed"] is False

    def test_untrusted_binding_never_resolves_const_prefix(self):
        edges = {
            "entry.php": [
                _edge(2, "literal", literal_tail="conf.php",
                      target="conf.php", cond=True),
                _const(3, "ROOT", "lib/t.php"),
            ],
            "conf.php": [], "lib/t.php": [],
        }
        defines = {"conf.php": [_define(1, "ROOT", "./")]}
        out = _walk(edges, defines, entries=["entry.php"])
        assert "lib/t.php" not in _prefix(out, "entry.php")
        [u] = out["prefixes"]["entry.php"]["unresolved"]
        assert u["reason"] == "env_conflict"

    def test_parse_errored_boundaries_never_skip(self):
        # A parse-errored gatekeeper's !defined guard shape may be
        # laundered — nothing in it is skippable even under a bound
        # constant.
        edges, meta = self._gatekeeper()
        meta["checker.php"]["parse_errors"] = True
        edges["entry.php"] = [
            _edge(3, "literal", literal_tail="checker.php",
                  target="checker.php")]
        defines = {"entry.php": [_define(2, "AUTH", "yes")]}
        out = _walk(edges, defines, meta=meta, entries=["entry.php"])
        assert _prefix(out, "entry.php")["gate.php"]["guaranteed"] is False

    def test_same_line_edge_resolves_before_define(self):
        # `include(C.'x'); define('C', …)` on ONE line: at runtime
        # the include runs first against an undefined constant —
        # applying the define first would guess.
        edges = {"e.php": [_const(3, "ROOT", "t.php")], "t.php": []}
        defines = {"e.php": [_define(3, "ROOT", "./")]}
        out = _walk(edges, defines, entries=["e.php"])
        assert "t.php" not in _prefix(out, "e.php")
        [u] = out["prefixes"]["e.php"]["unresolved"]
        assert u["reason"] == "env_unbound"

    def test_boundary_min_line_not_first_element(self):
        # Hostile out-of-order boundary list: a later-listed EARLIER
        # boundary must still bound.
        edges = {
            "a.php": [_edge(4, "literal", literal_tail="t.php",
                            target="t.php")],
            "t.php": [],
        }
        meta = {"a.php": {"boundaries": [
            {"line": 9, "kind": "conditional_return"},
            {"line": 2, "kind": "conditional_return"},
        ]}}
        out = _walk(edges, meta=meta, entries=["a.php"])
        pref = _prefix(out, "a.php")
        assert pref["t.php"]["guaranteed"] is False
        assert pref["a.php"]["boundary_line"] == 2

    def test_skipped_guard_boundary_still_yields_min_of_rest(self):
        edges = {
            "a.php": [_edge(6, "literal", literal_tail="t.php",
                            target="t.php")],
            "t.php": [],
        }
        meta = {"a.php": {"boundaries": [
            {"line": 2, "kind": "conditional_abort",
             "guard_constant": "OK", "guard_negated": True},
            {"line": 4, "kind": "conditional_return"},
        ]}}
        defines = {"a.php": [_define(1, "OK", "1")]}
        out = _walk(edges, defines, meta=meta, entries=["a.php"])
        # guard skipped under the binding, the guardless line-4
        # boundary still applies
        assert _prefix(out, "a.php")["t.php"]["guaranteed"] is False


class TestMemoIntegrity:
    def test_diamond_replay_loses_no_members(self):
        # E1: a -> c, then b -> c (skipped: visited) — b's subtree
        # walk omitted c, so it must NOT be memoised; E2 including
        # only b must still see c.
        edges = {
            "e1.php": [
                _edge(2, "literal", literal_tail="a.php",
                      target="a.php"),
                _edge(3, "literal", literal_tail="b.php",
                      target="b.php"),
            ],
            "e2.php": [_edge(2, "literal", literal_tail="b.php",
                             target="b.php")],
            "a.php": [_edge(1, "literal", literal_tail="c.php",
                            target="c.php")],
            "b.php": [_edge(1, "literal", literal_tail="c.php",
                            target="c.php")],
            "c.php": [],
        }
        out = _walk(edges, entries=["e1.php", "e2.php"])
        p2 = _prefix(out, "e2.php")
        assert "c.php" in p2
        assert p2["c.php"]["guaranteed"] is True

    def test_cycle_variant_replay_keeps_members(self):
        # a <-> b cycle: E1=a stores b's subtree WITHOUT a (outer
        # skip) — E2 including b directly must still see a.
        edges = {
            "e2.php": [_edge(2, "literal", literal_tail="b.php",
                             target="b.php")],
            "a.php": [_edge(1, "literal", literal_tail="b.php",
                            target="b.php")],
            "b.php": [_edge(1, "literal", literal_tail="a.php",
                            target="a.php")],
        }
        out = _walk(edges, entries=["a.php", "e2.php"])
        assert "a.php" in _prefix(out, "e2.php")

    def test_internal_double_include_still_memoises(self):
        # Two-direction: a file included twice WITHIN the subtree is
        # an internal skip — memoisation must still happen and stay
        # correct for a sharing entry.
        shared = {
            "hub.php": [
                _edge(1, "literal", literal_tail="x.php",
                      target="x.php"),
                _edge(2, "literal", literal_tail="y.php",
                      target="y.php"),
            ],
            "x.php": [_edge(1, "literal", literal_tail="y.php",
                            target="y.php")],
            "y.php": [],
        }
        edges = {
            "e1.php": [_edge(2, "literal", literal_tail="hub.php",
                             target="hub.php")],
            "e2.php": [_edge(2, "literal", literal_tail="hub.php",
                             target="hub.php")],
            **shared,
        }
        out = _walk(edges, entries=["e1.php", "e2.php"])
        assert out["outcomes"].get("walk_memo_hits", 0) >= 1
        p1 = sorted(m["file"] for m in
                    out["prefixes"]["e1.php"]["members"][1:])
        p2 = sorted(m["file"] for m in
                    out["prefixes"]["e2.php"]["members"][1:])
        assert p1 == p2 == ["hub.php", "x.php", "y.php"]


class TestWalkBudget:
    def test_global_budget_truncates_honestly(self, monkeypatch):
        import core.inventory.include_walk as iw
        monkeypatch.setattr(iw, "MAX_WALK_STMT_VISITS", 10)
        chain = {
            f"f{i}.php": [_edge(1, "literal",
                                literal_tail=f"f{i + 1}.php",
                                target=f"f{i + 1}.php")]
            for i in range(30)
        }
        chain["f30.php"] = []
        out = _walk(chain, entries=["f0.php"])
        assert out["budget_exhausted"] is True
        assert out["outcomes"]["walk_budget_exhausted"] >= 1
        assert out["prefixes"]["f0.php"]["closure_truncated"] is True
        assert out["prefixes"]["f0.php"]["class"] is None

    def test_entry_fanout_flood_stays_bounded(self):
        # entries × fan-out × defines is attacker-shaped; the global
        # statement budget bounds the product (pre-budget this class
        # of shape ran minutes inside build_inventory).
        import time
        shared_edges = [
            _edge(i, "literal", literal_tail=f"s{i}.php",
                  target=f"s{i}.php")
            for i in range(1, 120)
        ]
        shared_defines = [
            _define(200 + i, f"K{i}", "v", cond=True)
            for i in range(200)
        ]
        edges = {f"s{i}.php": [] for i in range(1, 120)}
        defines = {}
        for n in range(400):
            edges[f"e{n:03d}.php"] = list(shared_edges)
            defines[f"e{n:03d}.php"] = list(shared_defines)
        t0 = time.monotonic()
        out = _walk(edges, defines,
                    entries=sorted(k for k in edges
                                   if k.startswith("e")))
        elapsed = time.monotonic() - t0
        assert elapsed < 15.0
        # truncation is honest, never silent
        if out["budget_exhausted"]:
            assert out["outcomes"]["walk_budget_exhausted"] >= 1

    def test_unresolved_cap_sets_overflow_marker(self, monkeypatch):
        import core.inventory.include_walk as iw
        monkeypatch.setattr(iw, "MAX_WALK_UNRESOLVED", 3)
        edges = {"e.php": [
            _edge(i, "dynamic", raw="$x") for i in range(1, 8)
        ]}
        out = _walk(edges, entries=["e.php"])
        p = out["prefixes"]["e.php"]
        assert len(p["unresolved"]) == 3
        assert p["unresolved_overflow"] is True
        assert out["outcomes"]["walk_unresolved_overflow"] == 4

    def test_full_class_ids_no_truncated_prefix(self):
        edges = {"a.php": [], "b.php": []}
        out = _walk(edges, entries=["a.php", "b.php"])
        for p in out["prefixes"].values():
            assert len(p["class"]) == 2 + 64  # "ec" + full sha256

    def test_backslash_tail_resolves_literal_file(self):
        # POSIX runtimes include the literally-named file — no
        # separator rewriting; the forward-slash decoy must lose.
        edges = {
            "e.php": [_const(3, "SM", "x\\gate.php")],
            "lib/x\\gate.php": [],
            "lib/x/gate.php": [],
        }
        defines = {"e.php": [_define(2, "SM", "lib/")]}
        out = _walk(edges, defines, entries=["e.php"])
        pref = _prefix(out, "e.php")
        assert "lib/x\\gate.php" in pref
        assert "lib/x/gate.php" not in pref


class TestWalkMechanics:
    def test_cycles_and_once_semantics(self):
        edges = {
            "a.php": [_edge(2, "literal", literal_tail="b.php",
                            target="b.php")],
            "b.php": [_edge(2, "literal", literal_tail="a.php",
                            target="a.php")],
        }
        out = _walk(edges, entries=["a.php"])
        files = [m["file"] for m in out["prefixes"]["a.php"]["members"]]
        assert files == ["a.php", "b.php"]
        assert out["outcomes"]["walk_revisit_skipped"] == 1

    def test_unwalked_target_flagged(self):
        edges = {
            "a.php": [_edge(2, "literal", literal_tail="m.mod",
                            target="m.mod")],
        }
        out = _walk(edges, entries=["a.php"],
                    tree={"a.php", "m.mod"})
        pref = _prefix(out, "a.php")
        assert pref["m.mod"]["unwalked"] is True

    def test_memoisation_shares_prefixes_identically(self):
        # Two entries with the SAME binding walk the shared closure
        # once; results must equal the unshared walk.
        shared = {
            f"lib/f{i}.php": [_const(1, "APP", f"lib/f{i + 1}.php")]
            for i in range(6)
        }
        shared["lib/f6.php"] = []
        edges = {
            "e1.php": [_const(3, "APP", "lib/f0.php")],
            "e2.php": [_const(3, "APP", "lib/f0.php")],
            **shared,
        }
        defines = {"e1.php": [_define(2, "APP", "./")],
                   "e2.php": [_define(2, "APP", "./")]}
        out = _walk(edges, defines, entries=["e1.php", "e2.php"])
        assert out["outcomes"].get("walk_memo_hits", 0) >= 1
        p1 = [(m["file"], m["guaranteed"])
              for m in out["prefixes"]["e1.php"]["members"][1:]]
        p2 = [(m["file"], m["guaranteed"])
              for m in out["prefixes"]["e2.php"]["members"][1:]]
        assert p1 == p2
        assert (out["prefixes"]["e1.php"]["class"]
                == out["prefixes"]["e2.php"]["class"])

    def test_truncated_closure_is_unclassed(self):
        chain = {
            f"f{i}.php": [_edge(1, "literal",
                                literal_tail=f"f{i + 1}.php",
                                target=f"f{i + 1}.php")]
            for i in range(80)
        }
        chain["f80.php"] = []
        out = _walk(chain, entries=["f0.php"])
        p = out["prefixes"]["f0.php"]
        assert p["closure_truncated"] is True
        assert p["class"] is None
        assert out["outcomes"]["entries_unclassed_truncated"] == 1

    def test_env_resolutions_recorded_for_supersede(self):
        edges = {
            "a.php": [_const(3, "APP", "lib/t.php")],
            "lib/t.php": [],
        }
        defines = {"a.php": [_define(2, "APP", "./")]}
        out = _walk(edges, defines, entries=["a.php"])
        [(key, rec)] = list(out["env_resolutions"].items())
        assert key == ("a.php", 3)
        assert rec["targets"] == {"lib/t.php": ["a.php"]}
