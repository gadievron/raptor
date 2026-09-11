"""Tests for packages.ghidra.match — tiered cross-version matching."""

from __future__ import annotations

import json

import packages.ghidra.match as match_mod
from packages.ghidra.diff import diff_databases
from packages.ghidra.match import match_databases
from packages.ghidra.model import REDatabase, REFunction, REXref


def _func(name, address, size=0x40, decomp=None, auto=False,
          thunk=False, signature=None):
    return REFunction(
        name=name, address=address, size=size,
        decompilation=decomp, is_auto_named=auto, is_thunk=thunk,
        signature=signature, source_tool="ghidra",
    )


def _db(functions, xrefs=(), strings=()):
    return REDatabase(
        source_tool="ghidra",
        functions=list(functions),
        xrefs=[REXref(from_addr=f, to_addr=t, kind=k)
               for f, t, k in xrefs],
        strings=[{"address": a, "value": v} for a, v in strings],
    )


def _pairs_by_old_name(result):
    return {p.old_name: p for p in result.pairs}


class TestTier1Name:
    def test_unique_names_match(self):
        old = _db([_func("alpha", 0x1000), _func("beta", 0x1100)])
        new = _db([_func("beta", 0x2100), _func("alpha", 0x2000)])
        r = match_databases(old, new)
        by = _pairs_by_old_name(r)
        assert by["alpha"].new_address == 0x2000
        assert by["beta"].new_address == 0x2100
        assert all(p.tier == 1 for p in r.pairs)
        assert not r.unmatched_old and not r.unmatched_new

    def test_duplicate_names_never_force_matched_at_tier1(self):
        old = _db([_func("dup", 0x1000), _func("dup", 0x1100)])
        new = _db([_func("dup", 0x2000), _func("dup", 0x2100)])
        r = match_databases(old, new)
        assert r.stats["tier1_name"] == 0

    def test_auto_names_do_not_key(self):
        # FUN_1000 on both sides is a coincidence of layout, not
        # identity — matching on it would pair unrelated functions
        old = _db([_func("FUN_1000", 0x1000, auto=True)])
        new = _db([_func("FUN_1000", 0x1000, auto=True,
                         decomp=None)])
        r = match_databases(old, new)
        assert r.stats["tier1_name"] == 0

    def test_auto_name_shapes_refused_even_without_flag(self):
        # the r2 importer leaves is_auto_named False on address-
        # derived names — the shape itself must disqualify them
        for name in ("fcn.00001234", "sub_401000", "entry.init0",
                     "case.0x1000.3"):
            old = _db([_func(name, 0x1000, auto=False)])
            new = _db([_func(name, 0x2000, auto=False)])
            r = match_databases(old, new)
            assert r.stats["tier1_name"] == 0, name


class TestTier2DecompHash:
    BODY = ("int F(int x) { if (x < 0) return -1; "
            "return helper(x) + 0x40; }")

    def test_rebased_auto_names_and_constants_match(self):
        old = _db([_func("FUN_1000", 0x1000, auto=True,
                         decomp="int FUN_1000(int x) { if (x < 0) "
                                "return -1; return FUN_1100(x) + "
                                "0x40; }")])
        new = _db([_func("FUN_2000", 0x2000, auto=True,
                         decomp="int FUN_2000(int x) { if (x < 0) "
                                "return -1; return FUN_2100(x) + "
                                "0x80; }")])
        r = match_databases(old, new)
        assert r.stats["tier2_decomp_hash"] == 1
        assert r.pairs[0].new_name == "FUN_2000"

    def test_short_stub_decomp_does_not_key(self):
        old = _db([_func("FUN_1000", 0x1000, auto=True,
                         decomp="{ ret; }")])
        new = _db([_func("FUN_2000", 0x2000, auto=True,
                         decomp="{ ret; }")])
        r = match_databases(old, new)
        assert r.stats["tier2_decomp_hash"] == 0

    def test_duplicate_hash_on_one_side_refuses(self):
        old = _db([_func("FUN_1000", 0x1000, auto=True,
                         decomp=self.BODY),
                   _func("FUN_1100", 0x1100, auto=True,
                         decomp=self.BODY)])
        new = _db([_func("FUN_2000", 0x2000, auto=True,
                         decomp=self.BODY)])
        r = match_databases(old, new)
        assert r.stats["tier2_decomp_hash"] == 0


class TestTier3Anchors:
    def test_string_values_survive_strip_and_rebase(self):
        old = _db(
            [_func("check_pw", 0x1000)],
            xrefs=[(0x1010, 0x5000, "data")],
            strings=[(0x5000, "password:")],
        )
        new = _db(
            [_func("FUN_9000", 0x9000, auto=True)],
            xrefs=[(0x9010, 0x7000, "data")],
            strings=[(0x7000, "password:")],
        )
        r = match_databases(old, new)
        assert r.stats["tier3_strings"] == 1
        p = r.pairs[0]
        assert (p.old_name, p.new_name) == ("check_pw", "FUN_9000")

    def test_shared_string_set_is_ambiguous(self):
        old = _db(
            [_func("a", 0x1000), _func("b", 0x1100)],
            xrefs=[(0x1010, 0x5000, "data"), (0x1110, 0x5000, "data")],
            strings=[(0x5000, "shared")],
        )
        new = _db(
            [_func("FUN_1", 0x2000, auto=True),
             _func("FUN_2", 0x2100, auto=True)],
            xrefs=[(0x2010, 0x6000, "data"), (0x2110, 0x6000, "data")],
            strings=[(0x6000, "shared")],
        )
        r = match_databases(old, new)
        assert r.stats["tier3_strings"] == 0

    def test_import_callee_multiset_matches(self):
        # PLT thunk names come from the dynamic symbol table and
        # survive stripping
        old = _db(
            [_func("worker", 0x1000, size=0x60),
             _func("strcpy", 0x8000, thunk=True)],
            xrefs=[(0x1010, 0x8000, "call")],
        )
        new = _db(
            [_func("FUN_2000", 0x2000, size=0x60, auto=True),
             _func("strcpy", 0x9000, thunk=True)],
            xrefs=[(0x2010, 0x9000, "call")],
        )
        r = match_databases(old, new)
        by = _pairs_by_old_name(r)
        assert by["worker"].new_name == "FUN_2000"
        assert by["worker"].tier == 3


class TestTier4Propagation:
    BODIES = [
        "int F(void) { int r = next(); log_step(r); return r + 1; }",
        "int F(int x) { while (x > 3) { x = fold(x); } return x; }",
        "void F(char *p) { for (; *p; p++) *p |= 0x20; flush(p); }",
    ]

    def _linked(self, base, names, auto=False, mutate=False):
        # chain: n0 -> n1 -> n2 ..., each function 0x100 apart,
        # bodies similar across sides (the evidence floor requires
        # more than bare topology to accept a candidate); `mutate`
        # perturbs the text so the hash tier cannot claim the pair
        # while shingle similarity stays high
        funcs = []
        for i, n in enumerate(names):
            body = self.BODIES[i % len(self.BODIES)]
            if mutate:
                body = body.replace("return", "return /*w*/", 1)
            funcs.append(_func(n, base + i * 0x100, auto=auto,
                               decomp=body))
        xrefs = [(base + i * 0x100 + 0x10, base + (i + 1) * 0x100,
                  "call") for i in range(len(names) - 1)]
        return funcs, xrefs

    def test_matched_neighbor_pulls_in_the_chain(self):
        of, ox = self._linked(0x1000, ["root", "mid", "leaf"])
        nf, nx = self._linked(0x2000,
                              ["root", "FUN_2100", "FUN_2200"],
                              mutate=True)
        nf[1].is_auto_named = True
        nf[2].is_auto_named = True
        r = match_databases(_db(of, ox), _db(nf, nx))
        by = _pairs_by_old_name(r)
        assert by["mid"].tier == 4
        assert by["mid"].new_address == 0x2100
        assert by["leaf"].new_address == 0x2200

    def test_deleted_chain_does_not_cascade_onto_replacement(self):
        """One deletion must not convert into a cascade of wrong
        pairs: old chain root->X1->X2 was deleted and replaced by an
        unrelated chain root->W1->W2 — 'only one candidate left' is
        not identity."""
        of, ox = self._linked(0x1000, ["root", "x1", "x2"])
        nf, nx = self._linked(0x2000, ["root", "FUN_a", "FUN_b"],
                              auto=True)
        nf[0].is_auto_named = False
        nf[0].name = "root"
        # replacement bodies are genuinely different code
        nf[1].decompilation = ("void F(struct q *w) { enqueue(w); "
                               "if (w->depth > 9) { drain(w); } }")
        nf[2].decompilation = ("long F(long a, long b) { "
                               "return a * 31 + b ^ 0x55; }")
        r = match_databases(_db(of, ox), _db(nf, nx))
        assert r.stats["tier4_callgraph"] == 0
        assert {u["name"] for u in r.unmatched_old} == {"x1", "x2"}

    def test_bare_topology_single_vote_is_refused(self):
        """No decompilation, no strings, one voting neighbor: the
        candidate is unverifiable and stays unmatched."""
        old = _db(
            [_func("root", 0x1000), _func("mid", 0x1100)],
            xrefs=[(0x1010, 0x1100, "call")],
        )
        new = _db(
            [_func("root", 0x2000),
             _func("FUN_1", 0x2100, auto=True)],
            xrefs=[(0x2010, 0x2100, "call")],
        )
        r = match_databases(old, new)
        assert r.stats["tier4_callgraph"] == 0

    def test_two_independent_votes_accept_without_text_evidence(self):
        """Two distinct matched neighbors agreeing is corroboration
        enough when neither side carries decompilation or strings."""
        old = _db(
            [_func("a", 0x1000), _func("b", 0x1100),
             _func("mid", 0x1200)],
            xrefs=[(0x1010, 0x1200, "call"), (0x1110, 0x1200, "call")],
        )
        new = _db(
            [_func("a", 0x2000), _func("b", 0x2100),
             _func("FUN_1", 0x2200, auto=True)],
            xrefs=[(0x2010, 0x2200, "call"), (0x2110, 0x2200, "call")],
        )
        r = match_databases(old, new)
        by = _pairs_by_old_name(r)
        assert by["mid"].tier == 4
        assert by["mid"].new_address == 0x2200

    def test_two_unmatched_callees_stay_ambiguous(self):
        old = _db(
            [_func("root", 0x1000), _func("a", 0x1100),
             _func("b", 0x1200)],
            xrefs=[(0x1010, 0x1100, "call"), (0x1020, 0x1200, "call")],
        )
        new = _db(
            [_func("root", 0x2000),
             _func("FUN_1", 0x2100, auto=True),
             _func("FUN_2", 0x2200, auto=True)],
            xrefs=[(0x2010, 0x2100, "call"), (0x2020, 0x2200, "call")],
        )
        r = match_databases(old, new)
        # root matches by name; a and b each see TWO candidates
        assert r.stats["tier4_callgraph"] == 0
        assert len(r.unmatched_old) == 2

    def test_size_incompatible_candidate_refused(self):
        old = _db(
            [_func("root", 0x1000), _func("tiny", 0x1100, size=0x20)],
            xrefs=[(0x1010, 0x1100, "call")],
        )
        new = _db(
            [_func("root", 0x2000),
             _func("FUN_1", 0x2100, size=0x2000, auto=True)],
            xrefs=[(0x2010, 0x2100, "call")],
        )
        r = match_databases(old, new)
        assert r.stats["tier4_callgraph"] == 0


class TestTier5Similarity:
    A = ("int F(char *p, int n) { int i; for (i = 0; i < n; i++) "
         "{ if (p[i] == 0) break; } validate(p, i); "
         "return commit(p, i); }")
    B = ("void G(struct ctx *c) { lock(c); c->refs++; "
         "if (c->refs > MAX_REFS) { unlock(c); abort(); } "
         "unlock(c); }")

    def test_similar_bodies_match_uniquely(self):
        old = _db([_func("fa", 0x1000, decomp=self.A),
                   _func("fb", 0x1100, decomp=self.B)])
        # names all stripped, one call-less function each: only the
        # decompilation text can pair them
        new = _db([_func("FUN_1", 0x2000, auto=True, decomp=self.B),
                   _func("FUN_2", 0x2100, auto=True, decomp=self.A)])
        r = match_databases(old, new)
        by = _pairs_by_old_name(r)
        # identical text pairs at the hash tier — the recovery is the
        # point; the tests below perturb tokens to exercise tier 5
        assert by["fa"].new_name == "FUN_2"
        assert by["fb"].new_name == "FUN_1"
        assert r.stats["tier2_decomp_hash"] == 2

    def test_near_identical_with_edit_matches_at_tier5(self):
        edited = self.A.replace("i < n", "i <= n")
        old = _db([_func("fa", 0x1000, decomp=self.A)])
        new = _db([_func("FUN_1", 0x2000, auto=True, decomp=edited)])
        r = match_databases(old, new)
        assert r.stats["tier5_similarity"] == 1
        assert r.pairs[0].tier == 5
        assert 0.7 <= r.pairs[0].score <= 1.0

    def test_two_near_equal_candidates_refuse_on_margin(self):
        edited1 = self.A.replace("i < n", "i <= n")
        edited2 = self.A.replace("i < n", "i != n")
        old = _db([_func("fa", 0x1000, decomp=self.A)])
        new = _db([_func("FUN_1", 0x2000, auto=True, decomp=edited1),
                   _func("FUN_2", 0x2100, auto=True, decomp=edited2)])
        r = match_databases(old, new)
        assert r.stats["tier5_similarity"] == 0
        assert len(r.unmatched_old) == 1

    def test_pairwise_budget_skips_loudly(self, monkeypatch):
        monkeypatch.setattr(match_mod, "_MAX_PAIRWISE", 1)
        old = _db([_func("fa", 0x1000, decomp=self.A),
                   _func("fb", 0x1100, decomp=self.B)])
        new = _db([_func("FUN_1", 0x2000, auto=True,
                         decomp=self.A + " extra();"),
                   _func("FUN_2", 0x2100, auto=True,
                         decomp=self.B + " extra();")])
        r = match_databases(old, new)
        assert r.stats.get("tier5_similarity", 0) == 0
        assert any("pairwise budget" in n for n in r.notes)


class TestResidueSafety:
    """Fingerprint keys degrade to 'only one left' when the true
    counterpart is absent — the gates that bound that window."""

    def test_tier2_size_gate_refuses_giant_impostor(self):
        # same masked shape, 16x the size: not the same function
        body_o = ("int F(int *p) {{ helper(p, {c}); "
                  "if (*p == {m}) return {c}; return 0; }}")
        old = _db([_func("FUN_1", 0x1000, size=64, auto=True,
                         decomp=body_o.format(c="0x40", m="0x1337"))])
        new = _db([_func("FUN_2", 0x2000, size=1024, auto=True,
                         decomp=body_o.format(c="0x800",
                                              m="0xdead"))])
        r = match_databases(old, new)
        assert r.stats["tier2_decomp_hash"] == 0

    def test_tier3a_size_gate_refuses_planted_string_anchor(self):
        # attacker copies verify_sig's string into a tiny stub
        old = _db(
            [_func("verify_sig", 0x1000, size=0x200)],
            xrefs=[(0x1010, 0x5000, "data")],
            strings=[(0x5000, "sig: bad signature")],
        )
        new = _db(
            [_func("FUN_1", 0x2000, size=0x10, auto=True)],
            xrefs=[(0x2010, 0x6000, "data")],
            strings=[(0x6000, "sig: bad signature")],
        )
        r = match_databases(old, new)
        assert r.stats["tier3_strings"] == 0

    def test_tier3b_no_bucket_identity_theft(self):
        """Quantized size buckets let a deleted sibling inherit a
        grown function's identity: A grew across the bucket boundary,
        B was deleted — B_old must NOT pair with A_new."""
        thunk_o = _func("malloc", 0x8000, thunk=True)
        thunk_n = _func("malloc", 0x9000, thunk=True)
        old = _db(
            [_func("FUN_a", 0x1000, size=60, auto=True),
             _func("FUN_b", 0x2000, size=70, auto=True), thunk_o],
            xrefs=[(0x1010, 0x8000, "call"), (0x2010, 0x8000, "call")],
        )
        new = _db(
            [_func("FUN_x", 0x11000, size=70, auto=True), thunk_n],
            xrefs=[(0x11010, 0x9000, "call")],
        )
        r = match_databases(old, new)
        # both old functions share the import key: ambiguous, refuse
        assert r.stats["tier3_imports"] == 0

    def test_tier5_symmetric_margin_refuses_close_claimants(self):
        base = ("int F(char *p, int n) { int i; for (i = 0; i < n; "
                "i++) { if (p[i] == 0) break; } validate(p, i); "
                "return commit(p, i); }")
        old = _db([
            _func("fa", 0x1000, decomp=base),
            _func("fb", 0x1100,
                  decomp=base.replace("== 0", "== 9")),
        ])
        new = _db([_func("FUN_1", 0x9000, auto=True,
                         decomp=base.replace("i < n", "i <= n"))])
        r = match_databases(old, new)
        # both old functions clear the old-side margin against an
        # empty runner-up field; the new-side margin must refuse
        assert r.stats["tier5_similarity"] == 0

    def test_extended_auto_shapes_refused_at_tier1(self):
        for name in ("thunk_FUN_00401000", "j_FUN_00401000",
                     "switchD_00401000", "caseD_3", "Ordinal_17"):
            old = _db([_func(name, 0x1000, auto=False)])
            new = _db([_func(name, 0x2000, auto=False)])
            r = match_databases(old, new)
            assert r.stats["tier1_name"] == 0, name

    def test_planted_string_cannot_override_dissimilar_code(self):
        """String anchors are attacker-copyable; when decompilation
        exists on both sides it is the stronger evidence and a
        planted overlapping string must not outvote it at tier 4."""
        old = _db(
            [_func("root", 0x1000),
             _func("verify_token", 0x1100, size=0x80,
                   decomp="int verify_token(char *t) { if (!t) "
                          "return -1; return hmac_check(t, KEYLEN)"
                          " == 0; }")],
            xrefs=[(0x1010, 0x1100, "call"),
                   (0x1110, 0x5000, "data"),
                   (0x1118, 0x5010, "data")],
            strings=[(0x5000, "out of memory"),
                     (0x5010, "hmac: key too short")],
        )
        new = _db(
            [_func("root", 0x2000),
             _func("FUN_2100", 0x2100, size=0x80, auto=True,
                   decomp="void F(struct q *w) { while (w->n--) "
                          "{ emit(w->buf[w->n]); } reset(w); }")],
            xrefs=[(0x2010, 0x2100, "call"),
                   (0x2110, 0x6000, "data")],
            strings=[(0x6000, "out of memory")],
        )
        r = match_databases(old, new)
        assert r.stats["tier4_callgraph"] == 0

    def test_disjoint_strings_do_not_block_similar_code(self):
        """Disjoint strings are absence of corroboration, not
        disproof — a bumped version banner must not unmatch a pair
        the code itself supports."""
        body = ("void banner(void) { emit_line(version_string); "
                "flush_output(); log_startup(); }")
        old = _db(
            [_func("root", 0x1000), _func("banner", 0x1100,
                                          decomp=body)],
            xrefs=[(0x1010, 0x1100, "call"), (0x1110, 0x5000, "data")],
            strings=[(0x5000, "demo v1.0")],
        )
        new = _db(
            [_func("root", 0x2000),
             _func("FUN_2100", 0x2100, auto=True, decomp=body)],
            xrefs=[(0x2010, 0x2100, "call"), (0x2110, 0x6000, "data")],
            strings=[(0x6000, "demo v1.1")],
        )
        r = match_databases(old, new)
        # the identical body actually matches at tier 2; the point is
        # the pair matches at all instead of being string-blocked
        assert r.stats["matched"] == 2

    def test_nul_forged_sentinels_cannot_fake_equality(self):
        """Input text is attacker-derived and JSON round-trips NULs:
        literal sentinel bytes in a decompilation must not compare
        equal to a genuinely masked auto-name (silent suppression of
        decompilation_changed, and tier-2 identity theft)."""
        from packages.ghidra.diff import _compare_pair
        forged = ("int FUN_2000(int x) { return "
                  + chr(0) + "A1" + chr(0) + "(x) + 1; }")
        fo = _func("worker", 0x1000,
                   decomp="int worker(int x) { "
                          "return FUN_00401100(x) + 1; }")
        fn = _func("FUN_2000", 0x2000, auto=True, decomp=forged)
        change = _compare_pair(fo, fn, rename_aware=True,
                               match_tier=4)
        assert change is not None and change.decompilation_changed
        # and the hash tier must not pair them either
        old = _db([_func("f", 0x1000, auto=True,
                         decomp=str(fo.decompilation)
                         .replace("worker", "FUN_1000"))])
        new = _db([_func("g", 0x2000, auto=True, decomp=forged)])
        r = match_databases(old, new)
        assert r.stats["tier2_decomp_hash"] == 0

    def test_mask_sentinels_outside_identifier_space(self):
        """A genuine identifier named A1 or H must not hash-collide
        with a masked auto-name or hex constant."""
        old = _db([_func("f", 0x1000, auto=True,
                         decomp="int F(void) { g = A1 + A1; "
                                "n = H; return g + n; }")])
        new = _db([_func("g", 0x2000, auto=True,
                         decomp="int F(void) { g = FUN_00401000 + "
                                "FUN_00401000; n = 0x48; "
                                "return g + n; }")])
        r = match_databases(old, new)
        assert r.stats["tier2_decomp_hash"] == 0

    def test_auto_name_predicate_covers_parser_shapes(self):
        """match._is_auto_named must never lag parser's list — a
        shape parser flags but match accepts pairs coincidental
        layout names at tier 1, score 1.0."""
        import packages.ghidra.match as m
        from packages.ghidra.parser import _looks_auto_named
        for name in ("FUN_00401000", "fcn.00001234", "sub_401000",
                     "thunk_FUN_00401000", "Ordinal_17"):
            assert _looks_auto_named(name)
            f = _func(name, 0x1000, auto=False)
            assert m._is_auto_named(f), name

    def test_duplicate_addresses_surface_in_notes(self):
        old = _db([_func("a", 0x1000), _func("shadowed", 0x1000)])
        new = _db([_func("a", 0x2000)])
        r = match_databases(old, new)
        assert r.stats["duplicate_addresses_dropped"] == 1
        assert any("share an address" in n for n in r.notes)


class TestHostileResourceBounds:
    def test_duplicate_xref_spam_is_deduped(self):
        # 20k duplicate call xrefs collapse to one adjacency edge
        import time
        xrefs = [(0x1010, 0x1100, "call")] * 20_000
        old = _db([_func("root", 0x1000), _func("mid", 0x1100)],
                  xrefs=xrefs)
        new = _db([_func("root", 0x2000),
                   _func("FUN_1", 0x2100, auto=True)],
                  xrefs=[(0x2010, 0x2100, "call")] * 20_000)
        t0 = time.perf_counter()
        match_databases(old, new)
        assert time.perf_counter() - t0 < 2.0

    def test_long_chain_fixpoint_is_not_quadratic(self):
        import time
        n = 2000
        of = [_func("root", 0x10000)] + [
            _func(f"c{i}", 0x10000 + (i + 1) * 0x100,
                  decomp=f"int F(int x) {{ return step(x) + {i}; }}")
            for i in range(n)]
        nf = [_func("root", 0x900000)] + [
            _func(f"FUN_{i}", 0x900000 + (i + 1) * 0x100, auto=True,
                  decomp=f"int F(int x) {{ return step(x) + {i}; }}")
            for i in range(n)]
        ox = [(0x10000 + i * 0x100 + 0x10,
               0x10000 + (i + 1) * 0x100, "call") for i in range(n)]
        nx = [(0x900000 + i * 0x100 + 0x10,
               0x900000 + (i + 1) * 0x100, "call") for i in range(n)]
        t0 = time.perf_counter()
        r = match_databases(_db(of, ox), _db(nf, nx))
        elapsed = time.perf_counter() - t0
        assert elapsed < 10.0, f"{elapsed:.1f}s for a {n}-chain"
        assert r.stats["matched"] > n // 2

    def test_shingles_are_token_capped(self):
        import packages.ghidra.match as m
        f = _func("big", 0x1000,
                  decomp="x = a + b; " * 200_000)
        assert len(m._shingles(f)) <= m._MAX_SHINGLE_TOKENS

    def test_set_work_budget_skips_loudly(self, monkeypatch):
        monkeypatch.setattr(match_mod, "_MAX_SIM_WORK", 10)
        body_a = ("int F(char *p, int n) { int i; for (i = 0; i < n;"
                  " i++) { if (p[i] == 0) break; } return i; }")
        old = _db([_func("fa", 0x1000, decomp=body_a)])
        new = _db([_func("FUN_1", 0x2000, auto=True,
                         decomp=body_a.replace("i < n", "i <= n"))])
        r = match_databases(old, new)
        assert r.stats.get("tier5_similarity", 0) == 0
        assert any("set work" in n for n in r.notes)

    def test_clip_scrubs_control_chars(self):
        old = _db([_func("bad\x1b[2K\nAdded (999)", 0x1000)])
        new = _db([_func("other", 0x2000)])
        r = match_databases(old, new)
        name = r.unmatched_old[0]["name"]
        assert "\x1b" not in name and "\n" not in name


class TestResultShape:
    def test_accounting_is_consistent(self):
        old = _db([_func("a", 0x1000), _func("gone", 0x1100)])
        new = _db([_func("a", 0x2000), _func("fresh", 0x2100)])
        r = match_databases(old, new)
        assert r.stats["matched"] == 1
        assert [u["name"] for u in r.unmatched_old] == ["gone"]
        assert [u["name"] for u in r.unmatched_new] == ["fresh"]
        d = r.to_dict()
        assert set(d) == {"pairs", "unmatched_old", "unmatched_new",
                          "stats", "notes"}
        assert r.old_to_new() == {0x1000: 0x2000}

    def test_deterministic(self):
        funcs_o = [_func(f"f{i}", 0x1000 + i * 0x100)
                   for i in range(20)]
        funcs_n = [_func(f"f{i}", 0x9000 + i * 0x100)
                   for i in range(20)]
        old, new = _db(funcs_o), _db(funcs_n)
        assert (match_databases(old, new).to_dict()
                == match_databases(old, new).to_dict())

    def test_hostile_names_clipped_and_junk_tolerated(self):
        long_name = "n" * 5000
        old = REDatabase(
            source_tool="ghidra",
            functions=[_func(long_name, 0x1000),
                       REFunction(name="bad", address=True,  # type: ignore[arg-type]
                                  size=1, source_tool="t")],
            strings=["prose", {"address": "x", "value": 3}, None],
            xrefs=[REXref(from_addr=None, to_addr=None, kind="call")],  # type: ignore[arg-type]
        )
        new = _db([_func("other", 0x2000)])
        r = match_databases(old, new)
        assert all(len(u["name"]) <= 201 for u in r.unmatched_old)


class TestStrippedRecovery:
    """End-to-end perturbation: strip + rebase a synthetic binary and
    measure recovery against the known ground truth."""

    def _build(self, base, stripped):
        rng_strings = ["fmt: %s", "err: eof", "usage: demo",
                       "auth failed", "cfg loaded", "flush",
                       "retry limit", "bad magic"]
        funcs, xrefs, strings = [], [], []
        truth = {}
        for i in range(16):
            addr = base + i * 0x200
            name = f"FUN_{addr:08x}" if stripped else f"fn_{i:02d}"
            body = (f"int {name}(int x) {{ step_{i}(); "
                    f"if (x > {i}) return x * {i + 2}; "
                    "return fallback(x); }")
            funcs.append(_func(name, addr, size=0x80 + i * 8,
                               decomp=body, auto=stripped))
            truth[i] = addr
            # ring call graph + a string anchor for every 3rd fn
            callee = base + ((i + 1) % 16) * 0x200
            xrefs.append((addr + 0x10, callee, "call"))
            if i % 3 == 0:
                s_addr = base + 0x9000 + i
                strings.append((s_addr, rng_strings[i % 8] + str(i)))
                xrefs.append((addr + 0x20, s_addr, "data"))
        return _db(funcs, xrefs, strings), truth

    def test_full_recovery_under_strip_and_rebase(self):
        old, truth_old = self._build(0x1000, stripped=False)
        new, truth_new = self._build(0x400000, stripped=True)
        r = match_databases(old, new)
        expected = {truth_old[i]: truth_new[i] for i in truth_old}
        got = r.old_to_new()
        wrong = {oa: na for oa, na in got.items()
                 if expected.get(oa) != na}
        assert not wrong, f"mismatched pairs: {wrong}"
        assert len(got) >= 14  # ≥ 87% recovered


class TestMatchedDiff:
    def test_rename_reports_change_not_add_remove(self):
        body_old = ("int check(char *p) { if (!p) return -1; "
                    "return strlen(p) > 8; }")
        body_new = ("int FUN_2000(char *p) { if (!p) return -1; "
                    "return strlen(p) > 16; }")
        old = _db(
            [_func("check", 0x1000, decomp=body_old,
                   signature="int check(char *p)")],
            xrefs=[(0x1010, 0x5000, "data")],
            strings=[(0x5000, "anchor")],
        )
        new = _db(
            [_func("FUN_2000", 0x2000, auto=True, decomp=body_new,
                   signature="int FUN_2000(char *p)")],
            xrefs=[(0x2010, 0x6000, "data")],
            strings=[(0x6000, "anchor")],
        )
        m = match_databases(old, new)
        diff = diff_databases(old, new, matches=m)
        assert not diff.added and not diff.removed
        assert len(diff.changed) == 1
        c = diff.changed[0]
        assert c.name == "check" and c.name_new == "FUN_2000"
        assert c.decompilation_changed
        assert c.match_tier == 3
        assert diff.to_dict()["stats"]["match"]["matched"] == 1
        assert "renamed -> FUN_2000" in diff.summary()
        # tier labels stay distinct — tier3_strings and tier3_imports
        # must not collapse into duplicate "tier3=" entries
        assert "tier3_strings=1" in diff.summary()

    def test_pure_rename_and_rebase_is_not_a_change(self):
        body = ("int NAME(char *p) { if (!p) return -1; "
                "return strlen(p) > 8; }")
        old = _db(
            [_func("check", 0x1000, size=0x40,
                   decomp=body.replace("NAME", "check"),
                   signature="int check(char *p)")],
            xrefs=[(0x1010, 0x5000, "data")],
            strings=[(0x5000, "anchor")],
        )
        new = _db(
            [_func("FUN_2000", 0x2000, size=0x40, auto=True,
                   decomp=body.replace("NAME", "FUN_2000"),
                   signature="int FUN_2000(char *p)")],
            xrefs=[(0x2010, 0x6000, "data")],
            strings=[(0x6000, "anchor")],
        )
        m = match_databases(old, new)
        diff = diff_databases(old, new, matches=m)
        assert not diff.changed and not diff.added and not diff.removed

    def test_unmatched_functions_are_added_and_removed(self):
        old = _db([_func("keep", 0x1000), _func("dead", 0x1100)])
        new = _db([_func("keep", 0x2000), _func("born", 0x2100)])
        m = match_databases(old, new)
        diff = diff_databases(old, new, matches=m)
        assert [f.name for f in diff.removed] == ["dead"]
        assert [f.name for f in diff.added] == ["born"]

    def test_constant_only_patch_is_not_silent(self):
        """A patch that only changes a hex constant (bounds, masks,
        auth constants) must surface — full normalization exists for
        matching, not for swallowing the fix class patch-diffing
        exists to find."""
        body = ("int check(char *p, int n) { if (n > CONST) "
                "return -1; return copy(p, n); }")
        old = _db(
            [_func("check", 0x1000,
                   decomp=body.replace("CONST", "0x40"))],
            xrefs=[(0x1010, 0x5000, "data")],
            strings=[(0x5000, "anchor")],
        )
        new = _db(
            [_func("check", 0x2000,
                   decomp=body.replace("CONST", "0x3c"))],
            xrefs=[(0x2010, 0x6000, "data")],
            strings=[(0x6000, "anchor")],
        )
        m = match_databases(old, new)
        diff = diff_databases(old, new, matches=m)
        assert len(diff.changed) == 1
        c = diff.changed[0]
        assert c.constants_changed
        assert not c.decompilation_changed
        assert "constants changed" in diff.summary()
        assert diff.changed[0].to_dict()["constants_changed"] is True

    def test_autonamed_callee_retarget_is_not_silent(self):
        """Retargeting a call from FUN_A to FUN_B (a different
        function) is invisible to normalized text — the call-graph
        comparison through the match mapping must catch it."""
        def _side(base, target_idx, name_prefix, auto):
            helper_a = _func(f"{name_prefix}a", base + 0x100,
                             auto=auto,
                             decomp="int F(void) { return probe() "
                                    "* 7 + tag(); }")
            helper_b = _func(f"{name_prefix}b", base + 0x200,
                             auto=auto,
                             decomp="void F(long v) { while (v--) "
                                    "{ tick(v); } }")
            caller = _func("entry_point", base,
                           decomp="int entry_point(void) "
                                  "{ return helper(); }")
            target = base + 0x100 * (target_idx + 1)
            return ([caller, helper_a, helper_b],
                    [(base + 0x10, target, "call")])
        of, ox = _side(0x1000, 0, "h", auto=False)
        nf, nx = _side(0x2000, 1, "FUN_", auto=True)
        m = match_databases(_db(of, ox), _db(nf, nx))
        diff = diff_databases(_db(of, ox), _db(nf, nx), matches=m)
        by = {c.name: c for c in diff.changed}
        assert "entry_point" in by
        assert by["entry_point"].calls_changed
        assert "call targets changed" in diff.summary()

    def test_summary_scrubs_hostile_names(self):
        evil = ("x\x1b[2K\x1b[31mFAKE\x1b[0m‮"
                "\nAdded (999 functions):")
        old = _db([_func("keep", 0x1000)])
        new = _db([_func("keep", 0x2000), _func(evil, 0x2100)])
        m = match_databases(old, new)
        diff = diff_databases(old, new, matches=m)
        s = diff.summary()
        assert "\x1b" not in s and "‮" not in s
        assert "Added (999 functions):" not in s.splitlines()
        # the JSON layer scrubs too: jq straight to a terminal must
        # not emit live escapes or bidi overrides
        j = json.dumps(diff.to_dict())
        assert "\\u001b" not in j and "\\u202e" not in j

    def test_own_name_mask_does_not_collide_with_real_F(self):
        """A function whose body calls a REAL function named F must
        not compare as unchanged against its self-recursive twin."""
        from packages.ghidra.diff import _compare_pair
        fo = _func("worker", 0x1000,
                   decomp="int worker(int x) { return F(x - 1); }")
        fn = _func("FUN_2000", 0x2000, auto=True,
                   decomp="int FUN_2000(int x) "
                          "{ return FUN_2000(x - 1); }")
        change = _compare_pair(fo, fn, rename_aware=True,
                               match_tier=5)
        assert change is not None and change.decompilation_changed

    def test_match_notes_reach_the_diff(self):
        old = _db([_func("a", 0x1000), _func("dup", 0x1000)])
        new = _db([_func("a", 0x2000)])
        m = match_databases(old, new)
        diff = diff_databases(old, new, matches=m)
        assert any("share an address" in n for n in diff.match_notes)
        assert "share an address" in diff.summary()
        assert any("share an address" in n
                   for n in diff.to_dict()["match_notes"])

    def test_renamed_pair_has_no_spurious_signature_change(self):
        """Signatures embed the function's own name; a renamed pair
        with a real size change must not also claim its signature
        changed when the normalized forms agree."""
        old = _db([_func("check", 0x1000, size=0x40,
                         signature="int check(char *p)",
                         decomp="int check(char *p) { return 1; }")],
                  xrefs=[(0x1010, 0x5000, "data")],
                  strings=[(0x5000, "anchor")])
        new = _db([_func("FUN_2000", 0x2000, size=0x48, auto=True,
                         signature="int FUN_2000(char *p)",
                         decomp="int FUN_2000(char *p) "
                                "{ return 1; }")],
                  xrefs=[(0x2010, 0x6000, "data")],
                  strings=[(0x6000, "anchor")])
        m = match_databases(old, new)
        diff = diff_databases(old, new, matches=m)
        assert len(diff.changed) == 1
        c = diff.changed[0]
        assert c.size_delta == 8
        assert not c.signature_changed
        assert "signature changed" not in diff.summary()
        assert "signature_old" not in c.to_dict()

    def test_recursion_change_reports_calls_changed(self):
        """A function that became self-recursive is a real change
        even when size and text (absent) agree."""
        old = _db([_func("keep", 0x1000), _func("f", 0x1100)],
                  xrefs=[(0x1010, 0x1100, "call")])
        new = _db([_func("keep", 0x2000), _func("f", 0x2100)],
                  xrefs=[(0x2010, 0x2100, "call"),
                         (0x2110, 0x2100, "call")])
        m = match_databases(old, new)
        diff = diff_databases(old, new, matches=m)
        by = {c.name: c for c in diff.changed}
        assert "f" in by and by["f"].calls_changed

    def test_default_name_diff_unchanged_without_matches(self):
        old = _db([_func("a", 0x1000)])
        new = _db([_func("a", 0x2000)])
        diff = diff_databases(old, new)
        # name mode still counts an address shift as a change
        assert len(diff.changed) == 1
        assert diff.changed[0].address_shifted
        assert diff.match_stats == {}
