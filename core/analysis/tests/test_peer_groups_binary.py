"""Binary-native peer-group layers: formation, caps, determinism.

Every input here is attacker-shaped (names, call edges, decompiled
text recovered from a hostile binary), so the batteries pin the
bounds: group-count and group-size caps, the callee hub ceiling that
stops libc-wrapper glue, the K-shared-callee corroboration floor,
determinism under shuffled input, and the claiming semantics (anchor
families and callee signatures claim exclusively; decomp similarity
runs independent and tier-labelled).
"""

from __future__ import annotations

import random

from core.analysis.peer_groups import (
    CALLEE_HUB_MAX_CALLERS,
    MAX_BINARY_PEER_GROUP_SIZE,
    MAX_BINARY_PEER_GROUPS,
    MIN_SHARED_DISTINCTIVE_CALLEES,
    _anchor_family_groups,
    _decomp_similarity_groups,
    _shared_callee_signature_groups,
    resolve_peer_groups,
)

_FID_A = "a" * 16 + ":0x100"
_FID_B = "a" * 16 + ":0x200"


def _projection(groups):
    """Order- and identity-sensitive view for determinism asserts.

    ``SiblingGroup.to_dict`` assumes an enum sibling_type; the
    extended layers use plain strings (the documented extension
    pattern), so project manually.
    """
    return [
        (
            g.group_id, str(g.sibling_type), g.description,
            g.shared_context,
            [(s.function, s.file, s.line) for s in g.siblings],
        )
        for g in groups
    ]


def _funcs(names, file="binary:acmed"):
    return [{"name": n, "file": file, "line": 0} for n in names]


def _family(members, fam_id="BHUNTFAM-abc123", samples=("kdcc open",)):
    return {
        "id": fam_id,
        "members": [
            m if isinstance(m, dict) else {"name": m} for m in members
        ],
        "sample_strings": list(samples),
    }


class TestAnchorFamilyLayer:
    def test_family_joins_by_name(self):
        funcs = _funcs(["handle_a", "handle_b", "unrelated"])
        groups = _anchor_family_groups(
            [_family(["handle_a", "handle_b"])], funcs,
        )
        (g,) = groups
        assert g.sibling_type == "binary_anchor_family"
        assert sorted(s.function for s in g.siblings) == [
            "handle_a", "handle_b",
        ]
        assert "BHUNTFAM-abc123" in g.group_id
        assert "kdcc open" in g.shared_context

    def test_fid_join_beats_name(self):
        funcs = _funcs(["real_a", "real_b"])
        funcs[0]["fid"] = _FID_A
        funcs[1]["fid"] = _FID_B
        family = _family([
            {"name": "fcn.00000100", "fid": _FID_A},
            {"name": "fcn.00000200", "fid": _FID_B},
        ])
        (g,) = _anchor_family_groups([family], funcs)
        assert sorted(s.function for s in g.siblings) == [
            "real_a", "real_b",
        ]

    def test_fid_wins_when_name_matches_a_different_record(self):
        """Discrimination pin: a member whose NAME matches record X
        while its FID matches record Y resolves to Y — identity, not
        spelling (a name-first mutant fails here)."""
        funcs = _funcs(["real_a", "real_b", "anchor_mate"])
        funcs[0]["fid"] = _FID_A
        funcs[1]["fid"] = _FID_B
        family = _family([
            # name spells real_a, fid is real_b's.
            {"name": "real_a", "fid": _FID_B},
            {"name": "anchor_mate"},
        ])
        (g,) = _anchor_family_groups([family], funcs)
        assert sorted(s.function for s in g.siblings) == [
            "anchor_mate", "real_b",
        ]

    def test_single_match_forms_no_group(self):
        groups = _anchor_family_groups(
            [_family(["handle_a", "not_in_queue"])],
            _funcs(["handle_a"]),
        )
        assert groups == []

    def test_group_count_cap(self):
        families = [
            _family([f"fa_{i}", f"fb_{i}"], fam_id=f"BHUNTFAM-{i:06x}")
            for i in range(MAX_BINARY_PEER_GROUPS + 5)
        ]
        names = [m["name"] for f in families for m in f["members"]]
        groups = _anchor_family_groups(families, _funcs(names))
        assert len(groups) == MAX_BINARY_PEER_GROUPS

    def test_member_size_cap(self):
        members = [f"m_{i:03d}" for i in range(
            MAX_BINARY_PEER_GROUP_SIZE + 8)]
        (g,) = _anchor_family_groups(
            [_family(members)], _funcs(members),
        )
        assert len(g.siblings) == MAX_BINARY_PEER_GROUP_SIZE

    def test_junk_members_tolerated(self):
        family = _family(["handle_a", "handle_b"])
        family["members"].extend(["junk", 7, None, {"fid": 12}])
        (g,) = _anchor_family_groups(
            [family], _funcs(["handle_a", "handle_b"]),
        )
        assert len(g.siblings) == 2


class TestSharedCalleeLayer:
    def _callees(self):
        # parse_a / parse_b / parse_c share two distinctive helpers;
        # everyone calls the logging hub.
        hub_callers = {
            f"other_{i}": {"log_msg"}
            for i in range(CALLEE_HUB_MAX_CALLERS + 4)
        }
        return {
            "parse_a": {"read_hdr", "check_len", "log_msg"},
            "parse_b": {"read_hdr", "check_len", "log_msg"},
            "parse_c": {"read_hdr", "check_len"},
            "lonely": {"read_hdr"},
            **hub_callers,
        }

    def test_k_shared_distinctive_callees_join(self):
        funcs = _funcs(["parse_a", "parse_b", "parse_c", "lonely"])
        groups = _shared_callee_signature_groups(self._callees(), funcs)
        (g,) = groups
        assert g.sibling_type == "shared_callee_signature"
        assert sorted(s.function for s in g.siblings) == [
            "parse_a", "parse_b", "parse_c",
        ]
        assert "read_hdr" in g.shared_context
        assert str(MIN_SHARED_DISTINCTIVE_CALLEES) in g.description

    def test_hub_callee_glues_nothing(self):
        """A callee over the hub ceiling is vocabulary: two functions
        sharing ONLY the hub (plus one distinctive callee each — under
        K) never join."""
        callees = self._callees()
        callees["solo_x"] = {"log_msg", "x_only"}
        callees["solo_y"] = {"log_msg", "y_only"}
        callees["x_peer"] = {"x_only"}
        callees["y_peer"] = {"y_only"}
        funcs = _funcs(["solo_x", "solo_y", "parse_a", "parse_b"])
        groups = _shared_callee_signature_groups(callees, funcs)
        grouped = {
            s.function for g in groups for s in g.siblings
        }
        assert "solo_x" not in grouped
        assert "solo_y" not in grouped

    def test_hub_ceiling_exact_boundary(self):
        """Boundary pin: a callee with exactly CALLEE_HUB_MAX_CALLERS
        callers is still distinctive (joins); one more caller makes
        it a hub (refuses)."""
        from core.analysis.peer_groups import distinctive_callee_set

        def _callees(caller_count):
            callees = {
                f"c_{i:02d}": {"boundary_helper"}
                for i in range(caller_count)
            }
            return callees

        at_limit = distinctive_callee_set(
            _callees(CALLEE_HUB_MAX_CALLERS))
        assert "boundary_helper" in at_limit
        over_limit = distinctive_callee_set(
            _callees(CALLEE_HUB_MAX_CALLERS + 1))
        assert "boundary_helper" not in over_limit

    def test_below_k_never_joins(self):
        callees = {
            "a": {"shared_one", "a_own"},
            "b": {"shared_one", "b_own"},
            "w1": {"shared_one", "a_own", "b_own"},
        }
        funcs = _funcs(["a", "b"])
        # shared_one is distinctive (3 callers ≤ ceiling) but a and b
        # share only ONE distinctive callee — below K=2.
        assert _shared_callee_signature_groups(callees, funcs) == []

    def test_deterministic_under_shuffle(self):
        funcs = _funcs(["parse_a", "parse_b", "parse_c", "lonely"])
        baseline = _projection(_shared_callee_signature_groups(
            self._callees(), funcs))
        for seed in range(4):
            shuffled = list(funcs)
            random.Random(seed).shuffle(shuffled)
            got = _projection(_shared_callee_signature_groups(
                self._callees(), shuffled))
            assert got == baseline

    def test_group_size_cap_surfaced(self):
        n = MAX_BINARY_PEER_GROUP_SIZE + 6
        callees = {
            f"h_{i:03d}": {"helper_a", "helper_b"} for i in range(n)
        }
        funcs = _funcs(sorted(callees))
        # helper_a/b have n callers — over the hub ceiling; shrink to
        # a distinctive width by capping caller sets per helper pair.
        callees = {}
        for i in range(n):
            callees[f"h_{i:03d}"] = {
                f"helper_a{i % 3}", f"helper_b{i % 3}",
            }
        groups = _shared_callee_signature_groups(callees, funcs)
        assert groups
        for g in groups:
            assert len(g.siblings) <= MAX_BINARY_PEER_GROUP_SIZE


class TestDecompSimilarityLayer:
    _CLONE = (
        "int check_a(char *p, int n) { if (n < 0x10) return -1; "
        "memcpy(dst, p, n); return validate(p, n); }"
    )

    def test_exact_hash_clones_group_with_tier_label(self):
        funcs = _funcs(["check_a", "check_b", "other"])
        texts = {
            "check_a": self._CLONE,
            "check_b": self._CLONE.replace("check_a", "check_b"),
            "other": "void other(void) { unrelated(); done(1); }",
        }
        groups, note = _decomp_similarity_groups(texts, funcs)
        assert note == ""
        (g,) = groups
        assert g.sibling_type == "decomp_similarity"
        assert sorted(s.function for s in g.siblings) == [
            "check_a", "check_b",
        ]
        assert "lower confidence" in g.shared_context

    def test_near_duplicates_join_via_jaccard(self):
        near = self._CLONE.replace(
            "return validate(p, n);",
            "audit(p); return validate(p, n);",
        ).replace("check_a", "check_c")
        funcs = _funcs(["check_a", "check_c"])
        texts = {"check_a": self._CLONE, "check_c": near}
        groups, _ = _decomp_similarity_groups(texts, funcs)
        (g,) = groups
        assert sorted(s.function for s in g.siblings) == [
            "check_a", "check_c",
        ]

    def test_pairwise_budget_degrades_loudly_to_hash_only(
        self, monkeypatch,
    ):
        import core.analysis.peer_groups as pg
        monkeypatch.setattr(pg, "MAX_DECOMP_PAIRWISE", 0)
        funcs = _funcs(["check_a", "check_b"])
        texts = {
            "check_a": self._CLONE,
            "check_b": self._CLONE.replace("check_a", "check_b"),
        }
        groups, note = _decomp_similarity_groups(texts, funcs)
        assert "budget" in note
        assert len(groups) == 1  # exact-hash stage still ran


class TestResolverIntegration:
    def test_exclusive_layers_claim_and_decomp_does_not(self):
        funcs = _funcs(["handle_a", "handle_b", "handle_c"])
        groups = resolve_peer_groups(
            funcs,
            anchor_families=[_family(["handle_a", "handle_b"])],
            binary_callees={
                "handle_a": {"x1", "x2"},
                "handle_b": {"x1", "x2"},
                "handle_c": {"x1", "x2"},
                "w": {"x1", "x2"},
            },
            decomp_texts={
                "handle_a": TestDecompSimilarityLayer._CLONE,
                "handle_b": TestDecompSimilarityLayer._CLONE,
            },
        )
        by_type = {}
        for g in groups:
            by_type.setdefault(str(g.sibling_type), []).append(g)
        # Anchor family claimed a+b, so the callee-signature layer
        # (exclusive, later) only sees handle_c — no pair, no group.
        (fam,) = by_type["binary_anchor_family"]
        assert sorted(s.function for s in fam.siblings) == [
            "handle_a", "handle_b",
        ]
        assert "shared_callee_signature" not in by_type
        # Decomp similarity is independent: it still groups a+b.
        (dec,) = by_type["decomp_similarity"]
        assert sorted(s.function for s in dec.siblings) == [
            "handle_a", "handle_b",
        ]

    def test_absent_inputs_change_nothing(self):
        funcs = _funcs(["handle_a", "handle_b"])
        assert _projection(resolve_peer_groups(funcs)) == _projection(
            resolve_peer_groups(
                funcs, anchor_families=None, binary_callees=None,
                decomp_texts=None,
            ),
        )
