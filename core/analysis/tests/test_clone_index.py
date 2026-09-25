"""Tests for the standing clone-family index and the L9 layer.

Pins the build (winnowed fingerprints + keyed LSH + containment
verification), the hostile-input rails (bucket flood, verified-pair
budget, seeded — never first-N — survivor sampling), caps_hit
propagation onto absence claims, the fingerprint+version cache
contract, and the resolver layer's non-exclusive, tier-labelled join.
"""

from __future__ import annotations

import pytest

try:
    import tree_sitter  # noqa: F401
    _HAS_TS = True
except ImportError:
    _HAS_TS = False
pytestmark = pytest.mark.skipif(
    not _HAS_TS, reason="tree-sitter not installed",
)

from core.analysis.clone_index import (  # noqa: E402
    CLONE_INDEX_FILENAME,
    CLONE_INDEX_VERSION,
    GROUP_TYPE_CLONE_FAMILY,
    MAX_VERIFY_PAIRS,
    build_clone_index,
    load_or_build_clone_index,
    source_fingerprint,
)
from core.testing.treesitter import requires_ts  # noqa: E402


def _clone_fn(name: str, *, guard: bool = True) -> str:
    """A ~60-token function body; clones differ only in name (and
    optionally a dropped guard)."""
    guard_line = "    if (!input) { return -1; }\n" if guard else ""
    return (
        f"int {name}(char *input, int limit) {{\n"
        f"{guard_line}"
        f"    int total = 0;\n"
        f"    for (int i = 0; i < limit; i++) {{\n"
        f"        total = total + input[i] * 3 + i;\n"
        f"        if (total > 1000) {{ total = total - 500; }}\n"
        f"    }}\n"
        f"    process(input, total, limit);\n"
        f"    finish(total);\n"
        f"    return total;\n"
        f"}}\n"
    )


def _unrelated_fn(name: str) -> str:
    return (
        f"int {name}(double x, double y) {{\n"
        f"    double area = x * y / 2.0;\n"
        f"    double edge = x + y + x + y;\n"
        f"    log_shape(area, edge, x, y);\n"
        f"    if (area > edge) {{ return 1; }}\n"
        f"    while (area > 0.5) {{ area = area / 2.0; }}\n"
        f"    emit(area, edge);\n"
        f"    return 0;\n"
        f"}}\n"
    )


class TestBuild:
    @requires_ts("c")
    def test_clones_family_unrelated_stays_out(self):
        sources = {"a.c": (
            _clone_fn("copy_a") + _clone_fn("copy_b")
            + _clone_fn("copy_c") + _unrelated_fn("triangle")
        )}
        index = build_clone_index(sources, seed=b"t")
        assert index is not None
        assert len(index.families) == 1
        members = {
            m["function"] for m in index.families[0]["members"]
        }
        assert members == {"copy_a", "copy_b", "copy_c"}
        assert index.caps_hit is False

    @requires_ts("c")
    def test_dropped_guard_clone_still_joins(self):
        # Containment against the smaller set: the guard-less clone
        # is a subset of its peers — the missing guard must not
        # depress the score (the clone_drift rationale, inherited).
        sources = {"a.c": (
            _clone_fn("copy_a") + _clone_fn("copy_b")
            + _clone_fn("copy_naked", guard=False)
        )}
        index = build_clone_index(sources, seed=b"t")
        assert index is not None
        members = {
            m["function"] for m in index.families[0]["members"]
        }
        assert "copy_naked" in members

    @requires_ts("c")
    def test_no_clones_returns_none(self):
        sources = {"a.c": (
            _clone_fn("copy_a") + _unrelated_fn("triangle")
        )}
        assert build_clone_index(sources, seed=b"t") is None

    @requires_ts("c")
    def test_deterministic_given_seed(self):
        sources = {"a.c": (
            _clone_fn("copy_a") + _clone_fn("copy_b")
            + _clone_fn("copy_c")
        )}
        i1 = build_clone_index(sources, seed=b"fixed")
        i2 = build_clone_index(sources, seed=b"fixed")
        assert i1 is not None and i2 is not None
        assert i1.to_dict()["families"] == i2.to_dict()["families"]


class TestCostRails:
    @requires_ts("c")
    def test_clone_flood_stays_inside_the_pair_budget(self):
        # A saturated tree of near-identical functions is the LSH
        # worst case: every function lands in the same buckets. The
        # verified-pair budget and per-bucket survivor sampling keep
        # verification bounded and mark the degradation in-band.
        n = 90  # 90 identical clones -> 4005 raw pairs per band
        sources = {"flood.c": "".join(
            _clone_fn(f"copy_{i:03d}") for i in range(n)
        )}
        index = build_clone_index(sources, seed=b"t")
        assert index is not None
        assert index.stats["verified_pairs"] <= MAX_VERIFY_PAIRS
        # 90 > MAX_BUCKET_MEMBERS: sampling engaged and was marked.
        assert index.caps_hit is True

    @requires_ts("c")
    def test_verification_work_bounded_under_doubling(self):
        # Growth pin: doubling a saturated flood must not square the
        # verified-pair count past the budget (the rails' whole
        # point — reverting the bucket cap or the budget fails here).
        def pairs_for(n: int) -> int:
            sources = {"flood.c": "".join(
                _clone_fn(f"copy_{i:03d}") for i in range(n)
            )}
            index = build_clone_index(sources, seed=b"t")
            assert index is not None
            return index.stats["verified_pairs"]

        assert pairs_for(80) <= MAX_VERIFY_PAIRS
        assert pairs_for(160) <= MAX_VERIFY_PAIRS


class TestCache:
    @requires_ts("c")
    def test_cache_roundtrip_and_fingerprint_invalidation(
        self, tmp_path,
    ):
        sources = {"a.c": (
            _clone_fn("copy_a") + _clone_fn("copy_b")
        )}
        first = load_or_build_clone_index(sources, out_dir=tmp_path)
        assert first is not None
        assert (tmp_path / CLONE_INDEX_FILENAME).is_file()
        again = load_or_build_clone_index(sources, out_dir=tmp_path)
        assert again is not None
        assert again.to_dict()["families"] == \
            first.to_dict()["families"]
        # Edited source: the fingerprint differs, the cache must not
        # serve the stale families.
        edited = {"a.c": (
            _clone_fn("copy_a") + _clone_fn("copy_b")
            + _clone_fn("copy_c")
        )}
        rebuilt = load_or_build_clone_index(edited, out_dir=tmp_path)
        assert rebuilt is not None
        assert len(rebuilt.families[0]["members"]) == 3

    @requires_ts("c")
    def test_version_mismatch_never_serves_stale_index(
        self, tmp_path,
    ):
        import json

        sources = {"a.c": (
            _clone_fn("copy_a") + _clone_fn("copy_b")
        )}
        first = load_or_build_clone_index(sources, out_dir=tmp_path)
        assert first is not None
        path = tmp_path / CLONE_INDEX_FILENAME
        raw = json.loads(path.read_text())
        raw["version"] = CLONE_INDEX_VERSION + 1
        # Plant a poisoned family so serving the stale cache is
        # detectable, not just plausible.
        raw["families"] = [{"key": "stale", "members": [
            {"file": "x.c", "function": "stale_fn", "line": 1},
        ]}]
        path.write_text(json.dumps(raw))
        reloaded = load_or_build_clone_index(sources, out_dir=tmp_path)
        assert reloaded is not None
        assert all(
            f["key"] != "stale" for f in reloaded.families
        )

    def test_fingerprint_orders_and_contents(self):
        a = source_fingerprint({"a.c": "x", "b.c": "y"})
        b = source_fingerprint({"b.c": "y", "a.c": "x"})
        c = source_fingerprint({"a.c": "x", "b.c": "z"})
        assert a == b
        assert a != c


class TestResolverLayer:
    @requires_ts("c")
    def test_l9_groups_join_and_never_claim(self):
        from core.analysis.peer_groups import resolve_peer_groups

        sources = {"a.c": (
            _clone_fn("copy_a") + _clone_fn("copy_b")
            + _clone_fn("copy_c")
        )}
        index = build_clone_index(sources, seed=b"t")
        functions = [
            {"name": n, "file": "a.c", "line": 1}
            for n in ("copy_a", "copy_b", "copy_c")
        ]

        class _Table:
            function = "dispatch"
            file = "a.c"
            handlers = {"a": "copy_a", "b": "copy_b", "c": "copy_c"}

        groups = resolve_peer_groups(
            functions,
            dispatch_tables=[_Table()],
            clone_index=index,
        )
        types = [
            g.sibling_type if isinstance(g.sibling_type, str)
            else g.sibling_type.value
            for g in groups
        ]
        # Independent: the exclusive dispatch layer still claims its
        # group; the clone family rides beside it.
        assert "dispatch_site" in types
        assert GROUP_TYPE_CLONE_FAMILY in types
        l9 = next(
            g for g in groups
            if g.sibling_type == GROUP_TYPE_CLONE_FAMILY
        )
        assert "lower confidence" in l9.shared_context

    def test_clone_family_never_votes_in_interface_dimension(self):
        from core.audit.consistency_dimensions import (
            _INTERFACE_GROUP_TYPES,
        )
        assert GROUP_TYPE_CLONE_FAMILY not in _INTERFACE_GROUP_TYPES

    @requires_ts("c")
    def test_caps_note_propagates_to_resolver_notes(self):
        from core.analysis.peer_groups import resolve_peer_groups

        n = 90
        sources = {"flood.c": "".join(
            _clone_fn(f"copy_{i:03d}") for i in range(n)
        )}
        index = build_clone_index(sources, seed=b"t")
        assert index is not None and index.caps_hit
        functions = [
            {"name": f"copy_{i:03d}", "file": "flood.c", "line": 1}
            for i in range(n)
        ]
        notes: list[str] = []
        resolve_peer_groups(
            functions, clone_index=index, notes=notes,
        )
        assert any("absence of a clone match" in n for n in notes)
