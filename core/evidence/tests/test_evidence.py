"""Tests for core.evidence — the unified evidence vocabulary."""

from core.evidence import EvidenceTier, TIER_RANK, stronger, make_evidence


class TestEvidenceTierOrdering:
    """The tier ordering is a design constraint, not an implementation detail.

    OBSERVED_RUNTIME > REPLAYED_CRASH > SMT_PROVED > XREF_BACKED >
    HEADER_BACKED > DECOMPILER_INFERRED > HEURISTIC
    """

    def test_ordering(self):
        ordered = [
            EvidenceTier.OBSERVED_RUNTIME,
            EvidenceTier.REPLAYED_CRASH,
            EvidenceTier.SMT_PROVED,
            EvidenceTier.XREF_BACKED,
            EvidenceTier.HEADER_BACKED,
            EvidenceTier.DECOMPILER_INFERRED,
            EvidenceTier.HEURISTIC,
        ]
        for i in range(len(ordered) - 1):
            assert TIER_RANK[ordered[i]] > TIER_RANK[ordered[i + 1]], (
                f"{ordered[i]} should rank above {ordered[i + 1]}"
            )

    def test_all_tiers_ranked(self):
        for tier in EvidenceTier:
            assert tier in TIER_RANK


class TestStronger:
    def test_same_tier(self):
        assert stronger(EvidenceTier.HEURISTIC, EvidenceTier.HEURISTIC) == EvidenceTier.HEURISTIC

    def test_left_stronger(self):
        assert stronger(EvidenceTier.OBSERVED_RUNTIME, EvidenceTier.HEURISTIC) == EvidenceTier.OBSERVED_RUNTIME

    def test_right_stronger(self):
        assert stronger(EvidenceTier.HEURISTIC, EvidenceTier.XREF_BACKED) == EvidenceTier.XREF_BACKED


class TestMakeEvidence:
    def test_basic(self):
        rec = make_evidence(
            "abc123",
            kind="sink_call",
            source="readelf",
            summary="imports memcpy",
            tier=EvidenceTier.HEADER_BACKED,
            confidence="candidate",
            reproducible=True,
            tool="readelf",
        )
        assert rec.tier == EvidenceTier.HEADER_BACKED
        assert rec.id.startswith("evidence:")

    def test_to_dict(self):
        rec = make_evidence(
            "abc",
            kind="test",
            source="test",
            summary="test",
            tier=EvidenceTier.HEURISTIC,
            confidence="low",
            reproducible=False,
            tool="test",
        )
        d = rec.to_dict()
        assert d["tier"] == "heuristic"
        assert isinstance(d["data"], dict)

class TestEvidenceIndexScopeNormalisation:
    """Scope filtering mirrors core.audit.gaps._in_scope (the
    authority): './' spellings strip, absolute paths rebase against
    the checklist target_path, matching is separator-aware, and a
    root entry means the whole tree. The raw startswith it replaces
    made './ipc'-scoped runs silently evidence-blind."""

    @staticmethod
    def _checklist() -> dict:
        return {
            "target_path": "/repo",
            "files": [
                {"path": "ipc/channel.c",
                 "items": [{"name": "recv_msg", "line_start": 1,
                            "line_end": 9}]},
                {"path": "ipcz/driver.c",
                 "items": [{"name": "drive", "line_start": 1,
                            "line_end": 9}]},
                {"path": "ipc.c",
                 "items": [{"name": "ipc_main", "line_start": 1,
                            "line_end": 9}]},
            ],
        }

    def _keys(self, scope):
        from core.evidence import build_evidence_index
        return set(build_evidence_index(
            checklist=self._checklist(), scope=scope,
        ))

    def test_dot_slash_spelling_matches(self):
        assert self._keys("./ipc") == {
            "ipc/channel.c:recv_msg", "ipc.c:ipc_main",
        }

    def test_separator_aware_no_sibling_dir_bleed(self):
        # "ipc" matches ipc/... and ipc.c, never ipcz/.
        keys = self._keys("ipc")
        assert "ipcz/driver.c:drive" not in keys
        assert keys == {"ipc/channel.c:recv_msg", "ipc.c:ipc_main"}

    def test_absolute_scope_under_target_rebases(self):
        assert self._keys("/repo/ipc") == {
            "ipc/channel.c:recv_msg", "ipc.c:ipc_main",
        }

    def test_absolute_scope_outside_target_refuses_loudly(self):
        import pytest
        with pytest.raises(ValueError, match="outside the target"):
            self._keys("/elsewhere/ipc")

    def test_root_entry_means_whole_tree(self):
        for scope in (".", "./", ["."]):
            assert len(self._keys(scope)) == 3, scope

    def test_no_scope_unfiltered(self):
        assert len(self._keys(None)) == 3
