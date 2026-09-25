"""Tests for core.evidence — the unified evidence vocabulary."""

from core.evidence import (
    EvidenceRecord,
    EvidenceTier,
    TIER_RANK,
    evidence_id,
    make_evidence,
    stronger,
)


class TestEvidenceTierOrdering:
    """The tier ordering is a design constraint, not an implementation detail.

    OBSERVED_RUNTIME > REPLAYED_CRASH > SMT_PROVED >
    CORPUS_CORROBORATED > DECODED_INSTRUCTION > XREF_BACKED >
    HEADER_BACKED > DECOMPILER_INFERRED > HEURISTIC
    """

    def test_ordering(self):
        ordered = [
            EvidenceTier.OBSERVED_RUNTIME,
            EvidenceTier.REPLAYED_CRASH,
            EvidenceTier.SMT_PROVED,
            EvidenceTier.CORPUS_CORROBORATED,
            EvidenceTier.DECODED_INSTRUCTION,
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

    def test_ranks_are_a_total_order(self):
        # A tie would make stronger() argument-order-dependent for
        # that pair; the ladder is a total order by contract.
        ranks = list(TIER_RANK.values())
        assert len(ranks) == len(set(ranks))

    def test_value_roundtrip(self):
        # Artifacts persist the VALUE string, never the rank int —
        # every member must reconstruct from its serialised form.
        for tier in EvidenceTier:
            assert EvidenceTier(tier.value) is tier

    def test_new_member_values(self):
        # Serialised spelling is a cross-run artifact contract.
        assert EvidenceTier.DECODED_INSTRUCTION.value == "decoded_instruction"
        assert EvidenceTier.CORPUS_CORROBORATED.value == "corpus_corroborated"


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

class TestEvidenceId:
    def test_deterministic(self):
        args = ("sha256here", "sink_call", "nm", {"symbol": "memcpy"})
        assert evidence_id(*args) == evidence_id(*args)

    def test_bound_to_binary_bytes(self):
        # Same observation on a DIFFERENT binary must mint a different
        # id — ids are the dedup key across runs, and a rebuild of the
        # target must not silently alias its evidence onto the old one.
        a = evidence_id("sha-one", "sink_call", "nm", {"symbol": "memcpy"})
        b = evidence_id("sha-two", "sink_call", "nm", {"symbol": "memcpy"})
        assert a != b

    def test_bound_to_observation_data(self):
        a = evidence_id("sha", "sink_call", "nm", {"symbol": "memcpy"})
        b = evidence_id("sha", "sink_call", "nm", {"symbol": "strcpy"})
        assert a != b


class TestMakeEvidencePayloadIsolation:
    def test_data_is_copied_not_aliased(self):
        # The record must snapshot the caller's dict: producers reuse
        # scratch dicts across observations, and an aliased payload
        # would let a later mutation rewrite an already-minted record
        # (whose id was computed from the ORIGINAL contents).
        payload = {"symbol": "memcpy"}
        rec = make_evidence(
            "sha",
            kind="sink_call",
            source="nm",
            summary="calls memcpy",
            tier=EvidenceTier.HEADER_BACKED,
            confidence="candidate",
            reproducible=True,
            tool="nm",
            data=payload,
        )
        payload["symbol"] = "system"
        assert rec.data == {"symbol": "memcpy"}

    def test_to_dict_returns_fresh_data_dict(self):
        rec = make_evidence(
            "sha",
            kind="k",
            source="s",
            summary="x",
            tier=EvidenceTier.HEURISTIC,
            confidence="low",
            reproducible=False,
            tool="t",
            data={"a": 1},
        )
        d = rec.to_dict()
        d["data"]["a"] = 2
        assert rec.data["a"] == 1


class TestEvidenceRecordContracts:
    def test_typestate_violations_not_counted_as_evidence(self):
        # Documented contract: typestate_violations is populated
        # mid-loop, AFTER evidence-driven prioritisation ran, so it
        # must not flip has_any_evidence().
        rec = EvidenceRecord(file="a.c", function="f")
        rec.typestate_violations = [{"rule": "use_after_close"}]
        assert not rec.has_any_evidence()

    def test_sink_unreachable_not_counted_as_evidence(self):
        # sink_unreachable is a NEGATIVE signal (scope narrowing) —
        # counting it would make every unreachable function look like
        # it carries mechanical evidence.
        rec = EvidenceRecord(file="a.c", function="f")
        rec.sink_unreachable = True
        assert not rec.has_any_evidence()

    def test_binary_parser_boundary_counts_as_evidence(self):
        rec = EvidenceRecord(file="a.c", function="f")
        rec.binary_parser_boundary = True
        assert rec.has_any_evidence()

    def test_all_joern_flows_preserves_this_run_first_order(self):
        rec = EvidenceRecord(file="a.c", function="f")
        rec.joern_flows = ["this_run_flow"]
        rec.imported_joern_flows = ["imported_flow"]
        assert rec.all_joern_flows() == ["this_run_flow", "imported_flow"]


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

    def test_absolute_scope_equal_to_target_root_means_whole_tree(self):
        assert len(self._keys("/repo")) == 3

    def test_scope_naming_target_root_component_means_whole_tree(self):
        # Scope "proj" against target ".../proj" names the target root
        # itself, not a subdirectory — it must widen to the whole tree
        # rather than silently matching zero checklist paths.
        from core.evidence import build_evidence_index
        checklist = self._checklist()
        checklist["target_path"] = "/repo/proj"
        keys = set(build_evidence_index(checklist=checklist, scope="proj"))
        assert len(keys) == 3
