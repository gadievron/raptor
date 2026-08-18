"""Wiring tests: verification channels inside the orchestrator chain.

Covers _cwe_fallback_chain / _hypothesis_to_tool_chain entry emission
and _run_tool_chain dispatch for the joern_guard / joern_flow /
coccinelle_flow tool types, with the channel entry points monkeypatched
so nothing external runs.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import core.audit.orchestrator as orch
from core.audit.orchestrator import (
    TierCounters,
    _cwe_fallback_chain,
    _hypothesis_to_tool_chain,
    _run_tool_chain,
)
from core.audit.sweep import SweepResult


def _types(chain):
    return [e["type"] for e in chain]


class TestChainEmission:
    def test_guard_cwe_gets_joern_guard(self):
        for cwe in ("CWE-120", "CWE-122", "CWE-125", "CWE-787", "CWE-476"):
            assert "joern_guard" in _types(_cwe_fallback_chain(cwe)), cwe

    def test_flow_cwes_get_joern_flow(self):
        for cwe in ("CWE-20", "CWE-74", "CWE-78", "CWE-89", "CWE-79"):
            assert "joern_flow" in _types(_cwe_fallback_chain(cwe)), cwe

    def test_flow_cocci_cwes(self):
        for cwe in ("CWE-416", "CWE-415", "CWE-252", "CWE-367"):
            assert "coccinelle_flow" in _types(_cwe_fallback_chain(cwe)), cwe

    def test_unrelated_cwe_unchanged(self):
        types = _types(_cwe_fallback_chain("CWE-190"))
        assert "joern_guard" not in types
        assert "joern_flow" not in types
        assert "coccinelle_flow" not in types

    def test_hypothesis_chain_adds_coccinelle_flow(self):
        chain = _hypothesis_to_tool_chain(
            "use-after-free of `conn` in handler", "src/a.c",
        )
        entry = next(
            e for e in chain if e["type"] == "coccinelle_flow"
        )
        assert entry["config"]["template"] == "use_after_free"

    def test_hypothesis_chain_no_duplicate_with_cwe(self):
        chain = _hypothesis_to_tool_chain(
            "use-after-free of `conn` in handler", "src/a.c",
            cwe="CWE-416",
        )
        assert _types(chain).count("coccinelle_flow") == 1

    def test_new_tier_counters_exist(self):
        counters = orch._make_tier_counters()
        for key in ("joern_guard", "joern_flow", "coccinelle_flow",
                    "fail_open"):
            assert key in counters


class _Cfg:
    """Minimal OrchestratorConfig stand-in for _run_tool_chain."""

    def __init__(self, target: Path):
        self.target_path = target
        self.out_dir = None
        self.codeql_db_path = None
        self.project_sinks = None


def _mk_result(outcome, rule_id, **kw):
    return SweepResult(
        tool="joern", file_path="src/a.c", function_name="f",
        outcome=outcome, rule_id=rule_id, **kw,
    )


@pytest.fixture
def counters():
    return {
        "joern_guard": TierCounters(),
        "joern_flow": TierCounters(),
        "coccinelle_flow": TierCounters(),
    }


class TestRunToolChainDispatch:
    HYP_GUARD = "missing bounds check on `len` before memcpy"
    HYP_FLOW = "attacker data from `argv` reaches system()"
    HYP_UAF = "use-after-free of `conn` after free"

    _SERVER_SENTINEL = object()

    def _run(self, tmp_path, chain, hypothesis, counters,
             server=_SERVER_SENTINEL):
        return _run_tool_chain(
            chain,
            config=_Cfg(tmp_path),
            file_path="src/a.c",
            function_name="f",
            source="",
            hypothesis=hypothesis,
            tier_counters=counters,
            joern_server=server,
        )

    def test_guard_confirm_stamps(self, tmp_path, counters, monkeypatch):
        import core.audit.joern_verify as jv
        monkeypatch.setattr(
            jv, "run_guard_dominance_check",
            lambda **kw: _mk_result(
                "confirmed", "joern:guard-dominance",
                matches=[{"line": 4}],
            ),
        )
        confirmed = self._run(
            tmp_path,
            [{"type": "joern_guard", "config": {"sinks": ["memcpy"]}}],
            self.HYP_GUARD, counters,
        )
        assert confirmed == ["joern:guard-dominance"]
        assert counters["joern_guard"].confirmed == 1

    def test_guard_refuted_returns_no_confirmation(
        self, tmp_path, counters, monkeypatch,
    ):
        import core.audit.joern_verify as jv
        monkeypatch.setattr(
            jv, "run_guard_dominance_check",
            lambda **kw: _mk_result("refuted", "joern:guard-dominance"),
        )
        confirmed = self._run(
            tmp_path,
            [{"type": "joern_guard", "config": {"sinks": ["memcpy"]}}],
            self.HYP_GUARD, counters,
        )
        assert confirmed == []
        assert counters["joern_guard"].refuted == 1

    def test_guard_error_counts_error(
        self, tmp_path, counters, monkeypatch,
    ):
        import core.audit.joern_verify as jv
        monkeypatch.setattr(
            jv, "run_guard_dominance_check",
            lambda **kw: _mk_result(
                "error", "joern:guard-dominance", errors=["boom"],
            ),
        )
        confirmed = self._run(
            tmp_path,
            [{"type": "joern_guard", "config": {"sinks": ["memcpy"]}}],
            self.HYP_GUARD, counters,
        )
        assert confirmed == []
        assert counters["joern_guard"].errors == 1

    def test_guard_no_binding_skips_without_running(
        self, tmp_path, counters, monkeypatch,
    ):
        import core.audit.joern_verify as jv

        def _explode(**kw):
            raise AssertionError("must not run without binding")

        monkeypatch.setattr(jv, "run_guard_dominance_check", _explode)
        confirmed = self._run(
            tmp_path,
            [{"type": "joern_guard", "config": {"sinks": ["memcpy"]}}],
            "something vague about safety", counters,
        )
        assert confirmed == []
        assert counters["joern_guard"].skipped == 1

    def test_guard_no_server_skips(self, tmp_path, counters, monkeypatch):
        import core.audit.joern_verify as jv

        def _explode(**kw):
            raise AssertionError("must not run without a server")

        monkeypatch.setattr(jv, "run_guard_dominance_check", _explode)
        confirmed = self._run(
            tmp_path,
            [{"type": "joern_guard", "config": {"sinks": ["memcpy"]}}],
            self.HYP_GUARD, counters, server=None,
        )
        assert confirmed == []
        assert counters["joern_guard"].skipped == 1

    def test_flow_confirm_stamps(self, tmp_path, counters, monkeypatch):
        import core.audit.joern_verify as jv
        seen = {}

        def fake_flow(**kw):
            seen.update(kw)
            return _mk_result(
                "confirmed", "joern:flow", matches=[{"steps": []}],
            )

        monkeypatch.setattr(jv, "run_flow_reachability_check", fake_flow)
        confirmed = self._run(
            tmp_path,
            [{"type": "joern_flow", "config": {"sinks": ["system"]}}],
            self.HYP_FLOW, counters,
        )
        assert confirmed == ["joern:flow"]
        assert seen["source_id"] == "argv"
        assert seen["sink_call"] == "system"
        assert counters["joern_flow"].confirmed == 1

    def test_flow_inconclusive_counts(self, tmp_path, counters, monkeypatch):
        import core.audit.joern_verify as jv
        monkeypatch.setattr(
            jv, "run_flow_reachability_check",
            lambda **kw: _mk_result("inconclusive", "joern:flow"),
        )
        confirmed = self._run(
            tmp_path,
            [{"type": "joern_flow", "config": {"sinks": ["system"]}}],
            self.HYP_FLOW, counters,
        )
        assert confirmed == []
        assert counters["joern_flow"].inconclusive == 1

    def test_cocci_flow_confirm_stamps_coccinelle_namespace(
        self, tmp_path, counters, monkeypatch,
    ):
        import core.audit.cocci_flow as cf
        monkeypatch.setattr(
            cf, "run_flow_cocci_sweep",
            lambda **kw: SweepResult(
                tool="coccinelle_flow", file_path="src/a.c",
                function_name="f", outcome="confirmed",
                matches=[{"line": 9}],
                rule_id="cocci-flow:use_after_free",
            ),
        )
        confirmed = self._run(
            tmp_path,
            [{"type": "coccinelle_flow",
              "config": {"template": "use_after_free"}}],
            self.HYP_UAF, counters,
        )
        assert confirmed == ["coccinelle:flow-use_after_free"]
        assert counters["coccinelle_flow"].confirmed == 1
        # The stamp must count as tool evidence and must be allowed to
        # promote (dynamic rules are not detection-only).
        from core.audit.evidence_grade import is_tool_evidence
        from core.audit.orchestrator import _is_detection_only
        assert is_tool_evidence(confirmed[0])
        assert not _is_detection_only(confirmed[0])

    def test_cocci_flow_error_never_confirms(
        self, tmp_path, counters, monkeypatch,
    ):
        import core.audit.cocci_flow as cf
        monkeypatch.setattr(
            cf, "run_flow_cocci_sweep",
            lambda **kw: SweepResult(
                tool="coccinelle_flow", file_path="src/a.c",
                function_name="f", outcome="error",
                errors=["parse error"],
                rule_id="cocci-flow:use_after_free",
            ),
        )
        confirmed = self._run(
            tmp_path,
            [{"type": "coccinelle_flow",
              "config": {"template": "use_after_free"}}],
            self.HYP_UAF, counters,
        )
        assert confirmed == []
        assert counters["coccinelle_flow"].errors == 1

    def test_channel_exception_does_not_break_chain(
        self, tmp_path, counters, monkeypatch,
    ):
        import core.audit.joern_verify as jv

        def _boom(**kw):
            raise RuntimeError("channel exploded")

        monkeypatch.setattr(jv, "run_guard_dominance_check", _boom)
        # A later entry must still run.
        import core.audit.cocci_flow as cf
        monkeypatch.setattr(
            cf, "run_flow_cocci_sweep",
            lambda **kw: SweepResult(
                tool="coccinelle_flow", file_path="src/a.c",
                function_name="f", outcome="confirmed",
                matches=[{"line": 9}],
                rule_id="cocci-flow:use_after_free",
            ),
        )
        confirmed = self._run(
            tmp_path,
            [
                {"type": "joern_guard", "config": {"sinks": ["memcpy"]}},
                {"type": "coccinelle_flow",
                 "config": {"template": "use_after_free"}},
            ],
            self.HYP_GUARD + " and use-after-free of `conn`",
            counters,
        )
        assert confirmed == ["coccinelle:flow-use_after_free"]


class TestReceiptEntries:
    def test_guard_receipt_description(self):
        from core.audit.evidence_grade import grade_review_result

        items = grade_review_result(
            {"hypothesis": "h"}, evidence_tool="joern:guard-dominance",
        )
        tool_items = [i for i in items if i.source.value == "mechanical:joern"]
        assert tool_items
        assert "dominat" in tool_items[0].description

    def test_flow_receipt_description(self):
        from core.audit.evidence_grade import grade_review_result

        items = grade_review_result(
            {"hypothesis": "h"}, evidence_tool="joern:flow",
        )
        tool_items = [i for i in items if i.source.value == "mechanical:joern"]
        assert tool_items
        assert "reachableByFlows" in tool_items[0].description


class TestLifecycleChannelChainEmission:
    """Phase-A lifecycle channels (ptr_lifecycle / lock_region):
    classifier stanzas, CWE fallback membership, tier keys — additive
    wiring per the five-channel programme."""

    def test_ptr_lifecycle_owned_cwes(self):
        for cwe in ("CWE-825", "CWE-672"):
            assert "ptr_lifecycle" in _types(_cwe_fallback_chain(cwe)), cwe

    def test_cwe_416_membership_is_additive(self):
        types = _types(_cwe_fallback_chain("CWE-416"))
        assert "ptr_lifecycle" in types
        # The existing rich entry keeps its channels.
        assert "coccinelle_flow" in types
        assert "smt" in types

    def test_lock_region_owned_cwe(self):
        assert "lock_region" in _types(_cwe_fallback_chain("CWE-833"))

    def test_cwe_667_membership_is_additive(self):
        types = _types(_cwe_fallback_chain("CWE-667"))
        assert "lock_region" in types
        assert "smt" in types
        assert "coccinelle" in types

    def test_hypothesis_dispatches_ptr_lifecycle(self):
        chain = _hypothesis_to_tool_chain(
            "stale pointer: `obj->port` cached alias outlives the "
            "freed engine",
            "src/a.c",
        )
        assert "ptr_lifecycle" in _types(chain)
        assert "lock_region" not in _types(chain)

    def test_hypothesis_dispatches_lock_region(self):
        chain = _hypothesis_to_tool_chain(
            "the remove callback is invoked while the lock is held",
            "src/a.c",
        )
        assert "lock_region" in _types(chain)
        assert "ptr_lifecycle" not in _types(chain)

    def test_cross_channel_negatives(self):
        # Plain use-after-free stays with the CWE-416 tool chain; a
        # majority claim stays consistency; neither dispatches the
        # new channels by keyword.
        for hyp in (
            "use-after-free of `conn` in handler",
            "9/10 other callers check do_auth()'s return; this one "
            "discards it",
        ):
            types = _types(_hypothesis_to_tool_chain(hyp, "src/a.c"))
            assert "ptr_lifecycle" not in types, hyp
            assert "lock_region" not in types, hyp

    def test_tier_counters_exist(self):
        counters = orch._make_tier_counters()
        assert "ptr_lifecycle" in counters
        assert "lock_region" in counters

    def test_cheap_lane_membership(self):
        assert "ptr_lifecycle" in orch._REFUTED_CHEAP_CHANNELS
        assert "lock_region" in orch._REFUTED_CHEAP_CHANNELS

    def test_detection_only_variants(self):
        from core.audit.orchestrator import _is_detection_only
        assert _is_detection_only("ptr_lifecycle:stale-alias-naming")
        assert not _is_detection_only("ptr_lifecycle:stale-alias")
        assert _is_detection_only(
            "lock_region:callback-under-lock-naming",
        )
        assert not _is_detection_only("lock_region:callback-under-lock")

    def test_stamps_are_tool_evidence(self):
        from core.audit.evidence_grade import is_tool_evidence
        for stamp in (
            "ptr_lifecycle:stale-alias",
            "lock_region:callback-under-lock",
        ):
            assert is_tool_evidence(stamp), stamp
        # The -naming variants are detection-grade by each channel's
        # own is_detection_rule_id — they may ride in a composite with
        # a real receipt but are never full tool evidence alone.
        for stamp in (
            "ptr_lifecycle:stale-alias-naming",
            "lock_region:callback-under-lock-naming",
        ):
            assert not is_tool_evidence(stamp), stamp
            assert is_tool_evidence(f"coccinelle+{stamp}"), stamp

    def test_receipt_descriptions(self):
        from core.audit.evidence_grade import grade_review_result
        items = grade_review_result(
            {"hypothesis": "h"},
            evidence_tool="ptr_lifecycle:stale-alias",
        )
        assert any("alias" in i.description for i in items)
        items = grade_review_result(
            {"hypothesis": "h"},
            evidence_tool="lock_region:callback-under-lock",
        )
        assert any("lock" in i.description for i in items)


class TestLifecycleChannelDispatch:
    """_run_tool_chain branches for the phase-A channels, entry points
    monkeypatched so nothing external runs."""

    HYP_STALE = "stale pointer: cached alias outlives the freed owner"
    HYP_LOCK = "callback invoked while the lock is held"

    @pytest.fixture()
    def lifecycle_counters(self):
        return {
            "ptr_lifecycle": TierCounters(),
            "lock_region": TierCounters(),
        }

    def _run(self, tmp_path, chain, hypothesis, counters):
        return _run_tool_chain(
            chain,
            config=_Cfg(tmp_path),
            file_path="src/a.c",
            function_name="f",
            source="",
            hypothesis=hypothesis,
            tier_counters=counters,
            joern_server=None,
        )

    @staticmethod
    def _alias_res(outcome, rule_id="ptr_lifecycle:stale-alias"):
        from core.audit.ptr_lifecycle import AliasEvidence
        return AliasEvidence(
            outcome=outcome, reason="stubbed", rule_id=rule_id,
        )

    @staticmethod
    def _lock_res(outcome, rule_id="lock_region:callback-under-lock"):
        from core.audit.lock_region import LockRegionEvidence
        return LockRegionEvidence(
            outcome=outcome, reason="stubbed", rule_id=rule_id,
            lock={"acquire": "a_lock", "release": "a_unlock"},
        )

    def test_ptr_lifecycle_confirm_stamps(
        self, tmp_path, lifecycle_counters, monkeypatch,
    ):
        import core.audit.ptr_lifecycle as plmod
        monkeypatch.setattr(
            plmod, "run_ptr_lifecycle_check",
            lambda *a, **kw: self._alias_res("confirmed"),
        )
        confirmed = self._run(
            tmp_path,
            [{"type": "ptr_lifecycle", "config": {}}],
            self.HYP_STALE, lifecycle_counters,
        )
        assert confirmed == ["ptr_lifecycle:stale-alias"]
        assert lifecycle_counters["ptr_lifecycle"].confirmed == 1

    def test_ptr_lifecycle_inconclusive_never_confirms(
        self, tmp_path, lifecycle_counters, monkeypatch,
    ):
        import core.audit.ptr_lifecycle as plmod
        monkeypatch.setattr(
            plmod, "run_ptr_lifecycle_check",
            lambda *a, **kw: self._alias_res("inconclusive"),
        )
        confirmed = self._run(
            tmp_path,
            [{"type": "ptr_lifecycle", "config": {}}],
            self.HYP_STALE, lifecycle_counters,
        )
        assert confirmed == []
        assert lifecycle_counters["ptr_lifecycle"].inconclusive == 1

    def test_lock_region_confirm_adds_cocci_corroboration(
        self, tmp_path, lifecycle_counters, monkeypatch,
    ):
        import core.audit.lock_region as lrmod
        monkeypatch.setattr(
            lrmod, "run_lock_region_check",
            lambda *a, **kw: self._lock_res("confirmed"),
        )
        monkeypatch.setattr(
            lrmod, "cocci_corroboration",
            lambda *a, **kw: "coccinelle:callback_under_lock",
        )
        confirmed = self._run(
            tmp_path,
            [{"type": "lock_region", "config": {}}],
            self.HYP_LOCK, lifecycle_counters,
        )
        # Two INDEPENDENT namespaces: the channel receipt plus the
        # parametric cocci stamp (the aggregation shape).
        assert confirmed == [
            "lock_region:callback-under-lock",
            "coccinelle:callback_under_lock",
        ]
        assert lifecycle_counters["lock_region"].confirmed == 1

    def test_lock_region_refuted_skips_cocci(
        self, tmp_path, lifecycle_counters, monkeypatch,
    ):
        import core.audit.lock_region as lrmod
        monkeypatch.setattr(
            lrmod, "run_lock_region_check",
            lambda *a, **kw: self._lock_res("refuted"),
        )

        def _explode(*a, **kw):
            raise AssertionError("cocci leg must not run on refuted")

        monkeypatch.setattr(lrmod, "cocci_corroboration", _explode)
        confirmed = self._run(
            tmp_path,
            [{"type": "lock_region", "config": {}}],
            self.HYP_LOCK, lifecycle_counters,
        )
        assert confirmed == []
        assert lifecycle_counters["lock_region"].refuted == 1

    def test_channel_exception_does_not_break_chain(
        self, tmp_path, lifecycle_counters, monkeypatch,
    ):
        import core.audit.lock_region as lrmod
        import core.audit.ptr_lifecycle as plmod

        def _boom(*a, **kw):
            raise RuntimeError("channel exploded")

        monkeypatch.setattr(plmod, "run_ptr_lifecycle_check", _boom)
        monkeypatch.setattr(
            lrmod, "run_lock_region_check",
            lambda *a, **kw: self._lock_res("confirmed"),
        )
        monkeypatch.setattr(
            lrmod, "cocci_corroboration", lambda *a, **kw: None,
        )
        confirmed = self._run(
            tmp_path,
            [
                {"type": "ptr_lifecycle", "config": {}},
                {"type": "lock_region", "config": {}},
            ],
            self.HYP_STALE + " and " + self.HYP_LOCK,
            lifecycle_counters,
        )
        assert confirmed == ["lock_region:callback-under-lock"]


class TestResourceBoundsWiring:
    """Five-channel programme: resource_bounds chain wiring (§9)."""

    HYP = "the session list grows without limit — memory exhaustion"

    def test_cwe_fallback_emits_channel(self):
        for cwe in ("CWE-770", "CWE-400", "CWE-772"):
            assert "resource_bounds" in _types(_cwe_fallback_chain(cwe)), cwe

    def test_hypothesis_chain_emits_channel(self):
        chain = _hypothesis_to_tool_chain(self.HYP, "src/a.c")
        assert "resource_bounds" in _types(chain)

    def test_cross_channel_negatives(self):
        # A fail-open / consistency / memcpy hypothesis must not
        # dispatch resource_bounds.
        for hyp in (
            "the broad except swallows verification errors",
            "9/10 callers check do_auth()'s return; this one discards it",
            "unchecked memcpy overflow of `dst`",
        ):
            chain = _hypothesis_to_tool_chain(hyp, "src/a.c")
            assert "resource_bounds" not in _types(chain), hyp

    def test_tier_counter_exists(self):
        assert "resource_bounds" in orch._make_tier_counters()

    def test_cheap_lane_membership(self):
        assert "resource_bounds" in orch._REFUTED_CHEAP_CHANNELS

    def test_namespace_and_receipts(self):
        from core.audit.evidence_grade import (
            _RECEIPT_MAP,
            is_tool_evidence,
        )
        assert is_tool_evidence("resource_bounds:unbounded-accumulation")
        assert "resource_bounds:unbounded-accumulation" in _RECEIPT_MAP
        assert "resource_bounds" in _RECEIPT_MAP

    def test_detection_variant_never_tool_evidence_alone(self):
        from core.audit.evidence_grade import is_tool_evidence
        from core.audit.orchestrator import _is_detection_only
        naming = "resource_bounds:unbounded-accumulation-naming"
        assert not is_tool_evidence(naming)
        assert _is_detection_only(naming)
        assert not _is_detection_only(
            "resource_bounds:unbounded-accumulation",
        )
        # In an aggregation composite the variant may ride along.
        assert is_tool_evidence("joern+" + naming)

    def test_detection_variant_solo_promotion_trips_alarm(self, tmp_path):
        from types import SimpleNamespace

        from core.audit.promotion_alarm import check_and_emit
        record = check_and_emit(
            tmp_path,
            SimpleNamespace(
                file="src/a.c", function="f", status="finding",
                evidence_tool=(
                    "resource_bounds:unbounded-accumulation-naming"
                ),
                review_result=None, hypothesis=self.HYP,
            ),
            stage="test",
        )
        assert record is not None
        assert record["event"] == "promotion_without_tool_evidence"

    def test_run_tool_chain_dispatch(self, tmp_path, monkeypatch):
        import core.audit.resource_bounds as rb

        class _Res:
            outcome = "confirmed"
            reason = "r"
            rule_id = "resource_bounds:unbounded-accumulation"
            corroboration = []

            def to_dict(self):
                return {"outcome": self.outcome}

        monkeypatch.setattr(
            rb, "run_resource_bounds_check", lambda *a, **kw: _Res(),
        )
        counters = {"resource_bounds": TierCounters()}
        confirmed = _run_tool_chain(
            [{"type": "resource_bounds", "config": {}}],
            config=_Cfg(tmp_path),
            file_path="src/a.c",
            function_name="f",
            source="",
            hypothesis=self.HYP,
            tier_counters=counters,
        )
        assert confirmed == ["resource_bounds:unbounded-accumulation"]
        assert counters["resource_bounds"].confirmed == 1


class TestReleaseOrderWiring:
    """Five-channel programme: release_order chain wiring (§9)."""

    HYP = ("decrypted chunks are written to `out` before the cipher "
           "status is verified")

    def test_cwe_fallback_emits_channel(self):
        for cwe in ("CWE-354", "CWE-347", "CWE-345"):
            assert "release_order" in _types(_cwe_fallback_chain(cwe)), cwe

    def test_cwe_345_keeps_fail_open_membership(self):
        types = _types(_cwe_fallback_chain("CWE-345"))
        assert "fail_open" in types
        assert "release_order" in types

    def test_hypothesis_chain_emits_channel(self):
        chain = _hypothesis_to_tool_chain(self.HYP, "src/a.c")
        assert "release_order" in _types(chain)

    def test_cross_channel_negatives(self):
        # A resource_bounds hypothesis must not dispatch release_order
        # and vice versa.
        chain = _hypothesis_to_tool_chain(
            "the session list grows without limit", "src/a.c",
        )
        assert "release_order" not in _types(chain)
        chain = _hypothesis_to_tool_chain(self.HYP, "src/a.c")
        assert "resource_bounds" not in _types(chain)

    def test_tier_counter_and_cheap_lane(self):
        assert "release_order" in orch._make_tier_counters()
        assert "release_order" in orch._REFUTED_CHEAP_CHANNELS

    def test_namespace_receipts_and_detection_variant(self):
        from core.audit.evidence_grade import (
            _RECEIPT_MAP,
            is_tool_evidence,
        )
        from core.audit.orchestrator import _is_detection_only
        assert is_tool_evidence("release_order:release-before-verify")
        assert "release_order:release-before-verify" in _RECEIPT_MAP
        assert "release_order" in _RECEIPT_MAP
        naming = "release_order:release-before-verify-naming"
        assert not is_tool_evidence(naming)
        assert _is_detection_only(naming)
        assert not _is_detection_only(
            "release_order:release-before-verify",
        )

    def test_detection_variant_solo_promotion_trips_alarm(self, tmp_path):
        from types import SimpleNamespace

        from core.audit.promotion_alarm import check_and_emit
        record = check_and_emit(
            tmp_path,
            SimpleNamespace(
                file="src/a.c", function="f", status="finding",
                evidence_tool=(
                    "release_order:release-before-verify-naming"
                ),
                review_result=None, hypothesis=self.HYP,
            ),
            stage="test",
        )
        assert record is not None

    def test_run_tool_chain_dispatch_passes_joern_server(
        self, tmp_path, monkeypatch,
    ):
        import core.audit.release_order as ro

        seen = {}

        class _Res:
            outcome = "confirmed"
            reason = "r"
            rule_id = "release_order:release-before-verify"
            corroboration = []

            def to_dict(self):
                return {"outcome": self.outcome}

        def _fake(*a, **kw):
            seen.update(kw)
            return _Res()

        monkeypatch.setattr(ro, "run_release_order_check", _fake)
        counters = {"release_order": TierCounters()}
        server = object()
        confirmed = _run_tool_chain(
            [{"type": "release_order", "config": {}}],
            config=_Cfg(tmp_path),
            file_path="src/a.c",
            function_name="f",
            source="",
            hypothesis=self.HYP,
            tier_counters=counters,
            joern_server=server,
        )
        assert confirmed == ["release_order:release-before-verify"]
        assert seen["joern_server"] is server
        assert counters["release_order"].confirmed == 1


class TestProtocolStateWiring:
    """Five-channel programme: protocol_state chain wiring, including
    the smt_invariant precedence pair (§4.5/§9)."""

    HYP_INV = (
        "the protocol invariant largest_acked_pkt <= highest_sent can "
        "be violated: the peer can acknowledge packets never sent"
    )
    HYP_PROSE = "the peer controls the congestion state counter"

    def test_cwe_fallback_emits_channel(self):
        assert "protocol_state" in _types(_cwe_fallback_chain("CWE-372"))

    def test_state_invariant_precedence_over_smt_invariant(self):
        chain = _hypothesis_to_tool_chain(self.HYP_INV, "src/a.c")
        types = _types(chain)
        assert "protocol_state" in types
        # The census-driven harness claims the invariant slot — the
        # single-function harness must NOT double-run.
        assert "smt_invariant" not in types
        entry = next(e for e in chain if e["type"] == "protocol_state")
        assert entry["config"]["invariant"] == (
            "largest_acked_pkt <= highest_sent"
        )

    def test_local_invariant_still_routes_to_smt_invariant(self):
        # Regression guard for the landed channel: a plain local
        # buffer invariant keeps the single-function harness.
        chain = _hypothesis_to_tool_chain(
            "the buffer maintains obuf_len <= obuf_size at all times",
            "src/a.c",
        )
        types = _types(chain)
        assert "smt_invariant" in types
        assert "protocol_state" not in types

    def test_prose_shape_emits_without_invariant_config(self):
        chain = _hypothesis_to_tool_chain(self.HYP_PROSE, "src/a.c")
        entry = next(e for e in chain if e["type"] == "protocol_state")
        assert "invariant" not in entry["config"]

    def test_cross_channel_negatives(self):
        for hyp in (
            "decrypted chunks are written before the MAC is verified",
            "the session list grows without limit",
        ):
            chain = _hypothesis_to_tool_chain(hyp, "src/a.c")
            assert "protocol_state" not in _types(chain), hyp

    def test_tier_counter_and_cheap_lane(self):
        assert "protocol_state" in orch._make_tier_counters()
        assert "protocol_state" in orch._REFUTED_CHEAP_CHANNELS

    def test_namespace_receipts_and_detection_grades(self):
        from core.audit.evidence_grade import (
            _RECEIPT_MAP,
            is_tool_evidence,
        )
        from core.audit.orchestrator import _is_detection_only
        assert is_tool_evidence("protocol_state:invariant-violated")
        assert "protocol_state:invariant-violated" in _RECEIPT_MAP
        assert "protocol_state" in _RECEIPT_MAP
        for detection in (
            "protocol_state:invariant-violated-unreceipted",
            "protocol_state:dead-state-field",
            "protocol_state:unvalidated-peer-write",
        ):
            assert not is_tool_evidence(detection), detection
            assert _is_detection_only(detection), detection
        assert not _is_detection_only(
            "protocol_state:invariant-violated",
        )

    def test_lead_plus_lead_never_promotes(self):
        # The §9 aggregation firewall: two protocol_state leads share
        # ONE namespace.
        channels, _mean = orch._aggregate_channel_confirmations([
            "protocol_state:dead-state-field",
            "protocol_state:unvalidated-peer-write",
        ])
        assert channels == []
        # An independent namespace joining does aggregate.
        channels, _mean = orch._aggregate_channel_confirmations([
            "protocol_state:unvalidated-peer-write",
            "joern:flow",
        ])
        assert channels == ["joern", "protocol_state"]

    def test_detection_variant_solo_promotion_trips_alarm(self, tmp_path):
        from types import SimpleNamespace

        from core.audit.promotion_alarm import check_and_emit
        for stamp in (
            "protocol_state:invariant-violated-unreceipted",
            "protocol_state:dead-state-field",
            "protocol_state:unvalidated-peer-write",
        ):
            record = check_and_emit(
                tmp_path,
                SimpleNamespace(
                    file="src/a.c", function="f", status="finding",
                    evidence_tool=stamp,
                    review_result=None, hypothesis=self.HYP_PROSE,
                ),
                stage="test",
            )
            assert record is not None, stamp

    def test_run_tool_chain_dispatch_passes_invariant(
        self, tmp_path, monkeypatch,
    ):
        import core.audit.protocol_state as ps

        seen = {}

        class _Res:
            outcome = "confirmed"
            reason = "r"
            rule_id = "protocol_state:invariant-violated"
            corroboration = []

            def to_dict(self):
                return {"outcome": self.outcome}

        def _fake(*a, **kw):
            seen.update(kw)
            return _Res()

        monkeypatch.setattr(ps, "run_protocol_state_check", _fake)
        counters = {"protocol_state": TierCounters()}
        confirmed = _run_tool_chain(
            [{"type": "protocol_state",
              "config": {"invariant": "a_acked <= b_sent"}}],
            config=_Cfg(tmp_path),
            file_path="src/a.c",
            function_name="f",
            source="",
            hypothesis=self.HYP_INV,
            tier_counters=counters,
        )
        assert confirmed == ["protocol_state:invariant-violated"]
        assert seen["invariant"] == "a_acked <= b_sent"
        assert counters["protocol_state"].confirmed == 1
