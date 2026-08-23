"""ptr_lifecycle channel tests (five-channel programme §3).

Fixture pairs, CVE-anchored (CVE-2023-0215 BIO_new_NDEF shape for the
leg-B stale alias; the quic peeloff shape for leg-A parity), asserting
full receipts on the deviant form and the exact enumerated reason
string on the twin — the consistency test discipline. Hermetic: no
subprocesses, no LLM.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.audit import ptr_lifecycle as pl
from core.audit.field_census import TIER_REGEX, build_field_census
from core.audit.ptr_lifecycle import (
    DETECTION_VARIANT_SUFFIX,
    PTR_LIFECYCLE_CWES,
    RULE_STALE_ALIAS,
    detect_field_parity_deviations,
    is_detection_rule_id,
    is_ptr_lifecycle_hypothesis,
    ptr_lifecycle_applicable,
    run_ptr_lifecycle_check,
    run_ptr_lifecycle_prepass,
)


def _ts_available() -> bool:
    from core.audit.callsite_consistency import parse_source_cached
    tree, _ = parse_source_cached("probe.c", "int f(void) { return 0; }")
    return tree is not None


requires_ts = pytest.mark.skipif(
    not _ts_available(), reason="tree-sitter C grammar unavailable",
)


class _Vocab:
    """Learned-vocabulary stand-in (DomainVocabulary duck type)."""

    def __init__(self, deallocators=(), refcount_puts=()):
        self.deallocators = frozenset(deallocators)
        self.refcount_puts = frozenset(refcount_puts)


# CVE-2023-0215 anchor: BIO_new_NDEF leaves a cached alias dangling
# after the failure-path free; the accessor still returns it.
BIO_SHAPE = """
int ndef_setup(struct ctx *c, struct bio *b) {
    c->cached = b->pool;
    if (init_failed(b)) {
        BIO_free(b);
        return 0;
    }
    return 1;
}
struct pool *ctx_pool(struct ctx *h) {
    return h->cached;
}
"""

BIO_TWIN = BIO_SHAPE.replace(
    "        BIO_free(b);\n",
    "        BIO_free(b);\n        c->cached = NULL;\n",
)

PEELOFF = """
void peel_off(struct ch *obj, struct ch *tmp) {
    obj->engine = tmp->engine;
    obj->mux = tmp->mux;
    obj->tls = tmp->tls;
}
void ch_init(struct ch *obj, struct prt *p) {
    obj->port = p;
}
struct prt *ch_get_port(struct ch *c) {
    return c->port;
}
"""

PEELOFF_TWIN = PEELOFF.replace(
    "    obj->tls = tmp->tls;\n",
    "    obj->tls = tmp->tls;\n    obj->port = tmp->port;\n",
)

RCU_SHAPE = """
void reclaim(struct s *o) {
    struct n *p = rcu_dereference(o->node);
    kfree_rcu(o, rcu);
    consume(p);
}
"""

HYP = "stale pointer: the cached alias outlives the freed owner"


class TestClassifier:
    @pytest.mark.parametrize("text", [
        "stale pointer left in the cached field",
        "dangling reference: obj->port outlives the engine swap",
        "freed object is still read through the accessor later",
        "sibling fields re-targeted but port not reassigned "
        "(other field)",
        "the peel-off leaves the old referent reachable",
    ])
    def test_accepts(self, text):
        assert is_ptr_lifecycle_hypothesis(text)

    @pytest.mark.parametrize("text", [
        "",
        "use-after-free of `conn` in handler",          # CWE-416 chain
        "unchecked memcpy overflow",                     # bounds family
        "9/10 callers check do_auth()'s return",         # consistency
        "callback invoked while holding the lock",       # lock_region
    ])
    def test_rejects(self, text):
        assert not is_ptr_lifecycle_hypothesis(text)

    def test_cwe_membership(self):
        assert PTR_LIFECYCLE_CWES == {"CWE-825", "CWE-672", "CWE-416"}
        for cwe in ("CWE-825", "cwe-672", "416"):
            assert ptr_lifecycle_applicable(cwe)
        assert not ptr_lifecycle_applicable("CWE-415")

    def test_detection_rule_id(self):
        assert is_detection_rule_id(
            RULE_STALE_ALIAS + DETECTION_VARIANT_SUFFIX,
        )
        assert not is_detection_rule_id(RULE_STALE_ALIAS)
        assert not is_detection_rule_id("consistency:field-parity-majority")


@requires_ts
class TestLegBStaleAlias:
    def test_cve_2023_0215_shape_confirms_with_four_receipts(self):
        res = run_ptr_lifecycle_check(
            Path("/nonexistent"), "src/bio.c", "ndef_setup", HYP,
            source_texts={"src/bio.c": BIO_SHAPE},
            domain_vocab=_Vocab(deallocators={"BIO_free"}),
        )
        assert res.outcome == "confirmed"
        assert res.rule_id == RULE_STALE_ALIAS  # learned vocab: registry
        assert res.cwe == "CWE-416"             # dark-verify carrier
        d = res.to_dict()
        # The four structural receipts.
        assert d["alias"]["assign_site"]["line"] == 3
        assert d["alias"]["name"] == "cached"
        assert d["event"]["verb"] == "BIO_free"
        assert d["event"]["vocab_source"] == "learned"
        assert d["invalidation_search"]["found"] is None
        assert d["post_event_reads"][0]["function"] == "ctx_pool"
        assert d["owner"] == {"name": "b", "field": "pool"}

    def test_null_write_twin_refutes_with_receipt(self):
        res = run_ptr_lifecycle_check(
            Path("/nonexistent"), "src/bio.c", "ndef_setup", HYP,
            source_texts={"src/bio.c": BIO_TWIN},
            domain_vocab=_Vocab(deallocators={"BIO_free"}),
        )
        assert res.outcome == "refuted"
        assert "invalidated" in res.reason
        assert res.to_dict()["invalidation_search"]["kind"] == \
            "null-write"

    def test_naming_only_event_verb_is_detection_variant(self):
        # Vocab-policy: with no learned inputs, the target-specific
        # BIO_free binds only through the *_free naming stem — the
        # confirmation degrades to the -naming detection rule-id
        # (proves no hidden hardcoded project vocabulary).
        res = run_ptr_lifecycle_check(
            Path("/nonexistent"), "src/bio.c", "ndef_setup", HYP,
            source_texts={"src/bio.c": BIO_SHAPE},
            domain_vocab=None,
        )
        assert res.outcome == "confirmed"
        assert res.rule_id == RULE_STALE_ALIAS + DETECTION_VARIANT_SUFFIX
        assert res.to_dict()["event"]["vocab_source"] == "naming"

    def test_seed_deallocator_is_registry_grade(self):
        src = BIO_SHAPE.replace("BIO_free", "free")
        res = run_ptr_lifecycle_check(
            Path("/nonexistent"), "src/bio.c", "ndef_setup", HYP,
            source_texts={"src/bio.c": src},
        )
        assert res.outcome == "confirmed"
        assert res.rule_id == RULE_STALE_ALIAS
        assert res.to_dict()["event"]["vocab_source"] == "seed"

    def test_kfree_rcu_on_rcu_alias_refutes(self):
        res = run_ptr_lifecycle_check(
            Path("/nonexistent"), "src/r.c", "reclaim",
            "dangling pointer p read after the free",
            source_texts={"src/r.c": RCU_SHAPE},
        )
        assert res.outcome == "refuted"
        assert "rcu-safe deferred free" in res.reason

    def test_no_post_event_read_refutes(self):
        src = (
            "void f(struct ctx *c, struct bio *b) {\n"
            "    c->cached = b->pool;\n"
            "    free(b);\n"
            "}\n"
        )
        res = run_ptr_lifecycle_check(
            Path("/nonexistent"), "a.c", "f", HYP,
            source_texts={"a.c": src},
        )
        assert res.outcome == "refuted"
        assert "no post-event read" in res.reason

    def test_local_alias_escape_is_ownership_inconclusive(self):
        src = (
            "void f(struct s *o) {\n"
            "    struct n *p = o->node;\n"
            "    hand_off(p);\n"
            "    free(o);\n"
            "    consume(p);\n"
            "}\n"
        )
        res = run_ptr_lifecycle_check(
            Path("/nonexistent"), "a.c", "f",
            "stale pointer p outlives o",
            source_texts={"a.c": src},
        )
        assert res.outcome == "inconclusive"
        assert res.reason.startswith(pl.REASON_ALIAS_ESCAPES)

    def test_event_vocab_unbound(self):
        src = (
            "void f(struct s *o) {\n"
            "    struct n *p = o->node;\n"
            "    consume(p);\n"
            "}\n"
        )
        res = run_ptr_lifecycle_check(
            Path("/nonexistent"), "a.c", "f", HYP,
            source_texts={"a.c": src},
        )
        assert res.outcome == "inconclusive"
        assert res.reason.startswith(pl.REASON_EVENT_VOCAB_UNBOUND)

    def test_language_unsupported(self):
        res = run_ptr_lifecycle_check(
            Path("/nonexistent"), "a.py", "f", HYP,
            source_texts={"a.py": "x = 1\n"},
        )
        assert res.outcome == "inconclusive"
        assert res.reason.startswith(pl.REASON_LANGUAGE_UNSUPPORTED)

    def test_degraded_census_never_confirms(self):
        census = build_field_census({"src/bio.c": BIO_SHAPE})
        census.tier = TIER_REGEX
        res = run_ptr_lifecycle_check(
            Path("/nonexistent"), "src/bio.c", "ndef_setup", HYP,
            source_texts={"src/bio.c": BIO_SHAPE},
            census=census,
            domain_vocab=_Vocab(deallocators={"BIO_free"}),
        )
        assert res.outcome == "inconclusive"
        assert res.reason.startswith(pl.REASON_CENSUS_INCOMPLETE)

    def test_reachability_escalator_rides_confirmation(self):
        from core.audit.fail_open_roles import RoleContext
        ctx = RoleContext(context_map={"entry_points": [
            {"function": "ndef_setup", "file": "src/bio.c"},
        ]})
        res = run_ptr_lifecycle_check(
            Path("/nonexistent"), "src/bio.c", "ndef_setup", HYP,
            source_texts={"src/bio.c": BIO_SHAPE},
            domain_vocab=_Vocab(deallocators={"BIO_free"}),
            context=ctx,
        )
        assert res.outcome == "confirmed"
        assert res.reachability["status"] == "entry_reachable"


@requires_ts
class TestLegAFieldParity:
    def test_peeloff_shape_emits_consistency_namespace_receipt(self):
        census = build_field_census({"src/ch.c": PEELOFF})
        devs = detect_field_parity_deviations(census)
        assert len(devs) == 1
        dev = devs[0]
        assert dev.field == "port"
        assert dev.cluster_fields == ("engine", "mux", "tls")
        pe = dev.peer_evidence
        # The namespace split: parity is a majority statistic, so the
        # receipt lands under the consistency namespace by
        # construction — never a ptr_lifecycle rule-id.
        assert pe.rule_id == "consistency:field-parity-majority"
        assert not pe.registry_grade
        assert pe.contract_source == "majority"
        assert pe.n == 4 and pe.conforming == 3
        assert pe.deviant is not None

    def test_reassigned_twin_yields_no_deviation(self):
        census = build_field_census({"src/ch.c": PEELOFF_TWIN})
        assert detect_field_parity_deviations(census) == []

    def test_cluster_below_threshold_yields_nothing(self):
        two_field = PEELOFF.replace("    obj->tls = tmp->tls;\n", "")
        census = build_field_census({"src/ch.c": two_field})
        assert detect_field_parity_deviations(census) == []

    def test_parity_rule_id_is_detection_only_everywhere(self):
        from core.audit.evidence_grade import is_tool_evidence
        from core.audit.orchestrator import _is_detection_only
        rule = "consistency:field-parity-majority"
        # Alone it is a statistical prior, not tool evidence; inside
        # a composite it may ride along (existing consistency
        # machinery, zero edits to landed files).
        assert not is_tool_evidence(rule)
        assert is_tool_evidence(f"{rule}+ptr_lifecycle:stale-alias")
        assert _is_detection_only(rule)


class TestAggregationFirewall:
    def test_leg_a_plus_leg_b_are_two_namespaces(self):
        from core.audit.orchestrator import (
            _aggregate_channel_confirmations,
        )
        channels, mean = _aggregate_channel_confirmations([
            "consistency:field-parity-majority",
            "ptr_lifecycle:stale-alias" + DETECTION_VARIANT_SUFFIX,
        ])
        assert channels == ["consistency", "ptr_lifecycle"]
        assert mean > 0.0

    def test_two_leg_a_receipts_do_not_self_corroborate(self):
        from core.audit.orchestrator import (
            _aggregate_channel_confirmations,
        )
        channels, _ = _aggregate_channel_confirmations([
            "consistency:field-parity-majority",
            "consistency:return-check-majority",
        ])
        assert channels == []

    def test_parity_solo_promotion_trips_the_alarm(self):
        from core.audit.promotion_alarm import build_alarm_record
        record = build_alarm_record(
            stage="test",
            file="src/ch.c",
            function="peel_off",
            verdict="finding",
            evidence_tool="consistency:field-parity-majority",
        )
        assert record is not None
        assert record["event"] == "promotion_without_tool_evidence"

    def test_registry_stale_alias_promotion_is_legitimate(self):
        from core.audit.promotion_alarm import build_alarm_record
        assert build_alarm_record(
            stage="test",
            file="src/bio.c",
            function="ndef_setup",
            verdict="finding",
            evidence_tool=RULE_STALE_ALIAS,
        ) is None


@requires_ts
class TestPrepass:
    def test_prepass_emits_leads_mechanical_and_handoffs(self):
        texts = {"src/bio.c": BIO_SHAPE, "src/ch.c": PEELOFF}
        out = run_ptr_lifecycle_prepass(
            texts, domain_vocab=_Vocab(deallocators={"BIO_free"}),
        )
        detectors = {m["detector"] for m in out["mechanical"]}
        assert detectors == {
            "field_parity_deviation", "stale_alias_candidate",
        }
        parity = next(
            m for m in out["mechanical"]
            if m["detector"] == "field_parity_deviation"
        )
        assert parity["rule_id"] == "consistency:field-parity-majority"
        stale = next(
            m for m in out["mechanical"]
            if m["detector"] == "stale_alias_candidate"
        )
        assert stale["rule_id"] == RULE_STALE_ALIAS
        assert stale["cwe"] == "CWE-416"
        assert out["handoffs"] == [{
            "file": "src/bio.c",
            "function": "ndef_setup",
            "line": 5,
            "mechanism": out["handoffs"][0]["mechanism"],
        }]
        assert "stale alias" in out["handoffs"][0]["mechanism"]
        tel = out["telemetry"]
        assert tel["dimensions"]["field-parity"]["confirmed"] == 1
        assert tel["dimensions"]["stale-alias"]["confirmed"] == 1
        assert tel["census_tier"] == "tree_sitter"

    def test_degraded_census_emits_nothing_but_telemetry(self):
        census = build_field_census({"src/bio.c": BIO_SHAPE})
        census.tier = TIER_REGEX
        out = run_ptr_lifecycle_prepass(
            {"src/bio.c": BIO_SHAPE}, census=census,
        )
        assert out["mechanical"] == []
        assert out["handoffs"] == []
        assert out["telemetry"]["inconclusive_reasons"] == {
            pl.REASON_CENSUS_INCOMPLETE: 1,
        }


class TestSeedPolicy:
    def test_seed_set_stays_seed_sized(self):
        assert len(pl._SEED_DEALLOCATORS) <= 9


class TestOutOfSpanOffsetsClamped:
    """Production failure shape: an alias edge recorded OUTSIDE the
    adjudicated function's span produced a negative segment offset;
    past -len(segment) Python raised IndexError, which aborted the
    whole census/prepass block in the orchestrator (and took the
    lock_region prepass down with it)."""

    def _span(self, name="f", start=800, end=830):
        from types import SimpleNamespace
        return SimpleNamespace(name=name, start=start, end=end)

    def _edge(self, line):
        from core.audit.ptr_lifecycle import _AliasEdge
        return _AliasEdge(
            kind="local", name="alias", owner="obj",
            owner_field="ptr", file="a.c", line=line,
        )

    def test_edge_before_span_does_not_raise(self):
        from core.audit.ptr_lifecycle import _local_alias_escapes

        segment = ["int f(void)", "{", "    use(alias);", "}"]
        # edge.line=10 with span.start=800 → offset -789, far past
        # -len(segment): pre-fix IndexError. Post-fix the walk clamps
        # to the segment and may legitimately report an in-span
        # escape — the contract under test is "never raises, never
        # reads outside the span".
        result = _local_alias_escapes(
            self._edge(10), segment, self._span(), 820, set(),
        )
        assert result is None or "line 80" in result

    def test_event_before_span_reads_nothing(self):
        from core.audit.ptr_lifecycle import _local_post_event_reads

        segment = ["int f(void)", "{", "    use(alias);", "}"]
        reads = _local_post_event_reads(
            self._edge(10), segment, self._span(), 10,
        )
        # Clamped to offset 0: scans the whole segment forward, never
        # wraps around from the tail.
        assert all(r["line"] >= 800 for r in reads)

    def test_in_span_escape_still_detected(self):
        from core.audit.ptr_lifecycle import _local_alias_escapes

        segment = [
            "int f(void)",
            "{",
            "    alias = obj->ptr;",
            "    hand_off(alias);",
            "    free(obj->ptr);",
            "}",
        ]
        result = _local_alias_escapes(
            self._edge(802), segment, self._span(start=800, end=805),
            804, set(),
        )
        assert result is not None
        assert "hand_off" in result


class TestCensusBlockIsolationWiring:
    """The orchestrator's census/prepass block must isolate channels
    (ptr_lifecycle crash ≠ lock_region outage) and degrade LOUDLY.
    Source-level wiring check, the TestReviewOneFunctionTimeoutPath
    pattern."""

    def test_channels_isolated_and_loud(self):
        from pathlib import Path

        import core.audit.orchestrator as orch_mod

        src = Path(orch_mod.__file__).read_text()
        idx = src.find("def _census_prepass")
        assert idx != -1, "per-channel isolation wrapper missing"
        window = src[idx:idx + 2500]
        assert "logger.warning" in window[:800]
        assert '_census_prepass(\n                "ptr_lifecycle"' in src
        assert '_census_prepass(\n                "lock_region"' in src
        # The block-level swallow is loud too.
        assert (
            "lifecycle channel prepass block failed" in src
        )
