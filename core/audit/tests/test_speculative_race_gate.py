"""Tests for the speculative race demotion gate in core.audit.orchestrator."""

from __future__ import annotations

from core.audit.orchestrator import (
    ReviewOutcome,
    _apply_speculative_race_demotion,
)


def _outcome(status="finding", hypothesis="", body="", evidence_tool=""):
    o = ReviewOutcome(
        file="net/core/sock.c",
        function="sock_copy",
        status=status,
        body=body,
        hypothesis=hypothesis,
    )
    if evidence_tool:
        o.evidence_tool = evidence_tool
    return o


class TestSpeculativeRaceDemotion:
    def test_non_race_hypothesis_unchanged(self):
        o = _outcome(hypothesis="buffer overflow in memcpy")
        result = _apply_speculative_race_demotion(o)
        assert result.status == "finding"

    def test_race_finding_demoted_to_suspicious(self):
        o = _outcome(
            hypothesis="race condition between open and unlink",
        )
        result = _apply_speculative_race_demotion(o)
        assert result.status == "suspicious"

    def test_toctou_finding_demoted_to_suspicious(self):
        o = _outcome(hypothesis="TOCTOU in file access path")
        result = _apply_speculative_race_demotion(o)
        assert result.status == "suspicious"

    def test_concurrent_finding_demoted(self):
        o = _outcome(hypothesis="concurrent access to shared state")
        result = _apply_speculative_race_demotion(o)
        assert result.status == "suspicious"

    def test_race_with_tool_evidence_kept(self):
        o = _outcome(
            hypothesis="race condition in lock handling",
            evidence_tool="semgrep:race-double-check",
        )
        result = _apply_speculative_race_demotion(o)
        assert result.status == "finding"

    def test_race_with_smt_evidence_kept(self):
        o = _outcome(
            hypothesis="data race on counter",
            evidence_tool="smt:race-feasibility",
        )
        result = _apply_speculative_race_demotion(o)
        assert result.status == "finding"

    def test_race_with_joern_evidence_kept(self):
        o = _outcome(
            hypothesis="race condition in packet handler",
            evidence_tool="joern:concurrent-access",
        )
        result = _apply_speculative_race_demotion(o)
        assert result.status == "finding"

    def test_suspicious_race_with_protection_demoted_to_clean(self):
        o = _outcome(
            status="suspicious",
            hypothesis="race condition on shared buffer",
            body="The buffer is protected by a mutex. The mutex_held "
                 "ensures exclusive access during the copy operation.",
        )
        result = _apply_speculative_race_demotion(o)
        assert result.status == "clean"

    def test_suspicious_race_with_rcu_lock_demoted_to_clean(self):
        o = _outcome(
            status="suspicious",
            hypothesis="data race on list traversal",
            body="The list is traversed under rcu_read_lock protection.",
        )
        result = _apply_speculative_race_demotion(o)
        assert result.status == "clean"

    def test_suspicious_race_with_spin_lock_demoted_to_clean(self):
        o = _outcome(
            status="suspicious",
            hypothesis="concurrent modification",
            body="All accesses to this field are serialised by spin_lock_bh.",
        )
        result = _apply_speculative_race_demotion(o)
        assert result.status == "clean"

    def test_negated_protection_not_demoted(self):
        """'not protected by' should NOT count as protection."""
        o = _outcome(
            status="suspicious",
            hypothesis="race condition on shared state",
            body="The shared state is not protected by any lock. "
                 "Concurrent access from multiple threads is possible.",
        )
        result = _apply_speculative_race_demotion(o)
        assert result.status == "suspicious"

    def test_without_lock_not_demoted(self):
        o = _outcome(
            status="suspicious",
            hypothesis="race condition in packet processing",
            body="The counter is accessed without lock protection.",
        )
        result = _apply_speculative_race_demotion(o)
        assert result.status == "suspicious"

    def test_missing_mutex_not_demoted(self):
        o = _outcome(
            status="suspicious",
            hypothesis="toctou in file access",
            body="The operation lacks mutex_held for the critical section.",
        )
        result = _apply_speculative_race_demotion(o)
        assert result.status == "suspicious"

    def test_finding_race_no_protection_stays_suspicious(self):
        """finding → suspicious (race), but no protection phrase → stays suspicious."""
        o = _outcome(
            hypothesis="race condition between threads",
            body="Multiple threads access the same counter without synchronisation.",
        )
        result = _apply_speculative_race_demotion(o)
        assert result.status == "suspicious"

    def test_clean_status_passes_through(self):
        o = _outcome(
            status="clean",
            hypothesis="race condition",
            body="protected by lock",
        )
        result = _apply_speculative_race_demotion(o)
        assert result.status == "clean"

    def test_dormant_status_passes_through(self):
        o = _outcome(
            status="dormant",
            hypothesis="race condition on dead path",
        )
        result = _apply_speculative_race_demotion(o)
        assert result.status == "dormant"

    def test_init_only_protection_demotes(self):
        o = _outcome(
            status="suspicious",
            hypothesis="data race on configuration",
            body="This field is only written during init_only phase "
                 "before any threads are spawned.",
        )
        result = _apply_speculative_race_demotion(o)
        assert result.status == "clean"

    def test_single_threaded_protection_demotes(self):
        o = _outcome(
            status="suspicious",
            hypothesis="concurrent access to global",
            body="The function runs in a single-threaded context during boot.",
        )
        result = _apply_speculative_race_demotion(o)
        assert result.status == "clean"

    def test_prefilter_lock_evidence_kept(self):
        o = _outcome(
            hypothesis="race condition in locking",
            evidence_tool="prefilter:lock-analysis",
        )
        result = _apply_speculative_race_demotion(o)
        assert result.status == "finding"

    def test_prefilter_race_evidence_kept(self):
        o = _outcome(
            hypothesis="data race on shared map",
            evidence_tool="prefilter:race-detector",
        )
        result = _apply_speculative_race_demotion(o)
        assert result.status == "finding"

    def test_never_atomic_negation(self):
        """'not an atomic operation' — negation far from protection phrase."""
        o = _outcome(
            status="suspicious",
            hypothesis="race condition on counter",
            body="The increment is not an atomic operation. "
                 "However the field is protected by the socket lock.",
        )
        result = _apply_speculative_race_demotion(o)
        # The first sentence has "not" but it's not near a protection phrase.
        # The second sentence has a real protection phrase with no negation.
        assert result.status == "clean"
