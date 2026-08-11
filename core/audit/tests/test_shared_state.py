"""Tests for core.audit.shared_state — SharedState dataclass."""

import threading

from core.audit.shared_state import SharedState


def _prep_kwargs():
    """Minimal keyword set for SharedState.from_prep()."""
    return dict(
        checklist={"a.c:f": {}},
        context_map={"entry_points": []},
        evidence_index={},
        provenance_map={},
        security_decision_keys=frozenset(),
        feeds_security_keys=frozenset(),
        taint_approx_results={},
        sarif_cache=None,
        flow_traces=[],
        variant_targets=set(),
        entry_points=set(),
        sinks_set=set(),
        widely_used_keys=set(),
        conventions=[],
        sibling_ns_findings=[],
        sibling_postcond_violations=[],
        peer_groups=[],
        semantic_findings=[],
        mechanical_findings={},
        fuzz_coverage={},
        discovered_tests=None,
        typestate_models=None,
        summary_cache=None,
        checker_library=None,
        triage_results={},
        project_learnings=[],
        feedback_state=None,
        fp_patterns=[],
        prop_config=None,
        iris_taint_specs=[],
        call_edges=[],
    )


class TestFromPrep:
    def test_roundtrip(self):
        kw = _prep_kwargs()
        ss = SharedState.from_prep(**kw)
        assert ss.checklist == {"a.c:f": {}}
        assert ss.context_map == {"entry_points": []}

    def test_mutable_defaults_independent(self):
        ss1 = SharedState.from_prep(**_prep_kwargs())
        ss2 = SharedState.from_prep(**_prep_kwargs())
        ss1.session_observations.append({"key": "val"})
        assert ss2.session_observations == []

    def test_taint_summary_override(self):
        kw = _prep_kwargs()
        kw["taint_summary_results"] = {"fn": {"taint": True}}
        ss = SharedState.from_prep(**kw)
        assert ss.taint_summary_results == {"fn": {"taint": True}}

    def test_taint_summary_default(self):
        ss = SharedState.from_prep(**_prep_kwargs())
        assert ss.taint_summary_results == {}

    def test_constraints_override(self):
        kw = _prep_kwargs()
        kw["constraints"] = {"x": 1}
        ss = SharedState.from_prep(**kw)
        assert ss.constraints == {"x": 1}

    def test_missing_required_kwarg(self):
        kw = _prep_kwargs()
        del kw["checklist"]
        try:
            SharedState.from_prep(**kw)
            assert False, "should have raised TypeError"
        except TypeError:
            pass


class TestConstraintsLock:
    def test_lock_is_threading_lock(self):
        ss = SharedState.from_prep(**_prep_kwargs())
        assert isinstance(ss._constraints_lock, type(threading.Lock()))

    def test_lock_independent_per_instance(self):
        ss1 = SharedState.from_prep(**_prep_kwargs())
        ss2 = SharedState.from_prep(**_prep_kwargs())
        assert ss1._constraints_lock is not ss2._constraints_lock


class TestMutableFieldIsolation:
    def test_session_observations_isolated(self):
        ss = SharedState()
        ss2 = SharedState()
        ss.session_observations.append({"obs": "test"})
        assert ss2.session_observations == []

    def test_synthesis_queue_isolated(self):
        ss = SharedState()
        ss2 = SharedState()
        ss.synthesis_queue.append({"item": 1})
        assert ss2.synthesis_queue == []

    def test_reviewed_before_joern_isolated(self):
        ss = SharedState()
        ss2 = SharedState()
        ss.reviewed_before_joern.append({"fn": "test"})
        assert ss2.reviewed_before_joern == []
