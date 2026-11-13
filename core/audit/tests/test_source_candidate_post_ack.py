"""A real journal ACK does not make a later source edit current."""
import builtins
from types import ModuleType

import pytest

from core.audit import collector, orchestrator as orch
from core.audit.refutation_source import capture_source_identity
from core.audit.tests.test_study_claim_retention import (
    _knowledge_reassess, _new_suspicion,
    _owned_review_caches as _owned_review_caches,
    study_case as study_case,
)
from core.coverage.journal import load_entries
from core.testing.module_views import module_function_view


@pytest.mark.parametrize("change", ["none", "revision", "rewrite_restore"])
def test_source_candidate_rechecks_currentness_after_real_ack(study_case, monkeypatch, change):
    case = study_case
    path = case["config"].target_path / "owned.c"
    original_source = path.read_text()
    original_identity = capture_source_identity(case["config"].target_path, "owned.c")
    original_append = collector.append_journal_for_outcome
    acknowledgements = []

    def append_then_change(**kwargs):
        acknowledgement = original_append(**kwargs)
        assert acknowledgement is not None, "the actual writer did not acknowledge the candidate"
        acknowledgements.append(acknowledgement)
        if change != "none":
            path.write_text(original_source + "/* owned revision after ACK */\n")
            if change == "rewrite_restore":
                path.write_text(original_source)
        return acknowledgement

    private_collector = ModuleType(collector.__name__)
    vars(private_collector).update(vars(collector))
    private_collector.append_journal_for_outcome = append_then_change

    def import_local(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 1 and name == "collector":
            return private_collector
        return builtins.__import__(name, globals, locals, fromlist, level)

    # Own only this consumer's relative writer import. The actual collector,
    # shared import machinery and source-capture implementation stay intact.
    private = module_function_view(orch, import_hook=import_local)
    with monkeypatch.context() as patch:
        patch.setattr(orch, "_publish_study_candidates", private._publish_study_candidates)
        runtime = _knowledge_reassess(case, _new_suspicion())
    try:
        assert len(acknowledgements) == 1
        assert case["result"].total_cost_usd == pytest.approx(.7)
        assert case["result"].reviewed == case["result"].suspicious == 1
        assert case["result"].clean == 0
        # The successful append remains historical, even if current publication fails.
        assert len(load_entries(case["config"].out_dir, fresh=True)) == 1
        current = capture_source_identity(case["config"].target_path, "owned.c")
        if change == "none":
            assert current == original_identity
            assert case["result"].outcomes[0] is not case["prior"]
            assert len(case["result"].outcomes[0].hypotheses) == 3
        else:
            assert current != original_identity
            if change == "rewrite_restore":
                assert current.sha256 == original_identity.sha256
                assert current.version != original_identity.version
            assert case["result"].outcomes[0] is case["prior"]
            assert len(case["prior"].hypotheses) == 2
            assert any(event.get("reason") == "source_changed" for event in runtime.events())
        assert not runtime._active
    finally:
        runtime.close("test_complete")
