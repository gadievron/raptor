"""Owned-file availability caller qualification; no executor or provider."""
import builtins
import os
from types import SimpleNamespace

from core.audit import hypothesis_mapping, orchestrator
from core.run.scratch import write_temp_text
from core.testing.module_views import module_function_view


def _availability_case(tmp_path, *, cwe="CWE-1108", cleanup_error=False, borrowed=False):
    rules = tmp_path / 'rules'
    rules.mkdir()
    source = tmp_path / 'owned.php'
    original = '<?php function owned() {}\n'
    source.write_text(original)
    generated = []
    borrowed_path = rules / 'audit_sweep_borrowed.yaml'
    if borrowed:
        borrowed_path.write_text('borrowed rule must survive\n')
    retired = []

    def unlink_owned(path):
        assert path in {str(p) for p in generated}
        retired.append(path)
        os.unlink(path)
        if cleanup_error:
            raise OSError('after consuming owned rule unlink')

    owned_os = SimpleNamespace(**vars(os))
    owned_os.unlink = unlink_owned

    def write_owned(text, *, prefix, suffix):
        path = write_temp_text(text, prefix=prefix, suffix=suffix, dir=rules)
        generated.append(path)
        return path

    scratch = SimpleNamespace(write_temp_text=write_owned)

    def import_local(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name == 'core.run.scratch':
            return scratch
        return builtins.__import__(name, globals, locals, fromlist, level)

    def forbidden(*args, **kwargs):
        raise AssertionError('availability control must never execute tools or synthesis')

    mapping = module_function_view(hypothesis_mapping, import_hook=import_local)
    private = module_function_view(orchestrator, bindings={
        '_hypothesis_to_semgrep_rule_keyed': mapping.hypothesis_to_semgrep_rule_keyed,
        '_UNMAPPED_CWES_LOGGED': set(),
        'os': owned_os,
        '_run_tool_chain': forbidden,
        '_synthesize_unmapped_suspicious': forbidden,
    })
    if borrowed:
        private._hypothesis_to_tool_chain = lambda *a, **kw: [{
            'type': 'semgrep', 'config': {'rule': str(borrowed_path)},
        }]
    hypothesis = 'xss when the value is emitted'
    outcome = orchestrator.ReviewOutcome(
        file='owned.php', function='owned', status='suspicious', body='suspicious body',
        hypothesis=hypothesis,
        review_result={'cwe': cwe, 'hypothesis': hypothesis, 'hypotheses': [{
            'mechanism': hypothesis, 'confidence': 'medium',
            'counter': 'callers in other translation units always HTML-encode the value before invoking this function',
        }]},
    )
    result = orchestrator.OrchestratorResult()
    result.outcomes.append(outcome)
    result.suspicious = 1
    config = orchestrator.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / 'out')
    assert config.llm_budget_client is None
    assert private._has_refuting_counter(outcome, hypothesis=hypothesis)
    assert private._primary_hypothesis_entry(outcome, hypothesis) is not None
    queue = []
    try:
        returned = private._promote_suspicious_one(
            result, config, 0, outcome, checklist={'files': []}, synthesis_queue=queue,
        )
        assert returned is None
        assert result.outcomes == [outcome]
        assert outcome.status == 'suspicious'
        assert result.suspicious == 1
        assert result.findings == result.sweep_promoted == 0
        assert queue == []
        assert source.read_text() == original
        if cwe == 'CWE-1108' and not borrowed:
            assert generated, 'control must exercise actual temporary rule acquisition'
            assert retired == [str(p) for p in generated]
        else:
            assert generated == retired == []
        if borrowed:
            assert list(rules.iterdir()) == [borrowed_path]
            assert borrowed_path.read_text() == 'borrowed rule must survive\n'
        else:
            assert list(rules.iterdir()) == [], 'availability-only chain left an unreturned generated file' 
    finally:
        for path in generated:
            path.unlink(missing_ok=True)



def test_counter_availability_retires_unexecuted_generated_rule(tmp_path):
    _availability_case(tmp_path)


def test_availability_retains_ordinary_cleanup_error_policy(tmp_path):
    _availability_case(tmp_path, cleanup_error=True)


def test_curated_chain_does_not_acquire_disposable_rule(tmp_path):
    _availability_case(tmp_path, cwe='CWE-79')


def test_borrowed_rule_is_preserved_even_with_generated_prefix(tmp_path):
    _availability_case(tmp_path, borrowed=True)
