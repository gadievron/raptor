"""Completed control rejections should not restart synthesis each study batch."""

from copy import deepcopy
from types import SimpleNamespace

import pytest

from core.audit.orchestrator import OrchestratorConfig, _compile_eager_invariants
from core.audit.shared_state import SharedState
from core.concepts.compiler import compile_invariant
from core.concepts.model import Invariant


_RESPONSE = {
    'rule_body': 'rules:\n- id: test\n  pattern: f(...)\n  languages: [c]\n  message: test\n  severity: WARNING\n',
    'test_positive': 'void bad(void) { f(); }',
    'test_negative': 'void good(void) {}',
}


@pytest.mark.parametrize('engine_errors,negative_hit,expected', [
    ([], False, True),
    ([], True, True),
    (['scanner timed out'], False, False),
    (['scanner failed'], True, False),
])
def test_only_clean_control_rejections_are_reusable(
    tmp_path, monkeypatch, engine_errors, negative_hit, expected,
):
    from packages.checker_synthesis import synthesise as synthesis_module

    def run_engine(_rule, _path, target):
        if negative_hit or target.stem == 'test_negative':
            return [SimpleNamespace(line=1)], engine_errors
        return [], engine_errors

    monkeypatch.setattr(synthesis_module, '_run_engine', run_engine)
    inv = Invariant('inv', 'concept', 'f requires a guard', 'f without a guard')
    result = compile_invariant(
        inv, 'semgrep', lambda *_args: deepcopy(_RESPONSE),
        tmp_path, max_retries=0,
    )
    assert not result.success
    assert result.control_rejected is expected
    assert result.to_dict()['control_rejected'] is expected


@pytest.fixture
def eager_run(tmp_path, monkeypatch):
    from packages.checker_synthesis import synthesise as synthesis_module

    calls = []
    mode = {'errors': [], 'api_error': False, 'errors_by_engine': {}}

    def generate(**kwargs):
        calls.append(kwargs)
        if mode['api_error']:
            raise RuntimeError('temporary API failure')
        return deepcopy(_RESPONSE), None

    client = SimpleNamespace(generate_structured=generate, model_name='test-model')
    monkeypatch.setattr('core.audit.orchestrator._run_llm_client', lambda _cfg: client)
    # Run real compiler retry and fallback paths, with a hermetic scanner oracle.
    monkeypatch.setattr(
        synthesis_module, '_run_engine',
        lambda rule, *_args: (
            [], mode['errors_by_engine'].get(rule.engine, mode['errors']),
        ),
    )
    monkeypatch.setattr('core.audit.orchestrator._run_invariant_prescreening', lambda *_args: 0)
    entry = {
        'id': 'inv', 'concept': 'concept', 'statement': 'f requires a guard',
        'negation': 'f without a guard', 'confidence': 'traced',
        'evidence': ['a.c:1'], 'source_hash': 'first-source',
    }
    shared = SharedState(domain_model={'invariants': [deepcopy(entry)]})
    cfg = OrchestratorConfig(out_dir=tmp_path / 'out', target_path=tmp_path)
    return cfg, shared, entry, calls, mode, client


def test_unchanged_reloaded_invariant_does_not_repeat_paid_attempts(eager_run):
    cfg, shared, entry, calls, _mode, _client = eager_run
    _compile_eager_invariants(cfg, shared, {})
    first = len(calls)
    assert first == 4  # Two attempts per engine, including fallback.
    assert shared.eager_compile_rejections
    # The study consumer reloads model dictionaries between batches.
    shared.domain_model = {'invariants': [deepcopy(entry)]}
    _compile_eager_invariants(cfg, shared, {})
    assert len(calls) == first
    assert 'mechanical_rule' not in shared.domain_model['invariants'][0]
    assert not shared.mechanical_findings


@pytest.mark.parametrize('field,value', [
    ('negation', 'f after releasing ownership'),
    ('evidence', ['a.c:2']),
    ('source_hash', 'new-source'),
])
def test_new_knowledge_reopens_compilation(eager_run, field, value):
    cfg, shared, entry, calls, _mode, _client = eager_run
    _compile_eager_invariants(cfg, shared, {})
    first = len(calls)
    entry[field] = value
    shared.domain_model = {'invariants': [deepcopy(entry)]}
    _compile_eager_invariants(cfg, shared, {})
    assert len(calls) > first


@pytest.mark.parametrize('failure', ['tool', 'api'])
def test_transient_failures_are_retried_next_batch(eager_run, failure):
    cfg, shared, _entry, calls, mode, _client = eager_run
    if failure == 'tool':
        mode['errors'] = ['scanner timed out']
    else:
        mode['api_error'] = True
    _compile_eager_invariants(cfg, shared, {})
    first = len(calls)
    assert first > 0
    assert not shared.eager_compile_rejections
    _compile_eager_invariants(cfg, shared, {})
    assert len(calls) > first


def test_new_audit_has_no_rejections(eager_run):
    cfg, shared, entry, calls, _mode, _client = eager_run
    _compile_eager_invariants(cfg, shared, {})
    first = len(calls)
    fresh = SharedState(domain_model={'invariants': [deepcopy(entry)]})
    _compile_eager_invariants(cfg, fresh, {})
    assert len(calls) > first


def test_failed_fallback_can_retry_after_primary_rejection(eager_run):
    cfg, shared, _entry, calls, mode, _client = eager_run
    # C sources try Coccinelle first, then Semgrep. Only Semgrep is down.
    mode['errors_by_engine']['semgrep'] = ['scanner timed out']
    _compile_eager_invariants(cfg, shared, {})
    first = len(calls)
    assert len(shared.eager_compile_rejections) == 1
    _compile_eager_invariants(cfg, shared, {})
    assert first < len(calls) < first * 2


@pytest.mark.parametrize('failure', ['proposal', 'oracle'])
def test_later_exception_does_not_reuse_an_earlier_control_verdict(
    tmp_path, monkeypatch, failure,
):
    from packages.checker_synthesis import synthesise as synthesis_module

    calls = 0

    def generate(*_args):
        nonlocal calls
        calls += 1
        if calls == 2 and failure == 'proposal':
            raise RuntimeError('temporary API failure')
        return deepcopy(_RESPONSE)

    def run_engine(*_args):
        if calls == 2 and failure == 'oracle':
            raise OSError('temporary scratch failure')
        return [], []

    monkeypatch.setattr(synthesis_module, '_run_engine', run_engine)
    result = compile_invariant(
        Invariant('inv', 'concept', 'guard required', 'guard absent'),
        'semgrep', generate, tmp_path,
    )
    assert not result.success
    assert not result.control_rejected


def test_changed_model_reopens_compilation(eager_run):
    cfg, shared, _entry, calls, _mode, client = eager_run
    _compile_eager_invariants(cfg, shared, {})
    first = len(calls)
    client.model_name = 'different-model'
    _compile_eager_invariants(cfg, shared, {})
    assert len(calls) > first


def test_missing_controls_are_not_reusable(tmp_path):
    response = {**_RESPONSE, 'test_negative': ''}
    result = compile_invariant(
        Invariant('inv', 'concept', 'guard required', 'guard absent'),
        'semgrep', lambda *_args: response, tmp_path,
    )
    assert not result.success
    assert not result.control_rejected
