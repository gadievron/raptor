"""Registered unit ownership survives nested calls and refuses redirects."""
from contextvars import copy_context

import pytest

from core.audit.context import assemble_context
from core.audit.knowledge_calls import KnowledgeCallRefused
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.orchestrator import OrchestratorConfig, StudyQueue
from core.audit.tests.test_binary_review_availability import _reviewer


def _setup(tmp_path):
    (tmp_path / 'unit.py').write_text('def f():\n    return 1\n\ndef g():\n    return 2\n')
    (tmp_path / 'other.py').write_text('def f():\n    return 3\n')
    runtime = AuditKnowledgeRuntime(tmp_path, StudyQueue(), deadline=float('inf'), window=0)
    config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / 'run')
    review, calls = _reviewer()
    def context(file='unit.py', name='f', line=1):
        return assemble_context(target_path=tmp_path, file_path=file, function_name=name,
                                line_start=line, line_end=line + 1)
    return runtime, config, runtime.wrap_review(review), calls, context


@pytest.mark.parametrize('field', ['file', 'function', 'line_start'])
def test_nested_reviewer_cannot_replace_the_registered_unit(tmp_path, field):
    runtime, config, review, calls, context = _setup(tmp_path)
    ctx = context()
    if field == 'file':
        ctx = context(file='other.py')
    elif field == 'function':
        ctx['function'] = 'display_alias'
    else:
        ctx = context(line=4)
    try:
        unit = runtime.wrap_unit(lambda gap: review(ctx, config))
        with pytest.raises(KnowledgeCallRefused, match='review_unit_identity_mismatch'):
            unit({'file': 'unit.py', 'name': 'f', 'line_start': 1})
        assert calls == [] and runtime._calls == {}
        assert runtime._unit_lease.get() is None and not runtime._busy
        refusal, = [event for event in runtime.events() if event['event'] == 'review_unit_refused']
        assert refusal['unit'] == ['unit.py', 'f', 1]
        # A later standalone legacy call has no stale owned-unit context.
        assert review(context(name='g', line=4), config).status == 'clean'
        assert len(calls) == 1
    finally:
        runtime.close('test_complete')


def test_explicit_nested_unit_restores_the_parent_review_identity(tmp_path):
    runtime, config, review, calls, context = _setup(tmp_path)
    outer_gap = {'file': 'unit.py', 'name': 'f', 'line_start': 1}
    inner_gap = {'file': 'unit.py', 'name': 'g', 'line_start': 4}
    def inner(gap):
        assert review(context(name='g', line=4), config).status == 'clean'
    def outer(gap):
        assert review(context(), config).status == 'clean'
        runtime.wrap_unit(inner)(inner_gap)
        assert review(context(), config).status == 'clean'
    try:
        runtime.wrap_unit(outer)(outer_gap)
        assert len(calls) == 3
        assert runtime._calls == {('unit.py', 'f', 1): 2, ('unit.py', 'g', 4): 1}
        assert runtime._unit_lease.get() is None and not runtime._busy
    finally:
        runtime.close('test_complete')


def test_unit_identity_is_retired_on_base_exception(tmp_path):
    runtime, config, review, calls, context = _setup(tmp_path)
    def interrupted(gap):
        raise KeyboardInterrupt('captured interruption')
    try:
        with pytest.raises(KeyboardInterrupt, match='captured interruption'):
            runtime.wrap_unit(interrupted)({'file': 'unit.py', 'name': 'f', 'line_start': 1})
        assert runtime._unit_lease.get() is None and not runtime._busy
        assert review(context(name='g', line=4), config).status == 'clean'
        assert len(calls) == 1
    finally:
        runtime.close('test_complete')


def test_unknown_line_uses_the_existing_origin_zero_representation(tmp_path):
    runtime, config, review, calls, context = _setup(tmp_path)
    ctx = assemble_context(target_path=tmp_path, file_path='unit.py', function_name='f',
                           line_start=0, line_end=None)
    try:
        runtime.wrap_unit(lambda gap: review(ctx, config))(
            {'file': 'unit.py', 'name': 'f', 'line_start': None})
        assert len(calls) == 1
        assert runtime._calls == {('unit.py', 'f', 0): 1}
        assert runtime._unit_lease.get() is None and not runtime._busy
    finally:
        runtime.close('test_complete')


def test_copied_unit_context_cannot_reopen_a_finished_review_scope(tmp_path):
    runtime, config, review, calls, context = _setup(tmp_path)
    borrowed = []
    def original(gap):
        assert review(context(), config).status == 'clean'
        borrowed.append(copy_context())
    try:
        runtime.wrap_unit(original)({'file': 'unit.py', 'name': 'f', 'line_start': 1})
        with pytest.raises(KnowledgeCallRefused, match='unit_scope_closed'):
            borrowed[0].run(review, context(), config)
        assert len(calls) == 1
        assert runtime._calls == {('unit.py', 'f', 1): 1}
    finally:
        runtime.close('test_complete')


def test_old_copied_context_stays_closed_during_new_same_key_unit(tmp_path):
    runtime, config, review, calls, context = _setup(tmp_path)
    gap = {'file': 'unit.py', 'name': 'f', 'line_start': 1}
    old = runtime.wrap_unit(lambda gap: copy_context())(gap)
    def new_unit(gap):
        with pytest.raises(KnowledgeCallRefused, match='unit_scope_closed'):
            old.run(review, context(), config)
        assert review(context(), config).status == 'clean'
    try:
        runtime.wrap_unit(new_unit)(gap)
        assert len(calls) == 1
        assert runtime._calls == {('unit.py', 'f', 1): 1}
        assert runtime._unit_lease.get() is None and not runtime._busy
    finally:
        runtime.close('test_complete')
