"""Parent tool-chain cleanup preserves an interrupted memo adapter."""
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.audit import orchestrator
from core.testing.module_views import module_function_view


def _run_owned_rule(tmp_path, primary, cleanup, *, generated=True):
    source = tmp_path / 'owned.c'
    source.write_text('owned input\n')
    rule = tmp_path / ('audit_sweep_owned.yaml' if generated else 'curated-owned.yaml')
    rule.write_text('rules: []\n')
    info = rule.stat()
    calls = []

    def memo(config, tool, request, invoke):
        assert tool == 'semgrep'
        assert request['rule']
        assert request['file']
        calls.append('memo')
        if primary is not None:
            raise primary
        return SimpleNamespace(outcome='inconclusive', errors=[], matches=[], details={})

    def unlink(path):
        assert Path(path) == rule
        now = rule.stat()
        assert (now.st_dev, now.st_ino) == (info.st_dev, info.st_ino)
        calls.append('unlink')
        os.unlink(rule)
        if cleanup is not None:
            raise cleanup

    owned_os = SimpleNamespace(**vars(os))
    owned_os.unlink = unlink
    private = module_function_view(orchestrator, bindings={
        'os': owned_os,
        '_memoized_sweep_step': memo,
        '_substrate_registered_scope': lambda tool: None,
        '_checklist_line_end': lambda *args: 1,
    })
    config = SimpleNamespace(target_path=tmp_path, out_dir=None)
    caught = None
    result = None
    try:
        try:
            result = private._run_tool_chain(
                [{'type': 'semgrep', 'config': {'rule': str(rule), 'keyword': 'owned'}}],
                config=config, file_path='owned.c', function_name='owned',
                source=None, hypothesis='owned cleanup control',
            )
        except BaseException as exc:
            caught = exc
        assert calls == (['memo', 'unlink'] if generated else ['memo'])
        assert rule.exists() is (not generated)
        assert source.read_text() == 'owned input\n'
        return caught, result
    finally:
        rule.unlink(missing_ok=True)


def test_memo_interruption_survives_generated_rule_cleanup(tmp_path):
    primary = KeyboardInterrupt('inert memo interruption')
    caught, _ = _run_owned_rule(tmp_path, primary, SystemExit('after owned unlink'))
    assert caught is primary


@pytest.mark.parametrize('primary_kind', [KeyboardInterrupt, SystemExit, GeneratorExit])
@pytest.mark.parametrize('cleanup_kind', [OSError, KeyboardInterrupt])
def test_memo_cancellation_identity(tmp_path, primary_kind, cleanup_kind):
    primary = primary_kind('inert memo interruption')
    caught, result = _run_owned_rule(tmp_path, primary, cleanup_kind('after owned unlink'))
    assert caught is primary
    assert result is None


@pytest.mark.parametrize('cleanup_kind', [None, OSError, SystemExit])
def test_successful_memo_cleanup_policy(tmp_path, cleanup_kind):
    cleanup = cleanup_kind('after owned unlink') if cleanup_kind else None
    caught, result = _run_owned_rule(tmp_path, None, cleanup)
    if cleanup_kind is SystemExit:
        assert caught is cleanup
        assert result is None
    else:
        assert caught is None
        assert result == []
        assert [probe.verdict for probe in result.outcomes] == ['inconclusive']


def test_borrowed_curated_rule_is_not_unlinked(tmp_path):
    primary = KeyboardInterrupt('inert memo interruption')
    caught, _ = _run_owned_rule(tmp_path, primary, SystemExit('must not run'), generated=False)
    assert caught is primary


def test_caller_handled_error_does_not_hide_fresh_rule_cleanup(tmp_path):
    cleanup = SystemExit('fresh cleanup interruption')
    try:
        raise KeyboardInterrupt('handled by caller')
    except KeyboardInterrupt:
        caught, _ = _run_owned_rule(tmp_path, None, cleanup)
    assert caught is cleanup
