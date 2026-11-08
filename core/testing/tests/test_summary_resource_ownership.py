"""Native summary fixtures preserve caller state and close owned evidence."""

from contextlib import contextmanager
import functools
import importlib
import inspect
import json
import os
from pathlib import Path

import pytest

from core.domains import public_suffix
from core.sandbox import state, summary
from core.testing.module_state import isolated_module_state
from core.testing.sandbox_state_scope import (
    SUMMARY_DEFAULTS, SUMMARY_REGISTRIES, isolated_summary_state,
)


SPECS = json.loads((Path(__file__).parent / 'data/summary_resource_owners.json').read_text())
FIELDS = (*SUMMARY_DEFAULTS, *SUMMARY_REGISTRIES, '_evidence')


def _fixture(spec):
    module = importlib.import_module(spec['file'][:-3].replace('/', '.'))
    owner = getattr(module, spec['class'])() if spec['class'] else module
    function = getattr(owner, spec['fixture']).__wrapped__
    return module, owner, function


def _prime(tmp_path, active):
    caller = tmp_path / 'caller'
    caller.mkdir()
    if active:
        summary.set_active_run_dir(caller)
        summary.record_denial('owned caller', 1, 'write', path='/owned/caller')
        assert summary._evidence_handle is not None
        summary.record_run_posture(caller, mount_ns_active=True, restrict_reads=False)
    snapshot = {name: getattr(summary, name) for name in FIELDS}
    contents = {name: value.copy() for name, value in snapshot.items() if isinstance(value, dict)}
    files = {str(p.relative_to(caller)): p.read_bytes() for p in caller.rglob('*') if p.is_file()}
    return caller, snapshot, contents, files


def _retained(caller, snapshot, contents, files):
    for name, original in snapshot.items():
        assert getattr(summary, name) is original, name
    for name, before in contents.items():
        assert getattr(summary, name) == before, name
    assert {str(p.relative_to(caller)): p.read_bytes() for p in caller.rglob('*') if p.is_file()} == files
    handle = snapshot['_evidence_handle']
    if handle is not None:
        assert not handle._closed
        assert os.fstat(handle.fd).st_ino == handle._created_ino


@pytest.mark.parametrize('spec', SPECS, ids=[s['file'] + '::' + (s['class'] or '') + '::' + s['fixture'] for s in SPECS])
@pytest.mark.parametrize('active', [False, True], ids=['inactive-caller', 'live-caller'])
@pytest.mark.parametrize('finish', ['normal', 'error', 'interrupt', 'setup-error'])
def test_native_summary_fixture_owns_resources(spec, active, finish, monkeypatch, tmp_path):
    module, owner, function = _fixture(spec)
    with isolated_summary_state(), isolated_module_state(state, {'_cli_sandbox_disabled': False}):
        caller, snapshot, contents, files = _prime(tmp_path, active)
        body = pytest.MonkeyPatch()
        generator = None
        handles = []
        if finish == 'setup-error':
            real = module.isolated_summary_state

            @contextmanager
            def failed_setup():
                with real():
                    raise RuntimeError('fixture setup failed')
                    yield

            monkeypatch.setattr(module, 'isolated_summary_state', failed_setup)
        try:
            kwargs = {key: value for key, value in {'self': owner, 'tmp_path': tmp_path, 'monkeypatch': body}.items()
                      if key in inspect.signature(function).parameters}
            generator = function(**kwargs)
            next(generator)
            assert finish != 'setup-error'
            if active:
                assert not snapshot['_evidence_handle']._closed
            run = tmp_path / 'body'
            run.mkdir()
            summary.set_active_run_dir(run)
            summary.record_denial('owned body', 1, 'write', path='/owned/body')
            handle = summary._evidence_handle
            assert handle is not None
            handles.append(handle)
            # Detached handles must also be closed by the owner, even if a
            # later body monkeypatch replaces the active handle binding.
            body.setattr(summary, '_evidence_handle', None)
            body.setattr(summary, '_denial_count', 901)
            if finish == 'error':
                raise RuntimeError('body failed')
            if finish == 'interrupt':
                raise KeyboardInterrupt('body interrupted')
        except (RuntimeError, KeyboardInterrupt) as error:
            assert type(error) is (KeyboardInterrupt if finish == 'interrupt' else RuntimeError)
            assert finish != 'normal'
        finally:
            if generator is not None:
                generator.close()
            body.undo()
        for handle in handles:
            assert handle._closed and handle._fd_released
            with pytest.raises(OSError):
                os.fstat(handle.fd)
        _retained(caller, snapshot, contents, files)


@pytest.mark.parametrize('finish', ['normal', 'error', 'interrupt'])
@pytest.mark.parametrize('spec', [s for s in SPECS if s['file'].endswith(('test_disable_attribution.py', 'test_telemetry_key_posture.py'))], ids=lambda s: Path(s['file']).stem)
def test_native_empty_reset_preserves_live_caller(spec, finish, tmp_path):
    _, owner, function = _fixture(spec)
    with isolated_summary_state(), isolated_module_state(state, {'_cli_sandbox_disabled': False}):
        caller, snapshot, contents, files = _prime(tmp_path, True)
        body = pytest.MonkeyPatch()
        generator = function(tmp_path=tmp_path, monkeypatch=body)
        try:
            next(generator)
            if finish == 'error':
                raise RuntimeError('body failed')
            if finish == 'interrupt':
                raise KeyboardInterrupt('body interrupted')
        except (RuntimeError, KeyboardInterrupt) as error:
            assert type(error) is {'error': RuntimeError, 'interrupt': KeyboardInterrupt}[finish]
        finally:
            generator.close()
            body.undo()
        _retained(caller, snapshot, contents, files)


@pytest.mark.parametrize('finish', ['normal', 'error', 'interrupt'])
@pytest.mark.parametrize('snapshot_state', ['missing', 'invalid', 'unreadable'])
@pytest.mark.parametrize('host', ['cdn.example.com', '192.0.2.1'])
@pytest.mark.parametrize('shared_alias', [False, True], ids=['distinct-caller-caches', 'shared-caller-cache'])
def test_native_suffix_fault_retains_warm_cache(finish, snapshot_state, host, shared_alias, monkeypatch, tmp_path):
    from core.sandbox.tests import test_triage as native
    from core.sandbox import triage

    original = public_suffix.load_suffix_rules
    borrowed = functools.lru_cache(**original.cache_parameters())(original.__wrapped__)
    monkeypatch.setattr(public_suffix, 'load_suffix_rules', borrowed)
    alias = borrowed if shared_alias else functools.lru_cache(**original.cache_parameters())(original.__wrapped__)
    monkeypatch.setattr(triage, 'load_suffix_rules', alias)
    alias_value = alias()
    for _ in range(4):
        assert alias() is alias_value
    value = borrowed()
    for _ in range(4):
        assert borrowed() is value
    before = borrowed.cache_info()
    alias_before = alias.cache_info()
    body = pytest.MonkeyPatch()
    generator = native._owned_suffix_cache.__wrapped__(body)
    try:
        next(generator)
        native.TestDnsExfilIndicator().test_unavailable_snapshot_never_yields_clean_verdict(
            tmp_path, body, snapshot_state, host,
        )
        if finish == 'error':
            raise RuntimeError('body failed')
        if finish == 'interrupt':
            raise KeyboardInterrupt('body interrupted')
    except (RuntimeError, KeyboardInterrupt) as error:
        assert type(error) is {'error': RuntimeError, 'interrupt': KeyboardInterrupt}[finish]
    finally:
        generator.close()
        body.undo()
    assert public_suffix.load_suffix_rules is borrowed
    assert triage.load_suffix_rules is alias
    assert borrowed.cache_info() == before
    assert alias.cache_info() == alias_before
    assert borrowed() is value
    assert alias() is alias_value
