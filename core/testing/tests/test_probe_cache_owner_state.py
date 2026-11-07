"""Native probe fixtures own cold state without clearing their callers' caches."""

import importlib
import inspect
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from core.testing.module_state import isolated_module_state



SPECS = json.loads((Path(__file__).parent / 'data/probe_cache_owners.json').read_text())


# Capability skip markers probe these bindings while their native module loads.
_IMPORT_PROBE_STATE = (
    '_landlock_cache', '_net_available_cache', '_mount_available_cache',
    '_mount_ns_available_cache', '_unshare_path_cache', '_newuidmap_path_cache',
    '_newgidmap_path_cache', '_mount_unavailable_warned',
)


def _fixture(spec):
    from core.sandbox import state

    # Loading belongs to the harness, before the measured fixture lifetime.
    # Keep real capability probes, but restore any caller values they populate.
    with isolated_module_state(state, {
        name: getattr(state, name) for name in _IMPORT_PROBE_STATE
    }, lock=state._cache_lock):
        module = importlib.import_module(spec['file'][:-3].replace('/', '.'))
    owner = getattr(module, spec['class']) if spec['class'] else module
    return module, owner, getattr(owner, spec['fixture']).__wrapped__


def _start(spec, patch, tmp_path):
    module, owner, function = _fixture(spec)
    instance = owner() if spec['class'] else None
    kwargs = {'monkeypatch': patch, 'tmp_path': tmp_path}
    if instance is not None:
        kwargs['self'] = instance
    generator = function(**{key: value for key, value in kwargs.items()
                            if key in inspect.signature(function).parameters})
    next(generator)
    return module, instance, generator


def _inherited(name, shape, tmp_path):
    if shape == 'absent_result':
        return None if name.endswith('_cache') else 0.0 if 'decided_at' in name else False
    if name == '_user_limits_cache':
        return {'memory_mb': 77}
    if 'decided_at' in name:
        return 123.5
    if name == 'pycache_prefix' or '_path_cache' in name or name == '_gidmap_allow_cache':
        return str(tmp_path / 'caller-prefix-or-tool') if shape == 'available' else False
    return shape == 'available'


@pytest.mark.parametrize('spec', [s for s in SPECS if s.get('owner') != 'capabilities'],
                         ids=[s['fixture'] + '-' + (s['class'] or Path(s['file']).stem)
                              for s in SPECS if s.get('owner') != 'capabilities'])
@pytest.mark.parametrize('shape', ['absent_result', 'denied', 'available'])
@pytest.mark.parametrize('finish', ['normal', 'error', 'interrupt'])
def test_native_fixture_retains_caller_state(spec, shape, finish, monkeypatch, tmp_path):
    import sys
    from core.sandbox import preexec, state

    owner = sys if spec.get('owner') == 'sys' else state
    borrowed = {}
    for name in spec['state']:
        value = _inherited(name, shape, tmp_path)
        # sys.pycache_prefix accepts a path string or None, unlike a bool cache.
        if name == 'pycache_prefix':
            value = None if shape == 'absent_result' else str(tmp_path / ('prefix-' + shape))
        monkeypatch.setattr(owner, name, value)
        borrowed[name] = value
    path = tmp_path / 'caller-sandbox.json'
    if spec.get('path') or spec.get('preserve_path'):
        monkeypatch.setattr(preexec, '_CONFIG_PATH', path)
    body = pytest.MonkeyPatch()
    generator = None
    try:
        _, instance, generator = _start(spec, body, tmp_path)
        for name, expected in spec['state'].items():
            assert getattr(owner, name) == expected
        for name, value in borrowed.items():
            if isinstance(value, dict):
                assert value == {'memory_mb': 77}
            # Exercise production-shaped writes and body-level overrides before
            # the native fixture restores the original owner and object.
            replacement = {'cpu_seconds': 9} if name == '_user_limits_cache' else 42.0 if 'decided_at' in name else None if name == 'pycache_prefix' else False
            body.setattr(owner, name, replacement)
        if spec.get('path'):
            assert preexec._CONFIG_PATH is instance._config
            assert instance._config.parent == tmp_path
        if spec.get('path') or spec.get('preserve_path'):
            body.setattr(preexec, '_CONFIG_PATH', tmp_path / 'body-sandbox.json')
        if finish == 'error':
            raise RuntimeError('fixture body failed')
        if finish == 'interrupt':
            raise KeyboardInterrupt('fixture body interrupted')
    except (RuntimeError, KeyboardInterrupt) as error:
        assert type(error) is {'error': RuntimeError, 'interrupt': KeyboardInterrupt}.get(finish)
    finally:
        if generator is not None:
            generator.close()
        body.undo()
    assert all(getattr(owner, name) is value for name, value in borrowed.items())
    if spec.get('path') or spec.get('preserve_path'):
        assert preexec._CONFIG_PATH is path
    for value in borrowed.values():
        if isinstance(value, dict):
            assert value == {'memory_mb': 77}


@pytest.mark.parametrize('finish', ['normal', 'error', 'interrupt'])
def test_bytecode_preparation_preserves_nonempty_prefix(finish, monkeypatch, tmp_path):
    import sys
    from core.startup.tests import test_install_guard as native

    inherited = str(tmp_path / 'caller-cache')
    monkeypatch.setattr(sys, 'pycache_prefix', inherited)
    patch = pytest.MonkeyPatch()
    fixture = getattr(native, '_owned_bytecode_prefix', None)
    generator = fixture.__wrapped__(patch) if fixture is not None else None
    try:
        if generator is not None:
            next(generator)
        native.test_precompile_is_hashed_and_refreshes_after_pull(tmp_path, patch)
        if finish == 'error':
            raise RuntimeError('bytecode body failed')
        if finish == 'interrupt':
            raise KeyboardInterrupt('bytecode body interrupted')
    except (RuntimeError, KeyboardInterrupt) as error:
        assert type(error) is {'error': RuntimeError, 'interrupt': KeyboardInterrupt}.get(finish)
    finally:
        if generator is not None:
            generator.close()
        patch.undo()
    assert sys.pycache_prefix is inherited


@pytest.mark.parametrize('finish', ['normal', 'error', 'interrupt'])
def test_snapshot_shape_never_starts_ambient_tools(finish, monkeypatch, tmp_path):
    import shutil
    from core.audit import capabilities
    from core.audit.tests import test_capabilities as native
    from packages.joern import prereqs

    borrowed_which = shutil.which
    for name in ('joern', 'joern_parse', 'java'):
        monkeypatch.setattr(prereqs, '_resolved_' + name, str(tmp_path / name))
        monkeypatch.setattr(prereqs, '_' + name + '_resolved', True)
    launches = Mock(return_value=SimpleNamespace(stdout='', stderr='', returncode=0))
    sdk = Mock(return_value=True)
    solver = Mock(return_value=True)
    monkeypatch.setattr(prereqs, 'probe', launches)
    monkeypatch.setattr(capabilities, '_can_import', sdk)
    monkeypatch.setattr(capabilities, '_angr_available', solver)
    patch = pytest.MonkeyPatch()
    fixture = getattr(native.TestProbeCapabilities, '_owned_capability_discovery', None)
    case = native.TestProbeCapabilities()
    generator = fixture.__wrapped__(case, patch) if fixture is not None else None
    try:
        if generator is not None:
            next(generator)
        case.test_returns_dataclass()
        assert launches.call_count == 0
        assert sdk.call_count == 0
        assert solver.call_count == 0
        assert shutil.which is borrowed_which
        if finish == 'error':
            raise RuntimeError('snapshot failed')
        if finish == 'interrupt':
            raise KeyboardInterrupt('snapshot interrupted')
    except (RuntimeError, KeyboardInterrupt) as error:
        assert type(error) is {'error': RuntimeError, 'interrupt': KeyboardInterrupt}.get(finish)
    finally:
        if generator is not None:
            generator.close()
        patch.undo()
    assert capabilities._can_import is sdk
    assert capabilities._angr_available is solver
    assert shutil.which is borrowed_which


@pytest.mark.parametrize('finish', ['normal', 'error', 'interrupt'])
def test_availability_cache_test_retains_caller_verdict(finish, monkeypatch, tmp_path):
    from core.sandbox import probes, state
    from core.sandbox.tests import test_sandbox as native

    inherited_path = str(tmp_path / 'caller-unshare')
    monkeypatch.setattr(state, '_net_available_cache', False)
    monkeypatch.setattr(state, '_unshare_path_cache', inherited_path)
    probe = Mock(return_value=True)
    monkeypatch.setattr(probes, '_probe_net_available', probe)
    case = native.TestAvailabilityCheck('test_cached')
    patch = pytest.MonkeyPatch()
    fixture = getattr(native.TestAvailabilityCheck, '_owned_probe_cache', None)
    generator = fixture.__wrapped__(case, patch) if fixture is not None else None
    try:
        if generator is not None:
            next(generator)
        case.test_cached()
        assert probe.call_count == 1
        if finish == 'error':
            raise RuntimeError('cache body failed')
        if finish == 'interrupt':
            raise KeyboardInterrupt('cache body interrupted')
    except (RuntimeError, KeyboardInterrupt) as error:
        assert type(error) is {'error': RuntimeError, 'interrupt': KeyboardInterrupt}.get(finish)
    finally:
        if generator is not None:
            generator.close()
        patch.undo()
    assert state._net_available_cache is False
    assert state._unshare_path_cache is inherited_path


@pytest.mark.parametrize('finish', ['normal', 'error', 'interrupt'])
def test_parse_failure_retains_caller_cache_timestamp(finish, monkeypatch, tmp_path):
    from core.sandbox import preexec, state
    from core.sandbox.tests import test_sandbox as native

    inherited = {'memory_mb': 111}
    stamp = 123.5
    config = tmp_path / 'caller-sandbox.json'
    monkeypatch.setattr(state, '_user_limits_cache', inherited)
    monkeypatch.setattr(state, '_user_limits_cache_decided_at', stamp)
    monkeypatch.setattr(preexec, '_CONFIG_PATH', config)
    case = native.TestUserLimitsInvalidUtf8('test_invalid_utf8_config')
    patch = pytest.MonkeyPatch()
    fixture = getattr(native.TestUserLimitsInvalidUtf8, '_owned_user_limits', None)
    generator = fixture.__wrapped__(case, patch) if fixture is not None else None
    try:
        if generator is not None:
            next(generator)
        case.test_invalid_utf8_config()
        if finish == 'error':
            raise RuntimeError('parse body failed')
        if finish == 'interrupt':
            raise KeyboardInterrupt('parse body interrupted')
    except (RuntimeError, KeyboardInterrupt) as error:
        assert type(error) is {'error': RuntimeError, 'interrupt': KeyboardInterrupt}.get(finish)
    finally:
        if generator is not None:
            generator.close()
        patch.undo()
    assert state._user_limits_cache is inherited
    assert state._user_limits_cache_decided_at is stamp
    assert preexec._CONFIG_PATH is config
