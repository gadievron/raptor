"""Identity and provenance fixtures retain caller caches and warning history."""

from contextlib import contextmanager
import functools
import importlib
import inspect
import zipfile

import pytest

from core.project import sessions, trust
from core.run.pin import RunPin
from core.sandbox import telemetry_mac
from core.witness import provenance


CASES = (
    ('core.project.tests.test_trust_archive_target', 'ArchiveProjectFixture', 'setUp', trust,
     ('_gate_pin_memo', '_ARCHIVE_SNAP_MEMO')),
    ('core.project.tests.test_sessions', None, '_owned_identity_caches', sessions,
     ('boot_id', 'pidns_id', 'machine_id')),
    ('core.witness.tests.conftest', None, '_isolated_witness_mac_key', provenance, ('_warned_paths',)),
    ('core.sandbox.tests.test_telemetry_mac', None, '_owned_key_warnings', telemetry_mac, ('_warned_paths',)),
)


def _prime(owner, names, warm, monkeypatch, tmp_path):
    borrowed = {}
    for name in names:
        original = getattr(owner, name)
        if hasattr(original, 'cache_parameters'):
            value = functools.lru_cache(**original.cache_parameters())(original.__wrapped__)
            monkeypatch.setattr(owner, name, value)
            if warm:
                for _ in range(4):
                    value()
            borrowed[name] = (value, value.cache_info())
        else:
            value = set() if isinstance(original, set) else {}
            monkeypatch.setattr(owner, name, value)
            if warm:
                if name == '_warned_paths':
                    value.add(str(tmp_path / 'caller-key'))
                elif name == '_gate_pin_memo':
                    run = tmp_path / 'caller-run'
                    value[str(run)] = RunPin(None, 'unresolved', run, False, False)
                else:
                    archive = tmp_path / 'caller.zip'
                    with zipfile.ZipFile(archive, 'w') as stream:
                        stream.writestr('source.py', 'print(1)\n')
                    assert trust._archive_snapshot_memoised(archive) is not None
            borrowed[name] = (value, value.copy())
    return borrowed


def _retained(owner, borrowed):
    for name, (value, before) in borrowed.items():
        assert getattr(owner, name) is value
        if hasattr(value, 'cache_info'):
            assert value.cache_info() == before
        else:
            assert value == before


def _finish(mode):
    if mode == 'error':
        raise RuntimeError('body failed')
    if mode == 'interrupt':
        raise KeyboardInterrupt('body interrupted')


@pytest.mark.parametrize('case', CASES, ids=[c[0] for c in CASES])
@pytest.mark.parametrize('warm', [False, True], ids=['cold-caller', 'warm-caller'])
@pytest.mark.parametrize('mode', ['normal', 'error', 'interrupt', 'publication-error'])
def test_identity_fixture_preserves_caller(case, warm, mode, monkeypatch, tmp_path, tmp_path_factory):
    module_name, class_name, fixture_name, owner, names = case
    module = importlib.import_module(module_name)
    borrowed = _prime(owner, names, warm, monkeypatch, tmp_path)
    body = pytest.MonkeyPatch()
    instance = getattr(module, class_name)() if class_name else None
    generator = None
    if mode == 'publication-error':
        real = module.isolated_module_state

        @contextmanager
        def failing_publication(*args, **kwargs):
            with real(*args, **kwargs):
                raise RuntimeError('fixture publication failed')
                yield

        monkeypatch.setattr(module, 'isolated_module_state', failing_publication)
    try:
        function = getattr(instance or module, fixture_name)
        function = getattr(function, '__wrapped__', function)
        kwargs = {key: value for key, value in {
            'monkeypatch': body, 'tmp_path': tmp_path, 'tmp_path_factory': tmp_path_factory,
        }.items() if key in inspect.signature(function).parameters}
        result = function(**kwargs)
        if inspect.isgenerator(result):
            generator = result
            next(generator)
        assert mode != 'publication-error'
        for name, (value, _) in borrowed.items():
            private = getattr(owner, name)
            assert private is not value
            if hasattr(value, 'cache_parameters'):
                assert private.cache_parameters() == value.cache_parameters()
                assert private.cache_info().currsize == 0
                assert private.__wrapped__ is value.__wrapped__
                private()
                body.setattr(owner, name, lambda: None)
            elif isinstance(private, set):
                assert not private
                private.add(str(tmp_path / 'private-key'))
                if instance is None:
                    body.setattr(owner, name, set())
            else:
                assert not private
                private[str(tmp_path / 'private-run')] = None
        _finish(mode)
    except (RuntimeError, KeyboardInterrupt) as error:
        expected = KeyboardInterrupt if mode == 'interrupt' else RuntimeError
        assert type(error) is expected
        assert mode != 'normal'
    finally:
        # unittest-owned state exits after any body monkeypatch stack.
        body.undo() if instance is not None else None
        if generator is not None:
            generator.close()
        if instance is not None:
            assert instance.doCleanups()
        body.undo()
    _retained(owner, borrowed)


@pytest.mark.parametrize('mode', ['normal', 'error', 'interrupt'])
def test_native_archive_eviction_preserves_caller(mode, monkeypatch, tmp_path):
    from core.project.tests import test_trust_archive_target as native

    borrowed = _prime(trust, ('_ARCHIVE_SNAP_MEMO',), True, monkeypatch, tmp_path)
    case = native.TestSnapshotMemoValidity()
    try:
        case.setUp()
        case.test_same_size_swap_with_forged_mtime_fails_closed()
        _finish(mode)
    except (RuntimeError, KeyboardInterrupt) as error:
        assert type(error) is {'error': RuntimeError, 'interrupt': KeyboardInterrupt}[mode]
    finally:
        assert case.doCleanups()
    _retained(trust, borrowed)


@pytest.mark.parametrize('mode', ['normal', 'error', 'interrupt'])
def test_native_witness_refusal_preserves_warnings(mode, monkeypatch, tmp_path, tmp_path_factory):
    from core.witness.tests import conftest, test_provenance as native

    borrowed = _prime(provenance, ('_warned_paths',), True, monkeypatch, tmp_path)
    body = pytest.MonkeyPatch()
    owner = conftest._isolated_witness_mac_key.__wrapped__(tmp_path_factory, body)
    key = None
    try:
        next(owner)
        key = native._isolated_key.__wrapped__(tmp_path, body)
        next(key)
        native.TestMintVerify().test_group_readable_key_refused(tmp_path)
        _finish(mode)
    except (RuntimeError, KeyboardInterrupt) as error:
        assert type(error) is {'error': RuntimeError, 'interrupt': KeyboardInterrupt}[mode]
    finally:
        if key is not None:
            key.close()
        owner.close()
        body.undo()
    _retained(provenance, borrowed)


@pytest.mark.parametrize('mode', ['normal', 'error', 'interrupt'])
def test_native_telemetry_refusal_preserves_warnings(mode, monkeypatch, tmp_path):
    from core.sandbox.tests import test_telemetry_mac as native

    borrowed = _prime(telemetry_mac, ('_warned_paths',), True, monkeypatch, tmp_path)
    body = pytest.MonkeyPatch()
    owner = native._owned_key_warnings.__wrapped__(body)
    key = None
    try:
        next(owner)
        key = native._isolated_key.__wrapped__(tmp_path, body)
        next(key)
        native.TestKeyHandling().test_foreign_owned_key_refused_not_recovered(tmp_path, body)
        _finish(mode)
    except (RuntimeError, KeyboardInterrupt) as error:
        assert type(error) is {'error': RuntimeError, 'interrupt': KeyboardInterrupt}[mode]
    finally:
        if key is not None:
            key.close()
        owner.close()
        body.undo()
    _retained(telemetry_mac, borrowed)


@pytest.mark.parametrize('mode', ['normal', 'error', 'interrupt'])
def test_native_identity_hygiene_preserves_cache(mode, monkeypatch, tmp_path):
    from core.project.tests import test_sessions as native

    borrowed = _prime(sessions, ('machine_id',), True, monkeypatch, tmp_path)
    body = pytest.MonkeyPatch()
    owner = native._owned_identity_caches.__wrapped__(body)
    try:
        next(owner)
        native.PriorBootEntryTest().test_machine_id_is_a_hash_never_the_raw_value()
        _finish(mode)
    except (RuntimeError, KeyboardInterrupt) as error:
        assert type(error) is {'error': RuntimeError, 'interrupt': KeyboardInterrupt}[mode]
    finally:
        owner.close()
        body.undo()
    _retained(sessions, borrowed)
