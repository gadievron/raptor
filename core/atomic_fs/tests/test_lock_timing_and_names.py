"""Lock timing must remain bounded and valid artifact names must be lockable."""
import errno
import os

import pytest

from core.atomic_fs import fs_lock as locks
from core.testing.module_bindings import patch_module_attribute

BAD = [float('nan'), float('inf'), float('-inf'), -1, True, False, '1', [], object(), 10**1000]
IDS = ['nan', 'inf', 'negative-inf', 'negative', 'true', 'false', 'string', 'list', 'object', 'huge-int']


@pytest.mark.parametrize('value', BAD, ids=IDS)
@pytest.mark.parametrize('parameter', ['deadline_s', 'poll_s'])
def test_invalid_timing_refused_before_flock_or_stamp(monkeypatch, value, parameter):
    def attempted(*args):
        pytest.fail('invalid timing must fail before lock acquisition')
    monkeypatch.setattr(locks, '_try_flock_nb', attempted)
    with pytest.raises(ValueError, match='lock timing'):
        locks.acquire_flock_bounded(123, None, subject='test', **{parameter: value})


@pytest.mark.parametrize('value', BAD, ids=IDS)
@pytest.mark.parametrize('required', [False, True], ids=['best-effort', 'required'])
def test_sidecar_invalid_deadline_does_not_create_parent_or_enter(tmp_path, value, required):
    parent = tmp_path / 'new-parent'
    with pytest.raises(ValueError, match='lock timing'):
        with locks.sidecar_flock(parent / 'state.lock', deadline_s=value, required=required):
            pytest.fail('invalid timing entered body')
    assert not parent.exists()


@pytest.mark.parametrize('parameter,value', [('_ACQUIRE_DEADLINE_S', float('nan')),
    ('_ACQUIRE_DEADLINE_S', float('inf')), ('_ACQUIRE_DEADLINE_S', -1),
    ('_ACQUIRE_POLL_S', float('nan')), ('_ACQUIRE_POLL_S', float('inf')), ('_ACQUIRE_POLL_S', 0)],
    ids=['deadline-nan', 'deadline-inf', 'deadline-negative', 'poll-nan', 'poll-inf', 'poll-zero'])
def test_invalid_default_timing_is_also_refused(monkeypatch, parameter, value):
    monkeypatch.setattr(locks, parameter, value)
    with pytest.raises(ValueError, match='lock timing'):
        locks.acquire_flock_bounded(123, None, subject='test')


def test_zero_deadline_makes_one_nonblocking_attempt_without_sleep(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(locks, '_try_flock_nb', lambda fd: calls.append(fd) or False)
    def slept(*args):
        pytest.fail('zero-budget acquire must not sleep')
    patch_module_attribute(monkeypatch, locks, 'time', 'sleep', slept)
    assert not locks.acquire_flock_bounded(123, tmp_path / 'data', subject='test', deadline_s=0)
    assert calls == [123]


@pytest.mark.skipif(not locks._HAS_FCNTL, reason='requires flock')
@pytest.mark.parametrize('required', [False, True], ids=['best-effort', 'required'])
@pytest.mark.parametrize('name', ['a' * 251, 'a' * 255, 'é' * 125 + '.bin', '🙂' * 62 + '.json', '.' + 'a' * 253],
                         ids=['boundary', 'maximum', 'accented', 'emoji', 'hidden'])
def test_long_artifact_names_use_a_short_live_sidecar(tmp_path, required, name):
    artifact = tmp_path / name
    with locks.artifact_lock(artifact, required=required):
        artifact.write_text('data')
        fallback = locks._artifact_lock_path(artifact)
        assert fallback.read_text() == f'{os.getpid()}\n'
        with pytest.raises(TimeoutError):
            with locks.artifact_lock(artifact, required=True, deadline_s=0):
                pytest.fail('contender acquired the same artifact')
    assert artifact.read_text() == 'data'
    with locks.artifact_lock(artifact, required=True, deadline_s=0):
        pass


@pytest.mark.parametrize('name', ['state.json', '.state', 'a.b.c', 'é.json', 'a' * 249, 'a' * 250],
                         ids=['json', 'hidden', 'multiple-suffixes', 'unicode', 'near-limit', 'exact-limit'])
def test_existing_sidecar_names_keep_their_namespace(tmp_path, name):
    artifact = tmp_path / name
    assert locks._artifact_lock_path(artifact) == artifact.with_suffix(artifact.suffix + '.lock')


@pytest.mark.skipif(not locks._HAS_FCNTL, reason='requires flock')
def test_different_long_names_retain_independent_lock_namespaces(tmp_path):
    first, second = tmp_path / ('a' * 255), tmp_path / ('b' * 255)
    with locks.artifact_lock(first, required=True):
        with locks.artifact_lock(second, required=True, deadline_s=0):
            pass
    with locks.artifact_lock(second, required=True, deadline_s=0):
        pass
    assert len(list(tmp_path.iterdir())) == 2


@pytest.mark.skipif(not locks._HAS_FCNTL, reason='requires flock')
@pytest.mark.parametrize('shape', ['symlink', 'fifo', 'directory', 'hardlink'])
@pytest.mark.parametrize('required', [False, True], ids=['best-effort', 'required'])
def test_long_name_fallback_has_the_same_tamper_refusal(tmp_path, shape, required):
    artifact = tmp_path / ('a' * 255)
    fallback = locks._artifact_lock_path(artifact)
    outside = tmp_path / 'other'
    outside.write_text('unchanged')
    if shape == 'symlink':
        fallback.symlink_to(outside)
    elif shape == 'fifo':
        os.mkfifo(fallback)
    elif shape == 'directory':
        fallback.mkdir()
    else:
        os.link(outside, fallback)
    if required:
        with pytest.raises(OSError):
            with locks.artifact_lock(artifact, required=True):
                pytest.fail('invalid fallback admitted')
    else:
        with locks.artifact_lock(artifact):
            pass
    assert outside.read_text() == 'unchanged'


@pytest.mark.parametrize('limit', [64, 128, 255])
def test_mount_filename_limit_controls_fallback(tmp_path, monkeypatch, limit):
    patch_module_attribute(monkeypatch, locks, 'os', 'pathconf', lambda *args: limit, raising=False)
    artifact = tmp_path / ('a' * (limit - 1))
    selected = locks._artifact_lock_path(artifact)
    assert selected.name.startswith('.raptor-') and selected.name.endswith('.lock')
    assert len(os.fsencode(selected.name)) <= limit


def test_impossibly_small_mount_limit_refuses_without_creating_state(tmp_path, monkeypatch):
    patch_module_attribute(monkeypatch, locks, 'os', 'pathconf', lambda *args: 14, raising=False)
    with pytest.raises(OSError) as error:
        with locks.artifact_lock(tmp_path / ('a' * 14), required=True):
            pytest.fail('invalid filename limit admitted')
    assert error.value.errno == errno.ENAMETOOLONG
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('first,second', [
    ('A' * 251, 'a' * 251),
    ('a' * 249 + 'é', 'a' * 249 + 'e\u0301'),
], ids=['case-alias', 'canonical-unicode-alias'])
def test_long_name_alias_spellings_keep_one_lock_identity(tmp_path, first, second):
    assert locks._artifact_lock_path(tmp_path / first) == locks._artifact_lock_path(tmp_path / second)


@pytest.mark.parametrize('required', [False, True], ids=['best-effort', 'required'])
@pytest.mark.parametrize('name', ['state.json', 'a' * 255], ids=['ordinary', 'long'])
def test_missing_filename_limit_api_preserves_unavailable_backend_policy(tmp_path, monkeypatch, required, name):
    patch_module_attribute(monkeypatch, locks, 'os', 'pathconf', lambda *args: 255, raising=False)
    monkeypatch.delattr(locks.os, 'pathconf')
    monkeypatch.setattr(locks, '_HAS_FCNTL', False)
    artifact = tmp_path / name
    if required:
        with pytest.raises(OSError) as error:
            with locks.artifact_lock(artifact, required=True):
                pytest.fail('required lock entered without a backend')
        assert error.value.errno == errno.ENOSYS
        assert not artifact.exists()
    else:
        with locks.artifact_lock(artifact):
            (tmp_path / 'result').write_text('committed')
        assert (tmp_path / 'result').read_text() == 'committed'
        assert not artifact.exists()
    assert len(list(tmp_path.iterdir())) == (0 if required else 1)
