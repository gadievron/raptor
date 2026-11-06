"""New key publication must be validated before returning signing material."""
import os
from collections import Counter
from types import ModuleType

import pytest

from core.sandbox import telemetry_mac as mac
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture
def key(tmp_path):
    with pytest.MonkeyPatch.context() as monkeypatch:
        pin_user_state_dirs(monkeypatch, tmp_path / 'state')
        monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
        path = tmp_path / 'key'
        monkeypatch.setattr(mac, '_key_path', lambda: path)
        monkeypatch.setattr(mac, '_warned_paths', set())
        yield path


@pytest.fixture
def monkeypatch(key):
    """Undo body patches before restoring fixture-owned state."""
    with pytest.MonkeyPatch.context() as patch:
        yield patch


@pytest.mark.parametrize('phase', ['write', 'close'])
@pytest.mark.parametrize('mutation', ['replace', 'unlink', 'chmod', 'hardlink', 'rewrite', 'resize'])
def test_changed_publication_returns_no_key(key, monkeypatch, phase, mutation):
    private = ModuleType('key_publication_os')
    vars(private).update(vars(os))
    changed = False
    created_fd = None
    opened, closed = [], []

    def mutate():
        nonlocal changed
        if changed:
            return
        changed = True
        if mutation == 'replace':
            fresh = key.with_name('fresh')
            fresh.write_bytes(b'n' * mac._KEY_LEN)
            fresh.chmod(0o600)
            fresh.replace(key)
        elif mutation == 'unlink':
            key.unlink()
        elif mutation == 'chmod':
            key.chmod(0o644)
        elif mutation == 'hardlink':
            os.link(key, key.with_name('alias'))
        else:
            key.write_bytes(b'n' * (mac._KEY_LEN if mutation == 'rewrite' else mac._KEY_LEN * 2))

    def open_fd(*args, **kwargs):
        nonlocal created_fd
        fd = os.open(*args, **kwargs)
        opened.append(fd)
        if args[1] & os.O_CREAT:
            created_fd = fd
        return fd

    def write(fd, data):
        count = os.write(fd, data)
        if phase == 'write' and fd == created_fd:
            mutate()
        return count

    def close(fd):
        os.close(fd)
        closed.append(fd)
        if phase == 'close' and fd == created_fd:
            mutate()

    private.open, private.write, private.close = open_fd, write, close
    with monkeypatch.context() as scoped:
        scoped.setattr(mac, 'os', private)
        assert mac._load_or_create_key() is None
    assert changed
    assert created_fd is not None
    assert Counter(opened) == Counter(closed)
    # A later healthy call retains the established bounded recovery behavior.
    fields = {'kind': 'test', 'detail': 'owned metadata'}
    token = mac.mint(fields)
    assert token is not None
    assert mac.verify(fields, token)


def test_stable_new_publication_remains_verifiable(key):
    fields = {'kind': 'test'}
    token = mac.mint(fields)
    assert token is not None
    assert mac.verify(fields, token)
    assert len(key.read_bytes()) == mac._KEY_LEN
