"""Foreign ownership is a refusal for every existing key object shape."""
import os
from types import ModuleType

import pytest

from core.sandbox import telemetry_mac as mac
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def owned_state(tmp_path):
    with pytest.MonkeyPatch.context() as monkeypatch:
        pin_user_state_dirs(monkeypatch, tmp_path / 'state')
        monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'xdg'))
        monkeypatch.setattr(mac, '_warned_paths', set())
        yield


@pytest.fixture
def monkeypatch(owned_state):
    """Undo body patches before restoring the file-owned state."""
    with pytest.MonkeyPatch.context() as patch:
        yield patch


@pytest.mark.parametrize('shape', [
    'regular', 'directory', 'symlink',
    pytest.param('fifo', marks=pytest.mark.skipif(
        not hasattr(os, 'mkfifo'), reason='requires FIFO support')),
])
@pytest.mark.parametrize('foreign_owner', [True, False], ids=['foreign', 'own'])
def test_key_ownership_precedes_recovery(tmp_path, monkeypatch, shape, foreign_owner):
    key = mac._key_path()
    key.parent.mkdir(parents=True)
    destination = tmp_path / 'unrelated'
    destination.write_bytes(b'unchanged destination')
    if shape == 'regular':
        key.write_bytes(b'k' * mac._KEY_LEN)
        key.chmod(0o600)
    elif shape == 'directory':
        key.mkdir()
        (key / 'retained').write_bytes(b'unchanged directory')
    elif shape == 'symlink':
        key.symlink_to(destination)
    else:
        os.mkfifo(key, 0o600)
    before = os.lstat(key)
    identity = (before.st_dev, before.st_ino)
    local_os = ModuleType('key_owner_os')
    vars(local_os).update(vars(os))

    def foreign(st):
        if not foreign_owner or (st.st_dev, st.st_ino) != identity:
            return st
        fields = list(st)
        fields[4] = os.geteuid() + 1  # stat_result.st_uid; no privileged chown
        return os.stat_result(fields)

    local_os.fstat = lambda fd: foreign(os.fstat(fd))
    local_os.lstat = lambda *args, **kwargs: foreign(os.lstat(*args, **kwargs))
    monkeypatch.setattr(mac, 'os', local_os)

    fields = {'kind': 'proxy-event'}
    token = mac.mint(fields)
    assert destination.read_bytes() == b'unchanged destination'
    if not foreign_owner:
        assert token is not None and mac.verify(fields, token)
        assert key.is_file() and not key.is_symlink()
        quarantined = list(key.parent.glob(key.name + '.tampered-*'))
        if shape == 'regular':
            assert not quarantined
            assert key.read_bytes() == b'k' * mac._KEY_LEN
        else:
            assert len(quarantined) == 1
            moved = os.lstat(quarantined[0])
            assert (moved.st_dev, moved.st_ino) == identity
            assert mac.tamper_marker_path().is_file()
        return

    assert token is None
    after = os.lstat(key)
    assert (after.st_dev, after.st_ino, after.st_mode) == (
        before.st_dev, before.st_ino, before.st_mode)
    assert not list(key.parent.glob(key.name + '.tampered-*'))
    assert not mac.tamper_marker_path().exists()
    assert destination.read_bytes() == b'unchanged destination'
    if shape == 'regular':
        assert key.read_bytes() == b'k' * mac._KEY_LEN
    elif shape == 'directory':
        assert (key / 'retained').read_bytes() == b'unchanged directory'
