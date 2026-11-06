"""Key reads cannot return bytes after an observed identity/metadata change."""
import os
from types import ModuleType

import pytest

from core.sandbox import telemetry_mac as mac
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture
def key(tmp_path):
    with pytest.MonkeyPatch.context() as monkeypatch:
        pin_user_state_dirs(monkeypatch, tmp_path / 'state')
        path = tmp_path / 'key'
        path.write_bytes(b'k' * mac._KEY_LEN)
        path.chmod(0o600)
        monkeypatch.setattr(mac, '_key_path', lambda: path)
        monkeypatch.setattr(mac, '_warned_paths', set())
        yield path


@pytest.fixture
def monkeypatch(key):
    """Undo body patches before restoring fixture-owned state."""
    with pytest.MonkeyPatch.context() as patch:
        yield patch


def mutate_after_read(monkeypatch, key, mutation):
    private = ModuleType('key_snapshot_os')
    vars(private).update(vars(os))
    changed = False

    def read(fd, size):
        nonlocal changed
        data = os.read(fd, size)
        if not changed:
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
                before = key.stat()
                key.write_bytes(b'n' * (mac._KEY_LEN if mutation == 'rewrite' else mac._KEY_LEN * 2))
                os.utime(key, ns=(before.st_atime_ns, before.st_mtime_ns + 1))
        return data

    private.read = read
    monkeypatch.setattr(mac, 'os', private)


@pytest.mark.parametrize('mutation', ['replace', 'unlink', 'chmod', 'hardlink', 'rewrite', 'resize'])
def test_changed_snapshot_does_not_return_old_key(key, monkeypatch, mutation):
    mutate_after_read(monkeypatch, key, mutation)
    result = mac._read_existing_key(key)
    if mutation in ('replace', 'unlink', 'rewrite', 'resize'):
        assert result is None
    else:
        assert isinstance(result, mac._TamperedKey)
    assert result != b'k' * mac._KEY_LEN


@pytest.mark.parametrize('mutation', ['replace', 'unlink', 'chmod', 'hardlink', 'rewrite', 'resize'])
def test_mint_recovers_to_the_current_usable_key(key, monkeypatch, mutation):
    fields = {'kind': 'test', 'detail': 'owned evidence'}
    old_token = mac.mint(fields)
    mutate_after_read(monkeypatch, key, mutation)
    token = mac.mint(fields)
    assert token is not None
    assert mac.verify(fields, token) is True
    assert mac.verify(fields, old_token) is False
    assert key.stat().st_nlink == 1
    assert not (key.stat().st_mode & 0o077)


def test_stable_key_read_remains_usable(key):
    assert mac._read_existing_key(key) == b'k' * mac._KEY_LEN
    fields = {'kind': 'test'}
    assert mac.verify(fields, mac.mint(fields)) is True
