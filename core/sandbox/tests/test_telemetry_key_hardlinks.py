"""A telemetry key with extra filesystem aliases must not remain trusted."""
import os
from types import ModuleType

import pytest

from core.sandbox import telemetry_mac as mac
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'xdg'))
    monkeypatch.setattr(mac, '_warned_paths', set())


def aliases(tmp_path, key, count):
    linked = [tmp_path / f'key-alias-{index}' for index in range(count)]
    for alias in linked:
        os.link(key, alias)
    assert key.stat().st_nlink == count + 1
    return linked


@pytest.mark.parametrize('count', [1, 2], ids=['two-links', 'three-links'])
def test_linked_key_is_classified_before_reading_secret(tmp_path, monkeypatch, count):
    key = mac._key_path()
    key.parent.mkdir(parents=True)
    contents = b'k' * mac._KEY_LEN
    key.write_bytes(contents)
    key.chmod(0o600)
    linked = aliases(tmp_path, key, count)
    private = ModuleType('linked_key_os')
    vars(private).update(vars(os))

    def forbidden(*args):
        pytest.fail('multi-link key content was read before refusal')

    private.read = forbidden
    monkeypatch.setattr(mac, 'os', private)
    result = mac._read_existing_key(key)
    assert isinstance(result, mac._TamperedKey)
    assert 'hard link' in result.reason
    assert key.read_bytes() == contents
    assert all(alias.read_bytes() == contents for alias in linked)
    assert not list(key.parent.glob(key.name + '.tampered-*'))


@pytest.mark.parametrize('count', [1, 2], ids=['two-links', 'three-links'])
def test_recovery_rekeys_without_modifying_aliases(tmp_path, count):
    fields = {'kind': 'test', 'detail': 'owned telemetry'}
    previous_token = mac.mint(fields)
    assert previous_token is not None
    key = mac._key_path()
    original = key.read_bytes()
    identity = (key.stat().st_dev, key.stat().st_ino)
    linked = aliases(tmp_path, key, count)
    fresh_token = mac.mint(fields)
    assert fresh_token is not None
    assert fresh_token != previous_token
    assert mac.verify(fields, fresh_token) is True
    assert mac.verify(fields, previous_token) is False
    assert key.read_bytes() != original
    assert key.stat().st_nlink == 1
    assert (key.stat().st_dev, key.stat().st_ino) != identity
    assert all(alias.read_bytes() == original for alias in linked)
    quarantined = list(key.parent.glob(key.name + '.tampered-*'))
    assert len(quarantined) == 1
    assert (quarantined[0].stat().st_dev, quarantined[0].stat().st_ino) == identity
    events = mac.tamper_events()
    assert len(events) == 1
    assert 'hard link' in events[0]['reason']
    assert events[0]['quarantined_to'] == quarantined[0].name


@pytest.mark.parametrize('count', [1, 2], ids=['two-links', 'three-links'])
def test_foreign_owner_still_refuses_without_quarantine(tmp_path, monkeypatch, count):
    key = mac._key_path()
    key.parent.mkdir(parents=True)
    original = b'k' * mac._KEY_LEN
    key.write_bytes(original)
    key.chmod(0o600)
    linked = aliases(tmp_path, key, count)
    identity = (key.stat().st_dev, key.stat().st_ino)
    private = ModuleType('foreign_linked_key_os')
    vars(private).update(vars(os))

    def foreign_owner(fd):
        actual = os.fstat(fd)
        fields = list(actual)
        fields[4] = os.geteuid() + 1
        return os.stat_result(fields)

    private.fstat = foreign_owner
    monkeypatch.setattr(mac, 'os', private)
    assert mac._read_existing_key(key) is mac._REFUSED
    assert mac.mint({'kind': 'test'}) is None
    assert (key.stat().st_dev, key.stat().st_ino) == identity
    assert key.read_bytes() == original
    assert all(alias.read_bytes() == original for alias in linked)
    assert not list(key.parent.glob(key.name + '.tampered-*'))
    assert not mac.tamper_marker_path().exists()


@pytest.mark.parametrize('removed_alias', [False, True], ids=['private-key', 'alias-removed'])
def test_single_link_key_remains_usable(tmp_path, removed_alias):
    fields = {'kind': 'test'}
    token = mac.mint(fields)
    key = mac._key_path()
    original = key.read_bytes()
    if removed_alias:
        alias = aliases(tmp_path, key, 1)[0]
        alias.unlink()
    assert key.stat().st_nlink == 1
    assert mac._read_existing_key(key) == original
    assert mac.mint(fields) == token
    assert mac.verify(fields, token) is True
    assert not list(key.parent.glob(key.name + '.tampered-*'))
    assert not mac.tamper_marker_path().exists()
