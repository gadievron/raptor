"""The unprivileged mapper can request only the caller's single identity."""
from types import SimpleNamespace

import pytest

from core.sandbox import _spawn


def mapper(monkeypatch, *, uid=1000):
    writes = []
    opened = []
    closed = []
    native = _spawn.os
    def open_path(path, flags, *, dir_fd=None):
        opened.append((path, dir_fd, flags))
        return len(opened) + 10
    def write(fd, value):
        writes.append((opened[fd - 11][0], value))
        return len(value)
    monkeypatch.setattr(_spawn, 'os', SimpleNamespace(
        getuid=lambda: uid, getgid=lambda: 1001, open=open_path,
        write=write, close=closed.append,
        **{name: getattr(native, name) for name in
           ('O_RDONLY', 'O_DIRECTORY', 'O_CLOEXEC', 'O_NOFOLLOW', 'O_WRONLY')}))
    return writes, opened, closed


@pytest.mark.parametrize('inside', [0, 1000])
def test_own_mapping_pins_proc_and_denies_groups_before_gid(monkeypatch, inside):
    writes, opened, closed = mapper(monkeypatch)
    _spawn._map_own_ids_unprivileged(123, inside)
    assert writes == [('uid_map', f'{inside} 1000 1\n'.encode()),
                      ('setgroups', b'deny\n'),
                      ('gid_map', f'{inside} 1001 1\n'.encode())]
    assert opened[0][0] == '/proc/123'
    assert all(row[1] == 11 for row in opened[1:])
    assert all(row[2] & _spawn.os.O_NOFOLLOW for row in opened)
    assert sorted(closed) == [11, 12, 13, 14]


@pytest.mark.parametrize('uid,inside', [(0, 0), (1000, 1), (1000, -1)])
def test_unsupported_identity_refused_before_proc_access(monkeypatch, uid, inside):
    _, opened, _ = mapper(monkeypatch, uid=uid)
    with pytest.raises(ValueError):
        _spawn._map_own_ids_unprivileged(123, inside)
    assert opened == []


def test_kernel_refusal_aborts_without_later_maps(monkeypatch):
    _, opened, closed = mapper(monkeypatch)
    def refused(fd, value):
        raise PermissionError('kernel denied mapping')
    monkeypatch.setattr(_spawn.os, 'write', refused)
    with pytest.raises(PermissionError):
        _spawn._map_own_ids_unprivileged(123, 1000)
    assert [row[0] for row in opened] == ['/proc/123', 'uid_map']
    assert sorted(closed) == [11, 12]
