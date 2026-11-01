"""Delegated cgroup v2 process-tree scopes, independent of resource budgets.

The caller owns admission: attach the exact child it started while that child
is still behind a launch gate. A scope does not make an unrestricted same-UID
process adversarially contained. Never expose its writable controls to payloads.
"""
from __future__ import annotations

import errno
import os
from pathlib import Path
import re
import secrets
import threading
import time

CGROUP_ROOT = Path('/sys/fs/cgroup')


def current_group() -> Path:
    if not (CGROUP_ROOT / 'cgroup.controllers').is_file():
        raise OSError(errno.ENOTSUP, 'cgroup v2 is unavailable')
    membership = next((line[3:] for line in Path('/proc/self/cgroup').read_text().splitlines()
                       if line.startswith('0::')), None)
    if membership is None or '..' in Path(membership).parts:
        raise OSError(errno.ENOTSUP, 'unified cgroup membership unavailable')
    return CGROUP_ROOT / membership.lstrip('/')


def _open_directory(path: Path) -> int:
    # Never let a caller substitute a regular scratch directory for a kernel
    # cgroup. All paths must be below the actual cgroup v2 mount in this view.
    path.relative_to(CGROUP_ROOT)
    mounted = False
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        before, after = line.split(' - ', 1)
        mountpoint = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), before.split()[4])
        if mountpoint == str(CGROUP_ROOT) and after.split()[0] == 'cgroup2':
            mounted = True
    if not mounted or '..' in path.parts:
        raise OSError(errno.ENOTSUP, 'trusted cgroup v2 mount unavailable')
    node = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=node)
            os.close(node)
            node = child
        return node
    except BaseException:
        os.close(node)
        raise


def _read(node: int, name: str) -> str:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=node)
    try:
        raw = os.read(fd, 16385)
        if len(raw) > 16384:
            raise ValueError('oversized cgroup control file')
        return raw.decode('ascii')
    finally:
        os.close(fd)


def _write(node: int, name: str, data: str) -> None:
    fd = os.open(name, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=node)
    try:
        encoded = data.encode('ascii')
        if os.write(fd, encoded) != len(encoded):
            raise OSError(errno.EIO, 'incomplete cgroup control write')
    finally:
        os.close(fd)


class Scope:
    def __init__(self, path: Path, node: int, parent: int):
        self.path = path
        self.node = node
        self.parent = parent
        info = os.fstat(node)
        self.identity = [info.st_dev, info.st_ino]
        self.admission_closed = False
        self._admission_lock = threading.Lock()

    @classmethod
    def create(cls, parent: Path | None = None):
        parent = parent if parent is not None else current_group()
        parent_fd = _open_directory(parent)
        node = None
        name = 'raptor-' + secrets.token_hex(16)
        created = False
        try:
            os.mkdir(name, dir_fd=parent_fd)
            created = True
            node = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                           dir_fd=parent_fd)
            # Refuse a half-capable backend before any child can be released.
            _read(node, 'cgroup.events')
            fd = os.open('cgroup.kill', os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=node)
            os.close(fd)
            return cls(parent / name, node, parent_fd)
        except BaseException:
            if node is not None:
                os.close(node)
            if created:
                try:
                    os.rmdir(name, dir_fd=parent_fd)
                except OSError:
                    pass
            os.close(parent_fd)
            raise

    @classmethod
    def recover(cls, path: Path, identity: list[int]):
        parent = _open_directory(path.parent)
        node = None
        try:
            if not re.fullmatch(r'raptor-[a-f0-9]{32}', path.name):
                raise ValueError('invalid RAPTOR cgroup scope')
            node = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                           dir_fd=parent)
            info = os.fstat(node)
            if [info.st_dev, info.st_ino] != identity:
                raise PermissionError('cgroup identity changed')
            return cls(path, node, parent)
        except BaseException:
            if node is not None:
                os.close(node)
            os.close(parent)
            raise

    def attach(self, pid: int) -> None:
        with self._admission_lock:
            if self.admission_closed or type(pid) is not int or pid <= 0:
                raise ValueError('scope admission closed or invalid child PID')
            _write(self.node, 'cgroup.procs', str(pid))

    def close_admission(self) -> None:
        with self._admission_lock:
            self.admission_closed = True

    def populated(self) -> bool:
        values = dict(line.split() for line in _read(self.node, 'cgroup.events').splitlines())
        if values.get('populated') not in {'0', '1'}:
            raise ValueError('cgroup populated state unavailable')
        return values['populated'] == '1'

    def stop(self, *, timeout: float = 5, grace: float = 0) -> bool:
        if not self.admission_closed:
            raise ValueError('close scope admission before teardown')
        grace_deadline = time.monotonic() + max(0, grace)
        while self.populated() and time.monotonic() < grace_deadline:
            time.sleep(.02)
        killed = self.populated()
        if killed:
            _write(self.node, 'cgroup.kill', '1')
        deadline = time.monotonic() + timeout
        while self.populated():
            if time.monotonic() >= deadline:
                raise TimeoutError('cgroup still populated; retain scratch')
            time.sleep(.02)
        return killed

    def release(self) -> None:
        if not self.admission_closed or self.populated():
            raise ValueError('cannot release an open or populated cgroup')
        # This first backend owns a leaf. Future per-job child scopes must be
        # released by their controller first; never recursively delete unknown
        # cgroups or infer emptiness from a missing pathname.
        info = os.stat(self.path.name, dir_fd=self.parent, follow_symlinks=False)
        if [info.st_dev, info.st_ino] != self.identity:
            raise PermissionError('cgroup name now identifies another scope')
        os.rmdir(self.path.name, dir_fd=self.parent)

    def close(self) -> None:
        for attribute in ('node', 'parent'):
            fd = getattr(self, attribute)
            if fd is not None:
                os.close(fd)
                setattr(self, attribute, None)
