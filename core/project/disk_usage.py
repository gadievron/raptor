"""Allocated-space estimates for project views and completed cleanup receipts."""
from collections.abc import Generator
from dataclasses import dataclass, field
import os
from pathlib import Path
import stat
from typing import cast


_WalkRow = tuple[str, list[str], list[str]] | tuple[str, list[str], list[str], int]


_MAX_USAGE_RECORDS = 1_000_000


class _InventoryLimit(Exception):
    pass


def _key(info, path):
    if info.st_ino:
        return info.st_dev, info.st_ino
    return 'path', os.path.abspath(path)


def _allocated(info):
    blocks = getattr(info, 'st_blocks', None)
    return max(0, info.st_size if blocks is None or blocks < 0 else blocks * 512)


@dataclass(slots=True)
class Entry:
    mode: int
    size: int
    nlink: int
    links: set = field(default_factory=set)
    roots: set = field(default_factory=set)

    @property
    def reclaimable(self):
        return stat.S_ISDIR(self.mode) or len(self.links) >= self.nlink


@dataclass(slots=True)
class Usage:
    entries: dict = field(default_factory=dict)
    incomplete: bool = False
    truncated: bool = False
    _records: int = field(default=0, repr=False)

    def _reserve(self, count):
        if self._records + count > _MAX_USAGE_RECORDS:
            self.incomplete = self.truncated = True
            raise _InventoryLimit
        self._records += count

    def add(self, info, path, link, root):
        key = _key(info, path)
        if not info.st_ino:
            self.incomplete = True
        entry = self.entries.get(key)
        self._reserve((1 if entry is None else 0)
                      + (1 if entry is None or link not in entry.links else 0)
                      + (1 if entry is None or root not in entry.roots else 0))
        if entry is None:
            entry = self.entries[key] = Entry(info.st_mode, _allocated(info), info.st_nlink)
        entry.size = max(entry.size, _allocated(info))
        entry.nlink = max(entry.nlink, info.st_nlink)
        entry.links.add(link)
        entry.roots.add(root)

    def merge(self, other):
        self.incomplete |= other.incomplete
        for key, source in other.entries.items():
            entry = self.entries.get(key)
            links = source.links - (entry.links if entry else set())
            roots = source.roots - (entry.roots if entry else set())
            try:
                self._reserve((1 if entry is None else 0) + len(links) + len(roots))
            except _InventoryLimit:
                break
            if entry is None:
                entry = self.entries[key] = Entry(source.mode, source.size, source.nlink)
            entry.size = max(entry.size, source.size)
            entry.nlink = max(entry.nlink, source.nlink)
            entry.links.update(links)
            entry.roots.update(roots)
        self.truncated |= other.truncated

    @property
    def allocated_bytes(self):
        return sum(entry.size for entry in self.entries.values())

    @property
    def reclaimable_bytes(self):
        return sum(entry.size for entry in self.entries.values() if entry.reclaimable)

    def has_removals(self, remaining):
        return not remaining.incomplete and any(
            key not in remaining.entries or before.links - remaining.entries[key].links
            for key, before in self.entries.items())

    def removed_bytes(self, remaining):
        if remaining.incomplete:
            return 0  # Missing observations are not proof of removal.
        total = 0
        for key, before in self.entries.items():
            after = remaining.entries.get(key)
            if stat.S_ISDIR(before.mode):
                if after is None:
                    total += before.size
            # A renamed/relinked inode still present in the inventory keeps
            # its allocation even if every previous name has disappeared.
            elif after is None and len(before.links) >= before.nlink:
                total += before.size
        return total


def scan_usage(root: Path) -> Usage:
    """Read metadata only; never follow root or descendant symbolic links.

    POSIX fwalk pins each visited directory. The portable fallback checks the
    identity observed by its parent before accepting any yielded subtree.
    Directory storage and link inodes are included; missing st_blocks falls
    back to logical sizes. Inaccessible metadata or an exhausted metadata
    budget makes the estimate partial; inventories never grow without a bound.
    """
    root = Path(root)
    usage = Usage()
    try:
        initial = root.lstat()
    except FileNotFoundError:
        return usage
    except (OSError, ValueError):
        usage.incomplete = True
        return usage
    link = ('root', _key(initial, root))
    if not stat.S_ISDIR(initial.st_mode):
        # Use the same directory-entry identity as a containing tree scan.
        # An inode identifies shared data, not one particular hard link.
        try:
            parent = root.parent.stat()
        except OSError:
            usage.incomplete = True
            return usage
        if not stat.S_ISDIR(parent.st_mode) or not parent.st_ino:
            usage.incomplete = True
            return usage
        link = (_key(parent, root.parent), root.name)
    try:
        usage.add(initial, root, link, root)
    except _InventoryLimit:
        return usage
    if not stat.S_ISDIR(initial.st_mode):
        return usage
    expected = {str(root): _key(initial, root)}
    def failed(_error):
        usage.incomplete = True
    anchored = callable(getattr(os, 'fwalk', None))
    try:
        walker = cast(Generator[_WalkRow, None, None],
                      os.fwalk(root, follow_symlinks=False, onerror=failed) if anchored
                      else os.walk(root, followlinks=False, onerror=failed))
    except OSError:
        usage.incomplete = True
        return usage
    interrupted = False
    try:
        try:
            for row in walker:
                path, directories, files = row[:3]
                try:
                    parent = os.fstat(cast(tuple[str, list[str], list[str], int], row)[3]) if anchored else os.lstat(path)
                    parent_key = _key(parent, path)
                    if (not stat.S_ISDIR(parent.st_mode)
                            or expected.get(str(path)) != parent_key):
                        directories[:] = []
                        usage.incomplete = True
                        continue
                    usage.add(parent, path, ('root', parent_key), root)
                    for name in directories + files:
                        item = Path(path) / name
                        try:
                            info = (os.stat(name, dir_fd=cast(tuple[str, list[str], list[str], int], row)[3], follow_symlinks=False) if anchored
                                    else item.lstat())
                        except OSError:
                            usage.incomplete = True
                            continue
                        usage.add(info, item, (parent_key, name), root)
                        if stat.S_ISDIR(info.st_mode):
                            expected[str(item)] = _key(info, item)
                except OSError:
                    directories[:] = []
                    usage.incomplete = True
        except (OSError, _InventoryLimit):
            usage.incomplete = True
    except BaseException:
        interrupted = True
        raise
    finally:
        try:
            walker.close()
        except BaseException as exc:
            if not interrupted:
                if isinstance(exc, OSError):
                    usage.incomplete = True
                else:
                    raise
    return usage


def estimate_removals(paths):
    """Credit each unique reclaimable inode once, to its last selected root."""
    paths = list(dict.fromkeys(Path(path) for path in paths))
    inventory = Usage()
    for path in paths:
        if inventory.truncated:
            break
        inventory.merge(scan_usage(path))
    order = {path: index for index, path in enumerate(paths)}
    sizes = {path: 0 for path in paths}
    for entry in inventory.entries.values():
        if entry.reclaimable:
            owner = max(entry.roots, key=order.__getitem__)
            sizes[owner] += entry.size
    return sizes, inventory.incomplete
