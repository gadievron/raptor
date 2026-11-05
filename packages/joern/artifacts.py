"""Graph byte identity and private immutable copies for live Joern workers."""

from __future__ import annotations

import hashlib
import logging
import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path

from core.atomic_fs import rmtree_hardened
from core.json import dumps_canonical
from core.source import open_regular_gated

logger = logging.getLogger(__name__)


def graph_digest(path: Path) -> str:
    """Hash a regular graph through one descriptor; reject concurrent edits."""
    with open_regular_gated(path, follow_symlinks=False) as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("graph is not a regular file")
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size, after.st_mtime_ns, after.st_ctime_ns,
        ):
            raise ValueError("graph changed while being hashed")
        return digest


def toolchain_identity() -> str:
    """Identify installed frontend/runtime files without booting a JVM.

    Installation files are trusted; target inputs are not. Include library
    names and file versions so a distribution upgrade invalidates its cache.
    """
    from .prereqs import _java_path, _joern_parse_path, _joern_path

    entries: list[tuple[str, int, int, int] | tuple[str, None] | None] = []
    for index, executable in enumerate((_joern_path(), _joern_parse_path(), _java_path())):
        if executable is None:
            entries.append(None)
            continue
        path = Path(executable).resolve()
        library = path.parent.parent / "lib" if path.parent.name == "bin" else path.parent / "lib"
        paths = [path, *sorted(library.glob("*.jar"))]
        if index != 2:
            distribution = library.parent
            paths.extend(sorted(distribution.glob("*.sh")))
            paths.extend(sorted((distribution / "bin").glob("*")))
            paths.extend(sorted((distribution / "conf").glob("*")))
        if index == 2:
            paths.extend((library.parent / "release", library / "modules"))
        for item in paths:
            try:
                info = item.stat()
                entries.append((str(item), info.st_size, info.st_mtime_ns, info.st_ctime_ns))
            except OSError:
                entries.append((str(item), None))
    return hashlib.sha256(dumps_canonical(entries).encode()).hexdigest()


@dataclass
class FrozenGraph:
    """A service-owned copy; cache replacement/eviction cannot alter it."""

    path: Path
    digest: str

    @classmethod
    def copy(cls, source: Path, *, directory: Path, expected: str | None = None):
        directory.mkdir(parents=True, exist_ok=True)
        root = Path(tempfile.mkdtemp(prefix="graph-", dir=directory))
        destination = root / "cpg.bin"
        try:
            with open_regular_gated(source, follow_symlinks=False) as stream, destination.open("xb") as output:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode):
                    raise ValueError("graph is not a regular file")
                digest = hashlib.sha256()
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
                    output.write(chunk)
                after = os.fstat(stream.fileno())
                if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_size, after.st_mtime_ns, after.st_ctime_ns,
                ):
                    raise ValueError("graph changed while being copied")
            value = digest.hexdigest()
            if expected is not None and value != expected:
                raise ValueError("graph bytes do not match their build receipt")
            destination.chmod(0o400)
            return cls(destination, value)
        except BaseException:
            if not rmtree_hardened(root):
                logger.warning("incomplete frozen graph cleanup at %r", root)
            raise

    def close(self) -> bool:
        removed = rmtree_hardened(self.path.parent)
        if not removed:
            logger.warning("incomplete frozen graph cleanup at %r", self.path.parent)
        return removed
