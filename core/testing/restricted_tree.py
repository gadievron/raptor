"""Permission-restricted, test-owned trees with unconditional teardown."""

from contextlib import contextmanager
from pathlib import Path
from core.atomic_fs import rmtree_hardened


@contextmanager
def restricted_tree(path: Path, mode: int = 0o000):
    """Leave a nested tool-output directory unwritable until cleanup."""
    nested = path / "locked" / "nested"
    try:
        nested.mkdir(parents=True)
        (nested / "payload").write_bytes(b"x" * 4096)
        (path / "locked").chmod(mode)
        yield path
    finally:
        rmtree_hardened(path)
