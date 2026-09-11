"""Resolver-cache manifest hashing must be injective.

The resolver dry-run cache is shared machine-wide and keyed on a hash
of each project's manifest files. The old framing spliced raw file
bytes with ``\\0`` separators — content containing ``\\0`` could make
one project's single file byte-identical to another project's two
files, and unreadable files vanished from the hash entirely. Either
collision serves one project's cached ``ResolverResult`` (proposed
lockfile included) to a different project.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from packages.sca.resolvers._cache import manifest_hash


class _StubResolver:
    ecosystem = "npm"
    MANIFEST_FILES = ("a.manifest", "b.manifest")


class _NoOptInResolver:
    ecosystem = "npm"


def _project(tmp_path: Path, name: str, files: dict[str, bytes]) -> Path:
    d = tmp_path / name
    d.mkdir()
    for rel, payload in files.items():
        (d / rel).write_bytes(payload)
    return d


def test_separator_splice_no_longer_collides(tmp_path: Path) -> None:
    """One file whose CONTENT embeds the other file's framing must not
    hash like a project that really has both files."""
    one_file = _project(tmp_path, "one", {
        "a.manifest": b"x\x00b.manifest\x00y",
    })
    two_files = _project(tmp_path, "two", {
        "a.manifest": b"x",
        "b.manifest": b"y",
    })
    r = _StubResolver()
    h1 = manifest_hash(r, one_file)
    h2 = manifest_hash(r, two_files)
    assert h1 is not None and h2 is not None
    assert h1 != h2


def test_identical_inputs_still_hit(tmp_path: Path) -> None:
    files = {"a.manifest": b"alpha\x00beta", "b.manifest": b"gamma"}
    p1 = _project(tmp_path, "p1", files)
    p2 = _project(tmp_path, "p2", files)
    r = _StubResolver()
    assert manifest_hash(r, p1) == manifest_hash(r, p2)


@pytest.mark.skipif(os.geteuid() == 0,
                    reason="chmod 000 does not block reads for root")
def test_unreadable_file_is_distinct_from_absent(tmp_path: Path) -> None:
    """A present-but-unreadable lockfile must not hash identically to
    a project with no lockfile at all."""
    with_unreadable = _project(tmp_path, "unreadable", {
        "a.manifest": b"x",
        "b.manifest": b"whatever",
    })
    (with_unreadable / "b.manifest").chmod(0)
    without = _project(tmp_path, "without", {"a.manifest": b"x"})
    r = _StubResolver()
    h1 = manifest_hash(r, with_unreadable)
    h2 = manifest_hash(r, without)
    assert h1 is not None and h2 is not None
    assert h1 != h2


def test_absent_files_contribute_nothing(tmp_path: Path) -> None:
    """Declared-but-absent files keep not affecting the hash (a
    package.json-only project hashes the same regardless of the
    declaration list's other entries)."""
    p = _project(tmp_path, "only-a", {"a.manifest": b"x"})

    class _WiderResolver:
        ecosystem = "npm"
        MANIFEST_FILES = ("a.manifest", "b.manifest", "c.manifest")

    assert manifest_hash(_StubResolver(), p) == \
        manifest_hash(_WiderResolver(), p)


def test_no_opt_in_and_no_files_return_none(tmp_path: Path) -> None:
    empty = _project(tmp_path, "empty", {})
    assert manifest_hash(_NoOptInResolver(), empty) is None
    assert manifest_hash(_StubResolver(), empty) is None


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
