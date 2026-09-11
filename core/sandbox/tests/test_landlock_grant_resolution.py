"""Validation-time resolution of Landlock grant paths.

Threat under test: a symlink planted at a writable/readable rule path
AFTER the parent's validation but BEFORE the forked child's
add_rule(2). The child used to realpath the rule path itself, post
fork — so a symlink planted anywhere in the spawn window resolved like
a benign operator symlink and the WRITE grant landed beneath the
symlink's target. The planter need not be an unconfined same-UID
process: a Landlock-confined sibling with write access to a shared
output tree can create symlinks there (MAKE_SYM is in the granted
write mask) pointing at trees it cannot write, so a steered grant
hands the next sandbox access the planter never had.

Defense: ``_resolve_grant_paths`` realpaths every rule path in the
PARENT when the preexec closure is built; the child walks the
pre-resolved canonical string with the symlink-refusing pinned walk
(``_open_grant_pinned``), so any symlink that appears after
validation surfaces as ELOOP and the rule falls under the global
deny. A symlink already present at validation time resolves normally
(operator intent — usrmerge ``/bin``, symlinked homes) but the
redirect is announced once per (requested, resolved) pair.

Hermeticity: only the path-resolution and pinned-walk logic runs —
no Landlock ruleset is created, no restrict_self, no namespaces.
Needs Linux + O_PATH only.
"""

from __future__ import annotations

import errno
import logging
import os
import sys

import pytest

from core.sandbox import landlock

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "O_PATH"),
    reason="Linux-only sandbox internals (O_PATH pinned walk)",
)


def _close(fd: int) -> None:
    try:
        os.close(fd)
    except OSError:
        pass


class TestValidationTimeResolution:
    def test_factory_resolves_grants_at_creation_time(self, monkeypatch,
                                                      tmp_path):
        """The resolve step must run when the preexec closure is BUILT
        (parent, validation time), not deferred into the closure —
        deferring it reopens the whole fork/spawn plant window."""
        calls: list[tuple[list, str]] = []
        real = landlock._resolve_grant_paths

        def _recording(paths, kind):
            calls.append((list(paths), kind))
            return real(paths, kind)

        monkeypatch.setattr(landlock, "_resolve_grant_paths", _recording)
        writable = tmp_path / "out"
        writable.mkdir()
        readable = tmp_path / "ro"
        readable.mkdir()
        fn = landlock._make_landlock_preexec(
            [str(writable)], readable_paths=[str(readable)],
        )
        assert callable(fn)
        # Both grant lists resolved during factory construction; the
        # closure itself was never invoked.
        assert ([str(writable)], "writable") in calls
        assert ([str(readable)], "readable") in calls

    def test_benign_prevalidation_symlink_resolves_and_warns(self, tmp_path,
                                                             caplog):
        """A symlink already present at validation time is operator
        intent: it resolves to its target (grant follows the resolved
        tree) and the redirect is announced."""
        real = tmp_path / "real"
        real.mkdir()
        link = tmp_path / "link"
        link.symlink_to(real)
        landlock._grant_redirects_warned.clear()
        with caplog.at_level(logging.WARNING, logger="core.sandbox.landlock"):
            resolved = landlock._resolve_grant_paths([str(link)], "writable")
        assert resolved == [str(real)]
        assert any("resolves through a symlink" in r.message
                   for r in caplog.records)
        fd, is_dir = landlock._open_grant_pinned(resolved[0])
        try:
            assert is_dir
            # The pinned fd names the resolved target inode.
            assert os.fstat(fd).st_ino == real.stat().st_ino
        finally:
            _close(fd)

    def test_redirect_warning_once_per_pair(self, tmp_path, caplog):
        real = tmp_path / "real"
        real.mkdir()
        link = tmp_path / "link"
        link.symlink_to(real)
        landlock._grant_redirects_warned.clear()
        with caplog.at_level(logging.WARNING, logger="core.sandbox.landlock"):
            landlock._resolve_grant_paths([str(link)], "writable")
            landlock._resolve_grant_paths([str(link)], "writable")
        hits = [r for r in caplog.records
                if "resolves through a symlink" in r.message]
        assert len(hits) == 1

    def test_plain_path_resolves_silently(self, tmp_path, caplog):
        plain = tmp_path / "out"
        plain.mkdir()
        landlock._grant_redirects_warned.clear()
        with caplog.at_level(logging.WARNING, logger="core.sandbox.landlock"):
            resolved = landlock._resolve_grant_paths([str(plain)], "writable")
        assert resolved == [str(plain)]
        assert not [r for r in caplog.records
                    if "resolves through a symlink" in r.message]


class TestPostValidationSwapRefused:
    def test_component_swapped_to_symlink_refuses_eloop(self, tmp_path):
        """Attack shape: validation resolves the real grant dir; the
        sibling then renames it away and plants a symlink to a victim
        tree it cannot write. The child's pinned walk of the
        pre-resolved string must refuse — never pin the victim."""
        victim = tmp_path / "victim"
        victim.mkdir()
        shared = tmp_path / "shared"
        shared.mkdir()
        grant = shared / "run-1"
        grant.mkdir()

        resolved = landlock._resolve_grant_paths([str(grant)], "writable")
        assert resolved == [str(grant)]

        # Post-validation swap (the fork/spawn window).
        os.rename(grant, shared / "run-1.moved")
        (shared / "run-1").symlink_to(victim)

        with pytest.raises(OSError) as ei:
            landlock._open_grant_pinned(resolved[0])
        assert ei.value.errno == errno.ELOOP

    def test_parent_component_swap_refuses_eloop(self, tmp_path):
        """Same swap one level up: an intermediate component replaced
        by a symlink also refuses."""
        victim = tmp_path / "victim"
        (victim / "run-1").mkdir(parents=True)
        shared = tmp_path / "shared"
        (shared / "run-1").mkdir(parents=True)

        canonical = landlock._resolve_grant_paths(
            [str(shared / "run-1")], "writable",
        )[0]
        os.rename(shared, tmp_path / "shared.moved")
        (tmp_path / "shared").symlink_to(victim)

        with pytest.raises(OSError) as ei:
            landlock._open_grant_pinned(canonical)
        assert ei.value.errno == errno.ELOOP

    def test_file_grant_reports_not_dir(self, tmp_path):
        f = tmp_path / "grant.file"
        f.write_text("x")
        canonical = landlock._resolve_grant_paths([str(f)], "readable")[0]
        fd, is_dir = landlock._open_grant_pinned(canonical)
        try:
            assert not is_dir
        finally:
            _close(fd)
