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
import stat
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


def _link_stat(uid: int) -> os.stat_result:
    """A fabricated lstat result for a symlink owned by ``uid``."""
    return os.stat_result((stat.S_IFLNK | 0o777, 1, 1, 1, uid, 0, 0, 0, 0, 0))


def _dir_stat(uid: int) -> os.stat_result:
    """A fabricated lstat result for a plain directory owned by ``uid``."""
    return os.stat_result((stat.S_IFDIR | 0o755, 1, 1, 1, uid, 0, 0, 0, 0, 0))


def _file_stat(uid: int) -> os.stat_result:
    """A fabricated lstat result for a regular file owned by ``uid``."""
    return os.stat_result((stat.S_IFREG | 0o644, 1, 1, 1, uid, 0, 0, 0, 0, 0))


class TestUsrmergeRedirectExemption:
    """The canonical root-owned usrmerge aliases (/bin -> /usr/bin
    etc.) are exempt from the planted-redirect announcement — logging
    policy only, the grant still binds the resolved tree. Everything
    outside the exact three-condition match keeps the warning. All
    tests fabricate the filesystem view (realpath/lstat) so none needs
    a usrmerged host, real top-level symlinks, or root."""

    def _fake_fs(self, monkeypatch, realpaths: dict, lstats: dict) -> None:
        real_realpath = os.path.realpath
        real_lstat = os.lstat

        def fake_realpath(p, **kw):
            return realpaths.get(p, real_realpath(p, **kw))

        def fake_lstat(p, *a, **kw):
            if p in lstats:
                return lstats[p]
            return real_lstat(p, *a, **kw)

        monkeypatch.setattr(os.path, "realpath", fake_realpath)
        monkeypatch.setattr(os, "lstat", fake_lstat)

    @pytest.mark.parametrize(
        "alias", ["/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"],
    )
    def test_canonical_usrmerge_root_symlink_not_announced(
            self, monkeypatch, caplog, alias):
        # Every member of the canonical set is exempt — a shrunk
        # allowlist fails one of these parametrizations.
        target = "/usr" + alias
        self._fake_fs(monkeypatch, {alias: target},
                      {alias: _link_stat(0)})
        landlock._grant_redirects_warned.clear()
        with caplog.at_level(logging.WARNING, logger="core.sandbox.landlock"):
            resolved = landlock._resolve_grant_paths([alias], "readable")
        # Grant semantics unchanged: the rule still binds the
        # resolved tree; only the announcement is suppressed.
        assert resolved == [target]
        assert not [r for r in caplog.records
                    if "resolves through a symlink" in r.message]

    def test_cross_name_usr_target_warns(self, monkeypatch, caplog):
        # A root-owned symlink from one canonical name to a DIFFERENT
        # /usr directory is not the usrmerge shape — same-basename is
        # required, not merely "somewhere under /usr".
        self._fake_fs(monkeypatch, {"/bin": "/usr/sbin"},
                      {"/bin": _link_stat(0)})
        landlock._grant_redirects_warned.clear()
        with caplog.at_level(logging.WARNING, logger="core.sandbox.landlock"):
            resolved = landlock._resolve_grant_paths(["/bin"], "readable")
        assert resolved == ["/usr/sbin"]
        assert [r for r in caplog.records
                if "resolves through a symlink" in r.message]

    def test_trailing_slash_spelling_still_exempt(self, monkeypatch, caplog):
        # Normalization contract: the predicate must receive the
        # NORMALIZED requested path — a "/lib/" grant spelling is the
        # same canonical alias, not a warn-through miss.
        self._fake_fs(monkeypatch,
                      {"/lib/": "/usr/lib", "/lib": "/usr/lib"},
                      {"/lib": _link_stat(0)})
        landlock._grant_redirects_warned.clear()
        with caplog.at_level(logging.WARNING, logger="core.sandbox.landlock"):
            resolved = landlock._resolve_grant_paths(["/lib/"], "readable")
        assert resolved == ["/usr/lib"]
        assert not [r for r in caplog.records
                    if "resolves through a symlink" in r.message]

    def test_canonical_name_to_noncanonical_target_warns(
            self, monkeypatch, caplog):
        self._fake_fs(monkeypatch, {"/lib": "/opt/x"},
                      {"/lib": _link_stat(0)})
        landlock._grant_redirects_warned.clear()
        with caplog.at_level(logging.WARNING, logger="core.sandbox.landlock"):
            resolved = landlock._resolve_grant_paths(["/lib"], "readable")
        assert resolved == ["/opt/x"]
        assert [r for r in caplog.records
                if "resolves through a symlink" in r.message]

    def test_non_root_owned_symlink_warns(self, monkeypatch, caplog):
        self._fake_fs(monkeypatch, {"/sbin": "/usr/sbin"},
                      {"/sbin": _link_stat(1000)})
        landlock._grant_redirects_warned.clear()
        with caplog.at_level(logging.WARNING, logger="core.sandbox.landlock"):
            resolved = landlock._resolve_grant_paths(["/sbin"], "readable")
        assert resolved == ["/usr/sbin"]
        assert [r for r in caplog.records
                if "resolves through a symlink" in r.message]

    def test_non_listed_top_level_path_warns(self, monkeypatch, caplog):
        # Same /usr/<basename> shape, but /data is not in the
        # canonical set — exact-match allowlist, never a prefix rule.
        self._fake_fs(monkeypatch, {"/data": "/usr/data"},
                      {"/data": _link_stat(0)})
        landlock._grant_redirects_warned.clear()
        with caplog.at_level(logging.WARNING, logger="core.sandbox.landlock"):
            resolved = landlock._resolve_grant_paths(["/data"], "readable")
        assert resolved == ["/usr/data"]
        assert [r for r in caplog.records
                if "resolves through a symlink" in r.message]

    def test_non_symlink_grant_stays_silent(self, tmp_path, caplog):
        # Existing behavior regression pin: a plain (non-symlink)
        # grant path never triggers the redirect announcement.
        plain = tmp_path / "grants"
        plain.mkdir()
        landlock._grant_redirects_warned.clear()
        with caplog.at_level(logging.WARNING, logger="core.sandbox.landlock"):
            resolved = landlock._resolve_grant_paths([str(plain)], "writable")
        assert resolved == [str(plain)]
        assert not [r for r in caplog.records
                    if "resolves through a symlink" in r.message]

    # ---- the pure predicate, via the injectable lstat ----

    def test_predicate_true_only_on_full_match(self):
        assert landlock._is_canonical_usrmerge_redirect(
            "/lib64", "/usr/lib64", lambda p: _link_stat(0))

    def test_predicate_false_when_lstat_sees_no_symlink(self):
        # Resolution says redirect but lstat sees a plain directory
        # (e.g. a bind-mount shim): keep the warning.
        assert not landlock._is_canonical_usrmerge_redirect(
            "/bin", "/usr/bin", lambda p: _dir_stat(0))
        # ... or a regular file: a symlink is required specifically,
        # not merely "anything that is not a directory".
        assert not landlock._is_canonical_usrmerge_redirect(
            "/bin", "/usr/bin", lambda p: _file_stat(0))

    def test_predicate_false_on_system_but_nonzero_owner(self):
        # Root means uid 0 exactly — a low system uid (1) is not
        # trust-equivalent.
        assert not landlock._is_canonical_usrmerge_redirect(
            "/bin", "/usr/bin", lambda p: _link_stat(1))

    def test_predicate_false_on_lstat_failure(self):
        def _raise(p: str) -> os.stat_result:
            raise OSError(errno.EACCES, "denied", p)
        assert not landlock._is_canonical_usrmerge_redirect(
            "/bin", "/usr/bin", _raise)

    def test_predicate_false_on_prefix_spellings(self):
        # Children of a canonical alias are NOT exempt — only the
        # top-level path itself.
        assert not landlock._is_canonical_usrmerge_redirect(
            "/bin/sh", "/usr/bin/sh", lambda p: _link_stat(0))
        assert not landlock._is_canonical_usrmerge_redirect(
            "/lib64x", "/usr/lib64x", lambda p: _link_stat(0))


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


class TestPerProcessProcfsGrantsSkipped:
    """/proc/self/* and /proc/thread-self/* grant paths yield NO rule:
    the parent-side realpath would bind the rule to the RESOLVER's pid
    dir — granting the sandboxed child the parent's files (maps,
    cgroup) while never matching the child's own per-reader reads.
    Reads of the class ride the wholesale /proc grant where present;
    where /proc reads are withdrawn they stay withdrawn."""

    def test_per_process_procfs_paths_produce_no_rule(self, tmp_path):
        real = tmp_path / "real"
        real.mkdir()
        resolved = landlock._resolve_grant_paths(
            ["/proc/self/maps", "/proc/self/cgroup",
             "/proc/thread-self/stat", str(real)],
            "readable",
        )
        assert resolved == [os.path.realpath(str(real))]
        # In particular: no rule bound to THIS process's pid dir.
        assert not any(f"/proc/{os.getpid()}/" in p for p in resolved)

    def test_write_kind_also_skipped(self):
        assert landlock._resolve_grant_paths(
            ["/proc/self/oom_score_adj"], "writable",
        ) == []

    def test_skip_is_not_announced_as_planted_redirect(self, caplog):
        with caplog.at_level(logging.WARNING, logger="core.sandbox.landlock"):
            landlock._resolve_grant_paths(["/proc/self/cgroup"], "readable")
        assert not any(
            "planted redirect" in r.getMessage() for r in caplog.records
        )

    def test_pid_named_proc_path_still_resolves(self):
        # A pid-NAMED procfs path names one stable pid dir — not in
        # the per-reader class, so it keeps the normal resolution
        # (and with it the pinned-walk defense).
        path = f"/proc/{os.getpid()}/cmdline"
        assert landlock._resolve_grant_paths([path], "readable") == [path]
