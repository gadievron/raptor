"""Bind-source / Landlock-grant pinning (generalisation of the
.audit dirfd pin).

Host-root-mode ``target=`` / ``output=`` / readable-path bind sources
and the Landlock writable/readable grant opens were pathname-resolved
at mount/add_rule time: a concurrent sibling sandbox sharing a
writable output tree could rmdir+symlink-swap a component between the
parent's validation and the mount(2), steering a (writable) bind or a
WRITE grant onto an arbitrary host directory.

Contract under test: sources are canonicalised (realpath) immediately
before a component walk that refuses symlinks (``open_pinned``), and
the mount consumes ``/proc/self/fd/<fd>`` so exactly the walked inode
is bound. Benign operator symlinks keep working (they resolve at the
realpath step); a post-canonicalisation swap is refused. Scope is
window-narrowing: a symlink PRE-PLANTED before canonicalisation
resolves like a benign one and still steers the bind — unchanged from
the pathname-mount behaviour this replaces; see _pathpin's scope
statement.
"""

from __future__ import annotations

import errno
import os
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from core.sandbox._pathpin import open_pinned  # noqa: E402

pytestmark = pytest.mark.skipif(
    not hasattr(os, "O_PATH"),
    reason="O_PATH is Linux-only; the pinned walk never engages on this platform",
)

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="Linux O_PATH semantics",
)


class TestOpenPinned:
    def test_pins_the_walked_inode(self, tmp_path):
        nested = tmp_path / "a" / "b" / "c"
        nested.mkdir(parents=True)
        fd = open_pinned(str(nested))
        try:
            assert os.fstat(fd).st_ino == os.stat(nested).st_ino
        finally:
            os.close(fd)

    def test_final_component_symlink_refused(self, tmp_path):
        real = tmp_path / "real"
        real.mkdir()
        link = tmp_path / "swapped"
        link.symlink_to(real)
        with pytest.raises(OSError) as exc:
            open_pinned(str(link))
        assert exc.value.errno == errno.ELOOP

    def test_intermediate_component_symlink_refused(self, tmp_path):
        real = tmp_path / "real"
        (real / "sub").mkdir(parents=True)
        link = tmp_path / "swapped"
        link.symlink_to(real)
        with pytest.raises(OSError) as exc:
            open_pinned(str(link / "sub"))
        assert exc.value.errno == errno.ELOOP

    def test_file_final_component_supported(self, tmp_path):
        f = tmp_path / "file.txt"
        f.write_text("x")
        fd = open_pinned(str(f))
        try:
            assert os.fstat(fd).st_ino == os.stat(f).st_ino
        finally:
            os.close(fd)

    def test_relative_and_noncanonical_rejected(self, tmp_path):
        with pytest.raises(ValueError):
            open_pinned("relative/path")
        with pytest.raises(ValueError):
            open_pinned(str(tmp_path) + "/a/../b")

    def test_vanished_component_raises_enoent(self, tmp_path):
        with pytest.raises(OSError) as exc:
            open_pinned(str(tmp_path / "never" / "existed"))
        assert exc.value.errno == errno.ENOENT


class TestBindPinnedSource:
    """The mount_ns wrapper: realpath-then-pin, /proc/self/fd source."""

    def test_mount_consumes_pinned_fd_not_pathname(
            self, tmp_path, monkeypatch):
        from core.sandbox import mount_ns

        src = tmp_path / "outdir"
        src.mkdir()
        calls: list[tuple] = []
        monkeypatch.setattr(
            mount_ns, "_mount",
            lambda *a, **k: calls.append(a),
        )
        mount_ns._bind_pinned_source(
            str(src), "/ignored/inside", mount_ns.MS_BIND,
        )
        assert len(calls) == 1
        source_arg = calls[0][0]
        assert source_arg.startswith("/proc/self/fd/")

    def test_benign_operator_symlink_still_binds(
            self, tmp_path, monkeypatch):
        # Pre-existing symlinks in operator paths resolve at the
        # realpath step — the walk sees the canonical form.
        from core.sandbox import mount_ns

        real = tmp_path / "real-out"
        real.mkdir()
        link = tmp_path / "via-link"
        link.symlink_to(real)
        calls: list[tuple] = []
        monkeypatch.setattr(
            mount_ns, "_mount",
            lambda *a, **k: calls.append(a),
        )
        mount_ns._bind_pinned_source(
            str(link), "/ignored/inside", mount_ns.MS_BIND,
        )
        assert len(calls) == 1

    def test_post_canonicalisation_swap_fails_loudly(
            self, tmp_path, monkeypatch):
        # Deterministic race simulation: realpath returns the
        # pre-swap answer while the filesystem already carries the
        # attacker's symlink — the walk must refuse, the mount must
        # never run.
        from core.sandbox import mount_ns

        victim = tmp_path / "shared" / "out"
        victim.mkdir(parents=True)
        stolen = tmp_path / "stolen-target"
        stolen.mkdir()
        pre_swap_answer = str(victim)
        # The swap: out → symlink to an unrelated directory.
        victim.rmdir()
        (tmp_path / "shared" / "out").symlink_to(stolen)

        monkeypatch.setattr(
            mount_ns.os.path, "realpath",
            lambda p, **_kw: pre_swap_answer,
        )
        calls: list[tuple] = []
        monkeypatch.setattr(
            mount_ns, "_mount",
            lambda *a, **k: calls.append(a),
        )
        with pytest.raises(OSError) as exc:
            mount_ns._bind_pinned_source(
                pre_swap_answer, "/ignored/inside", mount_ns.MS_BIND,
            )
        assert exc.value.errno == errno.ELOOP
        assert calls == []
