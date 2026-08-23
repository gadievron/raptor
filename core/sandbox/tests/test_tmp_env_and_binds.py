"""Regressions for two /tmp-adjacent sandbox failure classes.

1. readable_paths FILE binds under /tmp: the mount-ns bind loop seeded
   its already-bound predicate with ALL per-ns shadow paths, but /tmp
   and /run are fresh EMPTY tmpfs — nothing populated their subtrees,
   so a file bind beneath them skipped mount-point-stub creation and
   failed with ENOENT at mount(2). Real-world shape: a RAPTOR checkout
   living under /tmp couldn't bind its own libexec helpers
   (raptor-pid1-shim) and every sandboxed r2 invocation exited 126.

2. Inherited TMPDIR under /tmp: the child inherits TMPDIR from the
   host; a custom value (operator TMPDIR, nested pytest basetemp)
   named a directory that doesn't exist in the private /tmp, and the
   Landlock writable baseline followed gettempdir() instead of /tmp —
   compilers failed with "Cannot create temporary file in /tmp/:
   Permission denied". Fixed twice over: mount-ns re-creates the
   inherited temp-env dirs inside its fresh tmpfs, and the writable
   baseline keeps /tmp alongside a custom gettempdir().

Both tests use real namespaces and skip on hosts that can't engage
them, following test_engagement_failloud's gating.
"""

import shutil
import sys
import tempfile
from pathlib import Path

import pytest

from core.sandbox import check_unshare_engages, sandbox

_linux_only = pytest.mark.skipif(
    sys.platform != "linux", reason="mount-ns sandbox is Linux-only",
)


def _require_namespaces():
    ok, _ = check_unshare_engages(["--user", "--pid", "--fork", "--ipc"])
    if not ok:
        pytest.skip("host cannot engage namespaces")


@_linux_only
class TestReadableFileBindUnderTmp:

    def test_file_under_tmp_readable_inside_sandbox(self, tmp_path):
        _require_namespaces()
        # The helper file must live under the REAL /tmp — that's the
        # shadowed-by-fresh-tmpfs region the bug lived in. Cleaned in
        # finally; short prefix keeps paths well under AF_UNIX-ish
        # length concerns.
        src_dir = tempfile.mkdtemp(prefix="rpt-bind-", dir="/tmp")
        try:
            helper = Path(src_dir) / "helper.txt"
            helper.write_text("bind-me-ok\n")
            tgt = tmp_path / "tgt"
            out = tmp_path / "out"
            tgt.mkdir()
            out.mkdir()
            # restrict_reads=True is what routes readable_paths into
            # the mount-ns extra_ro_paths binds — the same posture the
            # r2 wrapper (libexec/raptor-r2-sandboxed) runs with.
            with sandbox(block_network=True, target=str(tgt),
                         output=str(out), restrict_reads=True,
                         readable_paths=[str(helper)]) as run:
                r = run(["cat", str(helper)],
                        capture_output=True, text=True)
            if r.returncode == -9:
                pytest.skip("degrade path hit EBADF (CI container gap)")
            assert r.returncode == 0, (
                f"file bind under /tmp failed: rc={r.returncode} "
                f"stderr={r.stderr!r}"
            )
            assert "bind-me-ok" in (r.stdout or "")
        finally:
            shutil.rmtree(src_dir, ignore_errors=True)


@_linux_only
class TestInheritedTmpdirUnderTmp:

    def test_custom_tmpdir_usable_inside_sandbox(self, tmp_path,
                                                 monkeypatch):
        _require_namespaces()
        custom = tempfile.mkdtemp(prefix="rpt-tmpdir-", dir="/tmp")
        try:
            # monkeypatch covers the mount-setup child (it re-creates
            # temp-env dirs from the inherited os.environ); the
            # explicit env= covers the exec'd command itself. The
            # parent's cached tempfile.gettempdir() is unaffected,
            # mirroring production where children get TMPDIR at
            # process start.
            import os
            monkeypatch.setenv("TMPDIR", custom)
            tgt = tmp_path / "tgt"
            out = tmp_path / "out"
            tgt.mkdir()
            out.mkdir()
            with sandbox(block_network=True, target=str(tgt),
                         output=str(out)) as run:
                r = run(["sh", "-c", 'f=$(mktemp) && echo "made:$f"'],
                        capture_output=True, text=True,
                        env={**os.environ, "TMPDIR": custom})
            if r.returncode == -9:
                pytest.skip("degrade path hit EBADF (CI container gap)")
            assert r.returncode == 0, (
                f"mktemp under inherited TMPDIR failed: "
                f"rc={r.returncode} stderr={r.stderr!r}"
            )
            assert f"made:{custom}/" in (r.stdout or "")
        finally:
            shutil.rmtree(custom, ignore_errors=True)
