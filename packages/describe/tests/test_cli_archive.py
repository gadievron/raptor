"""Tests for ``packages/describe/cli.py`` — shared driver
covering archive handling.

End-to-end coverage:
* directory target — happy path (the existing tests already
  exercise this; here we cover the archive branches)
* tarball / zip targets — extracted on the fly, described,
  temp dir cleaned up
* non-archive binary file — refused with operator-actionable
  stderr
* JSON output preserves ``archive_label``
"""

from __future__ import annotations

import io
import json
import subprocess
import tarfile
import zipfile
from pathlib import Path


from packages.describe.cli import describe_main


def _make_c_daemon_source(d: Path) -> None:
    """Synthesise a c.userspace-daemon shape inside ``d``."""
    d.mkdir(parents=True, exist_ok=True)
    (d / "configure.ac").write_text("")
    (d / "Makefile.am").write_text("")
    src = d / "src"
    src.mkdir()
    for i in range(5):
        (src / f"f{i}.c").write_text("int main(){return 0;}")


def _make_tarball(src_dir: Path, dest_archive: Path) -> None:
    with tarfile.open(dest_archive, "w:gz") as tf:
        tf.add(src_dir, arcname=src_dir.name)


def _make_zip(src_dir: Path, dest_archive: Path) -> None:
    with zipfile.ZipFile(dest_archive, "w") as zf:
        for p in src_dir.rglob("*"):
            zf.write(p, arcname=p.relative_to(src_dir.parent))


class TestArchiveHandling:
    def test_tarball_extracted_and_described(self, tmp_path):
        src = tmp_path / "proj"
        _make_c_daemon_source(src)
        archive = tmp_path / "proj.tar.gz"
        _make_tarball(src, archive)

        out_buf = io.StringIO()
        err_buf = io.StringIO()
        rc = describe_main(
            str(archive), json_output=False,
            stdout=out_buf, stderr=err_buf,
        )
        assert rc == 0, err_buf.getvalue()
        out = out_buf.getvalue()
        # Operator sees "Source: archive ..." so they know
        # the rest of the block describes the extracted tree.
        assert "Source: archive proj.tar.gz" in out
        # Catalog match still triggers on the extracted tree.
        assert "Detected type: c.userspace-daemon" in out
        assert "autotools" in out

    def test_zip_extracted_and_described(self, tmp_path):
        src = tmp_path / "proj"
        _make_c_daemon_source(src)
        archive = tmp_path / "proj.zip"
        _make_zip(src, archive)

        out_buf = io.StringIO()
        err_buf = io.StringIO()
        rc = describe_main(
            str(archive), json_output=False,
            stdout=out_buf, stderr=err_buf,
        )
        assert rc == 0, err_buf.getvalue()
        assert "Source: archive proj.zip" in out_buf.getvalue()

    def test_non_archive_binary_refused(self, tmp_path):
        # Random binary blob (not a recognised archive format).
        blob = tmp_path / "mystery.bin"
        blob.write_bytes(b"\x00\x01\x02RANDOMBYTES\xff" * 100)

        out_buf = io.StringIO()
        err_buf = io.StringIO()
        rc = describe_main(
            str(blob), json_output=False,
            stdout=out_buf, stderr=err_buf,
        )
        assert rc == 1
        err = err_buf.getvalue()
        assert "not a recognised archive" in err

    def test_nonexistent_target_refused(self, tmp_path):
        out_buf = io.StringIO()
        err_buf = io.StringIO()
        rc = describe_main(
            str(tmp_path / "does-not-exist"), json_output=False,
            stdout=out_buf, stderr=err_buf,
        )
        assert rc == 1
        assert "does not exist" in err_buf.getvalue()

    def test_archive_label_surfaces_in_json(self, tmp_path):
        src = tmp_path / "proj"
        _make_c_daemon_source(src)
        archive = tmp_path / "proj.tar.gz"
        _make_tarball(src, archive)

        out_buf = io.StringIO()
        err_buf = io.StringIO()
        rc = describe_main(
            str(archive), json_output=True,
            stdout=out_buf, stderr=err_buf,
        )
        assert rc == 0, err_buf.getvalue()
        doc = json.loads(out_buf.getvalue())
        assert doc["archive_label"] == "proj.tar.gz"

    def test_directory_target_archive_label_is_null(self, tmp_path):
        src = tmp_path / "proj"
        _make_c_daemon_source(src)
        out_buf = io.StringIO()
        err_buf = io.StringIO()
        rc = describe_main(
            str(src), json_output=True,
            stdout=out_buf, stderr=err_buf,
        )
        assert rc == 0, err_buf.getvalue()
        doc = json.loads(out_buf.getvalue())
        assert doc["archive_label"] is None

    def test_temp_dir_cleaned_up_after_archive_describe(self, tmp_path):
        # After a successful archive-describe, no raptor-describe-*
        # temp dirs should remain under the system tmp.
        import tempfile as _tmp
        src = tmp_path / "proj"
        _make_c_daemon_source(src)
        archive = tmp_path / "proj.tar.gz"
        _make_tarball(src, archive)

        sys_tmp = Path(_tmp.gettempdir())
        before = set(sys_tmp.glob("raptor-describe-*"))

        out_buf = io.StringIO()
        err_buf = io.StringIO()
        rc = describe_main(
            str(archive), json_output=False,
            stdout=out_buf, stderr=err_buf,
        )
        assert rc == 0, err_buf.getvalue()

        after = set(sys_tmp.glob("raptor-describe-*"))
        assert after == before, (
            f"temp extract dirs leaked: {after - before}"
        )


class TestSymlinkDefences:
    """Adversarial-fixture pins for the symlink-safety
    refactor in cli.py."""

    def test_single_subdir_symlink_not_followed(self, tmp_path):
        # Pre-fix: a tarball whose only top-level entry is a
        # symlink named ``proj`` pointing at ``/`` would make
        # /describe retarget at the host filesystem root.
        from packages.describe.cli import _descend_single_subdir
        extract_root = tmp_path / "extract"
        extract_root.mkdir()
        (extract_root / "proj").symlink_to("/etc")
        # Symlink-only entry → no descent; describe stays at root.
        assert _descend_single_subdir(extract_root) == extract_root


class TestArchiveCacheHit:
    """Pins the cache-reuse contract: when a prior /scan or
    /agentic on the same archive (same active project) has
    already extracted to ``<project_out>/_sources/<name>-<sha>``,
    /describe MUST use that path — not re-extract.
    """

    def _set_active_project(
        self, monkeypatch, home: Path, project_out: Path,
    ) -> None:
        # Stand up a minimal project.json + .active symlink so
        # ``_resolve_active_project`` finds it.
        proj_dir = home / ".raptor" / "projects"
        proj_dir.mkdir(parents=True, exist_ok=True)
        import json as _json
        (proj_dir / "_t.json").write_text(_json.dumps({
            "name": "_t",
            "target": "/tmp",
            "output_dir": str(project_out),
        }))
        active = proj_dir / ".active"
        if active.is_symlink() or active.exists():
            active.unlink()
        active.symlink_to("_t.json")
        monkeypatch.setenv("HOME", str(home))

    def test_cache_hit_skips_extraction(
        self, tmp_path, monkeypatch,
    ):
        # 1. Create a real archive + its content sha + cache
        #    name (mirroring how /scan would have populated
        #    the cache via _unpack_archive_target).
        src = tmp_path / "proj"
        _make_c_daemon_source(src)
        archive = tmp_path / "proj.tar.gz"
        _make_tarball(src, archive)

        from core.archive import safe_cache_name
        from core.run.provenance import archive_snapshot
        snap = archive_snapshot(archive)
        assert snap is not None
        cache_name = safe_cache_name(
            snap["archive_name"], snap["archive_sha256"],
        )

        # 2. Pre-populate the cache dir with the same shape
        #    /scan would have left there (extracted tree).
        project_out = tmp_path / "project_out"
        cache_dir = project_out / "_sources" / cache_name
        cache_dir.mkdir(parents=True)
        # Mark the cached tree so we can detect /describe used IT
        # rather than a fresh extract. Catalog content is the same
        # shape as the source so c.userspace-daemon still matches.
        _make_c_daemon_source(cache_dir / "proj")
        (cache_dir / "proj" / "CACHE-MARKER").write_text(
            "from-cache",
        )

        # 3. Stand up an active project pointing at project_out.
        self._set_active_project(
            monkeypatch, tmp_path / "fakehome", project_out,
        )

        # 4. Run describe. Expect cache hit → no tmp extract dir
        #    created (verify with /tmp tally) + content reflects
        #    the cached tree.
        import tempfile as _tmp
        sys_tmp = Path(_tmp.gettempdir())
        before = set(sys_tmp.glob("raptor-describe-*"))

        out_buf = io.StringIO()
        err_buf = io.StringIO()
        rc = describe_main(
            str(archive), json_output=False,
            stdout=out_buf, stderr=err_buf,
        )
        assert rc == 0, err_buf.getvalue()

        after = set(sys_tmp.glob("raptor-describe-*"))
        assert after == before, (
            "cache hit must NOT create a tmp extract dir; "
            f"new tmp dirs: {after - before}"
        )
        assert "Source: archive proj.tar.gz" in out_buf.getvalue()
        assert "c.userspace-daemon" in out_buf.getvalue()


class TestRaptorDescribeArchiveE2E:
    """End-to-end through ``raptor.py describe`` with the
    real subprocess + argparse path, to confirm the
    mode_describe → describe_main wiring works."""

    def test_subprocess_invocation_on_archive(self, tmp_path):
        import os
        import sys as _sys

        src = tmp_path / "proj"
        _make_c_daemon_source(src)
        archive = tmp_path / "proj.tar.gz"
        _make_tarball(src, archive)

        repo = Path(__file__).resolve().parents[3]
        env = os.environ.copy()
        env["CLAUDECODE"] = "1"
        env["RAPTOR_DIR"] = str(repo)
        result = subprocess.run(
            [_sys.executable, str(repo / "raptor.py"),
             "describe", "--target", str(archive)],
            capture_output=True, text=True, env=env, timeout=30,
        )
        assert result.returncode == 0, result.stderr
        assert "Source: archive proj.tar.gz" in result.stdout
