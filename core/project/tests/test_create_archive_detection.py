"""project-create target-type detection sees inside archive targets.

Pre-fix `_detect_target_type` ran the extension/glob catalog against
the archive FILE, so every `/project create --target app.zip`
classified as ``generic`` and printed generic-wrong /scan pack
baselines in the create tuning block. Detection now runs on the
extracted tree via the /describe resolver (cache hit or one-shot tmp
extract, single-subdir descent), with tmp extractions cleaned up and
all failures collapsing to None (create never refuses over the
detection substrate).
"""

import io
import tarfile
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

from core.project.cli import _detect_target_type


def _make_c_daemon_tree(d: Path) -> None:
    d.mkdir(parents=True, exist_ok=True)
    (d / "configure.ac").write_text("")
    (d / "Makefile.am").write_text("")
    src = d / "src"
    src.mkdir()
    for i in range(5):
        (src / f"f{i}.c").write_text("int main(){return 0;}")


class TestCreateArchiveDetection(unittest.TestCase):
    def test_tarball_detected_on_extracted_tree(self):
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            src = tmp / "proj"
            _make_c_daemon_tree(src)
            archive = tmp / "proj.tar.gz"
            with tarfile.open(archive, "w:gz") as tf:
                tf.add(src, arcname=src.name)
            entry = _detect_target_type(str(archive))
            self.assertIsNotNone(entry)
            self.assertNotEqual(entry.name, "generic")

    def test_zip_detected_on_extracted_tree(self):
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            archive = tmp / "app.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("app/configure.ac", "")
                zf.writestr("app/Makefile.am", "")
                for i in range(5):
                    zf.writestr(f"app/src/f{i}.c",
                                "int main(){return 0;}")
            entry = _detect_target_type(str(archive))
            self.assertIsNotNone(entry)
            self.assertNotEqual(entry.name, "generic")

    def test_tmp_extraction_cleaned_up(self):
        import tempfile as _tempfile
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            src = tmp / "proj"
            _make_c_daemon_tree(src)
            archive = tmp / "proj.tar.gz"
            with tarfile.open(archive, "w:gz") as tf:
                tf.add(src, arcname=src.name)
            created: list[str] = []
            real_mkdtemp = _tempfile.mkdtemp

            def tracking(*a, **kw):
                d = real_mkdtemp(*a, **kw)
                if "raptor-describe" in d:
                    created.append(d)
                return d

            from unittest.mock import patch
            with patch("packages.describe.cli.tempfile.mkdtemp",
                       tracking):
                _detect_target_type(str(archive))
            for d in created:
                self.assertFalse(Path(d).exists(),
                                 f"tmp extraction leaked: {d}")

    def test_corrupt_archive_collapses_to_none(self):
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            bad = tmp / "broken.gz"
            bad.write_bytes(b"\x1f\x8b\x08" + b"\xff" * 8)
            buf = io.StringIO()
            import contextlib
            with contextlib.redirect_stderr(buf):
                self.assertIsNone(_detect_target_type(str(bad)))

    def test_directory_target_unchanged(self):
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            src = tmp / "proj"
            _make_c_daemon_tree(src)
            entry = _detect_target_type(str(src))
            self.assertIsNotNone(entry)
            self.assertNotEqual(entry.name, "generic")


if __name__ == "__main__":
    unittest.main()
