"""Regression test for the zip-bomb entry-count cap drift.

F029: `core/project/export.py::validate_zip_contents` (L67-110) wraps
`_check_zip_entries` with a 10,000-entry cap that short-circuits before
`zf.infolist()` materialises the whole entry table — defence against
zip-bomb-shaped archives with millions of entries (which exhaust RSS
during infolist materialisation, BEFORE any safety check runs).

`import_project` (L196 onwards) re-implements the safety check inline
at L237 by calling `_check_zip_entries(zf.infolist())` directly,
SKIPPING the entry-count cap. Same archive shape that
`validate_zip_contents` rejects in O(1) work is happily processed by
`import_project` until the underlying zipfile.infolist() consumes
multi-GB RSS.

This is the F029 drift: the public, tested validator has stricter
behaviour than the inlined call path the production importer uses.

Test strategy: craft a many-entry zip (just over 10,000 entries — the
documented cap), then assert:

  * `validate_zip_contents(zpath)` returns `(False, [bomb-shape warning])`.
  * `import_project(zpath, ...)` ALSO rejects it with the same shape
    warning (currently it does not — it goes on to materialise infolist
    and either succeeds or rejects on a different ground).
"""

from __future__ import annotations

import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

from core.project.export import import_project, validate_zip_contents


# One above the documented cap.
_OVER_CAP_ENTRIES = 10_001


def _make_over_cap_zip(zpath: Path) -> None:
    """Build a zip with > 10,000 small entries (no traversal, no symlinks)."""
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zf:
        # Add a `.project.json` so import_project doesn't bail on the
        # "not a RAPTOR archive" branch before reaching the cap check.
        zf.writestr(".project.json", '{"version": 1, "name": "bomb"}')
        for i in range(_OVER_CAP_ENTRIES):
            zf.writestr(f"f{i}.txt", "")


class ImportProjectEntryCapDriftTest(unittest.TestCase):

    def test_validate_rejects_over_cap_zip(self) -> None:
        """Baseline: the exported validator already rejects bomb-shape."""
        with TemporaryDirectory() as d:
            zpath = Path(d) / "bomb.zip"
            _make_over_cap_zip(zpath)
            safe, warnings = validate_zip_contents(zpath)
            self.assertFalse(safe)
            joined = " ".join(warnings).lower()
            self.assertIn("zip-bomb", joined)

    def test_import_project_rejects_over_cap_zip(self) -> None:
        """F029: `import_project` must apply the same cap."""
        with TemporaryDirectory() as d:
            zpath = Path(d) / "bomb.zip"
            _make_over_cap_zip(zpath)
            projects_dir = Path(d) / "projects"
            output_base = Path(d) / "output"
            with self.assertRaises(ValueError) as cm:
                import_project(zpath, projects_dir, output_base=output_base)
            # The rejection must cite the zip-bomb / entry-count shape,
            # not the secondary "absolute path" / "size" / "not a RAPTOR"
            # branches.
            self.assertIn("zip-bomb", str(cm.exception).lower())


if __name__ == "__main__":
    unittest.main()


def _make_forged_count_zip(zpath: Path) -> None:
    """A zip whose real central directory holds ~1 000 records but
    whose EOCD declares 3 entries. `ZipFile()` parses the central
    directory until the cd-size buffer is exhausted (ignoring the
    declared count), so a count-only pre-flight admits the archive
    and the construction cost is paid anyway."""
    import struct

    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(".project.json", '{"version": 1, "name": "forged"}')
        for i in range(1_000):
            zf.writestr(f"f{i}.txt", "")
    buf = bytearray(zpath.read_bytes())
    off = buf.rfind(b"\x50\x4b\x05\x06")
    assert off >= 0, "test fixture: EOCD signature not found"
    struct.pack_into("<HH", buf, off + 8, 3, 3)
    zpath.write_bytes(bytes(buf))


class ImportProjectForgedEntryCountTest(unittest.TestCase):
    """The EOCD pre-flight must cross-check the declared entry count
    against the declared central-directory size — a forged small
    count bypasses the count-only gate."""

    def test_validate_rejects_forged_count_zip(self) -> None:
        with TemporaryDirectory() as d:
            zpath = Path(d) / "forged.zip"
            _make_forged_count_zip(zpath)
            safe, warnings = validate_zip_contents(zpath)
            self.assertFalse(safe)
            joined = " ".join(warnings).lower()
            self.assertIn("zip-bomb", joined)
            self.assertIn("central directory", joined)

    def test_import_project_rejects_forged_count_zip(self) -> None:
        with TemporaryDirectory() as d:
            zpath = Path(d) / "forged.zip"
            _make_forged_count_zip(zpath)
            projects_dir = Path(d) / "projects"
            output_base = Path(d) / "output"
            with self.assertRaises(ValueError) as cm:
                import_project(zpath, projects_dir, output_base=output_base)
            msg = str(cm.exception).lower()
            self.assertIn("zip-bomb", msg)
            self.assertIn("central directory", msg)


class ImportProjectOversizedMetadataTest(unittest.TestCase):
    """The embedded .project.json is buffered and parsed wholesale in
    the trusted parent BEFORE the extraction loop's streaming size
    checks apply — it needs its own per-entry byte cap."""

    def _make_zip_with_meta(self, zpath: Path, meta: str) -> None:
        with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(".project.json", meta)
            zf.writestr("findings.json", '{"findings": []}')

    def test_oversized_metadata_rejected(self) -> None:
        with TemporaryDirectory() as d:
            zpath = Path(d) / "bigmeta.zip"
            # Valid JSON, ~2 MiB — over the 1 MiB metadata cap.
            meta = ('{"name": "bigmeta", "padding": "'
                    + "x" * (2 * 1024 * 1024) + '"}')
            self._make_zip_with_meta(zpath, meta)
            with self.assertRaises(ValueError) as cm:
                import_project(zpath, Path(d) / "projects",
                               output_base=Path(d) / "output")
            self.assertIn("metadata cap", str(cm.exception))

    def test_normal_metadata_still_imports(self) -> None:
        with TemporaryDirectory() as d:
            zpath = Path(d) / "ok.zip"
            self._make_zip_with_meta(zpath, '{"name": "okproj"}')
            result = import_project(zpath, Path(d) / "projects",
                                    output_base=Path(d) / "output")
            self.assertEqual(result["name"], "okproj")
