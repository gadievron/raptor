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
