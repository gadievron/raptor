"""Tests for the libexec/raptor-normalize-context-map wrapper."""

import json
import os
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


REPO_ROOT = Path(os.environ["RAPTOR_DIR"])
WRAPPER = REPO_ROOT / "libexec" / "raptor-normalize-context-map"


def _run(*args, **kwargs):
    """Invoke the wrapper as a real subprocess (matches how skills call it)."""
    return subprocess.run(
        [str(WRAPPER), *args],
        capture_output=True, text=True, timeout=15, **kwargs,
    )


class RaptorNormalizeContextMapWrapperTests(unittest.TestCase):

    def test_wrapper_exists_and_is_executable(self):
        self.assertTrue(WRAPPER.exists(), msg=f"missing: {WRAPPER}")
        self.assertTrue(os.access(WRAPPER, os.X_OK),
                        msg=f"not executable: {WRAPPER}")

    def test_no_args_prints_usage_and_fails(self):
        proc = _run()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("Usage:", proc.stderr)

    def test_missing_understand_dir_fails_cleanly(self):
        proc = _run("/nonexistent/path/that/does/not/exist")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("not a directory", proc.stderr)

    def test_missing_context_map_fails_cleanly(self):
        with TemporaryDirectory() as tmp:
            # Dir exists but no context-map.json — should fail with a
            # specific message, not a Python traceback.
            proc = _run(tmp)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("does not exist", proc.stderr)

    def test_normalises_in_place_with_checklist(self):
        # Happy path: context-map.json present, checklist present, wrapper
        # backfills the name and normalises the path. Verifies the wrapper
        # actually mutates the file on disk (the whole point of doing this
        # at write time rather than only on read).
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "context-map.json").write_text(json.dumps({
                "entry_points": [{"file": "./app.py", "line": 12}],
            }))
            (tmp / "checklist.json").write_text(json.dumps({
                "target_path": str(tmp),
                "files": [{
                    "path": "app.py", "lines": 50,
                    "functions": [{"name": "handle", "line_start": 10, "line_end": 25}],
                }],
            }))
            proc = _run(str(tmp))
            self.assertEqual(proc.returncode, 0,
                             msg=f"wrapper failed: {proc.stderr}")

            normalised = json.loads((tmp / "context-map.json").read_text())
            entry = normalised["entry_points"][0]
            self.assertEqual(entry["file"], "app.py")  # ./ stripped
            self.assertEqual(entry["name"], "handle")  # backfilled

    def test_works_without_checklist_present(self):
        # If checklist.json is absent (e.g. caller skipped MAP-0), the
        # wrapper should still normalise paths (the only fixup that doesn't
        # require ground-truth inventory).
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "context-map.json").write_text(json.dumps({
                "entry_points": [{"file": "./app.py", "line": 5}],
            }))
            proc = _run(str(tmp))
            self.assertEqual(proc.returncode, 0,
                             msg=f"wrapper failed: {proc.stderr}")
            normalised = json.loads((tmp / "context-map.json").read_text())
            self.assertEqual(normalised["entry_points"][0]["file"], "app.py")

    def test_idempotent_on_repeated_invocation(self):
        # Re-running the wrapper on already-normalised data must not change
        # it — important because the skill may invoke it multiple times in
        # iterative sessions.
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "context-map.json").write_text(json.dumps({
                "entry_points": [{"file": "app.py", "line": 12, "name": "h"}],
            }))
            (tmp / "checklist.json").write_text(json.dumps({
                "files": [{
                    "path": "app.py", "lines": 50,
                    "functions": [{"name": "h", "line_start": 10, "line_end": 25}],
                }],
            }))
            _run(str(tmp))
            first = (tmp / "context-map.json").read_text()
            _run(str(tmp))
            second = (tmp / "context-map.json").read_text()
            self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
