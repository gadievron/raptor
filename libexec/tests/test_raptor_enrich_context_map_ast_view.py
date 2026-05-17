"""Tests for the libexec/raptor-enrich-context-map-ast-view wrapper.

The underlying ``core.orchestration.context_map_ast_view`` module
has its own unit tests; this file pins the shim contracts (exit
codes, error paths, idempotency, on-disk mutation) as exercised
by the skill markdown when it calls the wrapper.
"""

import json
import os
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


REPO_ROOT = Path(__file__).resolve().parents[2]
WRAPPER = REPO_ROOT / "libexec" / "raptor-enrich-context-map-ast-view"


def _run(*args, **kwargs):
    """Invoke the wrapper as a real subprocess (matches how skills call it)."""
    env = {**os.environ, "_RAPTOR_TRUSTED": "1"}
    return subprocess.run(
        [str(WRAPPER), *args],
        capture_output=True, text=True, timeout=30,
        env=env, **kwargs,
    )


class RaptorEnrichContextMapAstViewTests(unittest.TestCase):

    def test_wrapper_exists_and_is_executable(self):
        self.assertTrue(WRAPPER.exists(), msg=f"missing: {WRAPPER}")
        self.assertTrue(os.access(WRAPPER, os.X_OK),
                        msg=f"not executable: {WRAPPER}")

    def test_no_args_prints_usage_and_fails(self):
        proc = _run()
        self.assertNotEqual(proc.returncode, 0)
        # argparse usage banner — exact format varies by argparse
        # version, but "usage" appears in every Python version we
        # care about.
        self.assertIn("usage", proc.stderr.lower())

    def test_missing_understand_dir_fails_cleanly(self):
        proc = _run("/nonexistent/path/that/does/not/exist")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("not a directory", proc.stderr)

    def test_missing_context_map_fails_cleanly(self):
        with TemporaryDirectory() as tmp:
            proc = _run(tmp)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("does not exist", proc.stderr)

    def test_missing_checklist_returns_zero_no_op(self):
        """If checklist.json is absent or doesn't carry target_path,
        the wrapper logs a warning and exits 0 — the skill is allowed
        to call the enricher even when inventory data is missing."""
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "context-map.json").write_text(json.dumps({
                "entry_points": [{"file": "x.py", "line": 1}],
            }))
            proc = _run(str(tmp))
            self.assertEqual(proc.returncode, 0,
                             msg=f"wrapper failed: {proc.stderr}")
            self.assertIn("checklist missing", proc.stderr)

    def test_corrupt_context_map_fails_cleanly(self):
        """A context-map.json that isn't a JSON object (e.g. a top-
        level list, or invalid JSON entirely) shouldn't traceback —
        the wrapper rejects it with a specific message."""
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "context-map.json").write_text("[]")  # list, not dict
            proc = _run(str(tmp))
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("not a JSON object", proc.stderr)

    def test_enriches_in_place(self):
        """Happy path: context-map.json + checklist.json present;
        wrapper attaches ast_view to the entry point and writes the
        file back. Verifies the wrapper actually mutates on disk."""
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            target = tmp / "target"
            target.mkdir()
            (target / "app.py").write_text(
                "def handle():\n"
                "    return 0\n"
            )
            (tmp / "context-map.json").write_text(json.dumps({
                "entry_points": [{
                    "id": "EP-001",
                    "file": "app.py",
                    "line": 1,
                }],
            }))
            (tmp / "checklist.json").write_text(json.dumps({
                "target_path": str(target),
            }))
            proc = _run(str(tmp))
            self.assertEqual(proc.returncode, 0,
                             msg=f"wrapper failed: {proc.stderr}")
            self.assertIn("enriched 1", proc.stdout)

            enriched = json.loads((tmp / "context-map.json").read_text())
            entry = enriched["entry_points"][0]
            self.assertIn("ast_view", entry)
            self.assertEqual(entry["ast_view"]["function"], "handle")
            self.assertEqual(entry["ast_view"]["language"], "python")

    def test_idempotent_on_repeated_invocation(self):
        """Re-running the wrapper on already-enriched data must
        produce the same output — skills may invoke iteratively."""
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            target = tmp / "target"
            target.mkdir()
            (target / "app.py").write_text(
                "def handle():\n    return 0\n"
            )
            (tmp / "context-map.json").write_text(json.dumps({
                "entry_points": [{"file": "app.py", "line": 1}],
            }))
            (tmp / "checklist.json").write_text(json.dumps({
                "target_path": str(target),
            }))
            _run(str(tmp))
            first = (tmp / "context-map.json").read_text()
            _run(str(tmp))
            second = (tmp / "context-map.json").read_text()
            self.assertEqual(first, second)

    def test_trust_marker_required(self):
        """No CLAUDECODE and no _RAPTOR_TRUSTED → refuse with exit 2."""
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "context-map.json").write_text("{}")
            # Strip both trust markers — must refuse.
            env = {k: v for k, v in os.environ.items()
                   if k not in ("CLAUDECODE", "_RAPTOR_TRUSTED")}
            proc = subprocess.run(
                [str(WRAPPER), str(tmp)],
                capture_output=True, text=True, timeout=10, env=env,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("internal dispatch script", proc.stderr)


if __name__ == "__main__":
    unittest.main()
