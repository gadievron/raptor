"""Tests for the libexec/raptor-enrich-flow-trace-ast-view wrapper."""

import json
import os
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


REPO_ROOT = Path(__file__).resolve().parents[2]
WRAPPER = REPO_ROOT / "libexec" / "raptor-enrich-flow-trace-ast-view"


def _run(*args, **kwargs):
    env = {**os.environ, "_RAPTOR_TRUSTED": "1"}
    return subprocess.run(
        [str(WRAPPER), *args],
        capture_output=True, text=True, timeout=30,
        env=env, **kwargs,
    )


class RaptorEnrichFlowTraceAstViewTests(unittest.TestCase):

    def test_wrapper_exists_and_is_executable(self):
        self.assertTrue(WRAPPER.exists(), msg=f"missing: {WRAPPER}")
        self.assertTrue(os.access(WRAPPER, os.X_OK),
                        msg=f"not executable: {WRAPPER}")

    def test_no_args_prints_usage_and_fails(self):
        proc = _run()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("usage", proc.stderr.lower())

    def test_missing_understand_dir_fails_cleanly(self):
        proc = _run("/nonexistent/path/that/does/not/exist")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("not a directory", proc.stderr)

    def test_missing_checklist_returns_zero_no_op(self):
        """If checklist.json is absent or doesn't carry target_path,
        the wrapper logs a warning and exits 0."""
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "flow-trace-001.json").write_text(json.dumps({
                "steps": [{"step": 1, "definition": "x.py:1"}],
            }))
            proc = _run(str(tmp))
            self.assertEqual(proc.returncode, 0,
                             msg=f"wrapper failed: {proc.stderr}")
            self.assertIn("checklist missing", proc.stderr)

    def test_no_trace_files_returns_zero(self):
        """An understand dir with checklist but no flow-trace-*.json
        files is fine — nothing to enrich, exit 0 with notice."""
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            target = tmp / "target"
            target.mkdir()
            (target / "x.py").write_text("def f(): return 1\n")
            (tmp / "checklist.json").write_text(json.dumps({
                "target_path": str(target),
            }))
            proc = _run(str(tmp))
            self.assertEqual(proc.returncode, 0,
                             msg=f"wrapper failed: {proc.stderr}")
            self.assertIn("no flow-trace-", proc.stdout)

    def test_enriches_single_trace_file(self):
        """Happy path: one trace file with a resolvable step gets
        enriched in place; wrapper reports the count."""
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            target = tmp / "target"
            target.mkdir()
            (target / "auth.py").write_text(
                "def check():\n    return 0\n"
            )
            (tmp / "checklist.json").write_text(json.dumps({
                "target_path": str(target),
            }))
            (tmp / "flow-trace-001.json").write_text(json.dumps({
                "id": "TRACE-001",
                "steps": [{"step": 1, "definition": "auth.py:1"}],
            }))
            proc = _run(str(tmp))
            self.assertEqual(proc.returncode, 0,
                             msg=f"wrapper failed: {proc.stderr}")
            self.assertIn("enriched 1", proc.stdout)

            enriched = json.loads((tmp / "flow-trace-001.json").read_text())
            step = enriched["steps"][0]
            self.assertIn("ast_view", step)
            self.assertEqual(step["ast_view"]["function"], "check")

    def test_enriches_multiple_trace_files(self):
        """Wrapper iterates every flow-trace-*.json in the dir."""
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            target = tmp / "target"
            target.mkdir()
            (target / "a.py").write_text("def fa(): return 1\n")
            (target / "b.py").write_text("def fb(): return 2\n")
            (tmp / "checklist.json").write_text(json.dumps({
                "target_path": str(target),
            }))
            (tmp / "flow-trace-a.json").write_text(json.dumps({
                "steps": [{"step": 1, "definition": "a.py:1"}],
            }))
            (tmp / "flow-trace-b.json").write_text(json.dumps({
                "steps": [{"step": 1, "definition": "b.py:1"}],
            }))
            proc = _run(str(tmp))
            self.assertEqual(proc.returncode, 0,
                             msg=f"wrapper failed: {proc.stderr}")
            self.assertIn("across 2 trace file(s)", proc.stdout)

    def test_corrupt_trace_file_skipped_others_enriched(self):
        """A single corrupt trace file doesn't abort the whole run —
        the wrapper logs and continues to other files."""
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            target = tmp / "target"
            target.mkdir()
            (target / "a.py").write_text("def fa(): return 1\n")
            (tmp / "checklist.json").write_text(json.dumps({
                "target_path": str(target),
            }))
            # Corrupt: top-level list, not dict
            (tmp / "flow-trace-bad.json").write_text("[]")
            # Valid
            (tmp / "flow-trace-good.json").write_text(json.dumps({
                "steps": [{"step": 1, "definition": "a.py:1"}],
            }))
            proc = _run(str(tmp))
            self.assertEqual(proc.returncode, 0,
                             msg=f"wrapper failed: {proc.stderr}")
            self.assertIn("not a JSON object", proc.stderr)
            self.assertIn("enriched 1", proc.stdout)
            # The good file was enriched.
            good = json.loads((tmp / "flow-trace-good.json").read_text())
            self.assertIn("ast_view", good["steps"][0])

    def test_idempotent_on_repeated_invocation(self):
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            target = tmp / "target"
            target.mkdir()
            (target / "a.py").write_text("def fa(): return 1\n")
            (tmp / "checklist.json").write_text(json.dumps({
                "target_path": str(target),
            }))
            (tmp / "flow-trace-001.json").write_text(json.dumps({
                "steps": [{"step": 1, "definition": "a.py:1"}],
            }))
            _run(str(tmp))
            first = (tmp / "flow-trace-001.json").read_text()
            _run(str(tmp))
            second = (tmp / "flow-trace-001.json").read_text()
            self.assertEqual(first, second)

    def test_trust_marker_required(self):
        with TemporaryDirectory() as tmp:
            env = {k: v for k, v in os.environ.items()
                   if k not in ("CLAUDECODE", "_RAPTOR_TRUSTED")}
            proc = subprocess.run(
                [str(WRAPPER), tmp],
                capture_output=True, text=True, timeout=10, env=env,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("internal dispatch script", proc.stderr)


if __name__ == "__main__":
    unittest.main()
