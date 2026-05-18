"""Tests for the libexec/raptor-render-diagrams wrapper.

Covers the --force overwrite-protection ported from the deleted
generate_diagram.py (commit a94fd36b) — without --force, the wrapper
must refuse to clobber an existing diagrams.md so an operator's
hand-edits survive a re-render.
"""

from __future__ import annotations

import json
import os
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


# parents[3] climbs:
#   [0] packages/diagram/tests/  (this file's directory)
#   [1] packages/diagram/
#   [2] packages/
#   [3] <repo root>
REPO_ROOT = Path(__file__).resolve().parents[3]
WRAPPER = REPO_ROOT / "libexec" / "raptor-render-diagrams"


def _run(*args, **kwargs):
    env = {**os.environ, "_RAPTOR_TRUSTED": "1"}
    return subprocess.run(
        [str(WRAPPER), *args],
        capture_output=True, text=True, timeout=20, env=env, **kwargs,
    )


def _seed_minimal_inputs(out_dir: Path) -> None:
    """Drop a minimal context-map.json so render_and_write has something
    to render. The renderer is robust to missing types; one input is
    enough to exercise the write path.
    """
    (out_dir / "context-map.json").write_text(
        json.dumps({
            "entry_points": [{"file": "app.py", "function": "main", "line": 1}],
            "trust_boundaries": [],
            "sinks": [],
            "flows": [],
        }),
        encoding="utf-8",
    )


class RaptorRenderDiagramsForceTests(unittest.TestCase):

    def test_writes_when_diagrams_md_absent(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp)
            _seed_minimal_inputs(out)
            result = _run(str(out))
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            self.assertTrue((out / "diagrams.md").exists())

    def test_refuses_to_overwrite_existing_diagrams_md(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp)
            _seed_minimal_inputs(out)
            (out / "diagrams.md").write_text("# operator hand-edit\n", encoding="utf-8")

            result = _run(str(out))

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("already exists", result.stderr)
            self.assertIn("--force", result.stderr)
            # Hand-edit preserved.
            self.assertEqual(
                (out / "diagrams.md").read_text(encoding="utf-8"),
                "# operator hand-edit\n",
            )

    def test_force_overwrites_existing_diagrams_md(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp)
            _seed_minimal_inputs(out)
            (out / "diagrams.md").write_text("# operator hand-edit\n", encoding="utf-8")

            result = _run(str(out), "--force")

            self.assertEqual(result.returncode, 0, msg=result.stderr)
            # File was overwritten with the rendered output.
            self.assertNotEqual(
                (out / "diagrams.md").read_text(encoding="utf-8"),
                "# operator hand-edit\n",
            )


if __name__ == "__main__":
    unittest.main()
