"""Completion-time project re-adjudication refresh.

``complete_run`` (and the adoption projections) must refresh the
project-level queue so a completing run's verdicts meet every SIBLING
run's recorded disproofs and confirmed verdicts — the import-time
detector only sees the destination run's own container. Both
directions are pinned: a pinned run refreshes its project's queue,
and a run without an authoritative pin writes nowhere.
"""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[3]
LIFECYCLE = str(REPO_ROOT / "libexec" / "raptor-run-lifecycle")

QUEUE_RELPATH = Path("_report") / "readjudication-queue.jsonl"


def _disproof_row() -> dict:
    return {
        "id": "FIND-1", "file": "src/parse.c", "function": "parse_header",
        "line": 40, "vuln_type": "buffer_overflow", "status": "disproven",
        "disproved_because": {"conclusion": "len clamped upstream"},
    }


def _claim_row(status: str = "not_disproven") -> dict:
    return {
        "id": "SCAN-7", "file": "src/parse.c", "function": "parse_header",
        "line": 42, "vuln_type": "buffer_overflow", "status": status,
    }


def _sibling_run(project_dir: Path, name: str, findings: list,
                 ts: str = "2026-01-01T00:00:00") -> Path:
    d = Path(project_dir) / name
    d.mkdir(parents=True)
    (d / "findings.json").write_text(json.dumps({"findings": findings}))
    (d / ".raptor-run.json").write_text(json.dumps({
        "status": "completed", "command": "validate", "timestamp": ts,
    }))
    return d


class TestRefreshHookUnit(unittest.TestCase):

    def test_explicit_project_dir_writes_queue(self):
        from core.run.metadata import _refresh_project_readjudication
        with TemporaryDirectory() as tmp:
            proj = Path(tmp) / "proj"
            _sibling_run(proj, "run_a", [_disproof_row()])
            run_b = _sibling_run(proj, "run_b", [_claim_row()],
                                 ts="2026-01-02T00:00:00")
            _refresh_project_readjudication(run_b, project_dir=proj)
            queue = proj / QUEUE_RELPATH
            self.assertTrue(queue.is_file())
            self.assertIn('"action": "queued"', queue.read_text())

    def test_non_authoritative_pin_writes_nowhere(self):
        from core.run import pin as pin_mod
        from core.run.metadata import _refresh_project_readjudication
        with TemporaryDirectory() as tmp:
            proj = Path(tmp) / "proj"
            _sibling_run(proj, "run_a", [_disproof_row()])
            run_b = _sibling_run(proj, "run_b", [_claim_row()],
                                 ts="2026-01-02T00:00:00")
            with patch.object(
                pin_mod, "resolve_run_pin",
                return_value=SimpleNamespace(authoritative=False,
                                             project=None),
            ):
                _refresh_project_readjudication(run_b)
            self.assertFalse((proj / QUEUE_RELPATH).exists())

    def test_authoritative_pin_resolves_project_and_writes(self):
        from core.run import metadata as meta_mod
        from core.run import pin as pin_mod
        with TemporaryDirectory() as tmp:
            proj = Path(tmp) / "proj"
            _sibling_run(proj, "run_a", [_disproof_row()])
            run_b = _sibling_run(proj, "run_b", [_claim_row()],
                                 ts="2026-01-02T00:00:00")
            with patch.object(
                pin_mod, "resolve_run_pin",
                return_value=SimpleNamespace(authoritative=True,
                                             project="proj"),
            ), patch.object(
                pin_mod, "pin_project_dir", return_value=proj,
            ), patch.object(
                pin_mod, "pinned_write_target_ok", return_value=True,
            ), patch.object(
                meta_mod, "_pin_witness_ok", return_value=True,
            ):
                meta_mod._refresh_project_readjudication(run_b)
            self.assertTrue((proj / QUEUE_RELPATH).is_file())

    def test_refused_write_target_writes_nowhere(self):
        from core.run import metadata as meta_mod
        from core.run import pin as pin_mod
        with TemporaryDirectory() as tmp:
            proj = Path(tmp) / "proj"
            _sibling_run(proj, "run_a", [_disproof_row()])
            run_b = _sibling_run(proj, "run_b", [_claim_row()],
                                 ts="2026-01-02T00:00:00")
            with patch.object(
                pin_mod, "resolve_run_pin",
                return_value=SimpleNamespace(authoritative=True,
                                             project="proj"),
            ), patch.object(
                pin_mod, "pin_project_dir", return_value=proj,
            ), patch.object(
                pin_mod, "pinned_write_target_ok", return_value=False,
            ), patch.object(
                meta_mod, "_pin_witness_ok", return_value=True,
            ):
                meta_mod._refresh_project_readjudication(run_b)
            self.assertFalse((proj / QUEUE_RELPATH).exists())

    def test_hook_never_raises(self):
        from core.run import metadata as meta_mod
        import core.project.readjudication as readj
        with TemporaryDirectory() as tmp:
            proj = Path(tmp) / "proj"
            run_b = _sibling_run(proj, "run_b", [_claim_row()])
            with patch.object(readj, "refresh_project_queue",
                              side_effect=RuntimeError("boom")):
                # Best-effort contract: an additive-trail failure must
                # never fail the lifecycle.
                meta_mod._refresh_project_readjudication(
                    run_b, project_dir=proj)


class TestRefreshHookLifecycle(unittest.TestCase):
    """End-to-end through the libexec lifecycle shim: start a pinned
    run, drop findings, complete — the project queue materialises."""

    @staticmethod
    def _run(*args, tmp_home):
        env = os.environ.copy()
        env.pop("RAPTOR_CALLER_DIR", None)
        env["HOME"] = tmp_home
        return subprocess.run(
            [sys.executable, LIFECYCLE] + list(args),
            capture_output=True, text=True, env=env,
        )

    @staticmethod
    def _setup_project(home_dir, project_dir):
        projects_dir = Path(home_dir) / ".raptor" / "projects"
        projects_dir.mkdir(parents=True, exist_ok=True)
        (projects_dir / "testproj.json").write_text(json.dumps({
            "name": "testproj",
            "target": "/tmp",
            "output_dir": str(project_dir),
        }))
        active = projects_dir / ".active"
        active.symlink_to("testproj.json")

    @staticmethod
    def _extract_out_dir(result):
        for line in reversed(result.stdout.strip().splitlines()):
            if line.startswith("OUTPUT_DIR="):
                return Path(line.split("=", 1)[1])
        raise ValueError(f"no OUTPUT_DIR= in stdout: {result.stdout!r}")

    def test_complete_queues_sibling_contradiction_and_own_split(self):
        with TemporaryDirectory() as d, TemporaryDirectory() as home:
            self._setup_project(home, d)
            # The sibling disproof the import-time detector cannot see.
            _sibling_run(Path(d), "validate_0", [_disproof_row()],
                         ts="2020-01-01T00:00:00")
            result = self._run("start", "validate", tmp_home=home)
            self.assertEqual(result.returncode, 0, result.stderr)
            out_dir = self._extract_out_dir(result)
            # This run's end-state: a claim contradicting the sibling
            # disproof, plus a confirmed/ruled_out split at another
            # site that only counts once the run is COMPLETED.
            (out_dir / "findings.json").write_text(json.dumps({
                "findings": [
                    _claim_row(),
                    {"id": "V-1", "file": "src/other.c", "function": "g",
                     "line": 7, "status": "confirmed"},
                    {"id": "V-2", "file": "src/other.c", "function": "g",
                     "line": 9, "status": "ruled_out"},
                ],
            }))
            result = self._run("complete", str(out_dir), tmp_home=home)
            self.assertEqual(result.returncode, 0, result.stderr)
            queue = Path(d) / QUEUE_RELPATH
            self.assertTrue(queue.is_file(), result.stderr)
            records = [json.loads(line) for line in
                       queue.read_text().splitlines()]
            shapes = sorted(
                r.get("shape") for r in records
                if r.get("action") == "queued"
            )
            self.assertEqual(
                shapes, ["claim_after_disproof", "intra_run_split"])
            # Never-auto-overturn: the run's own container is untouched.
            saved = json.loads((out_dir / "findings.json").read_text())
            statuses = sorted(f["status"] for f in saved["findings"])
            self.assertEqual(
                statuses, ["confirmed", "not_disproven", "ruled_out"])

    def test_standalone_complete_writes_no_project_queue(self):
        with TemporaryDirectory() as home, TemporaryDirectory() as scratch:
            out_dir = Path(scratch) / "validate-standalone"
            result = self._run("start", "validate", "--out", str(out_dir),
                               tmp_home=home)
            self.assertEqual(result.returncode, 0, result.stderr)
            (out_dir / "findings.json").write_text(json.dumps({
                "findings": [_claim_row()],
            }))
            result = self._run("complete", str(out_dir), tmp_home=home)
            self.assertEqual(result.returncode, 0, result.stderr)
            # No project anywhere near the run gained a queue.
            hits = list(Path(scratch).rglob("readjudication-queue.jsonl"))
            self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
