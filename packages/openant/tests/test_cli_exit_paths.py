"""Exit-path contract for the /openant command (raptor_openant.py).

A hard scanner failure (timeout, launch failure, exit >= 2, missing
pipeline output) must exit non-zero so the run lifecycle records a
FAILED run — an empty-findings exit 0 is indistinguishable from a
target that scanned clean. Genuine not-configured skips (no
openant-core checkout) keep exit 0 and the run completes.

No LLM ever launches here: the fake openant-core provides its own
``openant`` module that either exits with an error code or writes an
empty pipeline_output.json.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_REPO_ROOT = Path(__file__).parents[3]  # packages/openant/tests -> repo root
sys.path.insert(0, str(_REPO_ROOT))

_FAKE_MAIN_EXIT3 = "import sys\nsys.exit(3)\n"

_FAKE_MAIN_CLEAN = """\
import json
import sys

out = None
for i, a in enumerate(sys.argv):
    if a == "--output" and i + 1 < len(sys.argv):
        out = sys.argv[i + 1]
if out:
    with open(out + "/pipeline_output.json", "w") as f:
        json.dump({"findings": [], "pipeline_stats": {}}, f)
sys.exit(0)
"""


def _make_fake_core(src_dir: Path, main_body: str) -> Path:
    """Build a fake openant-core whose ``openant`` module runs
    ``main_body`` when the scanner launches ``python -m openant``.

    Nested INSIDE the scanned repo dir: the scanner subprocess runs
    sandboxed with only the target and output paths mounted, so a fake
    core elsewhere under the host tmp dir would be invisible as the
    subprocess cwd. Invocations pass --openant-core-unpinned alongside
    the stub path — the flag surface is consent-gated against
    non-pinned checkouts."""
    core = src_dir / "openant-core"
    (core / "core").mkdir(parents=True)
    (core / "core" / "scanner.py").touch()
    pkg = core / "openant"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "__main__.py").write_text(main_body)
    return core


def _run(cmd: list, env_extra: dict, env_drop: tuple = ()) -> subprocess.CompletedProcess:
    env = {**os.environ, "_RAPTOR_TRUSTED": "1", **env_extra}
    for key in env_drop:
        env.pop(key, None)
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=300,
        cwd=str(_REPO_ROOT), env=env,
    )


def _make_repo(base: Path) -> Path:
    src = base / "src"
    src.mkdir()
    (src / "app.py").write_text("import os\n")
    return src


def _run_status(out_dir: Path) -> str:
    meta = json.loads((out_dir / ".raptor-run.json").read_text())
    return meta.get("status", "")


def _discovery_would_succeed() -> bool:
    """Mirror the child's config discovery with OPENANT_CORE and
    RAPTOR_DIR removed — if a real openant-core sibling exists on this
    machine, the not-configured test cannot run hermetically."""
    from packages.openant.config import get_config
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("OPENANT_CORE", None)
        os.environ.pop("RAPTOR_DIR", None)
        try:
            get_config(raptor_dir=_REPO_ROOT)
            return True
        except RuntimeError:
            return False


class TestHardErrorFailsRun(unittest.TestCase):
    """Hard subprocess error → exit 1, lifecycle records status=failed."""

    def test_scanner_exit3_fails_lifecycle(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            src = _make_repo(base)
            core = _make_fake_core(src, _FAKE_MAIN_EXIT3)
            out_dir = base / "out"
            proc = _run(
                [sys.executable, str(_REPO_ROOT / "raptor.py"), "openant",
                 "--repo", str(src), "--out", str(out_dir),
                 "--openant-core", str(core),
                 "--openant-core-unpinned"],
                {},
            )
            self.assertEqual(proc.returncode, 1,
                             f"stdout={proc.stdout}\nstderr={proc.stderr}")
            self.assertIn("OpenAnt scan failed", proc.stdout + proc.stderr)
            self.assertEqual(_run_status(out_dir), "failed")

    def test_scanner_exit3_direct_exit_code(self):
        """Direct raptor_openant.py invocation: same exit 1 without the
        raptor.py lifecycle wrapper."""
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            src = _make_repo(base)
            core = _make_fake_core(src, _FAKE_MAIN_EXIT3)
            proc = _run(
                [sys.executable, str(_REPO_ROOT / "raptor_openant.py"),
                 "--repo", str(src), "--out", str(base / "out"),
                 "--openant-core", str(core),
                 "--openant-core-unpinned"],
                {},
            )
            self.assertEqual(proc.returncode, 1,
                             f"stdout={proc.stdout}\nstderr={proc.stderr}")


class TestNotConfiguredCompletesRun(unittest.TestCase):
    """Genuine not-configured skip → exit 0, lifecycle completes."""

    def test_invalid_core_path_completes(self):
        """--openant-core pointing nowhere is a config problem, not a
        failed scan: warn, empty report, exit 0, status=completed."""
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            src = _make_repo(base)
            out_dir = base / "out"
            proc = _run(
                [sys.executable, str(_REPO_ROOT / "raptor.py"), "openant",
                 "--repo", str(src), "--out", str(out_dir),
                 "--openant-core", str(base / "does-not-exist"),
                 "--openant-core-unpinned"],
                {},
            )
            self.assertEqual(proc.returncode, 0,
                             f"stdout={proc.stdout}\nstderr={proc.stderr}")
            self.assertIn("OpenAnt not available", proc.stdout + proc.stderr)
            self.assertEqual(_run_status(out_dir), "completed")

    @unittest.skipIf(_discovery_would_succeed(),
                     "a real openant-core is discoverable on this machine")
    def test_missing_core_checkout_exits_zero(self):
        """No OPENANT_CORE, no discoverable checkout: the discovery
        RuntimeError is the documented skip — exit 0."""
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            src = _make_repo(base)
            proc = _run(
                [sys.executable, str(_REPO_ROOT / "raptor_openant.py"),
                 "--repo", str(src), "--out", str(base / "out")],
                {}, env_drop=("OPENANT_CORE", "RAPTOR_DIR"),
            )
            self.assertEqual(proc.returncode, 0,
                             f"stdout={proc.stdout}\nstderr={proc.stderr}")
            self.assertIn("OpenAnt not available", proc.stdout + proc.stderr)


class TestCleanScanUnchanged(unittest.TestCase):
    """A scan that ran and found nothing still exits 0 and completes."""

    def test_zero_findings_scan_exit_zero(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            src = _make_repo(base)
            core = _make_fake_core(src, _FAKE_MAIN_CLEAN)
            out_dir = base / "out"
            proc = _run(
                [sys.executable, str(_REPO_ROOT / "raptor.py"), "openant",
                 "--repo", str(src), "--out", str(out_dir),
                 "--openant-core", str(core),
                 "--openant-core-unpinned"],
                {},
            )
            self.assertEqual(proc.returncode, 0,
                             f"stdout={proc.stdout}\nstderr={proc.stderr}")
            self.assertIn("OPENANT WORKFLOW COMPLETE", proc.stdout)
            self.assertEqual(_run_status(out_dir), "completed")
            findings = json.loads(
                (out_dir / "openant_findings.json").read_text())
            self.assertEqual(findings, [])


_FAKE_MAIN_60_FINDINGS = """\
import json
import sys

out = None
for i, a in enumerate(sys.argv):
    if a == "--output" and i + 1 < len(sys.argv):
        out = sys.argv[i + 1]
findings = []
for n in range(55):
    findings.append({
        "id": "VULN-%03d" % n,
        "stage1_verdict": "vulnerable",
        "location": {"file": "src/app.py", "function": "f%d" % n},
        "cwe_id": 78,
        "description": "warning-level finding",
    })
for n in range(55, 60):
    findings.append({
        "id": "VULN-%03d" % n,
        "stage1_verdict": "vulnerable",
        "stage2_verdict": "confirmed",
        "location": {"file": "src/app.py", "function": "f%d" % n},
        "cwe_id": 78,
        "description": "error-level finding emitted LAST",
    })
if out:
    with open(out + "/pipeline_output.json", "w") as f:
        json.dump({"findings": findings, "pipeline_stats": {}}, f)
sys.exit(1)
"""


class TestMaxFindingsArtifactHonesty(unittest.TestCase):
    """--max-findings caps only the markdown report (severity-first,
    truncation stated). The durable openant_findings.json artifact —
    what /validate, merged views and cross-run correlation consume —
    is NEVER capped: the pipeline-order slice dropped whatever OpenAnt
    emitted last, including every error-level finding, while the
    terminal, the JSON report and all doc surfaces claimed the full
    count."""

    def _scan_60(self, td: Path) -> Path:
        base = Path(td)
        src = _make_repo(base)
        core = _make_fake_core(src, _FAKE_MAIN_60_FINDINGS)
        out_dir = base / "out"
        proc = _run(
            [sys.executable, str(_REPO_ROOT / "raptor.py"), "openant",
             "--repo", str(src), "--out", str(out_dir),
             "--openant-core", str(core),
             "--openant-core-unpinned"],
            {},
        )
        self.assertEqual(proc.returncode, 0,
                         f"stdout={proc.stdout}\nstderr={proc.stderr}")
        return out_dir

    def test_artifact_uncapped_and_report_severity_first(self):
        with tempfile.TemporaryDirectory() as td:
            out_dir = self._scan_60(Path(td))
            findings = json.loads(
                (out_dir / "openant_findings.json").read_text())
            self.assertEqual(len(findings), 60)
            errors = [f for f in findings if f.get("level") == "error"]
            self.assertEqual(len(errors), 5)
            report = json.loads(
                (out_dir / "raptor_openant_report.json").read_text())
            phase = report["phases"]["openant_scan"]
            self.assertEqual(phase["translated_findings"], 60)
            self.assertEqual(phase["report_findings"], 50)
            self.assertEqual(phase["report_truncated"], 10)
            md = (out_dir / "openant-report.md").read_text()
            self.assertIn("**Findings:** 60", md)
            self.assertIn("Report truncated", md)
            self.assertIn("top 50 of 60", md)
            # Severity-first: ALL FIVE error-level findings (emitted
            # last by the scanner) survive the cut.
            self.assertIn("## High (5)", md)

    def test_negative_max_findings_refused_at_parse(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            src = _make_repo(base)
            core = _make_fake_core(src, _FAKE_MAIN_60_FINDINGS)
            proc = _run(
                [sys.executable, str(_REPO_ROOT / "raptor_openant.py"),
                 "--repo", str(src), "--out", str(base / "out"),
                 "--openant-core", str(core),
                 "--openant-core-unpinned",
                 "--max-findings", "-5"],
                {},
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("positive integer", proc.stderr)


class TestScannerResultShape(unittest.TestCase):
    """The scanner's skipped result carries the structured hard_error
    distinction consumers key off."""

    def test_empty_result_carries_hard_error_flag(self):
        from packages.openant.scanner import _empty_result
        hard = _empty_result("boom", hard_error=True)
        self.assertTrue(hard["skipped"])
        self.assertTrue(hard["hard_error"])
        soft = _empty_result("n/a", hard_error=False)
        self.assertTrue(soft["skipped"])
        self.assertFalse(soft["hard_error"])


if __name__ == "__main__":
    unittest.main()
