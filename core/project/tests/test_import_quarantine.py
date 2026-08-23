"""Import must not restore privileged artifacts to canonical paths.

An unsigned archive can ship forged trust-bearing artifacts:
coverage stores that mark code reviewed, review journals that credit
un-run reviews, witness stores, IRIS spec stores / refined specs,
verified-outcome sidecars, and exemplar pools. Pre-fix the
extraction loop restored every entry verbatim (only annotations got
a trust rewrite), so consumers found the forgeries at the canonical
locations and treated them as locally-earned.

Post-fix, import moves these artifact families into
``_imported-quarantine/`` (layout-preserving, content intact for
operator inspection); consumers looking at canonical paths simply
never see them.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.project.export import export_project, import_project

_QUARANTINE = "_imported-quarantine"


def _build_project_with_privileged_artifacts(src: Path) -> None:
    run = src / "scan_20260101-000000"
    run.mkdir(parents=True)
    (run / "findings.json").write_text('{"findings": []}')

    # Project-root artifacts.
    (src / "coverage.json").write_text('{"forged": "coverage store"}')
    (src / "coverage-progress.jsonl").write_text('{"trend": 1}\n')
    (src / "review-journal-index.json").write_text('{"forged": "index"}')
    (src / "iris-specs").mkdir()
    (src / "iris-specs" / "specs.json").write_text('{"forged": "specs"}')
    (src / "labeled_attempts").mkdir()
    (src / "labeled_attempts" / "pool.jsonl").write_text('{"x": 1}\n')

    # Run-local artifacts.
    (run / "review-journal.jsonl").write_text('{"forged": "journal"}\n')
    (run / "verified-outcomes.jsonl").write_text('{"forged": "outcome"}\n')
    (run / "iris-taint-specs-refined.json").write_text('{"forged": "iris"}')
    (run / "witnesses" / "manifests").mkdir(parents=True)
    (run / "witnesses" / "manifests" / "w1.json").write_text(
        '{"forged": "witness"}')
    # Nested store variant used by /agentic.
    (run / "autonomous" / "witnesses" / "manifests").mkdir(parents=True)
    (run / "autonomous" / "witnesses" / "manifests" / "w2.json").write_text(
        '{"forged": "witness2"}')

    # Benign files that must NOT be touched.
    (run / "summary.txt").write_text("plain artefact")


def _import(d: Path, src: Path, name: str = "myproj") -> Path:
    zip_path = d / f"{name}.zip"
    project_json = d / f"{name}.json"
    project_json.write_text(json.dumps({
        "name": name,
        "target": str(d / "fake-target"),
        "output_dir": str(src),
    }))
    export_project(src, zip_path, project_json_path=project_json)
    result = import_project(zip_path, d / "projects",
                            output_base=d / "imported_out")
    return Path(result["output_dir"])


class TestImportQuarantinesPrivilegedArtifacts(unittest.TestCase):
    def test_canonical_paths_absent_quarantine_populated(self):
        with TemporaryDirectory() as td:
            d = Path(td)
            src = d / "src" / "myproj"
            _build_project_with_privileged_artifacts(src)
            root = _import(d, src)
            run = root / "scan_20260101-000000"

            # Canonical locations are empty of trust-bearing artifacts.
            for canonical in (
                root / "coverage.json",
                root / "coverage-progress.jsonl",
                root / "review-journal-index.json",
                root / "iris-specs",
                root / "labeled_attempts",
                run / "review-journal.jsonl",
                run / "verified-outcomes.jsonl",
                run / "iris-taint-specs-refined.json",
                run / "witnesses",
                run / "autonomous" / "witnesses",
            ):
                self.assertFalse(canonical.exists(),
                                 f"{canonical} restored at canonical path")

            # Quarantine preserves layout + content for inspection.
            q = root / _QUARANTINE
            self.assertEqual(
                json.loads((q / "coverage.json").read_text()),
                {"forged": "coverage store"})
            self.assertTrue(
                (q / "scan_20260101-000000" / "review-journal.jsonl")
                .is_file())
            self.assertTrue(
                (q / "scan_20260101-000000" / "witnesses" / "manifests"
                 / "w1.json").is_file())
            self.assertTrue(
                (q / "scan_20260101-000000" / "autonomous" / "witnesses"
                 / "manifests" / "w2.json").is_file())
            self.assertTrue((q / "iris-specs" / "specs.json").is_file())
            self.assertTrue(
                (q / "labeled_attempts" / "pool.jsonl").is_file())
            self.assertTrue(
                (q / "scan_20260101-000000" / "verified-outcomes.jsonl")
                .is_file())

            # Benign artifacts stay put.
            self.assertTrue((run / "summary.txt").is_file())
            self.assertTrue((run / "findings.json").is_file())

    def test_witness_discovery_finds_no_imported_stores(self):
        """Consumer-level check: witness discovery over the imported
        project must not surface the archive's stores."""
        from core.witness.discovery import discover_witness_stores

        with TemporaryDirectory() as td:
            d = Path(td)
            src = d / "src" / "myproj"
            _build_project_with_privileged_artifacts(src)
            root = _import(d, src)
            stores = discover_witness_stores(
                root / "scan_20260101-000000", project_root=root)
            self.assertEqual(stores, [])

    def test_reimport_of_reexport_is_idempotent(self):
        """Re-exporting an imported project and importing it again
        must not re-nest the quarantine."""
        with TemporaryDirectory() as td:
            d = Path(td)
            src = d / "src" / "myproj"
            _build_project_with_privileged_artifacts(src)
            root = _import(d, src)

            d2 = root.parent / "second"
            d2.mkdir()
            (d2 / "projects").mkdir()
            root2 = _import(d2, root, name="myproj")
            q2 = root2 / _QUARANTINE
            self.assertTrue((q2 / "coverage.json").is_file())
            self.assertFalse((q2 / _QUARANTINE).exists(),
                             "quarantine must not nest on re-import")
            self.assertFalse((root2 / "coverage.json").exists())


if __name__ == "__main__":
    unittest.main()
