"""Imported runs must never read as locally-produced work.

``/project import`` restores run directories from an UNSIGNED
archive. Three trust properties are pinned here:

* every restored run dir (and the restored project root) carries a
  persisted imported marker (``.raptor-imported.json``);
* merge folds prefer a locally-produced status over an imported one
  — an archive-selected ``exploitable`` cannot override a local
  ruling, however "progressed" it looks;
* provenance refs restored from the archive are namespaced
  (``imported:<run_id>``) so they can never claim a run id on this
  install — a pre-seeded ref claiming the current run id would
  otherwise suppress canonical stamping (core/run/findings.py skips
  findings already carrying a ref for the run) and read as
  locally-verified work.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.project.export import export_project, import_project
from core.project.findings_utils import (
    IMPORTED_RUN_MARKER_FILE,
    run_is_imported,
)
from core.project.merge import merge_findings


def _import_archive(d: Path, src: Path, name: str = "myproj") -> Path:
    zip_path = d / f"{name}.zip"
    project_json = d / f"{name}.json"
    project_json.write_text(json.dumps({
        "name": name,
        "target": str(d / "fake-target"),
        "output_dir": str(src),
    }))
    export_project(src, zip_path, project_json_path=project_json)
    projects_dir = d / "projects"
    output_base = d / "imported_out"
    result = import_project(zip_path, projects_dir,
                            output_base=output_base)
    return Path(result["output_dir"])


def _finding(status: str, **extra) -> dict:
    return {
        "id": "f1", "file": "src/a.c", "function": "parse",
        "line": 10, "vuln_type": "CWE-787", "status": status,
        **extra,
    }


class TestImportedRunMarker(unittest.TestCase):
    def test_import_stamps_marker_on_root_and_runs(self):
        with TemporaryDirectory() as td:
            d = Path(td)
            src = d / "src" / "myproj"
            run = src / "scan_20260101-000000"
            run.mkdir(parents=True)
            (run / "findings.json").write_text(
                json.dumps({"findings": [_finding("exploitable")]}))
            imported_root = _import_archive(d, src)

            root_marker = imported_root / IMPORTED_RUN_MARKER_FILE
            run_marker = (imported_root / "scan_20260101-000000"
                          / IMPORTED_RUN_MARKER_FILE)
            self.assertTrue(root_marker.is_file())
            self.assertTrue(run_marker.is_file())
            data = json.loads(run_marker.read_text())
            self.assertIs(data["imported"], True)
            self.assertTrue(data["archive_sha256"])
            self.assertTrue(
                run_is_imported(imported_root / "scan_20260101-000000"))

    def test_local_runs_are_not_marked(self):
        with TemporaryDirectory() as td:
            run = Path(td) / "scan_20260101-000000"
            run.mkdir()
            (run / "findings.json").write_text('{"findings": []}')
            self.assertFalse(run_is_imported(run))


class TestMergePrefersLocalStatus(unittest.TestCase):
    def _write_run(self, base: Path, name: str, finding: dict,
                   imported: bool) -> Path:
        run = base / name
        run.mkdir(parents=True)
        (run / "findings.json").write_text(
            json.dumps({"findings": [finding]}))
        if imported:
            (run / IMPORTED_RUN_MARKER_FILE).write_text(
                '{"imported": true}')
        return run

    def test_imported_status_does_not_dominate_local(self):
        """An imported `exploitable` (rank 7) must not override a
        local `not_disproven` (rank 2)."""
        with TemporaryDirectory() as td:
            d = Path(td)
            local = self._write_run(
                d, "local_run", _finding("not_disproven", origin="local"),
                imported=False)
            imported = self._write_run(
                d, "imported_run",
                _finding("exploitable", origin="imported"), imported=True)

            for order in ([local, imported], [imported, local]):
                merged = merge_findings(order)
                self.assertEqual(len(merged), 1)
                self.assertEqual(merged[0]["status"], "not_disproven",
                                 f"order={order}")
                self.assertEqual(merged[0]["origin"], "local")

    def test_status_race_still_applies_within_same_origin(self):
        with TemporaryDirectory() as td:
            d = Path(td)
            a = self._write_run(
                d, "run_a", _finding("not_disproven", origin="a"),
                imported=False)
            b = self._write_run(
                d, "run_b", _finding("confirmed", origin="b"),
                imported=False)
            merged = merge_findings([b, a])
            self.assertEqual(merged[0]["status"], "confirmed")

    def test_imported_only_findings_still_merge(self):
        with TemporaryDirectory() as td:
            d = Path(td)
            imp = self._write_run(
                d, "imported_run", _finding("exploitable"), imported=True)
            merged = merge_findings([imp])
            self.assertEqual(len(merged), 1)
            self.assertEqual(merged[0]["status"], "exploitable")


class TestImportedProvenanceRefsNamespaced(unittest.TestCase):
    def test_refs_get_imported_prefix(self):
        with TemporaryDirectory() as td:
            d = Path(td)
            src = d / "src" / "myproj"
            run = src / "scan_20260101-000000"
            (run / "sca").mkdir(parents=True)
            finding = _finding("exploitable")
            # Pre-seeded refs: one claiming the restored run dir's own
            # id (the canonical-stamping suppression shape), one
            # claiming an arbitrary sibling.
            finding["provenance_refs"] = [
                {"run_id": "scan_20260101-000000",
                 "manifest_path": ".raptor-run.json"},
                {"run_id": "scan_20250505-000000",
                 "manifest_path": ".raptor-run.json"},
            ]
            (run / "findings.json").write_text(
                json.dumps({"findings": [finding]}))
            (run / "sca" / "findings.json").write_text(
                json.dumps([dict(finding)]))

            imported_root = _import_archive(d, src)
            for rel in ("findings.json", "sca/findings.json"):
                data = json.loads(
                    (imported_root / "scan_20260101-000000" / rel)
                    .read_text())
                findings = (data["findings"] if isinstance(data, dict)
                            else data)
                refs = findings[0]["provenance_refs"]
                run_ids = sorted(r["run_id"] for r in refs)
                self.assertEqual(run_ids, [
                    "imported:scan_20250505-000000",
                    "imported:scan_20260101-000000",
                ], rel)

    def test_namespacing_is_idempotent(self):
        with TemporaryDirectory() as td:
            d = Path(td)
            src = d / "src" / "myproj"
            run = src / "scan_20260101-000000"
            run.mkdir(parents=True)
            finding = _finding("confirmed")
            finding["provenance_refs"] = [
                {"run_id": "imported:scan_20250505-000000"},
            ]
            (run / "findings.json").write_text(
                json.dumps({"findings": [finding]}))
            imported_root = _import_archive(d, src)
            data = json.loads(
                (imported_root / "scan_20260101-000000" / "findings.json")
                .read_text())
            refs = data["findings"][0]["provenance_refs"]
            self.assertEqual(refs[0]["run_id"],
                             "imported:scan_20250505-000000")


if __name__ == "__main__":
    unittest.main()
