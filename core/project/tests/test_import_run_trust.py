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

    def test_generated_dirs_not_stamped_as_runs(self):
        """`findings` and `ghidra-attach` are generated project dirs,
        not runs — stamping them plants an imported marker (and
        namespaces provenance refs) inside the merge fold output /
        the attach caches."""
        with TemporaryDirectory() as td:
            d = Path(td)
            src = d / "src" / "myproj"
            run = src / "scan_20260101-000000"
            run.mkdir(parents=True)
            (run / "findings.json").write_text('{"findings": []}')
            for gen in ("findings", "ghidra-attach"):
                (src / gen).mkdir()
                (src / gen / "keep.json").write_text("{}")
            imported_root = _import_archive(d, src)
            for gen in ("findings", "ghidra-attach"):
                self.assertFalse(
                    (imported_root / gen
                     / IMPORTED_RUN_MARKER_FILE).exists(),
                    f"generated dir {gen} stamped as an imported run")
            self.assertTrue(
                (imported_root / "scan_20260101-000000"
                 / IMPORTED_RUN_MARKER_FILE).is_file())

    def test_ghidra_caches_never_ship_in_archives(self):
        """The cached re-database.json is the trust-bearing artifact
        context injection and decompile read FIRST — an unsigned
        archive restoring it byte-identical would hand the archive
        author the "derived" database. Caches are machine-local and
        recomputable by re-attach; a run dir that merely starts with
        "ghidra-" (no re-database.json) still ships."""
        with TemporaryDirectory() as td:
            d = Path(td)
            src = d / "src" / "myproj"
            run = src / "scan_20260101-000000"
            run.mkdir(parents=True)
            (run / "findings.json").write_text('{"findings": []}')
            slot = src / "ghidra-attach" / "fw-abcd1234"
            slot.mkdir(parents=True)
            (slot / "re-database.json").write_text('{"poisoned": 1}')
            legacy = src / "ghidra-fw"
            legacy.mkdir()
            (legacy / "re-database.json").write_text('{"poisoned": 2}')
            lookalike = src / "ghidra-notes"
            lookalike.mkdir()
            (lookalike / "readme.txt").write_text("keep me")
            imported_root = _import_archive(d, src)
            assert not (imported_root / "ghidra-attach").exists()
            assert not (imported_root / "ghidra-fw").exists()
            assert (imported_root / "ghidra-notes"
                    / "readme.txt").is_file()
            assert (imported_root
                    / "scan_20260101-000000").is_dir()

    def test_crafted_archive_caches_quarantined_on_import(self):
        """Export pruning does not bind an archive AUTHOR — a crafted
        zip can still carry re-database.json at the attach slot or
        the stem-keyed legacy slot, and restored in place it becomes
        the FIRST cache candidate injection/status/sync/decompile
        read. Import must quarantine it like the other trust-bearing
        artifact families."""
        import zipfile

        from core.project.export import (
            _QUARANTINE_DIR_NAME,
            import_project,
        )
        with TemporaryDirectory() as td:
            d = Path(td)
            zip_path = d / "crafted.zip"
            meta = json.dumps({
                "name": "crafted", "target": str(d / "t"),
                "output_dir": str(d / "ignored"),
            })
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("crafted/.project.json", meta)
                zf.writestr(
                    "crafted/scan_20260101-000000/findings.json",
                    '{"findings": []}')
                zf.writestr(
                    "crafted/ghidra-attach/fw-deadbeef/"
                    "re-database.json", '{"planted": "attach-slot"}')
                zf.writestr(
                    "crafted/ghidra-fw/re-database.json",
                    '{"planted": "legacy-slot"}')
            result = import_project(zip_path, d / "projects",
                                    output_base=d / "imported")
            root = Path(result["output_dir"])
            assert not (root / "ghidra-attach").exists()
            assert not (root / "ghidra-fw"
                        / "re-database.json").exists()
            q = root / _QUARANTINE_DIR_NAME
            assert (q / "ghidra-attach").exists() or list(
                q.rglob("re-database.json")), (
                "planted caches neither at canonical paths nor "
                "quarantined")

    def test_crafted_ghidra_attach_file_quarantined(self):
        """A plain FILE named ghidra-attach restored in place bricks
        every later attach (cache mkdir hits the name collision) —
        the export-side skip does not bind an archive author."""
        import zipfile

        from core.project.export import import_project
        with TemporaryDirectory() as td:
            d = Path(td)
            zip_path = d / "crafted.zip"
            meta = json.dumps({
                "name": "crafted2", "target": str(d / "t"),
                "output_dir": str(d / "ignored"),
            })
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("crafted2/.project.json", meta)
                zf.writestr("crafted2/ghidra-attach", "not a dir")
            result = import_project(zip_path, d / "projects",
                                    output_base=d / "imported")
            root = Path(result["output_dir"])
            assert not (root / "ghidra-attach").exists()

    def test_default_output_base_is_absolute(self):
        """The cwd-relative Path("out/projects") default minted
        RELATIVE output_dirs on CLI import — the restored project
        landed in whatever cwd the process had, outside
        RAPTOR_OUT_DIR, and derived JVM-facing paths later resolved
        against the sandbox scratch cwd (create() was fixed for this
        long ago; import kept the old minting)."""
        import zipfile
        from unittest import mock

        import core.project.project as project_mod
        from core.project.export import import_project
        with TemporaryDirectory() as td:
            d = Path(td)
            zip_path = d / "a.zip"
            meta = json.dumps({
                "name": "absbase", "target": str(d / "t"),
                "output_dir": str(d / "ignored"),
            })
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("absbase/.project.json", meta)
                zf.writestr("absbase/scan_20260101-000000/x.json",
                            "{}")
            with mock.patch.object(project_mod, "DEFAULT_OUTPUT_BASE",
                                   d / "outbase"):
                result = import_project(zip_path, d / "projects")
            out = Path(result["output_dir"])
            self.assertTrue(out.is_absolute())
            self.assertEqual(out, d / "outbase" / "absbase")

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


class TestImportedLivenessNeutralised(unittest.TestCase):
    """A restored ``status=running`` marker described a session on the
    EXPORTING machine (or a forged claim). Restored verbatim, its
    foreign stamp read fail-open alive forever — a permanent
    contention holder no sweep could clear. Import neutralises it."""

    def test_running_marker_becomes_interrupted_and_unstamped(self):
        with TemporaryDirectory() as td:
            d = Path(td)
            src = d / "src" / "myproj"
            run = src / "agentic-20260101-000000"
            run.mkdir(parents=True)
            (run / ".raptor-run.json").write_text(json.dumps({
                "version": 2, "command": "agentic",
                "timestamp": "2026-01-01T00:00:00+00:00",
                "status": "running",
                "session_pid": 4194000, "tool_pid": 4194001,
                "session_start": "123456",
                "session_boot_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000",
                "session_pidns": "999999999",
                "session_machine_id": "0" * 64,
                "session_id": "01234567-89ab-cdef-0123-456789abcdef",
            }))
            imported_root = _import_archive(d, src)
            meta = json.loads(
                (imported_root / "agentic-20260101-000000"
                 / ".raptor-run.json").read_text())
            self.assertEqual(meta["status"], "interrupted")
            self.assertIs(meta["import_liveness_neutralised"], True)
            for stamp in ("session_pid", "tool_pid", "session_start",
                          "session_boot_id", "session_pidns",
                          "session_machine_id", "session_id"):
                self.assertNotIn(stamp, meta)

    def test_terminal_statuses_restored_verbatim(self):
        # Two-direction: only non-terminal liveness is neutralised.
        with TemporaryDirectory() as td:
            d = Path(td)
            src = d / "src" / "myproj"
            run = src / "scan-20260101-000000"
            run.mkdir(parents=True)
            (run / ".raptor-run.json").write_text(json.dumps({
                "version": 2, "command": "scan",
                "timestamp": "2026-01-01T00:00:00+00:00",
                "status": "completed",
                "session_pid": 4194000,
            }))
            imported_root = _import_archive(d, src)
            meta = json.loads(
                (imported_root / "scan-20260101-000000"
                 / ".raptor-run.json").read_text())
            self.assertEqual(meta["status"], "completed")
            self.assertNotIn("import_liveness_neutralised", meta)
