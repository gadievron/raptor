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


class TestImportQuarantinesCoverageRecords(unittest.TestCase):
    """Per-run coverage records are a producer-named GLOB family
    (``coverage-<tool>.json``, legacy ``coverage-record.json``) — the
    fixed-name quarantine set could never cover them, so a forged
    archive still minted examined-coverage that shrank the gap-audit
    residual and passed ``/project coverage --fail-under``."""

    def _build(self, src: Path) -> Path:
        run = src / "scan_20260101-000000"
        run.mkdir(parents=True)
        (run / "findings.json").write_text('{"findings": []}')
        (run / "coverage-semgrep.json").write_text(json.dumps({
            "tool": "semgrep",
            "files_examined": ["src/a.py", "src/evil_marked_reviewed.py"],
            "timestamp": "2026-01-01T00:00:00+00:00",
        }))
        (run / "coverage-read.json").write_text(json.dumps({
            "tool": "llm-read", "files_examined": ["src/c.py"],
        }))
        (run / "coverage-record.json").write_text(json.dumps({
            "tool": "legacy", "files_examined": ["src/d.py"],
        }))
        # Tool-subdir variant the record glob also discovers.
        (run / "scan").mkdir()
        (run / "scan" / "coverage-codeql.json").write_text(json.dumps({
            "tool": "codeql", "files_examined": ["src/e.py"],
        }))
        return run

    def test_coverage_records_quarantined(self):
        with TemporaryDirectory() as td:
            d = Path(td)
            src = d / "src" / "myproj"
            self._build(src)
            root = _import(d, src)
            run = root / "scan_20260101-000000"
            for canonical in (
                run / "coverage-semgrep.json",
                run / "coverage-read.json",
                run / "coverage-record.json",
                run / "scan" / "coverage-codeql.json",
            ):
                self.assertFalse(canonical.exists(),
                                 f"{canonical} restored at canonical path")
            q = root / _QUARANTINE / "scan_20260101-000000"
            self.assertTrue((q / "coverage-semgrep.json").is_file())
            self.assertTrue((q / "scan" / "coverage-codeql.json").is_file())

    def test_coverage_view_sees_no_forged_records(self):
        """Consumer-level check: the file-level coverage view over the
        imported run must not count the archive's records as examined
        coverage."""
        from core.coverage.store_summary import file_level_view

        with TemporaryDirectory() as td:
            d = Path(td)
            src = d / "src" / "myproj"
            self._build(src)
            root = _import(d, src)
            view = file_level_view([root / "scan_20260101-000000"])
            self.assertEqual(view.get("tools", {}), {})


class TestImportQuarantinesChecklist(unittest.TestCase):
    """Run-level checklists are what ``_promote_checklist`` elects
    "newest" and copies to the project level (merging checked_by
    credit) — a forged archive would mint reviewed checklist state
    the next start_run promotes into authority."""

    def test_checklists_quarantined(self):
        with TemporaryDirectory() as td:
            d = Path(td)
            src = d / "src" / "myproj"
            run = src / "scan_20260101-000000"
            run.mkdir(parents=True)
            (run / "findings.json").write_text('{"findings": []}')
            (run / "checklist.json").write_text(
                '{"items": [{"id": 1, "checked_by": "forged"}]}')
            (src / "checklist.json").write_text(
                '{"items": [{"id": 1, "checked_by": "forged-root"}]}')
            root = _import(d, src)
            self.assertFalse((root / "checklist.json").exists())
            self.assertFalse(
                (root / "scan_20260101-000000" / "checklist.json").exists())
            q = root / _QUARANTINE
            self.assertTrue((q / "checklist.json").is_file())
            self.assertTrue(
                (q / "scan_20260101-000000" / "checklist.json").is_file())


class TestQuarantineUniverseDerivation(unittest.TestCase):
    """The quarantine set is trust-bearing and was hand-picked — two
    demonstrated escapes (the run marker's liveness claim; the
    coverage-record glob family) were both omissions of the SAME hand
    list. Derive the expected universe from the privileged consumers'
    own canonical-name spellings and assert closure: an owner renaming
    or re-homing a canonical artifact fails here until the quarantine
    set moves with it."""

    def _quarantine_covers(self, name: str) -> bool:
        import fnmatch

        from core.project.export import (
            _PRIVILEGED_DIR_NAMES,
            _PRIVILEGED_FILE_GLOBS,
            _PRIVILEGED_FILE_NAMES,
        )
        return (name in _PRIVILEGED_FILE_NAMES
                or name in _PRIVILEGED_DIR_NAMES
                or any(fnmatch.fnmatch(name, pat)
                       for pat in _PRIVILEGED_FILE_GLOBS))

    def test_importable_canonical_constants_covered(self):
        # Families whose owners export a canonical-name constant: the
        # derivation imports the REAL spelling, so a rename cannot
        # silently leave the quarantine matching a stale name.
        from core.coverage.journal import INDEX_FILENAME, JOURNAL_FILENAME
        from core.coverage.record import COVERAGE_RECORD_FILE
        from core.coverage.store import COVERAGE_STORE_FILE
        for name in (JOURNAL_FILENAME, INDEX_FILENAME,
                     COVERAGE_STORE_FILE, COVERAGE_RECORD_FILE):
            self.assertTrue(self._quarantine_covers(name), name)
        # The record family is a producer-named glob; the fixed legacy
        # name above must ride the same glob the consumers use.
        import core.coverage.record as record_mod
        import inspect
        self.assertIn('glob("coverage-*.json")',
                      inspect.getsource(record_mod))
        self.assertTrue(self._quarantine_covers("coverage-semgrep.json"))

    def test_literal_spelling_owners_covered(self):
        # Families whose owners spell the canonical name inline: pin
        # the spelling AT THE OWNER (a rename fails the pin, forcing
        # this test — and the quarantine set — to move with it), then
        # assert coverage.
        import inspect

        import core.coverage.store_summary as store_summary
        import core.iris.store as iris_store
        import core.labeled_attempts.view as outcomes_view
        import core.run.metadata as run_metadata
        import core.witness.discovery as witness_discovery
        cases = [
            (iris_store, "iris-taint-specs-refined.json"),
            (iris_store, "iris-specs"),
            (witness_discovery, "witnesses"),
            (store_summary, "coverage-progress.jsonl"),
            (outcomes_view, "verified-outcomes.jsonl"),
            (run_metadata, "checklist.json"),
        ]
        for owner, name in cases:
            src = inspect.getsource(owner)
            self.assertIn(name, src,
                          f"{owner.__name__} no longer spells "
                          f"{name!r} — update the derivation AND the "
                          f"quarantine set together")
            self.assertTrue(self._quarantine_covers(name), name)

    def test_labeled_attempts_store_dir_covered(self):
        from core.labeled_attempts.store import project_pool_path
        name = project_pool_path(Path("/x")).name
        self.assertTrue(self._quarantine_covers(name), name)


if __name__ == "__main__":
    unittest.main()
