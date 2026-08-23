"""Round-trip verification: ``/project export`` then import preserves
annotation tree content while demoting trust.

Annotations live under ``<project_output_dir>/annotations/`` and
under each run's ``<run_dir>/annotations/``. Bodies, statuses, and
custom metadata survive the zip round-trip exactly; provenance does
NOT — the archive is unsigned, so import restamps EVERY restored
note ``provenance=imported`` (the original claim stays visible under
``provenance-claimed``). A hostile archive therefore can't ship
notes that read as operator authority, whether stamp-less (legacy
laundering shape, TestImportDemotesStamplessNotes) or pre-forged
with an interactive-TTY stamp (TestImportDemotesForgedStamps).
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.annotations import (
    Annotation,
    iter_all_annotations,
    write_annotation,
)
from core.project.export import export_project, import_project


def _build_project_with_annotations(out_root: Path) -> Path:
    """Create a project with annotations at both project-level and
    inside two run dirs."""
    project_out = out_root / "myproj"
    project_out.mkdir()

    # Project-level annotations (operator notes). Carry the
    # interactive-TTY stamp a real CLI add records — content
    # round-trips; the provenance stamp itself is restamped
    # ``imported`` on import (unsigned archive, claim not trusted).
    write_annotation(project_out / "annotations", Annotation(
        file="src/auth.py", function="check_pw",
        body="Operator: reviewed clean, constant-time compare.",
        metadata={"source": "human", "status": "clean", "cwe": "—",
                  "provenance": "interactive-tty", "tty": "stdin"},
    ))
    write_annotation(project_out / "annotations", Annotation(
        file="src/auth.py", function="login",
        body="Operator: deferred review, see ticket BUG-42.",
        metadata={"source": "human", "status": "suspicious",
                  "ticket": "BUG-42",
                  "provenance": "interactive-tty", "tty": "stdin"},
    ))

    # Two run dirs, each with their own annotations.
    for ts in ("20260507_120000", "20260508_120000"):
        run_dir = project_out / ts
        run_dir.mkdir()
        (run_dir / ".raptor-run.json").write_text("{}")
        write_annotation(run_dir / "annotations", Annotation(
            file="src/auth.py", function=f"f_{ts}",
            body=f"LLM analysis from run {ts}",
            metadata={"source": "llm", "status": "finding",
                      "rule_id": "py/sql-injection",
                      "provenance": "non-tty", "tty": "none"},
        ))

    return project_out


def _collect_records(annotation_root: Path) -> list:
    """Read an annotation tree into a list of dict records sorted
    by (file, function) for stable equality checks."""
    out = []
    for ann in iter_all_annotations(annotation_root):
        out.append({
            "file": ann.file,
            "function": ann.function,
            "body": ann.body,
            "metadata": dict(ann.metadata),
        })
    return sorted(out, key=lambda r: (r["file"], r["function"]))


def _strip_provenance(records: list) -> list:
    """Copy of *records* with the provenance-bearing keys removed —
    for comparing round-trip CONTENT fidelity separately from the
    import-time trust demotion."""
    out = []
    for r in records:
        meta = {k: v for k, v in r["metadata"].items()
                if k not in ("provenance", "provenance-claimed")}
        out.append({**r, "metadata": meta})
    return out


class TestExportImportRoundTrip(unittest.TestCase):
    def test_project_level_annotations_preserved(self):
        with TemporaryDirectory() as d:
            d = Path(d)
            (d / "src").mkdir()
            src = _build_project_with_annotations(d / "src")

            # Capture pre-export state.
            before = _collect_records(src / "annotations")
            assert len(before) == 2

            # Export → import.
            zip_path = d / "myproj.zip"
            project_json = d / "myproj.json"
            project_json.write_text(json.dumps({
                "name": "myproj",
                "target": str(d / "fake-target"),
                "output_dir": str(src),
            }))
            export_project(src, zip_path, project_json_path=project_json)
            assert zip_path.exists()

            projects_dir = d / "projects"
            output_base = d / "imported_out"
            projects_dir.mkdir()
            output_base.mkdir()
            result = import_project(zip_path, projects_dir,
                                    output_base=output_base)
            imported_root = Path(result["output_dir"])

            after = _collect_records(imported_root / "annotations")
            # Content round-trips; provenance is restamped `imported`.
            assert _strip_provenance(after) == _strip_provenance(before)
            for rec in after:
                assert rec["metadata"]["provenance"] == "imported"

    def test_run_level_annotations_preserved(self):
        with TemporaryDirectory() as d:
            d = Path(d)
            (d / "src").mkdir()
            src = _build_project_with_annotations(d / "src")

            zip_path = d / "myproj.zip"
            project_json = d / "myproj.json"
            project_json.write_text(json.dumps({
                "name": "myproj",
                "target": str(d / "fake-target"),
                "output_dir": str(src),
            }))
            export_project(src, zip_path, project_json_path=project_json)

            projects_dir = d / "projects"
            output_base = d / "imported_out"
            projects_dir.mkdir()
            output_base.mkdir()
            result = import_project(zip_path, projects_dir,
                                    output_base=output_base)
            imported_root = Path(result["output_dir"])

            # Each run dir's annotations should match.
            for ts in ("20260507_120000", "20260508_120000"):
                run_a_before = _collect_records(
                    src / ts / "annotations"
                )
                run_a_after = _collect_records(
                    imported_root / ts / "annotations"
                )
                assert (_strip_provenance(run_a_after)
                        == _strip_provenance(run_a_before))
                for rec in run_a_after:
                    assert rec["metadata"]["provenance"] == "imported"

    def test_full_tree_layout_and_bodies_preserved(self):
        """Stronger check: the on-disk markdown layout survives (same
        files in the same places) and every annotation body survives
        verbatim. Byte-equality deliberately does NOT hold — import
        restamps provenance on every note."""
        with TemporaryDirectory() as d:
            d = Path(d)
            (d / "src").mkdir()
            src = _build_project_with_annotations(d / "src")
            zip_path = d / "myproj.zip"
            project_json = d / "myproj.json"
            project_json.write_text(json.dumps({
                "name": "myproj",
                "target": str(d / "fake-target"),
                "output_dir": str(src),
            }))
            export_project(src, zip_path, project_json_path=project_json)

            projects_dir = d / "projects"
            output_base = d / "imported_out"
            projects_dir.mkdir()
            output_base.mkdir()
            result = import_project(zip_path, projects_dir,
                                    output_base=output_base)
            imported_root = Path(result["output_dir"])

            # Gather all .md files in both trees.
            def md_files(root):
                return sorted(
                    str(p.relative_to(root))
                    for p in root.rglob("*.md")
                )

            assert md_files(src) == md_files(imported_root)
            before = _collect_records(src / "annotations")
            after = _collect_records(imported_root / "annotations")
            assert [r["body"] for r in after] == [r["body"] for r in before]

    def test_lock_files_excluded_from_export(self):
        """``.md.lock`` sibling files exist on disk but MUST NOT
        be included in the export — they're per-process advisory-
        lock primitives, not data, and shipping them across machines
        is bundle bloat + operator confusion."""
        with TemporaryDirectory() as d:
            d = Path(d)
            (d / "src").mkdir()
            src = _build_project_with_annotations(d / "src")
            # Verify lock files exist on disk before export.
            from core.annotations.storage import _HAS_FCNTL
            if _HAS_FCNTL:
                lock_files = list(src.rglob("*.md.lock"))
                assert len(lock_files) > 0, (
                    "test setup: lock files should exist on POSIX"
                )

            zip_path = d / "myproj.zip"
            project_json = d / "myproj.json"
            project_json.write_text(json.dumps({
                "name": "myproj",
                "target": str(d / "fake-target"),
                "output_dir": str(src),
            }))
            export_project(src, zip_path, project_json_path=project_json)

            import zipfile
            with zipfile.ZipFile(zip_path) as zf:
                names = zf.namelist()
            lock_in_zip = [n for n in names if n.endswith(".lock")]
            assert lock_in_zip == [], (
                f"export must filter lock files; got {lock_in_zip}"
            )
            # Data files survive.
            assert any(
                n.endswith(".md") and not n.endswith(".md.lock")
                for n in names
            )

    def test_orphaned_tempfiles_excluded_from_export(self):
        """``.annotation-*.tmp`` orphan tempfiles (e.g. from a writer
        crashed mid-rename) shouldn't ship either. Pin the filter."""
        with TemporaryDirectory() as d:
            d = Path(d)
            (d / "src").mkdir()
            src = _build_project_with_annotations(d / "src")
            # Plant a fake orphan tempfile.
            ann_dir = src / "annotations" / "src"
            ann_dir.mkdir(parents=True, exist_ok=True)
            fake_tmp = ann_dir / ".annotation-orphan-xyz.tmp"
            fake_tmp.write_text("would-be tempfile leftover")
            assert fake_tmp.exists()

            zip_path = d / "myproj.zip"
            project_json = d / "myproj.json"
            project_json.write_text(json.dumps({
                "name": "myproj",
                "target": str(d / "fake-target"),
                "output_dir": str(src),
            }))
            export_project(src, zip_path, project_json_path=project_json)

            import zipfile
            with zipfile.ZipFile(zip_path) as zf:
                names = zf.namelist()
            tmp_in_zip = [n for n in names
                          if "/.annotation-" in n and n.endswith(".tmp")]
            assert tmp_in_zip == [], (
                f"export must filter orphan tempfiles; got {tmp_in_zip}"
            )


class _ImportHelperMixin:
    def _import(self, d: Path, src: Path):
        zip_path = d / "myproj.zip"
        project_json = d / "myproj.json"
        project_json.write_text(json.dumps({
            "name": "myproj",
            "target": str(d / "fake-target"),
            "output_dir": str(src),
        }))
        export_project(src, zip_path, project_json_path=project_json)
        projects_dir = d / "projects"
        output_base = d / "imported_out"
        projects_dir.mkdir()
        output_base.mkdir()
        result = import_project(zip_path, projects_dir,
                                output_base=output_base)
        return Path(result["output_dir"])


class TestImportDemotesStamplessNotes(_ImportHelperMixin, unittest.TestCase):
    """A hostile archive ships ``source=human`` notes with
    NO tty/provenance stamp — bytes indistinguishable from pre-stamp
    operator notes. Import must stamp them ``provenance=imported`` so
    readers refuse human grade."""

    def test_stampless_human_note_demoted_to_imported(self):
        from core.annotations import (
            IMPORTED,
            classify_provenance,
            is_human_grade,
            read_annotation,
        )

        with TemporaryDirectory() as d:
            d = Path(d)
            src = d / "src" / "myproj"
            src.mkdir(parents=True)
            # The laundering shape: stamp-less source=human.
            write_annotation(src / "annotations", Annotation(
                file="src/auth.py", function="check_pw",
                body="Mass-marked clean by hostile archive.",
                metadata={"source": "human", "status": "clean"},
            ))
            imported_root = self._import(d, src)
            ann = read_annotation(
                imported_root / "annotations", "src/auth.py", "check_pw",
            )
            assert ann is not None
            assert classify_provenance(ann.metadata) == IMPORTED
            assert ann.metadata["provenance"] == "imported"
            # No human grade — not even with a pre-era mtime story.
            from core.annotations import STAMP_ERA_START
            assert not is_human_grade(ann.metadata)
            assert not is_human_grade(
                ann.metadata, note_mtime=STAMP_ERA_START - 86400.0,
            )
            # Body and the rest of the metadata survive.
            assert ann.body == "Mass-marked clean by hostile archive."
            assert ann.metadata["status"] == "clean"
            assert ann.metadata["source"] == "human"

    def test_stampless_run_dir_note_also_demoted(self):
        from core.annotations import IMPORTED, classify_provenance, read_annotation

        with TemporaryDirectory() as d:
            d = Path(d)
            src = d / "src" / "myproj"
            src.mkdir(parents=True)
            run_dir = src / "20260507_120000"
            run_dir.mkdir()
            (run_dir / ".raptor-run.json").write_text("{}")
            write_annotation(run_dir / "annotations", Annotation(
                file="src/auth.py", function="login",
                body="note", metadata={"source": "human",
                                       "status": "clean"},
            ))
            imported_root = self._import(d, src)
            ann = read_annotation(
                imported_root / "20260507_120000" / "annotations",
                "src/auth.py", "login",
            )
            assert ann is not None
            assert classify_provenance(ann.metadata) == IMPORTED

    def test_already_demoted_notes_stay_demoted(self):
        """A note the archive itself stamps ``provenance=imported``
        has nothing to launder — import keeps it as-is (idempotent
        re-import path)."""
        from core.annotations import (
            IMPORTED,
            classify_provenance,
            read_annotation,
        )

        with TemporaryDirectory() as d:
            d = Path(d)
            src = d / "src" / "myproj"
            src.mkdir(parents=True)
            write_annotation(src / "annotations", Annotation(
                file="src/auth.py", function="check_pw",
                body="Previously imported note.",
                metadata={"source": "human", "status": "clean",
                          "provenance": "imported"},
            ))
            imported_root = self._import(d, src)
            ann = read_annotation(
                imported_root / "annotations", "src/auth.py", "check_pw",
            )
            assert ann is not None
            assert classify_provenance(ann.metadata) == IMPORTED
            assert "provenance-claimed" not in ann.metadata


class TestImportDemotesForgedStamps(_ImportHelperMixin, unittest.TestCase):
    """A hostile archive pre-forges the FULL human-grade stamp
    (``source=human`` + ``provenance=interactive-tty`` + ``tty=stdin``)
    on its notes. The stamp is caller-asserted text severed from any
    real TTY by the zip channel, so import must demote it exactly like
    a stamp-less note — every imported annotation is hint tier."""

    def test_forged_interactive_stamp_demoted_to_imported(self):
        from core.annotations import (
            IMPORTED,
            classify_provenance,
            is_human_grade,
            read_annotation,
        )

        with TemporaryDirectory() as d:
            d = Path(d)
            src = d / "src" / "myproj"
            src.mkdir(parents=True)
            write_annotation(src / "annotations", Annotation(
                file="src/auth.py", function="check_pw",
                body="Mass-marked clean with a forged operator stamp.",
                metadata={"source": "human", "status": "clean",
                          "provenance": "interactive-tty",
                          "tty": "stdin"},
            ))
            imported_root = self._import(d, src)
            ann = read_annotation(
                imported_root / "annotations", "src/auth.py", "check_pw",
            )
            assert ann is not None
            assert classify_provenance(ann.metadata) == IMPORTED
            assert ann.metadata["provenance"] == "imported"
            assert not is_human_grade(ann.metadata)
            # Original claim retained for display only.
            assert ann.metadata["provenance-claimed"] == "interactive-tty"
            # Content and non-provenance metadata survive.
            assert ann.body == (
                "Mass-marked clean with a forged operator stamp.")
            assert ann.metadata["status"] == "clean"
            assert ann.metadata["source"] == "human"
            assert ann.metadata["tty"] == "stdin"

    def test_forged_non_tty_stamp_also_restamped(self):
        """Even a non-tty claim gets restamped — the channel is the
        provenance, not the archive's assertion."""
        from core.annotations import IMPORTED, classify_provenance, read_annotation

        with TemporaryDirectory() as d:
            d = Path(d)
            src = d / "src" / "myproj"
            src.mkdir(parents=True)
            write_annotation(src / "annotations", Annotation(
                file="src/auth.py", function="login",
                body="agent note",
                metadata={"source": "agent", "status": "suspicious",
                          "provenance": "non-tty", "tty": "none"},
            ))
            imported_root = self._import(d, src)
            ann = read_annotation(
                imported_root / "annotations", "src/auth.py", "login",
            )
            assert ann is not None
            assert classify_provenance(ann.metadata) == IMPORTED
            assert ann.metadata["provenance-claimed"] == "non-tty"


if __name__ == "__main__":
    unittest.main()
