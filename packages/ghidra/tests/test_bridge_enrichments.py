"""Tests for the pyghidra enrichment-apply program lookup.

All hermetic: pyghidra is mocked at the sys.modules seam (the suite's
standard pattern — see test_session.py), no JVM or Ghidra install is
touched.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from packages.ghidra.bridge import GhidraBridge, _walk_program_paths
from packages.ghidra.session import GhidraSession, GhidraSessionError


class _FakeFile:
    def __init__(self, name: str) -> None:
        self._name = name

    def getName(self) -> str:  # noqa: N802 — Ghidra API shape
        return self._name


class _FakeFolder:
    def __init__(self, name: str = "", files=(), folders=()) -> None:
        self._name = name
        self._files = [_FakeFile(n) for n in files]
        self._folders = list(folders)

    def getName(self) -> str:  # noqa: N802 — Ghidra API shape
        return self._name

    def getFiles(self):  # noqa: N802 — Ghidra API shape
        return list(self._files)

    def getFolders(self):  # noqa: N802 — Ghidra API shape
        return list(self._folders)


def _bridge(program_name: str | None) -> GhidraBridge:
    """GhidraBridge without __init__ (skips .gpr validation)."""
    bridge = GhidraBridge.__new__(GhidraBridge)
    bridge.gpr_path = Path("/nonexistent/proj.gpr")
    bridge.program_name = program_name
    bridge._session = None
    return bridge


class TestApplyEnrichmentsProgramLookup(unittest.TestCase):
    """The pyghidra apply path must honour program_name and resolve
    subfolder programs — pre-fix it always consumed the first ROOT
    file, silently enriching the wrong program on multi-program
    projects and refusing subfolder-only projects outright."""

    def _apply(self, root: _FakeFolder, program_name: str | None):
        bridge = _bridge(program_name)
        project = MagicMock()
        project.getProjectData.return_value.getRootFolder.return_value = root

        fake_api = MagicMock()
        fake_api.open_project.return_value = project
        program = MagicMock()
        consumer = MagicMock()
        fake_api.consume_program.return_value = (program, consumer)
        fake_pyghidra = MagicMock()
        fake_pyghidra.api = fake_api

        with patch.object(GhidraSession, "ensure_jvm"), patch(
            "packages.ghidra.detect.get_project_name",
            return_value="proj",
        ), patch.dict(
            "sys.modules",
            {"pyghidra": fake_pyghidra, "pyghidra.api": fake_api},
        ), patch.object(
            GhidraBridge, "_apply_comments", return_value=0,
        ), patch.object(
            GhidraBridge, "_apply_bookmarks", return_value=0,
        ), patch.object(
            GhidraBridge, "_apply_functions", return_value=0,
        ):
            bridge._apply_enrichments_pyghidra(
                Path("/nonexistent/proj.gpr"), {},
            )
        return fake_api, project, program

    def test_named_program_is_consumed(self):
        root = _FakeFolder(files=["prog_a", "prog_b"])
        fake_api, _, _ = self._apply(root, "prog_b")
        fake_api.consume_program.assert_called_once()
        self.assertEqual(
            fake_api.consume_program.call_args[0][1], "/prog_b")

    def test_subfolder_program_resolves(self):
        root = _FakeFolder(
            folders=[_FakeFolder(name="sub", files=["nested"])],
        )
        fake_api, _, _ = self._apply(root, "sub/nested")
        self.assertEqual(
            fake_api.consume_program.call_args[0][1], "/sub/nested")

    def test_default_uses_first_program_not_error(self):
        """No program_name → first walked program, including when all
        programs live in subfolders (pre-fix: 'contains no programs')."""
        root = _FakeFolder(
            folders=[_FakeFolder(name="sub", files=["only"])],
        )
        fake_api, _, _ = self._apply(root, None)
        self.assertEqual(
            fake_api.consume_program.call_args[0][1], "/sub/only")

    def test_missing_program_raises_and_closes_project(self):
        root = _FakeFolder(files=["prog_a"])
        with self.assertRaises(GhidraSessionError) as cm:
            self._apply(root, "prog_missing")
        self.assertIn("prog_missing", str(cm.exception))
        self.assertIn("prog_a", str(cm.exception))

    def test_suspicious_program_name_refused(self):
        root = _FakeFolder(files=["prog_a"])
        for hostile in ("-deleteProject", "sub/../etc", "a//b"):
            with self.assertRaises(GhidraSessionError, msg=hostile):
                self._apply(root, hostile)

    def test_empty_project_still_refused(self):
        root = _FakeFolder()
        with self.assertRaises(GhidraSessionError) as cm:
            self._apply(root, None)
        self.assertIn("contains no programs", str(cm.exception))

    def test_project_closed_on_lookup_failure(self):
        bridge = _bridge("nope")
        project = MagicMock()
        project.getProjectData.return_value.getRootFolder.return_value = (
            _FakeFolder(files=["prog_a"])
        )
        fake_api = MagicMock()
        fake_api.open_project.return_value = project
        fake_pyghidra = MagicMock()
        fake_pyghidra.api = fake_api
        with patch.object(GhidraSession, "ensure_jvm"), patch(
            "packages.ghidra.detect.get_project_name",
            return_value="proj",
        ), patch.dict(
            "sys.modules",
            {"pyghidra": fake_pyghidra, "pyghidra.api": fake_api},
        ), self.assertRaises(GhidraSessionError):
            bridge._apply_enrichments_pyghidra(
                Path("/nonexistent/proj.gpr"), {},
            )
        project.close.assert_called_once()
        fake_api.consume_program.assert_not_called()


class TestWalkProgramPaths(unittest.TestCase):
    def test_walk_orders_root_then_subfolders(self):
        root = _FakeFolder(
            files=["a", "b"],
            folders=[
                _FakeFolder(name="x", files=["c"]),
                _FakeFolder(
                    name="y",
                    files=["d"],
                    folders=[_FakeFolder(name="z", files=["e"])],
                ),
            ],
        )
        self.assertEqual(
            _walk_program_paths(root),
            ["a", "b", "x/c", "y/d", "y/z/e"],
        )


if __name__ == "__main__":
    unittest.main()


class TestExceptionTextScrubbing(unittest.TestCase):
    def test_hostile_program_names_scrubbed_from_error(self):
        # The "has:" list embeds names from the hostile project's own
        # database; the exception text reaches the operator's terminal.
        root = _FakeFolder(files=["prog\x1b[2J\x07name"])
        bridge = _bridge("prog_missing")
        project = MagicMock()
        project.getProjectData.return_value.getRootFolder.return_value = root
        fake_api = MagicMock()
        fake_api.open_project.return_value = project
        fake_pyghidra = MagicMock()
        fake_pyghidra.api = fake_api
        with patch.object(GhidraSession, "ensure_jvm"), patch(
            "packages.ghidra.detect.get_project_name",
            return_value="proj",
        ), patch.dict(
            "sys.modules",
            {"pyghidra": fake_pyghidra, "pyghidra.api": fake_api},
        ), self.assertRaises(GhidraSessionError) as cm:
            bridge._apply_enrichments_pyghidra(
                Path("/nonexistent/proj.gpr"), {},
            )
        text = str(cm.exception)
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\x07", text)
