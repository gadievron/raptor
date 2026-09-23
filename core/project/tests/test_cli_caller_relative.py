"""Relative operator paths resolve against ``RAPTOR_CALLER_DIR``.

The launcher's project route cd's into the RAPTOR repo dir before
exec'ing the project CLI, so a bare ``Path.resolve`` on a relative
``--target``/``--binary`` silently persisted a repo-relative path
(``--target ./code`` became ``<raptor>/code`` — or an existing repo
subdir like ``./core``), and every later default-target run aimed at
the wrong tree. The launcher records the operator's shell cwd in
RAPTOR_CALLER_DIR; relative paths must resolve against it.
"""

from __future__ import annotations

import contextlib
import io
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core.project.cli import _caller_relative, main


class TestCallerRelativeHelper(unittest.TestCase):
    def test_relative_resolves_against_caller_dir(self):
        with TemporaryDirectory() as d:
            (Path(d) / "code").mkdir()
            with patch.dict(os.environ, {"RAPTOR_CALLER_DIR": d}):
                got = _caller_relative("./code")
        self.assertEqual(got, str((Path(d) / "code").resolve()))

    def test_absolute_passes_through(self):
        with TemporaryDirectory() as d:
            with patch.dict(os.environ, {"RAPTOR_CALLER_DIR": d}):
                self.assertEqual(_caller_relative("/abs/x"), "/abs/x")

    def test_url_passes_through(self):
        with TemporaryDirectory() as d:
            with patch.dict(os.environ, {"RAPTOR_CALLER_DIR": d}):
                self.assertEqual(
                    _caller_relative("https://example.com"),
                    "https://example.com",
                )

    def test_tilde_passes_through(self):
        with TemporaryDirectory() as d:
            with patch.dict(os.environ, {"RAPTOR_CALLER_DIR": d}):
                self.assertEqual(_caller_relative("~/x"), "~/x")

    def test_none_and_missing_env_pass_through(self):
        self.assertIsNone(_caller_relative(None))
        env = {k: v for k, v in os.environ.items()
               if k != "RAPTOR_CALLER_DIR"}
        with patch.dict(os.environ, env, clear=True):
            # Historical cwd resolution holds without the env var.
            self.assertEqual(_caller_relative("./code"), "./code")


class TestCreateUsesCallerDir(unittest.TestCase):
    def test_create_resolves_relative_target(self):
        with TemporaryDirectory() as caller:
            (Path(caller) / "code").mkdir()
            with patch("core.project.cli.ProjectManager") as MockMgr:
                instance = MockMgr.return_value
                instance.create.return_value = type("P", (), {
                    "name": "reltest",
                    "output_dir": "/tmp/reltest-out",
                    "binaries": [],
                })()
                argv = ["raptor-project", "create", "reltest",
                        "--target", "./code"]
                with patch.dict(os.environ,
                                {"RAPTOR_CALLER_DIR": caller}), \
                        patch("sys.argv", argv), \
                        contextlib.redirect_stdout(io.StringIO()):
                    main()
                target_arg = instance.create.call_args.args[1]
        self.assertEqual(target_arg, str((Path(caller) / "code").resolve()))


if __name__ == "__main__":
    unittest.main()


class TestGhidraAddUsesCallerDir(unittest.TestCase):
    """The newer ghidra add/remove surface skipped _caller_relative —
    a relative <path.gpr> resolved against the RAPTOR repo dir the
    launcher moved cwd to, not the operator's shell."""

    def test_ghidra_add_resolves_relative_gpr_against_caller(self):
        from unittest.mock import patch as _patch

        from core.project.cli import main
        with TemporaryDirectory() as d:
            caller = Path(d) / "shell"
            caller.mkdir()
            gpr = caller / "proj.gpr"
            gpr.write_text("x")
            fake_p = type("P", (), {"ghidra_projects": [],
                                    "output_dir": str(Path(d) / "out"),
                                    "to_dict": lambda self: {}})()
            with _patch.dict(os.environ,
                             {"RAPTOR_CALLER_DIR": str(caller)}), \
                    _patch("core.project.cli.ProjectManager") as MockMgr:
                inst = MockMgr.return_value
                inst.load.return_value = fake_p
                inst.projects_dir = Path(d) / "projects"
                inst.projects_dir.mkdir()
                with _patch("sys.argv",
                            ["raptor-project", "ghidra", "add",
                             "proj.gpr", "myproj"]):
                    main()
            self.assertEqual(fake_p.ghidra_projects,
                             [str(gpr.resolve())])
