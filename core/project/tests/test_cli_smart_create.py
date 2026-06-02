"""Tests for smart ``raptor project create`` — catalog-driven
detection + tuning block + ``--require-target-type`` strict-CI
gate (QoL #18)."""

from __future__ import annotations

import contextlib
import io
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core.project.cli import (
    _detect_target_type,
    _format_project_tuning,
    main,
)
from core.run.target_types import CatalogEntry


class TestDetectTargetType(unittest.TestCase):
    """Smart-create's catalog wrapper — pure best-effort, never
    raises."""

    def test_c_userspace_daemon_tree_detected(self):
        with TemporaryDirectory() as d:
            target = Path(d)
            (target / "configure.ac").write_text("")
            (target / "Makefile.am").write_text("")
            (target / "src").mkdir()
            (target / "src" / "main.c").write_text("")
            entry = _detect_target_type(str(target))
            self.assertIsNotNone(entry)
            self.assertEqual(entry.name, "c.userspace-daemon")

    def test_python_web_app_tree_detected(self):
        with TemporaryDirectory() as d:
            target = Path(d)
            (target / "manage.py").write_text("")
            (target / "settings.py").write_text("")
            (target / "urls.py").write_text("")
            entry = _detect_target_type(str(target))
            self.assertIsNotNone(entry)
            self.assertEqual(entry.name, "python.web-app")

    def test_empty_target_falls_back_to_generic(self):
        with TemporaryDirectory() as d:
            entry = _detect_target_type(d)
            self.assertIsNotNone(entry)
            self.assertEqual(entry.name, "generic")

    def test_catalog_exception_returns_none_silently(self):
        # Substrate failure must not propagate — create must not
        # refuse over a catalog substrate bug.
        with patch(
            "core.run.target_types.load",
            side_effect=RuntimeError("catalog broken"),
        ):
            entry = _detect_target_type("/tmp/anything")
            self.assertIsNone(entry)


class TestFormatProjectTuning(unittest.TestCase):
    """Renderer — list of lines to print after the create
    confirmation. Caller decides where they land."""

    def test_full_entry_renders_all_sections(self):
        entry = CatalogEntry(
            name="c.userspace-daemon",
            estimated_cost_usd=(25.0, 50.0),
            estimated_time_min=(40, 75),
            semgrep_packs_default=("security-audit", "owasp-top-ten"),
            attack_surface_high=("src/http", "src/net"),
            pipeline_recommended=("understand-map", "scan", "agentic"),
        )
        lines = _format_project_tuning(entry)
        joined = "\n".join(lines)
        self.assertIn("Target type: c.userspace-daemon", joined)
        # Cost+time uses the estimator's renderer — verify the
        # range shape without re-asserting its exact format
        # (single source of truth lives in core/run/estimator.py).
        self.assertIn("$25", joined)
        self.assertIn("$50", joined)
        self.assertIn("40-75 min", joined)
        self.assertIn("security-audit, owasp-top-ten", joined)
        self.assertIn("src/http, src/net", joined)
        # Pipeline recommendation uses arrow separator —
        # operator-readable flow.
        self.assertIn("understand-map → scan → agentic", joined)

    def test_minimal_entry_only_renders_present_sections(self):
        # Catalog author shipped only ``name`` + packs — the
        # other sections should NOT print empty rows.
        entry = CatalogEntry(
            name="minimal",
            semgrep_packs_default=("security-audit",),
        )
        lines = _format_project_tuning(entry)
        joined = "\n".join(lines)
        self.assertIn("Target type: minimal", joined)
        self.assertIn("security-audit", joined)
        # No cost/time/dirs/pipeline sections — assert on the
        # CONTAINER labels (``Expected:``, ``preferred dirs``,
        # ``Recommended pipeline``) rather than substrings of
        # values; ``min`` would false-match ``minimal``.
        self.assertNotIn("$", joined)
        self.assertNotIn("Expected:", joined)
        self.assertNotIn("preferred dirs", joined)
        self.assertNotIn("Recommended pipeline", joined)

    def test_cost_only_entry_renders_cost_no_time(self):
        # Estimator's format_estimate trims the absent half.
        entry = CatalogEntry(
            name="cost-only",
            estimated_cost_usd=(10.0, 20.0),
        )
        lines = _format_project_tuning(entry)
        joined = "\n".join(lines)
        self.assertIn("$10", joined)
        self.assertNotIn("min", joined)


class TestCreateIntegration(unittest.TestCase):
    """End-to-end ``raptor project create`` — captures stdout and
    asserts the tuning block appears at the right place."""

    def _run_create(self, target_path: str, *extra_args):
        """Run ``main`` with mocked ProjectManager and capture
        stdout. Returns the captured output string."""
        with patch("core.project.cli.ProjectManager") as MockMgr:
            instance = MockMgr.return_value
            instance.create.return_value = type("P", (), {
                "name": "smart-test",
                "output_dir": "/tmp/smart-test-out",
                "binaries": [],
            })()
            argv = [
                "raptor-project", "create", "smart-test",
                "--target", target_path,
            ] + list(extra_args)
            buf = io.StringIO()
            with patch("sys.argv", argv):
                with contextlib.redirect_stdout(buf):
                    main()
            return buf.getvalue()

    def test_c_daemon_target_prints_tuning_block(self):
        with TemporaryDirectory() as d:
            target = Path(d)
            (target / "configure.ac").write_text("")
            (target / "src").mkdir()
            (target / "src" / "main.c").write_text("")
            (target / "Makefile.am").write_text("")
            out = self._run_create(str(target))
            self.assertIn("Created project 'smart-test'", out)
            self.assertIn("Target type: c.userspace-daemon", out)
            # Cost estimate present.
            self.assertIn("$25", out)
            # Suggested packs present.
            self.assertIn("security-audit", out)
            # Suggested dirs present.
            self.assertIn("src/http", out)

    def test_empty_target_prints_generic_tuning(self):
        with TemporaryDirectory() as d:
            out = self._run_create(d)
            self.assertIn("Created project", out)
            self.assertIn("Target type: generic", out)


class TestRequireTargetTypeGate(unittest.TestCase):
    """``--require-target-type`` — strict-CI assertion that
    detection picked a specific entry. Mismatch refuses to
    create."""

    def _run_create_expecting_exit(self, target_path: str, *extra_args):
        """Like ``_run_create`` but expects SystemExit; returns
        (stdout, exit_code)."""
        with patch("core.project.cli.ProjectManager") as MockMgr:
            instance = MockMgr.return_value
            instance.create.return_value = type("P", (), {
                "name": "x", "output_dir": "/tmp/x", "binaries": [],
            })()
            argv = [
                "raptor-project", "create", "x",
                "--target", target_path,
            ] + list(extra_args)
            buf = io.StringIO()
            with patch("sys.argv", argv):
                with contextlib.redirect_stdout(buf):
                    try:
                        main()
                        return buf.getvalue(), 0
                    except SystemExit as e:
                        return buf.getvalue(), int(e.code or 0)

    def test_matching_required_type_proceeds(self):
        with TemporaryDirectory() as d:
            target = Path(d)
            (target / "configure.ac").write_text("")
            (target / "Makefile.am").write_text("")
            (target / "src").mkdir()
            (target / "src" / "main.c").write_text("")
            out, exit_code = self._run_create_expecting_exit(
                str(target),
                "--require-target-type", "c.userspace-daemon",
            )
            self.assertEqual(exit_code, 0)
            self.assertIn("Created project", out)

    def test_mismatched_required_type_refuses(self):
        with TemporaryDirectory() as d:
            target = Path(d)
            (target / "manage.py").write_text("")
            (target / "settings.py").write_text("")
            (target / "urls.py").write_text("")
            out, exit_code = self._run_create_expecting_exit(
                str(target),
                "--require-target-type", "c.userspace-daemon",
            )
            self.assertEqual(exit_code, 1)
            # Operator-readable error.
            self.assertIn("mismatch", out)
            self.assertIn("c.userspace-daemon", out)  # required
            self.assertIn("python.web-app", out)      # detected
            # Project should NOT have been created — refusing the
            # gate means the ProjectManager.create call never
            # happens.
            self.assertNotIn("Created project", out)


if __name__ == "__main__":
    unittest.main()
