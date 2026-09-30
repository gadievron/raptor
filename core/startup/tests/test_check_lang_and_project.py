"""Test coverage for `core.startup.init.check_lang` and `check_active_project`.

F077: pre-fix, 4 of the 5 public `check_*` functions in
`core/startup/init.py` had no test coverage. `check_env` was tested via
`test_check_env_macos.py`. The other four (`check_tools`, `check_llm`,
`check_lang`, `check_active_project`) had nothing.

This file ports the `test_check_env_macos.py` shape (mock-driven probe
of one `check_*` function) to two of the four untested members:
`check_lang` and `check_active_project`. The remaining two
(`check_tools`, `check_llm`) shell out to many external binaries and
are deferred to a follow-up (they need more elaborate fixtures).

For each tested function, three scenarios are pinned:
  * happy path — function returns a well-formed string
  * empty/missing-precondition path — function returns the documented
    fallback (None or "✗" branch)
  * exception path — function swallows internal errors and returns None
    rather than crashing the banner
"""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from core.startup import init as startup_init


class CheckLangTest(unittest.TestCase):
    """`check_lang` — tree-sitter probe; returns (line or None, warnings)."""

    def test_returns_check_mark_with_languages(self) -> None:
        with mock.patch(
            "core.inventory.extractors._get_ts_languages",
            return_value=["python", "javascript", "go"],
        ):
            line, warnings = startup_init.check_lang()
        self.assertIsNotNone(line)
        # Documented format: "  lang: tree-sitter ✓ (lang1, lang2, ...)"
        self.assertIn("tree-sitter", line)
        self.assertIn("✓", line)
        self.assertIn("python", line)
        self.assertIn("javascript", line)
        # Grammars present — nothing to warn about.
        self.assertEqual(warnings, [])

    def test_returns_cross_mark_and_warning_when_no_languages(self) -> None:
        """Zero grammars is a WARNING, not just a glyph — production
        inventory silently degrades to regex extraction and operators
        repeatedly missed the ✗ alone."""
        with mock.patch(
            "core.inventory.extractors._get_ts_languages",
            return_value=[],
        ):
            line, warnings = startup_init.check_lang()
        self.assertIsNotNone(line)
        self.assertIn("tree-sitter", line)
        self.assertIn("✗", line)
        self.assertEqual(len(warnings), 1)
        self.assertIn("no tree-sitter grammars installed", warnings[0])
        self.assertIn("regex extraction", warnings[0])

    def test_returns_none_on_exception(self) -> None:
        """check_lang must swallow probe failures and return None.

        The banner runs in a `try/except` at module scope (`init.main`);
        any uncaught exception from a `check_*` function aborts banner
        rendering. Each `check_*` MUST therefore catch its own
        exceptions and return None.
        """
        with mock.patch(
            "core.inventory.extractors._get_ts_languages",
            side_effect=RuntimeError("tree-sitter probe blew up"),
        ):
            line, warnings = startup_init.check_lang()
        self.assertIsNone(line)
        self.assertEqual(warnings, [])


class CheckActiveProjectTest(unittest.TestCase):
    """`check_active_project` — return one-line project status or None."""

    def test_returns_none_when_no_active_project(self) -> None:
        with mock.patch(
            "core.startup.get_active_name", return_value=None,
        ):
            line = startup_init.check_active_project()
        self.assertIsNone(line)

    def test_returns_status_line_for_active_project(self) -> None:
        """Active project name + target render into the banner line."""
        with TemporaryDirectory() as d:
            projects_dir = Path(d)
            name = "myproj"
            target = "/some/target/path"
            (projects_dir / f"{name}.json").write_text(
                '{"version": 1, "name": "myproj", "target": "/some/target/path"}'
            )
            with mock.patch("core.startup.get_active_name", return_value=name), \
                 mock.patch("core.startup.PROJECTS_DIR", projects_dir):
                line = startup_init.check_active_project()
            self.assertIsNotNone(line)
            self.assertIn(name, line)
            self.assertIn(target, line)
            self.assertIn("/project none", line)

    def test_returns_none_on_missing_project_json(self) -> None:
        """Active name but no on-disk project.json → None (not crash)."""
        with TemporaryDirectory() as d:
            projects_dir = Path(d)
            with mock.patch("core.startup.get_active_name", return_value="ghost"), \
                 mock.patch("core.startup.PROJECTS_DIR", projects_dir):
                line = startup_init.check_active_project()
        self.assertIsNone(line)

    def test_returns_none_on_exception(self) -> None:
        """check_active_project must swallow probe failures and return None."""
        with mock.patch(
            "core.startup.get_active_name",
            side_effect=RuntimeError("registry lookup blew up"),
        ):
            line = startup_init.check_active_project()
        self.assertIsNone(line)

    def test_project_line_escapes_control_bytes(self) -> None:
        """The target field is deliberately charset-unrestricted
        (paths may carry odd bytes), so the READ side owns escaping:
        a registry target with ESC/OSC/BEL/bidi bytes must render
        inert on the banner line — which reaches the operator's
        terminal at every session start and is reprinted verbatim
        from .startup-output."""
        import json
        with TemporaryDirectory() as d:
            projects_dir = Path(d)
            name = "demo-proj"
            hostile_target = "/srv/repo\x1b]0;pwned\x07\x1b[2J‮-clone"
            (projects_dir / f"{name}.json").write_text(json.dumps(
                {"version": 1, "name": name, "target": hostile_target}
            ))
            with mock.patch("core.startup.get_active_name",
                            return_value=name), \
                 mock.patch("core.startup.PROJECTS_DIR", projects_dir):
                line = startup_init.check_active_project()
            self.assertIsNotNone(line)
            for raw in ("\x1b", "\x07", "‮"):
                self.assertNotIn(raw, line)
            self.assertIn("pwned", line)  # content survives, escaped
            self.assertIn("/srv/repo", line)

    def test_seeded_by_auto_returns_auto_detected_line(self) -> None:
        """The auto-detect variant comes from the session entry's
        seeded_by field (the retired machine-global `.auto` marker
        raced concurrent launches — one clearing another's — and could
        mislabel a later explicit activation)."""
        import os
        from core.project import sessions
        with TemporaryDirectory() as d:
            projects_dir = Path(d) / "projects"
            projects_dir.mkdir()
            sessions_dir = Path(d) / "sessions.d"
            name = "myproj"
            (projects_dir / f"{name}.json").write_text(
                '{"version": 1, "name": "myproj", "target": "/t"}'
            )
            with mock.patch("core.startup.get_active_name", return_value=name), \
                 mock.patch("core.startup.PROJECTS_DIR", projects_dir), \
                 mock.patch.object(sessions, "SESSIONS_DIR", sessions_dir), \
                 mock.patch.object(sessions, "resolve_session_pid",
                                   return_value=os.getpid()), \
                 mock.patch.object(sessions, "_comm",
                                   lambda pid: "claude"):
                sessions.record_session(name, pid=os.getpid(),
                                        seeded_by="auto")
                line = startup_init.check_active_project()
            self.assertIsNotNone(line)
            self.assertIn("Auto-detected", line)
            self.assertIn(name, line)

    def test_binding_differs_from_bookmark_names_both_layers(self) -> None:
        """An auto-detect launch leaves binding != bookmark at t=0 —
        the banner names both, so the operator sees the divergence."""
        import os
        from core.project import sessions
        with TemporaryDirectory() as d:
            projects_dir = Path(d) / "projects"
            projects_dir.mkdir()
            sessions_dir = Path(d) / "sessions.d"
            name = "myproj"
            (projects_dir / f"{name}.json").write_text(
                '{"version": 1, "name": "myproj", "target": "/t"}'
            )
            (projects_dir / "other.json").write_text(
                '{"version": 1, "name": "other", "target": "/o"}'
            )
            (projects_dir / ".active").symlink_to("other.json")
            with mock.patch("core.startup.get_active_name", return_value=name), \
                 mock.patch("core.startup.PROJECTS_DIR", projects_dir), \
                 mock.patch.object(sessions, "SESSIONS_DIR", sessions_dir), \
                 mock.patch.object(sessions, "resolve_session_pid",
                                   return_value=os.getpid()), \
                 mock.patch.object(sessions, "_comm",
                                   lambda pid: "claude"):
                sessions.record_session(name, pid=os.getpid(),
                                        seeded_by="auto")
                line = startup_init.check_active_project()
            self.assertIsNotNone(line)
            self.assertIn("(default: other)", line)

    def test_stale_auto_marker_is_ignored(self) -> None:
        """A leftover `.auto` file from a pre-series launcher must not
        produce the auto variant — the marker is retired."""
        with TemporaryDirectory() as d:
            projects_dir = Path(d)
            name = "myproj"
            (projects_dir / f"{name}.json").write_text(
                '{"version": 1, "name": "myproj", "target": "/t"}'
            )
            (projects_dir / ".auto").write_text(f"{name}\n")
            with mock.patch("core.startup.get_active_name", return_value=name), \
                 mock.patch("core.startup.PROJECTS_DIR", projects_dir):
                line = startup_init.check_active_project()
            self.assertIsNotNone(line)
            self.assertNotIn("Auto", line)
            self.assertTrue(line.startswith("Project: "))


if __name__ == "__main__":
    unittest.main()
