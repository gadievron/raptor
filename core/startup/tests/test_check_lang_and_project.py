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
    """`check_lang` — tree-sitter probe; returns formatted line or None."""

    def test_returns_check_mark_with_languages(self) -> None:
        with mock.patch(
            "core.inventory.extractors._get_ts_languages",
            return_value=["python", "javascript", "go"],
        ):
            line = startup_init.check_lang()
        self.assertIsNotNone(line)
        # Documented format: "  lang: tree-sitter ✓ (lang1, lang2, ...)"
        self.assertIn("tree-sitter", line)
        self.assertIn("✓", line)
        self.assertIn("python", line)
        self.assertIn("javascript", line)

    def test_returns_cross_mark_when_no_languages(self) -> None:
        with mock.patch(
            "core.inventory.extractors._get_ts_languages",
            return_value=[],
        ):
            line = startup_init.check_lang()
        self.assertIsNotNone(line)
        self.assertIn("tree-sitter", line)
        self.assertIn("✗", line)

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
            line = startup_init.check_lang()
        self.assertIsNone(line)


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

    def test_auto_marker_matching_name_returns_auto_activated_line(self) -> None:
        """When `.auto` contains the active project name, the banner
        shows the `Auto-activated project: ...` variant rather than
        the plain `Project: ...` variant.

        Also a regression guard for the bounded-read at init.py:461-478:
        the function uses a capped `.read(cap)` and decodes/strips ─
        an oversized hostile `.auto` (symlink to `/dev/zero`, sparse
        file) MUST NOT OOM the banner. Here we exercise the matching-
        prefix case directly; the comment at the code site documents
        the OOM motivation that the read-cap defends against.
        """
        with TemporaryDirectory() as d:
            projects_dir = Path(d)
            name = "myproj"
            (projects_dir / f"{name}.json").write_text(
                '{"version": 1, "name": "myproj", "target": "/t"}'
            )
            # `.auto` content matches name (with trailing whitespace
            # that the .strip() in init.py:475 must tolerate).
            (projects_dir / ".auto").write_text(f"{name}\n")
            with mock.patch("core.startup.get_active_name", return_value=name), \
                 mock.patch("core.startup.PROJECTS_DIR", projects_dir):
                line = startup_init.check_active_project()
            self.assertIsNotNone(line)
            self.assertIn("Auto-activated", line)
            self.assertIn(name, line)

    def test_auto_marker_oversize_does_not_match_returns_plain_project(self) -> None:
        """If `.auto` is larger than the bounded-read cap, the strip
        comparison cannot equal `name` and the function falls through
        to the plain `Project: ...` line — never raises.
        """
        with TemporaryDirectory() as d:
            projects_dir = Path(d)
            name = "myproj"
            (projects_dir / f"{name}.json").write_text(
                '{"version": 1, "name": "myproj", "target": "/t"}'
            )
            # `.auto` head looks like the name then has padding that
            # makes the stripped comparison miss. Cap in code is
            # `max(len(name) + 64, 256)`. 4 KiB of trailing bytes
            # ensures the strip comparison fails.
            (projects_dir / ".auto").write_bytes(
                name.encode() + b"\nUNRELATED_TRAILING_BYTES" + b"X" * 4096
            )
            with mock.patch("core.startup.get_active_name", return_value=name), \
                 mock.patch("core.startup.PROJECTS_DIR", projects_dir):
                line = startup_init.check_active_project()
            self.assertIsNotNone(line)
            # Plain Project: line (NOT Auto-activated)
            self.assertNotIn("Auto-activated", line)
            self.assertTrue(line.startswith("Project: "))


if __name__ == "__main__":
    unittest.main()
