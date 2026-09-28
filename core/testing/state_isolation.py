"""In-file user-state pin for tests that reach the run lifecycle.

The root ``conftest.py`` redirects the projects registry
(``core.project.project.PROJECTS_DIR`` plus the ``core.startup``
import-time copies) and the sessions registry
(``core.project.sessions.SESSIONS_DIR`` with its session-pid
resolution) into per-test scratch. Release archives ship without any
``conftest.py`` (``export-ignore``), so for a test file executed from
an extracted tree that layer does not exist: a test that calls
``start_run`` (or constructs a default :class:`ProjectManager`)
resolves the REAL ``~/.raptor/projects`` and
``~/.local/share/raptor/sessions.d``. Under a live launcher session
the run-ledger writer then appends the test's foreign ``started`` /
``completed`` / ``pin`` records to that session's real ledger —
state that attribution, sibling discovery, and the pin-witness
verifiers consume.

Test files whose tests reach that machinery therefore carry the pin
IN-FILE, via one thin autouse fixture::

    from core.testing.state_isolation import pin_user_state_dirs

    @pytest.fixture(autouse=True)
    def _user_state_in_tmp(tmp_path, monkeypatch):
        pin_user_state_dirs(monkeypatch, tmp_path)

Autouse fixtures wrap ``unittest.TestCase`` methods too, so the same
three lines protect unittest-style files. The root conftest's own
redirect (when present) simply layers underneath — both point into
scratch, the innermost wins.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover — typing only
    import pytest


def pin_user_state_dirs(monkeypatch: "pytest.MonkeyPatch",
                        base: Path) -> None:
    """Point every user-level registry a run start resolves at *base*.

    Mirrors the root conftest's ``_sessions_registry_in_tmp`` /
    ``_projects_registry_in_tmp`` redirect surface: the projects
    registry (manager path AND the ``core.startup`` light-reader
    copies), the sessions registry, and session-pid resolution (env
    credential vars deleted, ancestor walk pinned to ``None`` — a
    claude-shaped ancestor of the test process must never be adopted
    as the owning session).
    """
    base = Path(base)
    # Hard-stop: the pin target must be scratch, never the real home
    # or a directory covering the real user-state roots (pinning at
    # such a base would re-route "isolated" writes straight back to
    # the state this exists to protect). A real raise, not an assert:
    # this is a guard, and asserts strip under ``python -O``. A base
    # merely BENEATH the home (e.g. a TMPDIR under the home) is fine
    # — only a base that CONTAINS a protected root is refused.
    home = Path.home()
    for root in (home, home / ".raptor",
                 home / ".local" / "share" / "raptor"):
        if root == base or root.is_relative_to(base):
            raise ValueError(
                f"refusing pin base {base}: it covers real user "
                f"state at {root}")
    registry = base / "projects"

    import core.startup as startup
    from core.project import project, sessions

    monkeypatch.setattr(project, "PROJECTS_DIR", registry)
    monkeypatch.setattr(startup, "PROJECTS_DIR", registry)
    monkeypatch.setattr(startup, "ACTIVE_LINK", registry / ".active")
    monkeypatch.setattr(sessions, "SESSIONS_DIR", base / "sessions.d")
    monkeypatch.setattr(sessions, "_walk_session_pid", lambda: None)
    monkeypatch.delenv(sessions.ENV_SESSION_PID, raising=False)
    monkeypatch.delenv(sessions.ENV_SESSION_TOKEN, raising=False)
