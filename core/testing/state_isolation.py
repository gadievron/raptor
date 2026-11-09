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
    def _user_state_in_tmp(tmp_path):
        with pytest.MonkeyPatch.context() as patch:
            pin_user_state_dirs(patch, tmp_path)
            yield

    @pytest.fixture
    def monkeypatch(_user_state_in_tmp):
        with pytest.MonkeyPatch.context() as patch:
            yield patch

The registry owner must outlive the test body's monkeypatch stack:
``monkeypatch.undo()`` must not expose the caller's registry, and body
patches must unwind before the caller's bindings are restored.
Autouse fixtures wrap ``unittest.TestCase`` methods too, so this pattern
also protects unittest-style files. The root conftest's own
redirect (when present) simply layers underneath — both point into
scratch, the innermost wins.
"""

from __future__ import annotations

import os
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
    # Entry-point imports can refresh authorization and cache its scratch path.
    # Register borrowed values before those producers run; do not clear a
    # valid caller context or weaken restoration/refusal behaviour.
    from core.security import env_sanitisation, launch_scratch

    for module, name in (
        (launch_scratch, "_restored"),
        (launch_scratch, "_metadata_path"),
        (env_sanitisation, "_subprocess_tmpdir"),
    ):
        monkeypatch.setattr(module, name, getattr(module, name))
    authorization = "_RAPTOR_SCRATCH_AUTH"
    if authorization in os.environ:
        monkeypatch.setenv(authorization, os.environ[authorization])
    else:
        monkeypatch.setenv(authorization, "")
        monkeypatch.delenv(authorization)
    registry = base / "projects"

    # These public names are resolved lazily by module __getattr__. Pin their
    # dictionaries so undo removes a previously missing override rather than
    # freezing the path returned by that dynamic getter.

    import core.startup as startup
    from core.project import project, registry_home, sessions

    monkeypatch.setitem(vars(project), "PROJECTS_DIR", registry)
    monkeypatch.setitem(vars(startup), "PROJECTS_DIR", registry)
    monkeypatch.setitem(vars(startup), "ACTIVE_LINK", registry / ".active")
    monkeypatch.setitem(vars(sessions), "SESSIONS_DIR", base / "sessions.d")
    # Same base through the resolution seam's env override: the
    # module-attribute pins above cover in-process consumers, the env
    # covers everything that resolves through
    # ``core.project.registry_home`` afresh — child processes (bash
    # hooks, libexec helpers) and any consumer module reloaded or
    # imported after the pins. The seam's layout (``<base>/projects``,
    # ``<base>/sessions.d``, ``.active`` inside the projects dir)
    # matches the attribute pins by construction.
    monkeypatch.setenv(registry_home.ENV_REGISTRY_HOME, str(base))
    monkeypatch.setattr(sessions, "_walk_session_pid", lambda: None)
    # Register absence too: entry points can write credentials directly.
    for name in (sessions.ENV_SESSION_PID, sessions.ENV_SESSION_TOKEN):
        monkeypatch.setenv(name, "")
        monkeypatch.delenv(name)
