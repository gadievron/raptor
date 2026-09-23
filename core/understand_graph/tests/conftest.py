"""Suite-wide hermeticity for the understand-graph tests.

``graph_path_for_run`` consults the REAL ProjectManager registry and
active-project state, and the journal MAC key lives under the real
XDG data dir. A dev machine with a registered project whose
output_dir is an ancestor of pytest tmp dirs would cross-contaminate
a real project graph (run-state-in-scratch class), and MAC tests
would mint against the operator's key. Pin every ambient state root
to the test's own tmp dir.
"""

import pytest


@pytest.fixture(autouse=True)
def _hermetic_ambient_state(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))

    import core.project.project as project_mod
    import core.project.sessions as sessions_mod

    # Module-level constants are bound at import time; env alone is
    # not enough once the modules are loaded.
    monkeypatch.setattr(
        project_mod, "PROJECTS_DIR", tmp_path / "projects-registry")
    monkeypatch.setattr(
        sessions_mod, "SESSIONS_DIR", tmp_path / "sessions.d")
