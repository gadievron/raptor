"""Bridge to the repo root conftest.

This directory ships its own ``pytest.ini`` (marker registration), so
pytest resolves rootdir HERE for any invocation targeting the kit —
whether run from inside this directory or by path from the repository
root — and the upward conftest scan therefore never reaches the repo
root ``conftest.py``. That left this suite outside the session
containment every other suite gets: git hermeticity env pins, the
ambient-config drift guard, and tmp containment.

Close the gap by loading the root conftest as a plugin at configure
time. Everything it does at import time (env pinning, sys.path setup)
runs, and registering the module hands its fixtures and session hooks
to this session as well.

The root conftest is located by a bounded upward WALK with an identity
check, never by fixed-depth indexing: the first ancestor that carries
a ``conftest.py`` must also carry a sibling ``raptor.py`` and a
content marker in the conftest, or the bridge refuses — executing a
FOREIGN conftest that pytest's own confcutdir rules would never have
loaded is worse than running uncontained. A standalone kit copy (no
matching ancestor, or a copy shallower than the in-repo depth) runs
self-contained, exactly as before.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_PLUGIN_NAME = "raptor-root-conftest"
#: Upward-walk bound. The in-repo depth is 4 (kit → oss-forensics →
#: skills → .claude → repo root); the slack tolerates the kit being
#: nested deeper without scanning the whole filesystem.
_MAX_WALK = 12
#: Identity marker the repo root conftest must contain (its git
#: hermeticity wiring) — a same-named sibling arrangement without it
#: is not the RAPTOR root.
_ROOT_MARKER = "git_hermeticity"
#: Bounded read for the marker probe.
_MARKER_READ_LIMIT = 1 << 20


def _find_repo_root(start: Path) -> Path | None:
    """Walk up from *start* to the first ancestor holding a
    ``conftest.py``; return it only when it passes the identity check
    (sibling ``raptor.py`` + content marker), else ``None``.

    Stopping at the FIRST conftest.py mirrors pytest's confcutdir
    spirit: the bridge never reaches past an intermediate project
    boundary to execute something above it. Never raises: shallow
    paths terminate at the filesystem root, unreadable candidates
    refuse.
    """
    current = start
    for _ in range(_MAX_WALK):
        conftest = current / "conftest.py"
        if conftest.is_file():
            if not (current / "raptor.py").is_file():
                return None
            try:
                text = conftest.read_text(
                    encoding="utf-8", errors="replace")[:_MARKER_READ_LIMIT]
            except OSError:
                return None
            return current if _ROOT_MARKER in text else None
        parent = current.parent
        if parent == current:
            return None  # filesystem root — standalone copy
        current = parent
    return None


def _root_conftest_already_loaded(config: pytest.Config,
                                  root_conftest: Path) -> bool:
    """True when pytest itself loaded the root conftest (an invocation
    whose args span the repo root, making IT the rootdir) — loading it
    twice would double-register session hooks and fixtures."""
    for plugin in config.pluginmanager.get_plugins():
        if getattr(plugin, "__file__", None) == str(root_conftest):
            return True
    return config.pluginmanager.has_plugin(_PLUGIN_NAME)


def pytest_configure(config: pytest.Config) -> None:
    root = _find_repo_root(Path(__file__).resolve().parent.parent)
    if root is None:
        return  # standalone kit copy — run self-contained
    root_conftest = root / "conftest.py"
    if _root_conftest_already_loaded(config, root_conftest):
        return
    spec = importlib.util.spec_from_file_location(
        "_raptor_root_conftest", root_conftest)
    if spec is None or spec.loader is None:
        return
    module = importlib.util.module_from_spec(spec)
    sys.modules["_raptor_root_conftest"] = module
    spec.loader.exec_module(module)
    config.pluginmanager.register(module, _PLUGIN_NAME)
