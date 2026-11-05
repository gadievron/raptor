"""Shared fixtures for packages.semgrep tests."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path,
                   monkeypatch: pytest.MonkeyPatch) -> None:
    """Bare runs of this package write into the developer's real home.

    The live scope tests run real semgrep (``unsandboxed=True``),
    which unconditionally appends to ``~/.semgrep/semgrep.log`` and
    reads/writes ``~/.semgrep/settings.yml`` — keyed off HOME
    directly. The sandboxed-runner tests additionally cache
    calibration profiles under ``~/.cache/raptor/sandbox-profiles/``
    (``core.sandbox.calibrate``, ``Path.home()``-keyed). Point HOME
    at a per-test tmp dir so bare runs never touch real user state.
    """
    monkeypatch.setenv("HOME", str(tmp_path / "home"))


@pytest.fixture(autouse=True)
def _isolated_scope_probe_cache(monkeypatch):
    """Preserve caller probe results, coordination and warning state."""
    from packages.semgrep import runner
    from core.testing.module_state import isolated_module_state

    lock = runner._SCOPE_PROBE_LOCK
    with isolated_module_state(runner, {
        "_SCOPE_PROBE_LOCK": lock,
        "_SCOPE_PROBE_CACHE": None,
        "_SCOPE_PROBE_PENDING": None,
        "_scope_upgrade_warned": False,
    }, lock=lock):
        try:
            yield
        finally:
            # Body patches must unwind before borrowed bindings return.
            monkeypatch.undo()


@pytest.fixture
def semgrep_scratch(tmp_path, monkeypatch):
    """Own scanner scratch trees and registration hooks without a ticker."""
    from contextlib import ExitStack
    from types import ModuleType

    from core.atomic_fs import rmtree_hardened
    from core.run import scratch
    from core.testing.module_state import isolated_module_state
    from packages.semgrep import runner

    scratch_view = ModuleType(scratch.__name__)
    scratch_view.__dict__.update(vars(scratch))
    scratch_view._keepalive_paths = set()
    scratch_view.keepalive_register = lambda path: scratch_view._keepalive_paths.add(str(path))
    scratch_view.keepalive_unregister = lambda path: scratch_view._keepalive_paths.discard(str(path))
    temporary = ModuleType(runner.tempfile.__name__)
    temporary.__dict__.update(vars(runner.tempfile))
    original_mkdtemp = temporary.mkdtemp
    owned = set()
    inherited = set(tmp_path.glob("semgrep-sbx-*"))

    def mkdtemp(prefix="", dir=None, **kwargs):
        path = original_mkdtemp(prefix=prefix, dir=tmp_path if dir is None else dir, **kwargs)
        owned.add(Path(path))
        return path

    def remove(path):
        assert rmtree_hardened(path), f"scanner scratch cleanup failed: {path}"

    temporary.mkdtemp = mkdtemp
    lock = runner._SCRATCH_LOCK
    with isolated_module_state(runner, {
        "_SCRATCH_LOCK": lock,
        "_scratch_parent": None,
        "_scratch_owner_pid": None,
        "tempfile": temporary,
        "keepalive_register": scratch_view.keepalive_register,
        "keepalive_unregister": scratch_view.keepalive_unregister,
    }, lock=lock):
        try:
            yield scratch_view
        finally:
            try:
                # Restore body fault injections while our private hooks still exist.
                monkeypatch.undo()
                runner._reset_sandbox_scratch()
            finally:
                # Also cover a failed reset and descendants allocated after fork.
                owned.update(set(tmp_path.glob("semgrep-sbx-*")) - inherited)
                try:
                    with ExitStack() as cleanup:
                        for path in sorted(owned, key=lambda p: len(p.parts)):
                            cleanup.callback(remove, path)
                finally:
                    scratch_view._keepalive_paths.clear()
