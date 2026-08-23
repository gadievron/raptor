"""The repo root conftest must govern this suite despite the kit's own
pytest.ini — and the bridge that achieves it must stay safe for
standalone copies.

This directory carries a ``pytest.ini`` (marker registration), so
pytest resolves rootdir HERE for any invocation targeting the kit —
from inside the directory or by path from the repo root — and the
upward conftest scan stops before the repository root. Without the
bridge in the kit-level ``conftest.py``, none of the root conftest's
session containment (git hermeticity env pins, ambient-config drift
guard, tmp containment) applies to this suite.

The git env pins are asserted as the sentinel because they are forced
(never ``setdefault``) by the root conftest, so their presence proves
the bridge actually executed it.

The safety half: the bridge locates the root by a bounded identity-
checked walk. A kit copy at any depth with no RAPTOR root above it
must run self-contained (no crash at pytest startup), and an ancestor
carrying a FOREIGN conftest.py must be refused, never executed.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

_KIT_DIR = Path(__file__).resolve().parents[1]


def _find_raptor_root() -> Path | None:
    """Lenient upward scan (test-side skip probe only — the bridge's
    own walk is stricter and is what the safety tests exercise)."""
    current = _KIT_DIR
    for _ in range(12):
        if (current / "conftest.py").is_file() and \
                (current / "raptor.py").is_file():
            return current
        if current.parent == current:
            return None
        current = current.parent
    return None


_REPO_ROOT = _find_raptor_root()


@pytest.mark.skipif(
    _REPO_ROOT is None,
    reason="standalone kit checkout — no repo root conftest to bridge",
)
def test_root_conftest_git_hermeticity_active() -> None:
    assert os.environ.get("GIT_CONFIG_GLOBAL") == "/dev/null", (
        "repo root conftest not loaded: the kit's pytest.ini makes this "
        "directory the rootdir, so the root conftest's session "
        "containment (git hermeticity, tmp containment) must be pulled "
        "in by the kit-level conftest bridge"
    )
    assert os.environ.get("GIT_CONFIG_SYSTEM") == "/dev/null"


def _load_bridge_module():
    spec = importlib.util.spec_from_file_location(
        "_kit_conftest_under_test", _KIT_DIR / "conftest.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_walk_is_shallow_safe() -> None:
    """A kit copy so shallow the old fixed-depth indexing would have
    raised IndexError at pytest startup: the walk must terminate at the
    filesystem root and report 'standalone', never raise."""
    bridge = _load_bridge_module()
    assert bridge._find_repo_root(Path("/")) is None
    assert bridge._find_repo_root(Path("/nonexistent-shallow-dir")) is None


def test_walk_refuses_foreign_conftest(tmp_path: Path) -> None:
    """An ancestor with a conftest.py that is not the RAPTOR root
    (no sibling raptor.py, or no identity marker) must be refused —
    the bridge widens conftest execution beyond pytest's confcutdir
    rules only for the one file it can positively identify."""
    bridge = _load_bridge_module()

    # Case 1: foreign conftest, no raptor.py sibling.
    foreign = tmp_path / "foreign"
    (foreign / "a" / "b").mkdir(parents=True)
    (foreign / "conftest.py").write_text("SENTINEL = True\n")
    assert bridge._find_repo_root(foreign / "a" / "b") is None

    # Case 2: conftest + raptor.py sibling but no identity marker.
    fake = tmp_path / "fake-raptor"
    (fake / "a" / "b").mkdir(parents=True)
    (fake / "conftest.py").write_text("# not the raptor root conftest\n")
    (fake / "raptor.py").write_text("")
    assert bridge._find_repo_root(fake / "a" / "b") is None

    # Control: full identity (conftest with marker + raptor.py) matches.
    real = tmp_path / "real-raptor"
    (real / "a" / "b").mkdir(parents=True)
    (real / "conftest.py").write_text("from core.testing import "
                                      "git_hermeticity\n")
    (real / "raptor.py").write_text("")
    assert bridge._find_repo_root(real / "a" / "b") == real


def _copy_kit_skeleton(dest: Path) -> None:
    dest.mkdir(parents=True)
    shutil.copy2(_KIT_DIR / "conftest.py", dest / "conftest.py")
    shutil.copy2(_KIT_DIR / "pytest.ini", dest / "pytest.ini")
    (dest / "test_smoke.py").write_text(textwrap.dedent(
        """\
        def test_smoke():
            assert True
        """))


def _run_pytest(cwd: Path, extra_env: dict[str, str] | None = None,
                ) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.update(extra_env or {})
    return subprocess.run(
        [sys.executable, "-m", "pytest", "test_smoke.py", "-q",
         "-p", "no:cacheprovider"],
        cwd=cwd, env=env, capture_output=True, text=True, timeout=120,
    )


def test_standalone_copy_runs_self_contained(tmp_path: Path) -> None:
    """A kit copied out of the repository (no RAPTOR ancestors) must
    collect and pass without the bridge crashing pytest startup."""
    copy = tmp_path / "isolated" / "kit-copy"
    _copy_kit_skeleton(copy)
    proc = _run_pytest(copy)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_foreign_conftest_never_executed(tmp_path: Path) -> None:
    """A foreign conftest.py above a relocated kit copy must not be
    executed by the bridge (pytest's own confcutdir rules would not
    have loaded it either). The foreign conftest writes a sentinel
    file at import time — it must not exist afterwards."""
    sentinel = tmp_path / "foreign-conftest-executed"
    fakeroot = tmp_path / "fakeroot"
    copy = fakeroot / "a" / "b" / "kit-copy"
    _copy_kit_skeleton(copy)
    (fakeroot / "conftest.py").write_text(textwrap.dedent(
        f"""\
        from pathlib import Path
        Path({str(sentinel)!r}).write_text("loaded")
        """))
    # Both foreign shapes: bare, and with a marker-less raptor.py twin.
    (fakeroot / "raptor.py").write_text("")
    proc = _run_pytest(copy)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not sentinel.exists(), (
        "bridge executed a foreign conftest.py above the kit copy"
    )
