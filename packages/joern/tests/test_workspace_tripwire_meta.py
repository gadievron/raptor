"""Meta-tests pinning the repo-root workspace tripwire's behavior.

The tripwire (``_no_repo_root_workspace_debris`` in this package's
conftest) fires only at session teardown and only on a dirtied repo
root, so nothing in the joern suites exercises it on a healthy tree —
a gutted tripwire would survive the whole battery silently. These
tests run a nested pytest session (pytester) whose conftest re-exports
the REAL fixture object loaded from the REAL conftest file — never a
copy — with its ``_repo_root`` seam retargeted at a scratch root, and
pin both directions:

* firing: a nested suite that drops ``workspace/`` at the (fake) repo
  root fails its session with the tripwire's message, and the tripwire
  does NOT delete the debris (report-only contract — the evidence must
  survive for forensics);
* exemption: a ``workspace/`` that predates the session is left alone
  and unblamed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest_plugins = "pytester"

_REAL_CONFTEST = Path(__file__).resolve().with_name("conftest.py")
_REPO_ROOT = Path(__file__).resolve().parents[3]


def _install_real_tripwire(pytester: pytest.Pytester, fake_root: Path) -> None:
    """Give the nested session a conftest that loads the REAL joern
    tests conftest module and re-exports ONLY the tripwire fixture,
    with its root seam retargeted at *fake_root*. Gutting the real
    fixture therefore turns these meta-tests red."""
    pytester.makeconftest(
        f"""
import importlib.util
import pathlib
import sys

# pytester chdirs away from the repo, so anchor imports explicitly
# (test-side setup; runtime code never touches sys.path like this).
sys.path.insert(0, {str(_REPO_ROOT)!r})

_spec = importlib.util.spec_from_file_location(
    "_real_joern_tests_conftest", {str(_REAL_CONFTEST)!r})
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
_mod._repo_root = lambda: pathlib.Path({str(fake_root)!r})

# Re-export ONLY the tripwire: the real conftest's other autouse
# fixtures are irrelevant to the nested session.
_no_repo_root_workspace_debris = _mod._no_repo_root_workspace_debris
"""
    )


class TestTripwireFires:
    def test_debris_dropping_suite_fails_and_debris_survives(
        self, pytester: pytest.Pytester,
    ) -> None:
        fake_root = pytester.mkdir("fake-repo-root")
        _install_real_tripwire(pytester, fake_root)
        pytester.makepyfile(
            f"""
import os

def test_drops_debris():
    os.makedirs(os.path.join({str(fake_root)!r}, "workspace", "cpg.bin"))
"""
        )
        result = pytester.runpytest_inprocess()
        assert result.ret != 0
        result.stdout.fnmatch_lines(
            ["*left workspace/ debris at the repo root*"],
        )
        # Report-only contract: the tripwire never deletes the debris —
        # the evidence must survive for forensics.
        assert (fake_root / "workspace" / "cpg.bin").is_dir()


class TestTripwireExemption:
    def test_preexisting_workspace_is_not_blamed(
        self, pytester: pytest.Pytester,
    ) -> None:
        fake_root = pytester.mkdir("fake-repo-root")
        (fake_root / "workspace").mkdir()
        _install_real_tripwire(pytester, fake_root)
        pytester.makepyfile("def test_clean(): pass\n")
        result = pytester.runpytest_inprocess()
        result.assert_outcomes(passed=1)
        assert result.ret == 0
        # ... and the pre-existing dir is left alone.
        assert (fake_root / "workspace").is_dir()
