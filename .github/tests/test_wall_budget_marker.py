"""Pin the root conftest's @pytest.mark.wall_budget override.

The default-tier slow-test guard (root conftest.py, active when
RAPTOR_MAX_TEST_SECONDS is set) supports a raise-only per-test wall
budget for deliberate default-tier sentinels. These pins run REAL
nested pytest sessions — the guard verdicts are session-level
(exit status + terminal section), so an in-process unit of the hook
functions could pass while the wired-up guard does nothing. Each
nested session loads the repo root conftest explicitly via
``-p conftest`` (cwd = repo root puts it on sys.path) with its own
rootdir in tmp, so the outer session's config never bleeds in.

Pinned properties:
  * an unmarked test over the global budget flags (the guard is live
    in the harness — the other arms cannot be vacuously green);
  * a marker BELOW the global budget does not lower it (raise-only);
  * a marked test over its own raised budget still flags (the marker
    widens the net, never disables it);
  * a marker above the observed cost lifts the test out of both the
    failure and the half-budget warn band (the override takes effect),
    even when the test itself writes a colliding entry under the
    stamp's own key via ``record_property`` — the collision can
    neither disable the guard nor suppress the genuine stamp;
  * setup overruns count, while teardown overruns do not;
  * a real measured sleep still trips the unmarked guard;
  * a malformed marker fails collection loudly.

Threshold cases supply exact phase durations through pytest's report hook;
the real-sleep sentinel independently checks elapsed-time wiring. All cases
still use the root hooks, real test reports and session exit handling.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

# Keep the explicitly loaded child plugin visible to CI dependency routing.
import core.testing.llm_tripwire  # noqa: F401

REPO_ROOT = Path(__file__).resolve().parents[2]

NESTED_INI = """\
[pytest]
markers =
    wall_budget(seconds): raise-only per-test wall-budget override
"""


def _run_nested(
    tmp_path: Path, budget: str, test_source: str,
    phase_durations: dict[tuple[str, str], float] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run one nested pytest session over ``test_source`` with the
    root conftest loaded and RAPTOR_MAX_TEST_SECONDS=``budget``."""
    (tmp_path / "pytest.ini").write_text(NESTED_INI, encoding="utf-8")
    test_file = tmp_path / "test_nested.py"
    test_file.write_text(test_source, encoding="utf-8")
    if phase_durations:
        # Exercise the real report/stamp/logreport/session-exit pipeline at
        # precise thresholds without waiting for those durations to elapse.
        # Unlisted phases retain pytest's measured wall time.
        (tmp_path / "conftest.py").write_text(
            "import pytest\n"
            f"DURATIONS = {phase_durations!r}\n"
            "@pytest.hookimpl(wrapper=True)\n"
            "def pytest_runtest_makereport(item, call):\n"
            "    report = yield\n"
            "    key = (item.name, report.when)\n"
            "    if key in DURATIONS:\n"
            "        report.duration = DURATIONS[key]\n"
            "    return report\n",
            encoding="utf-8",
        )
    home = tmp_path / "home"
    home.mkdir()
    env = dict(
        os.environ,
        HOME=str(home), TMPDIR=str(tmp_path),
        XDG_CONFIG_HOME=str(home / "config"),
        XDG_CACHE_HOME=str(home / "cache"),
        XDG_DATA_HOME=str(home / "data"),
        RAPTOR_REGISTRY_HOME=str(tmp_path / "registry"),
        RAPTOR_OUT_DIR=str(tmp_path / "out"),
    )
    env["RAPTOR_MAX_TEST_SECONDS"] = budget
    # These sessions exercise root hooks, not installed third-party plugins.
    # Load the LLM guard explicitly rather than inheriting arbitrary plugins.
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    # The outer tier's knobs must not steer the nested session: its
    # addopts (faulthandler timeout), session budget, shuffle seed,
    # and the egress-guard dir handoff all belong to THIS session.
    # PYTEST_XDIST_WORKER is inheritable and stale in a subprocess
    # (the root conftest decides worker-ness from workerinput, but
    # other plugins may key on the env var).
    for key in (
        "PYTEST_ADDOPTS",
        "PYTEST_PLUGINS",
        "RAPTOR_MAX_SESSION_SECONDS",
        "RAPTOR_RANDOMISE_TESTS",
        "RAPTOR_EGRESS_LEAK_DIR",
        "PYTEST_XDIST_WORKER",
    ):
        env.pop(key, None)
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-p",
            "conftest",
            "-p",
            "core.testing.llm_tripwire",
            "-p",
            "no:cacheprovider",
            str(test_file),
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def _flagged_nodeids(stdout: str) -> set[str]:
    """Nodeids listed in the guard's FAILED section (only — the warn
    band and the --durations table list nodeids in the same line
    shape, so a whole-output substring check would be ambiguous)."""
    flagged: set[str] = set()
    in_section = False
    for line in stdout.splitlines():
        if "slow-test guard FAILED" in line:
            in_section = True
            continue
        if not in_section:
            continue
        if line.startswith("="):
            break
        match = re.match(r"\s+[\d.]+s\s+(?:setup|call)\s+(\S+)", line)
        if match:
            flagged.add(match.group(1))
    return flagged


# Keep headroom for nested interpreter/plugin startup on loaded runners.
# Threshold cases use report durations; one real sleep below also pins the
# elapsed-time wiring independently of the report-duration fixture.
@pytest.mark.wall_budget(30.0)
class TestWallBudgetMarker:
    def test_guard_semantics_raise_only(self, tmp_path: Path) -> None:
        """One nested session, global budget 0.6 s:
        unmarked-over flags, marked-below-global stays governed by
        the global (raise-only), marked-over-own-budget still flags.
        """
        proc = _run_nested(
            tmp_path,
            "0.6",
            (
                "import time\n"
                "import pytest\n"
                "\n"
                "\n"
                "def test_unmarked_over_budget():\n"
                "    pass\n"
                "\n"
                "\n"
                "@pytest.mark.wall_budget(0.15)\n"
                "def test_marker_never_lowers():\n"
                "    pass\n"
                "\n"
                "\n"
                "@pytest.mark.wall_budget(0.9)\n"
                "def test_marked_over_own_budget():\n"
                "    pass\n"
                "\n"
                "def test_real_elapsed_time():\n"
                "    time.sleep(0.8)\n"
                "\n"
                "def test_setup_counts():\n"
                "    pass\n"
                "\n"
                "def test_teardown_is_excluded():\n"
                "    pass\n"
            ),
            phase_durations={
                ("test_unmarked_over_budget", "call"): 1.2,
                ("test_marker_never_lowers", "call"): 0.35,
                ("test_marked_over_own_budget", "call"): 1.5,
                ("test_setup_counts", "setup"): 1.2,
                ("test_teardown_is_excluded", "teardown"): 1.2,
            },
        )
        assert "6 passed" in proc.stdout, proc.stdout
        assert proc.returncode == 1, (proc.stdout, proc.stderr)
        flagged = _flagged_nodeids(proc.stdout)
        assert flagged == {
            "test_nested.py::test_unmarked_over_budget",
            "test_nested.py::test_marked_over_own_budget",
            "test_nested.py::test_real_elapsed_time",
            "test_nested.py::test_setup_counts",
        }, proc.stdout

    def test_marker_raises_budget(self, tmp_path: Path) -> None:
        """A test over the global budget but marked well above its
        cost passes the session — and sits under the raised warn
        band, so the guard stays silent about it entirely. The test
        also writes a colliding inf entry under the stamp's own key
        via ``record_property`` (which lands in the call report's
        ``user_properties`` copy BEFORE the stamp): the collision
        must neither disable the guard nor suppress the genuine
        stamp — the hook appends unconditionally and the reader
        filters to finite positives, taking the max of every valid
        entry."""
        proc = _run_nested(
            tmp_path,
            "0.6",
            (
                "import pytest\n"
                "\n"
                "\n"
                "@pytest.mark.wall_budget(30.0)\n"
                "def test_marked_over_global_only(record_property):\n"
                "    record_property('raptor-wall-budget', float('inf'))\n"
            ),
            phase_durations={
                ("test_marked_over_global_only", "call"): 1.0,
            },
        )
        assert "1 passed" in proc.stdout, proc.stdout
        assert proc.returncode == 0, (proc.stdout, proc.stderr)
        assert "slow-test guard" not in proc.stdout, proc.stdout

    def test_malformed_marker_fails_collection(
        self, tmp_path: Path
    ) -> None:
        """A wall_budget marker without its seconds argument aborts
        the session loudly instead of silently doing nothing."""
        proc = _run_nested(
            tmp_path,
            "0.6",
            (
                "import pytest\n"
                "\n"
                "\n"
                "@pytest.mark.wall_budget\n"
                "def test_marker_missing_argument():\n"
                "    pass\n"
            ),
        )
        assert proc.returncode != 0, proc.stdout
        combined = proc.stdout + proc.stderr
        assert (
            "@pytest.mark.wall_budget takes exactly one positional"
            in combined
        ), combined
