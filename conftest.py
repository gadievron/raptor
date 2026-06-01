"""Root-level pytest config.

libexec/ scripts now refuse to run without one of CLAUDECODE,
_RAPTOR_TRUSTED, or RAPTOR_DIR set in the environment (see the
trust-marker block at the top of each script). Several test suites
subprocess-invoke libexec scripts and inherit env from this test
runner — set the marker once here so every test is treated as a
trusted caller by default.

Tests that exercise the refusal path explicitly pop the marker from
the subprocess env when they spawn the wrapper.

`RAPTOR_DIR` is also set here. Modules that follow the project's
"hard lookup, no fallbacks" path-safety rule (CLAUDE.md, e.g.
packages/recon/agent.py) read `os.environ["RAPTOR_DIR"]` at
import time and KeyError if unset. CI runners and developer
shells that don't pre-export RAPTOR_DIR would otherwise fail
test collection. Set it here to the project root (the directory
this conftest.py lives in) so the import-time lookup succeeds
in every test invocation, while production code paths still
require operators to set it explicitly per the launcher rule.
"""

import os
import sys
from pathlib import Path

os.environ.setdefault("_RAPTOR_TRUSTED", "1")

# Disable reach_verdict_log atexit flush during tests so the synthetic
# inventories that test suites build don't pollute the operator-facing
# sidecar (the cross-project verdict-frequency log is supposed to
# reflect real operator runs, not the test corpus). Tests that
# exercise the log directly opt back in via ``RAPTOR_REACH_VERDICT_LOG``
# pointing at a tmp file (see core/inventory/tests/test_reach_verdict_log.py).
os.environ.setdefault("RAPTOR_REACH_VERDICT_LOG_DISABLED", "1")

# Force RAPTOR_DIR to point at THIS worktree, not whatever the
# developer's login shell exports. ``setdefault`` is a no-op when the
# env var is already set, so a developer with multiple checkouts who
# exports ``RAPTOR_DIR=/home/me/other-raptor`` in their profile would
# silently run the test SUBPROCESS bootstrap (e.g.
# core/sandbox/tests/test_fork_safe_warn*.py) against the wrong tree
# — failing with "No module named core.sandbox._fork_safe_warn" when
# the module is new on this branch but missing from the other tree.
#
# CI environments that pre-export RAPTOR_DIR correctly are unaffected
# (the path already matches). Mismatch surfaces as a one-line warning
# on stderr so the developer notices the divergence.
_conftest_dir = str(Path(__file__).resolve().parent)
_existing = os.environ.get("RAPTOR_DIR")
if _existing and _existing != _conftest_dir:
    print(
        f"conftest: overriding RAPTOR_DIR ({_existing!r} → {_conftest_dir!r}) "
        f"to match the worktree this test run lives in",
        file=sys.stderr,
    )
os.environ["RAPTOR_DIR"] = _conftest_dir


# ---------------------------------------------------------------------------
# Default-tier slow-test guard
# ---------------------------------------------------------------------------
#
# Preventive backstop for the "a default-tier test is slow because it
# does real I/O it should mock" class — real subprocess / network /
# time.sleep / sandbox setup that turns a 30ms unit test into a 30s one.
# faulthandler_timeout (set in tests.yml) catches a *hang*; this catches
# slow-but-finishes, the day it lands, instead of in a later --durations
# sweep.
#
# Activated ONLY when RAPTOR_MAX_TEST_SECONDS is set — tests.yml sets it
# for the default-tier matrix; nightly.yml deliberately does NOT (its
# `-m "slow or integration"` tests are legitimately slow), and local
# `pytest` is unaffected. The guard FLAGS, it does not kill: every test
# still runs to completion; the session then fails at the end naming the
# offenders, so the signal is "this test got slow", not "killed mid-run".
#
# A genuinely-heavy test is not a bug — mark it @pytest.mark.slow (moves
# it to the nightly tier, out of this guard's scope).

_MAX_TEST_SECONDS = os.environ.get("RAPTOR_MAX_TEST_SECONDS")
_slow_test_threshold = float(_MAX_TEST_SECONDS) if _MAX_TEST_SECONDS else None
_slow_test_overruns: "list[tuple[str, float]]" = []


def pytest_runtest_logreport(report):
    """Record any test whose CALL phase exceeds the threshold."""
    if _slow_test_threshold is None:
        return
    if report.when == "call" and report.duration > _slow_test_threshold:
        _slow_test_overruns.append((report.nodeid, report.duration))


def pytest_sessionfinish(session, exitstatus):
    """Fail an otherwise-green session if any test overran the threshold."""
    if _slow_test_threshold is None or not _slow_test_overruns:
        return
    if session.exitstatus == 0:
        session.exitstatus = 1


def pytest_terminal_summary(terminalreporter):
    if _slow_test_threshold is None or not _slow_test_overruns:
        return
    tr = terminalreporter
    tr.section("default-tier slow-test guard FAILED", red=True, bold=True)
    tr.write_line(
        f"{len(_slow_test_overruns)} test(s) exceeded "
        f"RAPTOR_MAX_TEST_SECONDS={_slow_test_threshold}s in the default tier."
    )
    tr.write_line(
        "A default-tier test this slow is almost always real I/O that "
        "should be mocked (subprocess / network / time.sleep / sandbox "
        "setup). Fix it — or, if the cost is genuine, mark it "
        "@pytest.mark.slow so it runs in the nightly tier instead.",
    )
    for nodeid, dur in sorted(_slow_test_overruns, key=lambda x: -x[1]):
        tr.write_line(f"  {dur:7.1f}s  {nodeid}")
