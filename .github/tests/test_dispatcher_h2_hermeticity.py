"""Lean-runner regression probe for the dispatcher suite's h2 gate.

Why this test exists
--------------------
core/llm/dispatcher/tests/ relays real requests through the
dispatcher's upstream-forwarding leg, whose httpx clients are built
with ``http2=http2_enabled()``. When HTTP/2 is opted in via
RAPTOR_HTTP2 that flag's h2 probe runs inside the relay thread on
first forward, so on a runner where the optional ``h2`` package is
unavailable every relaying test used to die with a client-side
RemoteProtocolError — 93 errors where a missing optional dependency
must produce skips. The suite's conftest now gates the marked
``upstream_forward`` tests: skip when opted in and h2 is unavailable,
run untouched otherwise.

This probe pins that gate in BOTH directions by running subprocess
pytest with h2 hidden by a meta_path blocker (raising from
``find_spec``, the shape of a broken install — strictly harsher than
plain absence):

* opted in (RAPTOR_HTTP2=1): the gated tests must SKIP, the
  h2-independent tests must still run and pass — zero failures,
  zero errors.
* no opt-in (RAPTOR_HTTP2 unset): the gate must be INERT — zero
  skips, everything passes. CI runners deliberately do not install
  h2 (requirements.txt ships the pin commented out); this leg is the
  proof the gate costs them no relay coverage.

Subset, not the whole directory: the full suite is ~2-4.5 minutes
per leg. Each leg below finishes in ~15s while still crossing every
gate seam kind — whole-module pytestmark, class decorators, and
per-test marks inside mixed classes — plus unmarked tests in the
same files, so a gate that over- or under-selects at any seam kind
turns the leg red.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]

# Runner for the subprocess leg: install the blocker BEFORE pytest
# imports anything, then hand the remaining argv to pytest verbatim.
_RUNNER = '''\
import importlib.abc
import sys


class _Blocker(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name == "h2" or name.startswith("h2."):
            raise ModuleNotFoundError("h2 hidden by hermeticity probe")
        return None


sys.meta_path.insert(0, _Blocker())

import pytest

sys.exit(pytest.main(sys.argv[1:]))
'''

_SUITE = "core/llm/dispatcher/tests"

# Every gate seam kind is represented: whole-module pytestmark
# (relay_limits, error_row_provenance), class decorators
# (child_ledger_vetoed_death, handler_hardening,
# usage_scan_integrity), and per-test marks inside mixed classes
# (body_limits,
# child_path_allowlist, upstream_state_header) — with unmarked
# neighbours in the same files proving the h2-independent tests
# keep running.
_GATED_SUBSET = (
    f"{_SUITE}/test_relay_limits.py",
    f"{_SUITE}/test_error_row_provenance.py",
    f"{_SUITE}/test_child_ledger_vetoed_death.py",
    f"{_SUITE}/test_handler_hardening.py",
    f"{_SUITE}/test_usage_scan_integrity.py",
    f"{_SUITE}/test_body_limits.py",
    f"{_SUITE}/test_child_path_allowlist.py",
    f"{_SUITE}/test_upstream_state_header.py",
)

# Inert-gate leg: small but still two seam kinds (whole-module and
# per-test marks) — enough to prove marked tests RUN when HTTP/2 is
# not opted in.
_INERT_SUBSET = (
    f"{_SUITE}/test_error_row_provenance.py",
    f"{_SUITE}/test_upstream_state_header.py",
)


class _LegResult:
    """Counts pytest reported for one subprocess leg."""

    def __init__(self, returncode: int, tests: int, failures: int,
                 errors: int, skipped: int, tail: str) -> None:
        self.returncode = returncode
        self.tests = tests
        self.failures = failures
        self.errors = errors
        self.skipped = skipped
        self.tail = tail


@pytest.mark.slow
class TestDispatcherH2Hermeticity(unittest.TestCase):

    def _run_leg(self, subset: tuple[str, ...], *,
                 http2_opt_in: bool) -> _LegResult:
        # Enumerated lacks on a lean runner: the dispatcher tests
        # need httpx (h2 itself is hidden by the blocker either way,
        # so its absence is never a lack here).
        if importlib.util.find_spec("httpx") is None:
            self.skipTest(
                "httpx not installed — the dispatcher suite this "
                "probe drives cannot import",
            )
        with tempfile.TemporaryDirectory(
            prefix="h2-hermeticity-probe-",
        ) as scratch:
            runner = Path(scratch) / "blocked_pytest.py"
            runner.write_text(_RUNNER, encoding="utf-8")
            junit = Path(scratch) / "leg.xml"
            # Inherit the ambient env (interpreter/site config), but
            # pin the single variable under test in both directions
            # and drop ambient pytest option injection.
            env = os.environ.copy()
            env.pop("PYTEST_ADDOPTS", None)
            if http2_opt_in:
                env["RAPTOR_HTTP2"] = "1"
            else:
                env.pop("RAPTOR_HTTP2", None)
            cmd = [
                sys.executable, str(runner), *subset,
                "-q", "--tb=short", "-p", "no:cacheprovider",
                f"--junitxml={junit}",
            ]
            try:
                proc = subprocess.run(
                    cmd, cwd=str(_REPO), env=env,
                    capture_output=True, text=True, timeout=240,
                )
            except OSError as exc:  # interpreter not spawnable
                self.skipTest(f"cannot spawn subprocess pytest: {exc}")
            tail = (proc.stdout + proc.stderr)[-2000:]
            self.assertTrue(
                junit.is_file(),
                "subprocess pytest produced no junit report "
                f"(rc={proc.returncode}): {tail}",
            )
            suite = ET.parse(junit).getroot().find("testsuite")
            self.assertIsNotNone(suite, f"junit report malformed: {tail}")
            return _LegResult(
                returncode=proc.returncode,
                tests=int(suite.get("tests", "0")),
                failures=int(suite.get("failures", "0")),
                errors=int(suite.get("errors", "0")),
                skipped=int(suite.get("skipped", "0")),
                tail=tail,
            )

    def test_opted_in_h2_hidden_skips_gated_and_passes_rest(self) -> None:
        leg = self._run_leg(_GATED_SUBSET, http2_opt_in=True)
        # Not vacuous: tests were collected and a real mix ran.
        self.assertGreater(leg.tests, 0, leg.tail)
        self.assertEqual(leg.failures, 0, leg.tail)
        self.assertEqual(leg.errors, 0, leg.tail)
        # The gate fired for the marked tests...
        self.assertGreater(leg.skipped, 0, leg.tail)
        # ...and the h2-independent tests still ran and passed.
        self.assertGreater(leg.tests - leg.skipped, 0, leg.tail)
        self.assertEqual(leg.returncode, 0, leg.tail)

    def test_no_opt_in_gate_is_inert_and_everything_passes(self) -> None:
        leg = self._run_leg(_INERT_SUBSET, http2_opt_in=False)
        self.assertGreater(leg.tests, 0, leg.tail)
        self.assertEqual(leg.failures, 0, leg.tail)
        self.assertEqual(leg.errors, 0, leg.tail)
        # No opt-in: nothing may skip — CI's relay coverage with h2
        # absent is exactly this shape.
        self.assertEqual(leg.skipped, 0, leg.tail)
        self.assertEqual(leg.returncode, 0, leg.tail)
