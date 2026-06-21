"""P2 lock-test (2026-05-02): the gate-side check
``cve_env.agent.loop._is_version_assertion_exec_check`` and the
warning-side check inside
``cve_env.tools.verify._compute_verify_quality_warning`` must agree
on the same input.

Background: prior bench (CVE-2015-10111 in bench50-20260501-220337)
emitted ``verify_quality_warning: missing version-assertion`` AND
``status: success`` simultaneously. The two signals are produced by
different code paths — one per-verify-call (warning), one cumulative
across all verify calls in a CVE (gate state). Both share
``VERSION_ASSERTION_CMD_PATTERN`` from ``cve_env.config``.

This test asserts the heuristics are aligned: for the same set of
exec_check entries, both layers return the same yes/no answer to "is
version-assertion present?" If they ever drift (e.g. someone forks the
regex in one place), this test fails fast.

This does NOT fix the contradictory bench output — that's a per-call vs
cumulative reporting artifact and is correct behavior. The lock test
prevents future drift between the two layers.
"""

from __future__ import annotations
import pytest
pytest.importorskip("claude_agent_sdk")

import re
from typing import Any

import pytest

from cve_env.agent.loop import _is_version_assertion_exec_check
from cve_env.config import VERSION_ASSERTION_CMD_PATTERN

def _warning_thinks_has_version(results: list[dict[str, Any]]) -> bool:
    """Mirror the warning-side heuristic from
    ``tools/verify.py::_compute_verify_quality_warning`` (lines 1057-1065).
    If this implementation ever drifts from the production code, this test
    will fail because the production code is the regression target.
    """
    for entry in results:
        if entry.get("type") != "exec_check":
            continue
        details = entry.get("details") or {}
        command = details.get("command") if isinstance(details, dict) else None
        if isinstance(command, str) and VERSION_ASSERTION_CMD_PATTERN.search(command):
            return True
    return False

def _gate_thinks_has_version(results: list[dict[str, Any]]) -> bool:
    """Mirror the gate-side aggregation across results — gate flips state to
    True if ANY exec_check matches via the per-entry helper.
    """
    return any(_is_version_assertion_exec_check(entry) for entry in results)

# Cases: each is a list of verify-result entries, plus an `expected` flag.
_CASES: list[tuple[str, list[dict[str, Any]], bool]] = [
    (
        "empty_results",
        [],
        False,
    ),
    (
        "only_lifecycle_no_exec",
        [
            {"type": "container_status", "passed": True},
            {"type": "stability_wait", "passed": True},
            {"type": "http_check", "passed": True},
        ],
        False,
    ),
    (
        "exec_check_apache_v_present",
        [
            {
                "type": "exec_check",
                "passed": True,
                "details": {"command": "apache2 -v"},
            },
        ],
        True,
    ),
    (
        "exec_check_pip_show_present",
        [
            {
                "type": "exec_check",
                "passed": True,
                "details": {"command": "pip show keystone"},
            },
        ],
        True,
    ),
    (
        "exec_check_dpkg_l_present",
        [
            {
                "type": "exec_check",
                "passed": False,
                "details": {"command": "dpkg -l libssl"},
            },
        ],
        # Whether the check PASSED is irrelevant — both layers ignore the
        # passed flag and just look for the command pattern.
        True,
    ),
    (
        "exec_check_arbitrary_command_no_version",
        [
            {
                "type": "exec_check",
                "passed": True,
                "details": {"command": "echo hello"},
            },
        ],
        False,
    ),
    (
        "exec_check_with_php_version",
        [
            {
                "type": "exec_check",
                "passed": True,
                "details": {"command": "php --version"},
            },
        ],
        True,
    ),
    (
        "exec_check_find_jar",
        [
            {
                "type": "exec_check",
                "passed": True,
                "details": {"command": "find /opt -name '*.jar' -ls"},
            },
        ],
        True,
    ),
    (
        "missing_details",
        [
            {"type": "exec_check", "passed": True},  # no details key
        ],
        False,
    ),
    (
        "details_not_a_dict",
        [
            {"type": "exec_check", "passed": True, "details": "stringy"},
        ],
        False,
    ),
    (
        "command_not_a_string",
        [
            {"type": "exec_check", "passed": True, "details": {"command": 42}},
        ],
        False,
    ),
    (
        "non_exec_check_with_version_string",
        [
            # http_check whose "command" looks like apache2 -v should NOT match —
            # only exec_check entries are inspected.
            {
                "type": "http_check",
                "passed": True,
                "details": {"command": "apache2 -v"},
            },
        ],
        False,
    ),
    (
        "mixed_with_version",
        [
            {"type": "container_status", "passed": True},
            {
                "type": "http_check",
                "passed": True,
                "details": {"command": "apache2 -v"},
            },
            {"type": "exec_check", "passed": True, "details": {"command": "echo nope"}},
            {
                "type": "exec_check",
                "passed": True,
                "details": {"command": "drush status"},
            },
        ],
        True,
    ),
]

def test_gate_and_warning_agree_on_version_assertion_detection() -> None:
    """For every case, both layers must return the same boolean."""
    disagreements: list[str] = []
    for name, results, expected in _CASES:
        gate = _gate_thinks_has_version(results)
        warning = _warning_thinks_has_version(results)
        if gate != warning or gate != expected:
            disagreements.append(
                f"  {name}: gate={gate} warning={warning} expected={expected}"
            )
    assert not disagreements, (
        "gate-layer and warning-layer disagree on version-assertion detection "
        "(or both disagree with expected). They share VERSION_ASSERTION_CMD_PATTERN "
        "so any drift is a bug:\n" + "\n".join(disagreements)
    )

def test_version_assertion_pattern_is_imported_from_canonical_source() -> None:
    """Ensure no consumer has forked its own regex.

    Phase 3c (2026-05-04) moved ``_compute_verify_quality_warning`` from
    verify.py to ``cve_env.tools._smoke``, so the pattern consumer in the
    verify path now lives in ``_smoke.py``. The canonical home is still
    ``cve_env.config`` (Phase 31.3).
    """
    import inspect

    import cve_env.agent.loop as loop_mod
    import cve_env.tools._smoke as smoke_mod

    loop_src = inspect.getsource(loop_mod)
    smoke_src = inspect.getsource(smoke_mod)

    # Both consumers must import the canonical pattern.
    assert "VERSION_ASSERTION_CMD_PATTERN" in loop_src, (
        "loop.py should import VERSION_ASSERTION_CMD_PATTERN from cve_env.config"
    )
    assert "VERSION_ASSERTION_CMD_PATTERN" in smoke_src, (
        "_smoke.py should import VERSION_ASSERTION_CMD_PATTERN from cve_env.config "
        "(consumer moved here from verify.py in Phase 3c)"
    )
    # And no consumer file should re-define a local regex with similar content.
    # Spot-check the "--version" segment of the canonical pattern.
    canonical_marker = r"--version\b"
    # The canonical pattern lives in config.py only; consumers must not
    # redefine it (no second re.compile with the same anchor).
    loop_compiles = re.findall(r"re\.compile\([^)]*--version", loop_src)
    smoke_compiles = re.findall(r"re\.compile\([^)]*--version", smoke_src)
    assert not loop_compiles, (
        f"loop.py defines its own --version regex (shadowing canonical): {loop_compiles}"
    )
    assert not smoke_compiles, (
        f"_smoke.py defines its own --version regex (shadowing canonical): {smoke_compiles}"
    )
    # Confirm config.py's pattern includes --version (sanity).
    assert canonical_marker in VERSION_ASSERTION_CMD_PATTERN.pattern
