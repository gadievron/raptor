"""Phase 24B — version-assertion runtime injection (Stage 3 of Phase 27).

Closes CF-3 (Phase 52.1 strict-marker gate demotes plain `success` to
`verified_partial`). The agent often runs a version-discovery command
(``pip show``, ``dpkg -l``, ``apache2 -v``) but populates
``expected_stdout_contains`` with the product name only (no version
digits). The Phase 52.1 ``_has_specific_version_marker`` regex requires
``\\d+\\.\\d+`` in the marker.

Runtime injector: for each exec_check whose ``command`` matches
``VERSION_ASSERTION_CMD_PATTERN`` AND whose ``expected_stdout_contains``
is missing/under-specified, overwrite it with the CVE's version string
(or its major.minor prefix). Safe by construction: if the deployed
version actually differs, the check still fails (we filled in the
assertion the agent forgot — not lied about the result).

RED→GREEN per Phase 21.1 / 26.1 pattern.
"""
from __future__ import annotations

import pytest


def _try_import_injector():
    try:
        from cve_env.tools.verify import _inject_version_assertion
        return _inject_version_assertion
    except ImportError:
        return None


def test_injects_into_exec_check_with_missing_expected_stdout_contains():
    """Agent omitted expected_stdout_contains — runtime injects cve_version."""
    inject = _try_import_injector()
    assert inject is not None
    plan = [
        {"type": "exec_check", "command": "dpkg -l libssl"},
    ]
    new_plan, injected_indices = inject(plan, cve_version="1.0.1f")
    assert 0 in injected_indices
    assert new_plan[0]["expected_stdout_contains"] == "1.0.1f"


def test_injects_when_agent_set_product_name_only_no_version_digits():
    """Agent set expected_stdout_contains='Apache' (no \\d+\\.\\d+) — overwrite."""
    inject = _try_import_injector()
    assert inject is not None
    plan = [
        {
            "type": "exec_check",
            "command": "apache2 -v",
            "expected_stdout_contains": "Apache",
        },
    ]
    new_plan, injected_indices = inject(plan, cve_version="2.4.49")
    assert 0 in injected_indices
    assert new_plan[0]["expected_stdout_contains"] == "2.4.49"


def test_no_inject_when_agent_already_has_version_literal():
    """Agent already put '2.4.49' in expected_stdout_contains — don't clobber."""
    inject = _try_import_injector()
    assert inject is not None
    plan = [
        {
            "type": "exec_check",
            "command": "apache2 -v",
            "expected_stdout_contains": "Apache/2.4.49",
        },
    ]
    new_plan, injected_indices = inject(plan, cve_version="2.4.49")
    assert injected_indices == set()
    assert new_plan[0]["expected_stdout_contains"] == "Apache/2.4.49"


def test_no_inject_when_command_is_not_version_discovery():
    """Command doesn't match VERSION_ASSERTION_CMD_PATTERN — leave alone."""
    inject = _try_import_injector()
    assert inject is not None
    plan = [
        {"type": "exec_check", "command": "curl http://target/api"},
    ]
    new_plan, injected_indices = inject(plan, cve_version="1.0.1f")
    assert injected_indices == set()
    assert "expected_stdout_contains" not in new_plan[0]


def test_no_inject_when_cve_version_empty():
    """cve_version is '' — passthrough (no signal to inject)."""
    inject = _try_import_injector()
    assert inject is not None
    plan = [
        {"type": "exec_check", "command": "apache2 -v"},
    ]
    new_plan, injected_indices = inject(plan, cve_version="")
    assert injected_indices == set()


def test_no_inject_when_cve_version_has_no_digits():
    """cve_version that's not a version literal (e.g., 'unknown') — passthrough."""
    inject = _try_import_injector()
    assert inject is not None
    plan = [
        {"type": "exec_check", "command": "apache2 -v"},
    ]
    new_plan, injected_indices = inject(plan, cve_version="unknown")
    assert injected_indices == set()


def test_preserves_non_exec_check_steps_unchanged():
    """container_status, http_check, etc. are untouched by injector."""
    inject = _try_import_injector()
    assert inject is not None
    plan = [
        {"type": "container_status"},
        {"type": "http_check", "expected_status": 200},
        {"type": "exec_check", "command": "dpkg -l libssl"},
        {"type": "log_check", "patterns": ["ready"]},
    ]
    new_plan, injected_indices = inject(plan, cve_version="1.0.1f")
    assert injected_indices == {2}
    # other steps unchanged
    assert new_plan[0] == {"type": "container_status"}
    assert new_plan[1] == {"type": "http_check", "expected_status": 200}
    assert new_plan[3] == {"type": "log_check", "patterns": ["ready"]}
