"""Phase 43.1.3 (2026-05-16): coverage gap closure for `set_cve_version_context`.

Per Phase 42.5 coverage report — MED-risk no-test gap on Phase 24B's
per-build CVE version context setter at `src/cve_env/agent/tools.py:704`.

The function registers a module-level `_CURRENT_CVE_VERSION` that the
verify tool wrapper reads (tools.py:690) and passes to the runtime
version-assertion injector. Build() calls this once at run start with
``cve.version``.

Tests cover:
- Round-trip: set then read
- Empty string preserved (cleared context)
- None coerced to empty string (defensive)
- Overwrite (second set wins; lifecycle)
- The `version or ""` predicate (line 711) explicitly maps falsy → ""

Location: src/cve_env/agent/tools.py:704-711.
"""

from __future__ import annotations

import pytest
pytest.importorskip("claude_agent_sdk")

import cve_env.agent.tools as cve_tools

from cve_env.agent.tools import set_cve_version_context


@pytest.fixture(autouse=True)
def _reset_context() -> None:
    """Reset module-level state before AND after each test. Without this
    fixture, a test setting "1.0" leaks into the next test's read.
    Module-level state is shared per-process; explicit reset matters.
    """
    cve_tools._CURRENT_CVE_VERSION = ""
    yield
    cve_tools._CURRENT_CVE_VERSION = ""


def test_set_then_read_roundtrip() -> None:
    """Basic contract: set propagates to the module-level variable."""
    set_cve_version_context("1.0.1f")
    assert cve_tools._CURRENT_CVE_VERSION == "1.0.1f"


def test_empty_string_clears_context() -> None:
    """Setting empty string clears the context (lifecycle reset)."""
    set_cve_version_context("2.4.49")
    assert cve_tools._CURRENT_CVE_VERSION == "2.4.49"
    set_cve_version_context("")
    assert cve_tools._CURRENT_CVE_VERSION == ""


def test_none_coerced_to_empty() -> None:
    """`version or ""` predicate at tools.py:711 coerces None → "".
    Defensive: callers can pass through unset cve.version safely.
    """
    # mypy would normally reject this; the function signature is `str` but
    # the defensive `or ""` handles None at runtime.
    set_cve_version_context(None)  # type: ignore[arg-type]
    assert cve_tools._CURRENT_CVE_VERSION == ""


def test_overwrite_second_set_wins() -> None:
    """Second call overwrites; not append, not merge."""
    set_cve_version_context("1.0")
    set_cve_version_context("2.0")
    assert cve_tools._CURRENT_CVE_VERSION == "2.0"


def test_complex_version_string_preserved() -> None:
    """Real CVE versions can be complex (suffixes, hyphens, ubuntu tags).
    The setter is opaque — preserves whatever string the caller provides.
    """
    set_cve_version_context("21.1.3-2ubuntu2~22.04.1")
    assert cve_tools._CURRENT_CVE_VERSION == "21.1.3-2ubuntu2~22.04.1"


def test_falsy_zero_coerced_to_empty() -> None:
    """The `or ""` predicate treats falsy values uniformly. Numeric 0
    (theoretically passable via misuse) → "". Documents the defensive
    behavior for non-string inputs."""
    set_cve_version_context(0)  # type: ignore[arg-type]
    assert cve_tools._CURRENT_CVE_VERSION == ""


def test_initial_state_is_empty() -> None:
    """Before any set_cve_version_context call, the module-level state
    defaults to empty (tools.py:701). Verify the fixture's reset works.
    """
    assert cve_tools._CURRENT_CVE_VERSION == ""
