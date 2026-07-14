"""SCA-test fixtures.

Most pipeline tests don't care about the cascade resolver — they're
exercising parsers, finding shapes, CLI plumbing. But ``cli.main``
defaults to ``enable_transitive_expansion=True`` for production
correctness, which fires ``npm --version`` (~1s on most systems) and
sometimes ``pip --version`` / ``go version`` per scan.

Session-autouse fixture below pre-populates the per-process tool-
availability cache with ``False`` for every resolver tool so the
probes return immediately without running subprocess. The cascade
gracefully no-ops when no resolver is "available". Tests that need
to exercise the real resolver-availability codepath (or a
specifically-mocked resolver) can clear/override the cache via the
``unstub_check_tool_cache`` fixture.

Net effect on the dev box: removes ~1s from every test that calls
``cli.main`` or ``run_sca`` with default options.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# LLM isolation: default-deny live API calls
# ---------------------------------------------------------------------------
#
# SCA tests must NOT hit real LLM providers by default. Prior state:
# several pipeline/verify tests exercised the full SCA pipeline —
# including the triage / inline-review / upgrade-impact passes — and
# those passes call ``packages.sca.llm.get_llm_client()`` internally.
# When those tests ran without an explicit stub, ``get_llm_client()``
# read the operator's local LLM config, resolved to a real provider,
# and made live API calls to whatever model was auto-selected
# (Gemini-flash-lite in the observed case), silently costing money
# per test run and shipping fixture content over the wire.
#
# The autouse fixture below patches ``get_llm_client`` to return
# ``None`` for every SCA test. SCA pipeline code paths already handle
# the ``None`` case gracefully — they treat it as "LLM disabled — skip
# the review pass" — so tests exercising pipeline logic that isn't
# specifically about LLM behaviour continue to pass unchanged.
#
# Tests that need a stubbed client (e.g. ``@patch("...get_llm_client")``
# with a MagicMock return value) work as before: the inner context-
# managed patch shadows this fixture's outer patch for the duration
# of the test.
#
# Tests that genuinely need a live LLM (e.g. a specific-model smoke
# test) opt in with ``@pytest.mark.integration``, which the root
# ``pytest.ini`` deselects by default anyway.


@pytest.fixture(autouse=True)
def _sca_no_live_llm(request):
    """Deny live LLM calls in SCA tests; see comment above."""
    if request.node.get_closest_marker("integration"):
        yield
        return
    with patch("packages.sca.llm.get_llm_client", return_value=None):
        yield


# Tool probes the resolver registry runs. Conservative — real list
# lives in the per-resolver ``is_available`` methods. Adding more here
# is harmless (extra cache entries that never get queried).
_TOOL_PROBES = (
    ("npm", "--version"),
    ("pnpm", "--version"),
    ("yarn", "--version"),
    ("pip", "--version"),
    ("pip-compile", "--version"),
    ("poetry", "--version"),
    ("uv", "--version"),
    ("go", "version"),
    ("cargo", "--version"),
    ("bundle", "--version"),
    ("composer", "--version"),
    ("dotnet", "--version"),
    ("mvn", "--version"),
    ("gradle", "--version"),
)


@pytest.fixture(autouse=True, scope="session")
def _stub_resolver_tool_probes_at_session_start():
    """Pre-populate ``_CHECK_TOOL_CACHE`` so ``is_available`` returns
    False for every resolver tool without spawning subprocess.

    Tests that exercise real-tool detection should depend on
    ``unstub_check_tool_cache`` to clear the relevant entries.
    """
    from packages.sca.resolvers import _CHECK_TOOL_CACHE
    for cmd in _TOOL_PROBES:
        _CHECK_TOOL_CACHE[cmd] = False
    yield
    # No cleanup — the cache is process-scoped and the next test run
    # is a fresh process.


@pytest.fixture
def unstub_check_tool_cache():
    """Opt-out fixture for tests that want to exercise the real
    ``_check_tool`` path (e.g. a regression test that the npm probe
    is actually invoked end-to-end). Clears the cache for the test
    and re-stubs it on teardown so neighbouring tests stay fast.
    """
    from packages.sca.resolvers import _CHECK_TOOL_CACHE
    saved = dict(_CHECK_TOOL_CACHE)
    _CHECK_TOOL_CACHE.clear()
    yield
    _CHECK_TOOL_CACHE.clear()
    _CHECK_TOOL_CACHE.update(saved)
