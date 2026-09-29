"""Meta-test pinning the wiring of the shared cache-isolation fixture.

The stub-swap regression test in ``test_compat.py`` requests
``_fresh_recommendation_cache`` by name, so it keeps passing even if
the fixture silently loses ``autouse=True`` — yet every OTHER test in
this suite relies on the autouse wiring for its cache isolation, and
only an unlucky worker partition would surface the loss. This module
pins the wiring itself: it loads the actual shipped conftest and
asserts the fixture is still autouse and function-scoped.
"""

from __future__ import annotations

from pathlib import Path

from packages.sca.wheel_compat.tests import conftest as _shipped_conftest


def _shipped_fixture_marker() -> object:
    """Return the pytest fixture marker of the REAL shipped fixture.

    pytest >= 8.4 wraps fixture functions in a definition object that
    carries the marker as ``_fixture_function_marker``; earlier pytest
    stashes it on the plain function as ``_pytestfixturefunction``.
    Fail loudly (rather than skip) if neither shape is found, so a
    pytest upgrade that changes the introspection surface breaks this
    pin visibly instead of letting it silently stop checking.
    """
    fixture_obj = _shipped_conftest._fresh_recommendation_cache
    marker = getattr(fixture_obj, "_fixture_function_marker", None)
    if marker is None:
        marker = getattr(fixture_obj, "_pytestfixturefunction", None)
    assert marker is not None, (
        "_fresh_recommendation_cache carries no pytest fixture marker "
        "— either it is no longer a fixture, or this pytest version "
        "stores the marker elsewhere and this meta-test needs updating"
    )
    return marker


def test_isolation_fixture_module_is_the_shipped_conftest() -> None:
    """Guard the pin's own subject: the module inspected here must be
    the conftest file that sits next to this test on disk, not some
    same-named module resolved from elsewhere on ``sys.path``."""
    inspected = Path(_shipped_conftest.__file__).resolve()
    shipped = Path(__file__).resolve().with_name("conftest.py")
    assert inspected == shipped, (
        f"meta-test inspected {inspected}, expected the shipped "
        f"conftest at {shipped}"
    )


def test_isolation_fixture_is_autouse_and_function_scoped() -> None:
    """Every test in this suite hands stubs to a cache whose key
    ignores the client, so the per-test clear must apply to every
    test WITHOUT being requested (autouse) and must run around each
    individual test (function scope). Losing either property
    re-opens the cross-test stub-poisoning hazard for all tests that
    do not request the fixture by name."""
    marker = _shipped_fixture_marker()
    autouse = getattr(marker, "autouse", None)
    scope = getattr(marker, "scope", None)
    assert autouse is True, (
        "_fresh_recommendation_cache is no longer autouse — tests "
        "that do not request it by name have lost their per-test "
        "recommendation-cache isolation"
    )
    assert scope == "function", (
        f"_fresh_recommendation_cache scope is {scope!r}, expected "
        "'function' — a wider scope stops clearing the cache between "
        "individual tests"
    )
