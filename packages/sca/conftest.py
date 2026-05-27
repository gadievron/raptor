"""Shared SCA test fixtures.

Deterministic typosquat popular-list: SCA unit tests must not depend on the
bundled, weekly-refreshed ``packages/sca/data/popular/<eco>.json`` lists. A
refresh can grow a list to thousands of real packages — and a name a test
uses as a *synthetic* typosquat may itself be a real package in the refreshed
list (``loadash`` genuinely exists on npm). When that happens the detector
treats it as an exact popular match and the test's distance / "flagged"
assertions silently break (this took out ~11 tests after a list refresh).

Pinning a small curated list of unambiguous top packages makes every
typosquat-path test deterministic and immune to future data refreshes. The
list is intentionally small and free of near-typosquats; names are all ≥4
chars so single-letter transitive-test deps (``a``/``b``) never collide.
"""

from __future__ import annotations

import pytest

# Genuine top packages per ecosystem. Ecosystems absent here resolve to an
# empty list (matching "unsupported ecosystem → no typosquat findings").
_CURATED_POPULAR = {
    "npm": [
        "lodash", "react", "express", "axios", "chalk", "debug",
        "commander", "vue", "webpack", "eslint", "typescript", "jest",
        "next", "request", "moment", "async", "yargs", "bluebird",
    ],
    "PyPI": [
        "requests", "django", "flask", "numpy", "pandas", "boto3",
        "urllib3", "setuptools", "pytest", "pyyaml", "click", "jinja2",
        "scipy", "sqlalchemy", "werkzeug",
    ],
}


@pytest.fixture(autouse=True)
def _deterministic_typosquat_popular(monkeypatch):
    from packages.sca.supply_chain import typosquat

    monkeypatch.setattr(
        typosquat, "_load_popular",
        lambda eco: list(_CURATED_POPULAR.get(eco, [])),
    )
    # The derived caches (set view + length buckets) are built lazily from
    # _load_popular and memoised per ecosystem; clear them so they re-derive
    # from the curated list (and again on teardown so anything running after
    # the SCA suite sees the real bundled data).
    _caches = (typosquat._POPULAR_BY_ECO, typosquat._POPULAR_SET,
               typosquat._POPULAR_BY_LEN)
    for cache in _caches:
        cache.clear()
    yield
    for cache in _caches:
        cache.clear()
