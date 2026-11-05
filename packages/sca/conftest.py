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

from core.testing.tempdirs import isolated_test_dir

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
def _isolated_sca_home(monkeypatch, tmp_path_factory):
    # sca_cache_root() uses HOME/.raptor/cache/sca, not XDG_CACHE_HOME.
    # Keep persistent inventories and metadata out of the operator's store.
    # A sibling allocation also stays outside a test's walked source tree.
    monkeypatch.setenv("HOME", str(isolated_test_dir(tmp_path_factory, "sca-home")))


@pytest.fixture(autouse=True)
def _deterministic_typosquat_popular(monkeypatch):
    from packages.sca.supply_chain import slopsquat, typosquat

    load_popular = lambda eco: list(_CURATED_POPULAR.get(eco, []))
    monkeypatch.setattr(typosquat, "_load_popular", load_popular)
    monkeypatch.setattr(slopsquat, "_load_popular", load_popular)
    # Both detectors derive memoized views from the chosen popular list.
    # Use private containers so teardown preserves the caller's warm caches.
    for name in ("_POPULAR_BY_ECO", "_POPULAR_SET", "_POPULAR_BY_LEN",
                 "_DENYLIST_BY_ECO", "_ALLOWLIST_BY_ECO"):
        monkeypatch.setattr(typosquat, name, {})
    monkeypatch.setattr(slopsquat, "_COLLAPSED_INDEX", {})
    monkeypatch.setattr(typosquat, "_DENYLIST_RAW", None)
    monkeypatch.setattr(typosquat, "_ALLOWLIST_RAW", None)
