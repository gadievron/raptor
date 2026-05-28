"""Typosquat denylist: hand-vetted confusable names subtracted from the
trusted popular list at load time.

The bundled popularity feeds (``data/popular/<eco>.json``) are download/
dependent rank lists; a name one edit from a far-more-popular package (npm
``loadash`` vs ``lodash``) can rank high enough to slip in, and once it sits in
the trusted list an exact match short-circuits the scan so it can never be
flagged. ``data/typosquat_denylist.json`` subtracts such hand-confirmed names
at the point of trust, with zero false positives by construction (only names a
human vetted are removed — legit near-names like ``preact``/``litellm`` stay).

These tests exercise the REAL ``_load_popular`` (the shared autouse fixture in
``packages/sca/conftest.py`` swaps it for a curated stub, which would bypass the
subtraction), so they capture and restore it explicitly.
"""

from __future__ import annotations

import dataclasses
import json

import pytest

from packages.sca.models import Dependency
from packages.sca.supply_chain import typosquat

# Captured at import (collection) time, before any per-test autouse fixture
# replaces ``_load_popular`` with the curated stub. The denylist subtraction
# lives inside the real function, so the integration tests need it back.
_REAL_LOAD_POPULAR = typosquat._load_popular


def _dep(name: str, eco: str = "npm") -> Dependency:
    kw = {}
    for f in dataclasses.fields(Dependency):
        if f.name == "name":
            kw[f.name] = name
        elif f.name == "ecosystem":
            kw[f.name] = eco
        elif f.name == "direct":
            kw[f.name] = True
        elif f.name == "version":
            kw[f.name] = "1.0.0"
        elif (f.default is not dataclasses.MISSING
              or f.default_factory is not dataclasses.MISSING):
            pass
        else:
            kw[f.name] = None
    return Dependency(**kw)


def _reset_caches() -> None:
    for c in (typosquat._POPULAR_BY_ECO, typosquat._POPULAR_SET,
              typosquat._POPULAR_BY_LEN, typosquat._DENYLIST_BY_ECO):
        c.clear()
    typosquat._DENYLIST_RAW = None


@pytest.fixture
def real_loader(tmp_path, monkeypatch):
    """Restore the real ``_load_popular`` and point the data dir + denylist at
    tmp files. Clears every cache on entry and exit so nothing leaks."""
    pop = tmp_path / "popular"
    pop.mkdir()
    monkeypatch.setattr(typosquat, "_DATA_DIR", pop)
    monkeypatch.setattr(typosquat, "_DENYLIST_PATH",
                        tmp_path / "typosquat_denylist.json")
    monkeypatch.setattr(typosquat, "_load_popular", _REAL_LOAD_POPULAR)
    _reset_caches()
    yield tmp_path
    _reset_caches()


def _write(tmp, popular, denylist=None):
    (tmp / "popular" / "npm.json").write_text(json.dumps(popular))
    if denylist is not None:
        (tmp / "typosquat_denylist.json").write_text(json.dumps(denylist))
    _reset_caches()


def test_denylisted_name_is_flagged_not_trusted(real_loader):
    # loadash rode the popularity feed in; denylisting it forces the detector
    # to evaluate it as distance-1 from lodash instead of trusting the match.
    _write(real_loader, ["lodash", "loadash"], {"npm": ["loadash"]})
    res = typosquat.scan_deps([_dep("loadash")])
    assert res, "denylisted loadash should be flagged"
    assert res[0].nearest_popular == "lodash"
    assert res[0].distance == 1


def test_non_denylisted_near_name_stays_trusted(real_loader):
    # preact is a legitimate package one edit from react and is NOT denylisted
    # → it remains a trusted exact-match (no false positive).
    _write(real_loader, ["react", "preact"], {"npm": ["loadash"]})
    assert typosquat.scan_deps([_dep("preact")]) == []


def test_denylist_only_affects_its_ecosystem(real_loader):
    # The entry is filed under PyPI, so npm's loadash is untouched.
    _write(real_loader, ["lodash", "loadash"], {"PyPI": ["loadash"]})
    assert typosquat.scan_deps([_dep("loadash")]) == []


def test_missing_denylist_file_is_noop(real_loader):
    # No denylist file at all → nothing subtracted, loadash stays trusted.
    _write(real_loader, ["lodash", "loadash"], denylist=None)
    assert typosquat.scan_deps([_dep("loadash")]) == []


def test_malformed_denylist_degrades_to_empty(real_loader):
    _write(real_loader, ["lodash", "loadash"], denylist=None)
    (real_loader / "typosquat_denylist.json").write_text("{not json")
    _reset_caches()
    # Malformed file must not raise; loadash simply stays trusted.
    assert typosquat.scan_deps([_dep("loadash")]) == []
    assert typosquat._load_denylist("npm") == set()


def test_load_denylist_lowercases_and_scopes(real_loader):
    _write(real_loader, [], {"npm": ["LoAdAsh"], "Cargo": ["serdex"]})
    assert typosquat._load_denylist("npm") == {"loadash"}      # lowercased
    assert typosquat._load_denylist("Cargo") == {"serdex"}
    assert typosquat._load_denylist("PyPI") == set()           # unknown → empty


def test_bundled_denylist_contains_loadash():
    """Regression guard on the shipped data file (real _DENYLIST_PATH)."""
    raw = json.loads(typosquat._DENYLIST_PATH.read_text(encoding="utf-8"))
    assert "loadash" in {n.lower() for n in raw.get("npm", [])}
