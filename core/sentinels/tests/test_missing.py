"""Tests for the reload-stable ``MISSING`` sentinel.

The reason this module exists at ``core/sentinels/`` (not under
``core/json/*``) is to survive ``sys.modules`` resets in
``core/json/tests/test_f046_lazy_reexports.py``. These tests pin
that contract: singleton identity, ``bool(MISSING) is False``,
and survival across a sub-package reload.
"""

from __future__ import annotations

import importlib
import sys


def test_missing_is_singleton():
    """Repeated instantiation yields the same object."""
    from core.sentinels import MISSING, _MissingType

    assert _MissingType() is MISSING
    assert _MissingType() is _MissingType()


def test_missing_is_falsy():
    """``bool(MISSING)`` must be False so ``if cached:`` short-circuits
    on a negative-cache hit even when the caller forgets the explicit
    ``is MISSING`` check."""
    from core.sentinels import MISSING

    assert not MISSING
    assert bool(MISSING) is False


def test_missing_survives_core_json_reload():
    """Mirror of test_f046_lazy_reexports.py's reset pattern: deleting
    ``core.json.*`` from sys.modules must NOT replace ``MISSING``.

    Pre-fix the sentinel lived in ``core.json.cache``; the reload
    minted a fresh singleton, breaking ``is MISSING`` checks held by
    pre-import consumers (twelve ``packages/sca/registries/*`` modules).
    """
    from core.sentinels import MISSING

    pre_id = id(MISSING)
    for mod in list(sys.modules):
        if mod == "core.json" or mod.startswith("core.json."):
            del sys.modules[mod]
    importlib.import_module("core.json")

    from core.sentinels import MISSING as MISSING_after

    assert id(MISSING_after) == pre_id, (
        "MISSING singleton replaced by core.json.* reload — sentinel "
        "must live outside any namespace that test suites manipulate."
    )
