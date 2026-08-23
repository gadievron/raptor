"""Tests for the reload-stable ``MISSING`` sentinel.

The reason this module exists at ``core/sentinels/`` (not under
``core/json/*``) is to survive ``sys.modules`` resets in
``core/json/tests/test_f046_lazy_reexports.py``. These tests pin
that contract: singleton identity, ``bool(MISSING) is False``,
survival across a sub-package reload, and a ``repr`` that names
the sentinel's actual location.
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


def test_repr_names_actual_location():
    """repr must point at core.sentinels.MISSING, where the object lives."""
    from core.sentinels import MISSING

    assert repr(MISSING) == "<core.sentinels.MISSING>"


def test_repr_has_no_stale_pre_split_label():
    """The pre-split 'JsonCache._MISSING' label must not resurface.

    The ``__repr__`` once returned ``'<JsonCache._MISSING>'`` — a
    leftover label from the pre-split location in ``core.json.cache``
    naming a symbol path that no longer exists."""
    from core.sentinels import MISSING

    assert "JsonCache" not in repr(MISSING)


def test_repr_is_stable_across_instantiations():
    """Every instantiation is the singleton, so every repr matches."""
    from core.sentinels import MISSING, _MissingType

    assert repr(_MissingType()) == repr(MISSING)


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
