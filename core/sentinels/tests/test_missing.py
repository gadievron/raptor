"""Tests for the reload-stable ``MISSING`` sentinel.

The reason this module exists at ``core/sentinels/`` (not under
``core/json/*``) is to survive ``sys.modules`` resets in
``core/json/tests/test_f046_lazy_reexports.py``. These tests pin
that contract: singleton identity, ``bool(MISSING) is False``,
survival across a sub-package reload, and a ``repr`` that names
the sentinel's actual location.
"""

from __future__ import annotations

import contextlib
import importlib
import sys
from typing import Iterator


@contextlib.contextmanager
def _purged_core_json_window() -> Iterator[None]:
    """Purge ``core.json.*`` from sys.modules, then RESTORE the
    pre-purge module objects on exit (same shape as
    ``core/json/tests/test_f046_lazy_reexports.py``).

    Both directions matter. The purge is load-bearing for the survival
    test — minting fresh ``core.json`` module objects is exactly the
    hostile reload the sentinel must survive. The restoration is
    load-bearing for every LATER test in the process: production
    modules bind ``from core.json import load_json`` at import time,
    so leaving fresh duplicates in sys.modules detaches those held
    functions from what a later ``import core.json.utils`` resolves —
    that test's ``patch.object()`` then lands on a module the
    executing code never reads (observed: the openant recovery test's
    stdlib-json forcing was defeated and the live orjson lane rejected
    its non-finite fixture).
    """
    saved = {
        mod: sys.modules.pop(mod)
        for mod in list(sys.modules)
        if mod == "core.json" or mod.startswith("core.json.")
    }
    try:
        yield
    finally:
        for mod in list(sys.modules):
            if mod == "core.json" or mod.startswith("core.json."):
                del sys.modules[mod]
        sys.modules.update(saved)
        # A fresh ``import core.json`` inside the window rebinds the
        # parent package's ``json`` attribute; point it back at the
        # restored original (attribute access on an already-imported
        # package bypasses sys.modules).
        core_pkg = sys.modules.get("core")
        if core_pkg is not None:
            if "core.json" in saved:
                core_pkg.json = saved["core.json"]
            else:
                core_pkg.__dict__.pop("json", None)


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
    with _purged_core_json_window():
        importlib.import_module("core.json")

        from core.sentinels import MISSING as MISSING_after

        assert id(MISSING_after) == pre_id, (
            "MISSING singleton replaced by core.json.* reload — "
            "sentinel must live outside any namespace that test "
            "suites manipulate."
        )


def test_purged_window_restores_preexisting_modules():
    """The survival test's purge window must hand back the ORIGINAL
    ``core.json.*`` module objects when it closes.

    In-process regression for the deterministic 2-test repro: running
    this file's survival test then packages/openant test_recovery's
    test_nonfinite_confidence_dropped_record_stays_serializable in one
    pytest process. recovery.py binds ``from core.json import
    load_json`` at import time; the recovery test patches ``_orjson``
    on whatever ``import core.json.utils`` resolves at call time. A
    purge that leaves fresh duplicates in sys.modules makes those two
    different module objects, so the patch lands where the executing
    code never looks.
    """
    import core.json.utils as utils_before

    held = utils_before.load_json  # what an import-time consumer holds
    with _purged_core_json_window():
        fresh = importlib.import_module("core.json.utils")
        # The window really is fresh: the re-import mints a new
        # module object (the survival test's precondition).
        assert fresh is not utils_before

    import core.json.utils as utils_after

    assert utils_after is utils_before, (
        "purge window did not restore the pre-purge core.json.utils; "
        "import-time consumers now hold a module object patch.object() "
        "can no longer reach"
    )
    assert held.__globals__ is utils_after.__dict__
