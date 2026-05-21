"""Reload-stable sentinel objects.

Lives at ``core/`` root (not under ``core.json.*``) so that test
suites which manipulate ``sys.modules`` to force fresh imports of
sub-packages — notably ``core/json/tests/test_f046_lazy_reexports.py``
which does ``del sys.modules['core.json.*']`` to test PEP 562 lazy
re-exports — do NOT replace the sentinel singletons.

Without this split, ``MISSING`` was redefined every time
``core.json.cache`` was reloaded. Consumer modules (e.g.
``packages/sca/registries/*``) imported ``MISSING`` once at module-load
time and held a binding to the OLD object; the reloaded cache
returned the NEW object. ``if cached is not MISSING`` then mismatched
across the reload boundary, breaking negative-cache contracts.

The ``_MissingType`` class-level ``_instance`` singleton already
preserved identity *within* a single module load — the reload-stable
location preserves identity *across* test-suite-induced reloads too.
"""

from __future__ import annotations

from typing import Optional


class _MissingType:
    _instance: Optional["_MissingType"] = None

    def __new__(cls) -> "_MissingType":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "<JsonCache._MISSING>"

    def __bool__(self) -> bool:
        return False


MISSING: _MissingType = _MissingType()
