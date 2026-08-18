"""Tests for ``core.analysis.typestate`` lock-model discovery.

Pins the ``_LOCK_METHODS`` invariant: every member must be producible
by a model-discovery source (builtin lifecycle pairs or the
``_lock``/``_unlock`` naming convention), so membership tests can
actually fire.
"""
from __future__ import annotations

from core.analysis.typestate import (
    _INIT_DESTROY_PATTERNS,
    _LIFECYCLE_PAIRS,
    _LOCK_METHODS,
    _build_alloc_free_model,
    build_builtin_models,
)


def _producible(name: str) -> bool:
    if name in {alloc for alloc, _free in _LIFECYCLE_PAIRS}:
        return True
    return any(
        init_pat.match(name) for init_pat, _destroy_pat in _INIT_DESTROY_PATTERNS
    )


class TestLockMethodsReachable:
    def test_every_member_is_producible(self) -> None:
        dead = {m for m in _LOCK_METHODS if not _producible(m)}
        assert dead == set()

    def test_undiscoverable_kernel_names_removed(self) -> None:
        for name in ("down", "down_read", "down_write", "spin_lock_irqsave"):
            assert name not in _LOCK_METHODS

    def test_builtin_lock_models_unchanged(self) -> None:
        models = build_builtin_models()
        mutex = models["pthread_mutex_lock/pthread_mutex_unlock"]
        assert mutex.states == ["unlocked", "locked"]
        sem = models["sem_wait/sem_post"]
        assert sem.states == ["unlocked", "locked"]

    def test_convention_discovered_lock_still_classified(self) -> None:
        # spin_lock/spin_unlock arrives via the _lock/_unlock naming
        # convention; the membership test must still classify it as a
        # lock model.
        model = _build_alloc_free_model("spin_lock", "spin_unlock")
        assert model.states == ["unlocked", "locked"]
