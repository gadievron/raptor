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


class TestChecklistJoinContract:
    """Pair discovery must join the shape the checklist producer emits.

    The contract tests build the artifact through the ACTUAL producer
    (``build_inventory``) instead of hand-writing fixture keys — a
    hand-built flat ``items`` fixture is exactly the phantom shape
    that masked the dead checklist leg.
    """

    def test_real_inventory_checklist_discovers_pairs(self, tmp_path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        (src / "conn.c").write_text(
            "int conn_create(void) { return 0; }\n"
            "void conn_destroy(int c) { (void)c; }\n",
            encoding="utf-8",
        )
        from core.inventory import build_inventory

        checklist = build_inventory(str(src))
        from core.analysis.typestate import extract_typestate_models

        models = extract_typestate_models(checklist)
        assert "conn_create/conn_destroy" in models

    def test_flat_items_shape_discovers_nothing(self) -> None:
        # Control: no producer emits a flat top-level ``items`` list;
        # the walker must NOT resurrect the phantom shape.
        from core.analysis.typestate import extract_typestate_models

        flat = {"items": [{"name": "conn_create"}, {"name": "conn_destroy"}]}
        models = extract_typestate_models(flat)
        assert "conn_create/conn_destroy" not in models

    def test_walker_skips_junk_rows(self) -> None:
        from core.inventory import iter_checklist_items

        checklist = {
            "files": [
                "junk",
                {"path": "a.c", "items": ["junk", {"name": "f"}]},
                {"file": "b.c", "functions": [{"name": "g"}]},
            ],
        }
        walked = list(iter_checklist_items(checklist))
        assert [(p, i["name"]) for p, _fe, i in walked] == [
            ("a.c", "f"), ("b.c", "g"),
        ]
