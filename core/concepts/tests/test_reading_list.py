"""Tests for core.concepts.reading_list — shared reading list primitive."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.concepts.reading_list import (
    Priority,
    ReadingList,
    ReadingListItem,
)

# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

def _item(
    id: str,
    question: str = "what is this?",
    command: str = "/audit",
    priority: str = Priority.NORMAL,
    **kw,
) -> ReadingListItem:
    return ReadingListItem(
        id=id, question=question, source_command=command,
        priority=priority, **kw,
    )


# ------------------------------------------------------------------
# ReadingListItem
# ------------------------------------------------------------------

class TestReadingListItem:
    def test_defaults(self) -> None:
        item = _item("rl-001")
        assert not item.resolved
        assert item.resolved_concept_id is None
        assert item.resolved_at is None

    def test_resolve(self) -> None:
        item = _item("rl-001")
        item.resolve("page_ownership")
        assert item.resolved
        assert item.resolved_concept_id == "page_ownership"
        assert item.resolved_at is not None

    def test_source_fields(self) -> None:
        item = ReadingListItem(
            id="rl-002",
            question="what does sg_chain do?",
            source_command="/patch",
            source_file="crypto/algif_aead.c",
            source_line=244,
            source_function="aead_recvmsg",
            priority=Priority.HIGH,
            context="generating fix for page-cache corruption",
        )
        assert item.source_command == "/patch"
        assert item.source_file == "crypto/algif_aead.c"
        assert item.source_line == 244
        assert item.priority == Priority.HIGH


# ------------------------------------------------------------------
# ReadingList — queue operations
# ------------------------------------------------------------------

class TestReadingListQueue:
    def test_queue_adds_item(self) -> None:
        rl = ReadingList()
        rl.queue(_item("rl-001"))
        assert len(rl) == 1

    def test_dedup_same_question(self) -> None:
        rl = ReadingList()
        rl.queue(_item("rl-001", question="what is page ownership?"))
        rl.queue(_item("rl-002", question="what is page ownership?"))
        assert len(rl) == 1

    def test_dedup_allows_resolved(self) -> None:
        rl = ReadingList()
        item = _item("rl-001", question="what is page ownership?")
        item.resolve("page_ownership")
        rl.queue(item)
        rl.queue(_item("rl-002", question="what is page ownership?"))
        assert len(rl) == 2

    def test_dedup_escalates_priority(self) -> None:
        rl = ReadingList()
        rl.queue(_item("rl-001", question="what is page ownership?",
                        priority=Priority.NORMAL))
        rl.queue(_item("rl-002", question="what is page ownership?",
                        priority=Priority.CRITICAL))
        assert len(rl) == 1
        assert rl.items[0].priority == Priority.CRITICAL

    def test_dedup_does_not_downgrade_priority(self) -> None:
        rl = ReadingList()
        rl.queue(_item("rl-001", question="what is page ownership?",
                        priority=Priority.CRITICAL))
        rl.queue(_item("rl-002", question="what is page ownership?",
                        priority=Priority.LOW))
        assert len(rl) == 1
        assert rl.items[0].priority == Priority.CRITICAL

    def test_different_questions_not_deduped(self) -> None:
        rl = ReadingList()
        rl.queue(_item("rl-001", question="what is page ownership?"))
        rl.queue(_item("rl-002", question="what is scatterlist aliasing?"))
        assert len(rl) == 2

    def test_pending_excludes_resolved(self) -> None:
        rl = ReadingList()
        rl.queue(_item("rl-001"))
        item2 = _item("rl-002", question="q2")
        item2.resolve("some_concept")
        rl.queue(item2)
        assert len(rl.pending()) == 1
        assert len(rl.resolved()) == 1

    def test_by_command(self) -> None:
        rl = ReadingList()
        rl.queue(_item("rl-001", command="/audit"))
        rl.queue(_item("rl-002", command="/patch", question="q2"))
        rl.queue(_item("rl-003", command="/audit", question="q3"))
        assert len(rl.by_command("/audit")) == 2
        assert len(rl.by_command("/patch")) == 1
        assert len(rl.by_command("/exploit")) == 0


# ------------------------------------------------------------------
# ReadingList — drain (priority ordering)
# ------------------------------------------------------------------

class TestReadingListDrain:
    def test_drain_returns_priority_order(self) -> None:
        rl = ReadingList()
        rl.queue(_item("rl-low", question="q1", priority=Priority.LOW))
        rl.queue(_item("rl-crit", question="q2", priority=Priority.CRITICAL))
        rl.queue(_item("rl-high", question="q3", priority=Priority.HIGH))
        rl.queue(_item("rl-norm", question="q4", priority=Priority.NORMAL))
        drained = rl.drain()
        assert [d.id for d in drained] == [
            "rl-crit", "rl-high", "rl-norm", "rl-low",
        ]

    def test_drain_max_items(self) -> None:
        rl = ReadingList()
        for i in range(10):
            rl.queue(_item(f"rl-{i}", question=f"q{i}"))
        assert len(rl.drain(max_items=3)) == 3

    def test_drain_excludes_resolved(self) -> None:
        rl = ReadingList()
        rl.queue(_item("rl-001"))
        rl.resolve("rl-001", "page_ownership")
        assert len(rl.drain()) == 0

    def test_drain_empty(self) -> None:
        rl = ReadingList()
        assert rl.drain() == []


# ------------------------------------------------------------------
# ReadingList — resolve
# ------------------------------------------------------------------

class TestReadingListResolve:
    def test_resolve_marks_item(self) -> None:
        rl = ReadingList()
        rl.queue(_item("rl-001"))
        assert rl.resolve("rl-001", "page_ownership")
        assert rl.items[0].resolved
        assert rl.items[0].resolved_concept_id == "page_ownership"

    def test_resolve_nonexistent_returns_false(self) -> None:
        rl = ReadingList()
        assert not rl.resolve("nonexistent", "page_ownership")


# ------------------------------------------------------------------
# ReadingList — unresolvable semantics
# ------------------------------------------------------------------

class TestReadingListUnresolvable:
    """An unresolvable item was attempted and cannot be answered from
    the source.  It must leave pending() (never re-studied) while
    NEVER counting as resolved — the assumption stays unverified."""

    def test_mark_unresolvable(self) -> None:
        rl = ReadingList()
        rl.queue(_item("rl-001"))
        assert rl.mark_unresolvable("rl-001", "monkey-patched at runtime")
        item = rl.items[0]
        assert item.unresolvable
        assert item.unresolvable_reason == "monkey-patched at runtime"

    def test_unresolvable_leaves_pending(self) -> None:
        rl = ReadingList()
        rl.queue(_item("rl-001"))
        rl.mark_unresolvable("rl-001", "reason")
        assert rl.pending() == []

    def test_unresolvable_is_not_resolved(self) -> None:
        rl = ReadingList()
        rl.queue(_item("rl-001"))
        rl.mark_unresolvable("rl-001", "reason")
        assert rl.resolved() == []
        assert rl.items[0].resolved_concept_id is None
        assert len(rl.unresolvable_items()) == 1

    def test_resolved_item_cannot_become_unresolvable(self) -> None:
        rl = ReadingList()
        rl.queue(_item("rl-001"))
        rl.resolve("rl-001", "some_concept")
        assert not rl.mark_unresolvable("rl-001", "reason")
        assert rl.items[0].resolved

    def test_mark_nonexistent_returns_false(self) -> None:
        rl = ReadingList()
        assert not rl.mark_unresolvable("nope", "reason")

    def test_requeue_does_not_revive_unresolvable(self) -> None:
        rl = ReadingList()
        rl.queue(_item("rl-001", question="q1"))
        rl.mark_unresolvable("rl-001", "reason")
        rl.queue(_item("rl-002", question="q1"))
        assert rl.pending() == []
        assert len(rl.items) == 1

    def test_unresolvable_round_trips(self, tmp_path: Path) -> None:
        p = tmp_path / "reading-list.json"
        rl = ReadingList()
        rl.queue(_item("rl-001"))
        rl.mark_unresolvable("rl-001", "dynamic dispatch")
        rl.save(p)
        loaded = ReadingList.load(p)
        assert loaded.items[0].unresolvable
        assert loaded.items[0].unresolvable_reason == "dynamic dispatch"
        assert loaded.pending() == []
        assert loaded.resolved() == []


# ------------------------------------------------------------------
# ReadingList — persistence
# ------------------------------------------------------------------

class TestReadingListPersistence:
    def test_save_and_load(self, tmp_path: Path) -> None:
        p = tmp_path / "reading-list.json"
        rl = ReadingList()
        rl.queue(_item("rl-001", question="what is page ownership?",
                        command="/audit", priority=Priority.HIGH))
        rl.queue(_item("rl-002", question="what does sg_chain do?",
                        command="/patch"))
        rl.resolve("rl-001", "page_ownership")
        rl.save(p)

        loaded = ReadingList.load(p)
        assert len(loaded) == 2
        assert loaded.items[0].resolved
        assert loaded.items[0].resolved_concept_id == "page_ownership"
        assert loaded.items[1].source_command == "/patch"

    def test_load_nonexistent_returns_empty(self, tmp_path: Path) -> None:
        p = tmp_path / "nonexistent.json"
        loaded = ReadingList.load(p)
        assert len(loaded) == 0

    def test_atomic_write(self, tmp_path: Path) -> None:
        p = tmp_path / "reading-list.json"
        rl = ReadingList()
        rl.queue(_item("rl-001"))
        rl.save(p)
        assert not p.with_suffix(".tmp").exists()

    def test_creates_parent_dirs(self, tmp_path: Path) -> None:
        p = tmp_path / "nested" / "deep" / "reading-list.json"
        rl = ReadingList()
        rl.queue(_item("rl-001"))
        rl.save(p)
        assert p.exists()

    def test_save_no_path_raises(self) -> None:
        rl = ReadingList()
        with pytest.raises(ValueError, match="no path"):
            rl.save()

    def test_save_remembers_path(self, tmp_path: Path) -> None:
        p = tmp_path / "reading-list.json"
        rl = ReadingList()
        rl.queue(_item("rl-001"))
        rl.save(p)
        rl.queue(_item("rl-002", question="q2"))
        rl.save()
        loaded = ReadingList.load(p)
        assert len(loaded) == 2

    def test_load_ignores_extra_keys(self, tmp_path: Path) -> None:
        import json
        p = tmp_path / "reading-list.json"
        p.write_text(json.dumps({
            "items": [{
                "id": "rl-001",
                "question": "what is this?",
                "source_command": "/audit",
                "priority": "normal",
                "resolved": False,
                "future_field": "should be ignored",
                "another_new_thing": 42,
            }],
        }) + "\n", encoding="utf-8")
        loaded = ReadingList.load(p)
        assert len(loaded) == 1
        assert loaded.items[0].id == "rl-001"
        assert not hasattr(loaded.items[0], "future_field")

    def test_concurrent_writers_no_clobber(self, tmp_path: Path) -> None:
        p = tmp_path / "reading-list.json"
        rl1 = ReadingList()
        rl1.queue(_item("rl-001"))
        rl1.save(p)
        rl2 = ReadingList()
        rl2.queue(_item("rl-002", question="q2"))
        rl2.save(p)
        import os
        leftover_tmps = [f for f in os.listdir(tmp_path)
                         if f.endswith(".tmp")]
        assert leftover_tmps == []
        loaded = ReadingList.load(p)
        assert len(loaded) == 1
        assert loaded.items[0].id == "rl-002"


# ------------------------------------------------------------------
# Multi-consumer scenario
# ------------------------------------------------------------------

class TestMultiConsumer:
    def test_audit_patch_exploit_all_queue(self) -> None:
        rl = ReadingList()
        rl.queue(ReadingListItem(
            id="rl-audit-001",
            question="what is scatterlist page ownership?",
            source_command="/audit",
            source_file="crypto/algif_aead.c",
            source_line=244,
            priority=Priority.NORMAL,
        ))
        rl.queue(ReadingListItem(
            id="rl-patch-001",
            question="what does sg_chain do to page references?",
            source_command="/patch",
            source_file="crypto/algif_aead.c",
            source_line=244,
            priority=Priority.CRITICAL,
            context="generating fix — need to know if pages are copied or aliased",
        ))
        rl.queue(ReadingListItem(
            id="rl-exploit-001",
            question="what happens when page-cache pages are corrupted?",
            source_command="/exploit",
            priority=Priority.HIGH,
            context="assessing impact of write-through-shared-pages",
        ))

        assert len(rl) == 3
        assert len(rl.by_command("/audit")) == 1
        assert len(rl.by_command("/patch")) == 1
        assert len(rl.by_command("/exploit")) == 1

        drained = rl.drain()
        assert drained[0].id == "rl-patch-001"
        assert drained[1].id == "rl-exploit-001"
        assert drained[2].id == "rl-audit-001"

    def test_resolution_visible_to_all_consumers(self, tmp_path: Path) -> None:
        p = tmp_path / "reading-list.json"
        rl = ReadingList()
        rl.queue(_item("rl-audit", question="what is page ownership?",
                        command="/audit"))
        rl.queue(_item("rl-patch", question="what is page ownership?",
                        command="/patch"))

        assert len(rl) == 1

        rl.resolve("rl-audit", "page_ownership")
        rl.save(p)

        loaded = ReadingList.load(p)
        assert len(loaded.pending()) == 0
