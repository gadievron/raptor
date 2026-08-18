import time
from pathlib import Path

from packages.autonomous.memory import FuzzingKnowledge, FuzzingMemory


def test_fuzzing_memory_adapter_round_trip(tmp_path: Path):
    adapter = FuzzingMemory(memory_file=tmp_path / "fuzzing_memory.json")
    knowledge = FuzzingKnowledge(
        knowledge_type="strategy",
        key="strategy_a",
        value={"name": "strategy_a"},
        confidence=0.9,
    )
    adapter.remember(knowledge)
    recalled = adapter.recall("strategy", "strategy_a")
    assert recalled is not None
    assert recalled.value["name"] == "strategy_a"
    assert (tmp_path / "fuzzing_memory.json").exists()


def test_fuzzing_memory_loads_existing_json(tmp_path: Path):
    memory_file = tmp_path / "fuzzing_memory.json"
    adapter = FuzzingMemory(memory_file=memory_file)
    adapter.remember(
        FuzzingKnowledge(
            knowledge_type="strategy",
            key="legacy",
            value={"name": "legacy_strategy"},
            confidence=0.7,
            success_count=2,
            failure_count=1,
            binary_hash="abc123",
            campaign_id="camp-1",
        )
    )
    adapter_reloaded = FuzzingMemory(memory_file=memory_file)
    recalled = adapter_reloaded.recall("strategy", "legacy")
    assert recalled is not None
    assert recalled.value["name"] == "legacy_strategy"
    assert recalled.success_count == 2
    assert recalled.failure_count == 1
    assert recalled.binary_hash == "abc123"


def test_fuzzing_memory_persists_knowledge_in_json_store(tmp_path: Path):
    memory_file = tmp_path / "fuzzing_memory.json"
    adapter = FuzzingMemory(memory_file=memory_file)
    adapter.remember(
        FuzzingKnowledge(
            knowledge_type="strategy",
            key="persisted_strategy",
            value={"name": "persisted_strategy"},
            confidence=0.85,
            success_count=3,
        )
    )
    adapter_reloaded = FuzzingMemory(memory_file=memory_file)
    recalled = adapter_reloaded.recall("strategy", "persisted_strategy")
    assert recalled is not None
    assert recalled.value["name"] == "persisted_strategy"
    assert recalled.success_count == 3


# ``record_campaign`` and ``prune_low_confidence`` reset the save-batching
# counters (``_dirty_count`` / ``_last_save_time``) after their full-state
# ``save()``, exactly like ``flush()`` and the ``remember()`` batch trigger
# do — so a subsequent ``flush()`` no longer redundantly rewrites data that
# was just persisted.


def _memory_with_dirty_state(tmp_path: Path) -> FuzzingMemory:
    mem = FuzzingMemory(memory_file=tmp_path / "fuzzing_memory.json")
    mem.knowledge["strategy:s1"] = FuzzingKnowledge(
        knowledge_type="strategy", key="s1", value={"name": "s1"}, confidence=0.9,
    )
    mem._dirty_count = 5
    mem._last_save_time = time.time() - 10.0
    return mem


def test_record_campaign_resets_batch_counters(tmp_path: Path):
    mem = _memory_with_dirty_state(tmp_path)
    before = mem._last_save_time

    mem.record_campaign({"binary_name": "target"})

    assert mem._dirty_count == 0
    assert mem._last_save_time > before


def test_prune_low_confidence_resets_batch_counters(tmp_path: Path):
    mem = _memory_with_dirty_state(tmp_path)
    mem.knowledge["strategy:junk"] = FuzzingKnowledge(
        knowledge_type="strategy", key="junk", value={}, confidence=0.05,
    )
    before = mem._last_save_time

    mem.prune_low_confidence(threshold=0.2)

    assert "strategy:junk" not in mem.knowledge
    assert mem._dirty_count == 0
    assert mem._last_save_time > before


def test_prune_without_removals_leaves_counters_alone(tmp_path: Path):
    """No prune → no save → counters untouched (still dirty)."""
    mem = _memory_with_dirty_state(tmp_path)
    before_dirty = mem._dirty_count
    before_time = mem._last_save_time

    mem.prune_low_confidence(threshold=0.2)

    assert mem._dirty_count == before_dirty
    assert mem._last_save_time == before_time


def test_flush_is_noop_after_record_campaign(tmp_path: Path):
    """A save that just happened must not be redundantly repeated."""
    mem = _memory_with_dirty_state(tmp_path)
    mem.record_campaign({"binary_name": "target"})

    saves = []
    original_save = mem.save

    def counting_save():
        saves.append(1)
        original_save()

    mem.save = counting_save
    mem.flush()
    assert saves == []
