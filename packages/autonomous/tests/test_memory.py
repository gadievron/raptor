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
