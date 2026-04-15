from pathlib import Path

from packages.autonomous.memory import FuzzingKnowledge, FuzzingMemory
from packages.autonomous.memory_exports import export_memory_views
from packages.autonomous.unified_memory import SecretScanPolicy, UnifiedMemory


def test_unified_memory_upsert_and_query(tmp_path: Path):
    memory = UnifiedMemory(db_path=tmp_path / "memory.db")
    memory.upsert_knowledge(
        domain="fuzzing",
        knowledge_type="strategy",
        key="default",
        value={"name": "default", "score": 1},
        confidence=0.8,
        success_count=2,
    )
    rows = memory.query_knowledge(domain="fuzzing", knowledge_type="strategy")
    assert len(rows) == 1
    assert rows[0]["key"] == "default"
    assert rows[0]["value"]["name"] == "default"


def test_secret_redaction_happens_before_persist(tmp_path: Path):
    memory = UnifiedMemory(
        db_path=tmp_path / "memory.db",
        policy=SecretScanPolicy(enabled=True, run_trufflehog=False),
    )
    memory.record_event("agentic", "prompt_payload", {"api_key": "AKIAABCDEFGHIJKLMNOP"})
    metrics = memory.aggregate_metrics()
    assert metrics["events_by_tool"].get("agentic", 0) == 1
    rows = memory.query_knowledge(domain="agentic")
    assert rows == []


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
    exports = export_memory_views(adapter.unified, base_dir=tmp_path)
    assert (tmp_path / "unified_knowledge.json").exists()
    assert "fuzzing_memory" in exports
