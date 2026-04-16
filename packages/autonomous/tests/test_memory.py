from pathlib import Path

from core.json import save_json
from packages.autonomous.memory import FuzzingKnowledge, FuzzingMemory
from packages.autonomous.memory_exports import export_memory_views
from packages.autonomous.memory_store import SecretScanPolicy, Memory


def test_memory_upsert_and_query(tmp_path: Path):
    memory = Memory(db_path=tmp_path / "memory.db")
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
    memory = Memory(
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
    exports = export_memory_views(adapter.memory, base_dir=tmp_path)
    assert (tmp_path / "memory_knowledge.json").exists()
    assert "fuzzing_memory" in exports


def test_fuzzing_memory_migrates_legacy_json_to_sqlite(tmp_path: Path):
    legacy_file = tmp_path / "fuzzing_memory.json"
    save_json(
        legacy_file,
        {
            "knowledge": {
                "strategy:legacy": {
                    "knowledge_type": "strategy",
                    "key": "legacy",
                    "value": {"name": "legacy_strategy"},
                    "confidence": 0.7,
                    "success_count": 2,
                    "failure_count": 1,
                    "binary_hash": "abc123",
                    "campaign_id": "camp-1",
                }
            },
            "campaigns": [{"binary_name": "demo-bin"}],
        },
    )

    adapter = FuzzingMemory(memory_file=legacy_file)
    recalled = adapter.recall("strategy", "legacy")
    assert recalled is not None
    assert recalled.value["name"] == "legacy_strategy"
    assert recalled.success_count == 2
    assert recalled.failure_count == 1
    assert recalled.binary_hash == "abc123"
    assert not legacy_file.exists()
    assert (tmp_path / "fuzzing_memory.migrated.json").exists()


def test_fuzzing_memory_persists_knowledge_in_sqlite_store(tmp_path: Path):
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

    rows = adapter.memory.query_knowledge(domain="fuzzing", knowledge_type="strategy")
    persisted = [row for row in rows if row["key"] == "persisted_strategy"]
    assert len(persisted) == 1
    assert persisted[0]["value"]["name"] == "persisted_strategy"
    assert persisted[0]["success_count"] == 3
