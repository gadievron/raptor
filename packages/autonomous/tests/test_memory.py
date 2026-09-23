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


# ---------------------------------------------------------------------------
# Concurrent writers — shared store must merge, not last-writer-wins
# ---------------------------------------------------------------------------


def _k(key: str, value: str = "v", confidence: float = 0.9) -> FuzzingKnowledge:
    return FuzzingKnowledge(
        knowledge_type="strategy", key=key, value={"name": value},
        confidence=confidence,
    )


def test_concurrent_instances_do_not_lose_each_others_knowledge(
    tmp_path: Path,
):
    """Two campaigns share the default store. Each loads before the
    other saves (the classic RMW race); the save-side merge must keep
    the union instead of the last writer discarding the first's
    learning."""
    memory_file = tmp_path / "fuzzing_memory.json"
    mem1 = FuzzingMemory(memory_file=memory_file)
    mem2 = FuzzingMemory(memory_file=memory_file)  # loads pre-k1 state

    mem1.remember(_k("from_campaign_1"))
    mem1.flush()
    mem2.remember(_k("from_campaign_2"))
    mem2.flush()  # without merge this would drop from_campaign_1

    reloaded = FuzzingMemory(memory_file=memory_file)
    assert reloaded.recall("strategy", "from_campaign_1") is not None
    assert reloaded.recall("strategy", "from_campaign_2") is not None


def test_concurrent_campaign_records_are_united(tmp_path: Path):
    memory_file = tmp_path / "fuzzing_memory.json"
    mem1 = FuzzingMemory(memory_file=memory_file)
    mem2 = FuzzingMemory(memory_file=memory_file)
    mem1.record_campaign({"binary_name": "target-a"})
    mem2.record_campaign({"binary_name": "target-b"})
    reloaded = FuzzingMemory(memory_file=memory_file)
    names = {c.get("binary_name") for c in reloaded.campaigns}
    assert {"target-a", "target-b"} <= names


def test_merge_keeps_newest_entry_per_key(tmp_path: Path):
    """Same key updated by both writers: last_updated decides, so a
    stale in-memory copy never clobbers a fresher on-disk one."""
    memory_file = tmp_path / "fuzzing_memory.json"
    mem1 = FuzzingMemory(memory_file=memory_file)
    mem2 = FuzzingMemory(memory_file=memory_file)

    old = _k("shared", value="old")
    old.last_updated = time.time() - 100
    mem1.knowledge["strategy:shared"] = old

    fresh = _k("shared", value="fresh")
    fresh.last_updated = time.time()
    mem2.knowledge["strategy:shared"] = fresh
    mem2.save()

    mem1.save()  # stale copy must not win
    reloaded = FuzzingMemory(memory_file=memory_file)
    recalled = reloaded.recall("strategy", "shared")
    assert recalled is not None
    assert recalled.value["name"] == "fresh"


def test_prune_is_not_resurrected_by_merge(tmp_path: Path):
    """prune_low_confidence removes an on-disk entry; the merge-on-save
    must honour the removal rather than re-adopting the disk copy."""
    memory_file = tmp_path / "fuzzing_memory.json"
    mem = FuzzingMemory(memory_file=memory_file)
    mem.remember(_k("weak", confidence=0.05))
    mem.flush()

    mem.prune_low_confidence(threshold=0.2)
    reloaded = FuzzingMemory(memory_file=memory_file)
    assert reloaded.recall("strategy", "weak") is None


def test_parallel_flush_threads_keep_all_entries(tmp_path: Path):
    """Interleaved writers under real lock contention: every entry
    from both writers survives."""
    import threading

    memory_file = tmp_path / "fuzzing_memory.json"

    def writer(tag: str) -> None:
        mem = FuzzingMemory(memory_file=memory_file)
        for i in range(10):
            mem.remember(_k(f"{tag}_{i}"))
            mem.flush()

    threads = [threading.Thread(target=writer, args=(t,))
               for t in ("a", "b")]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    reloaded = FuzzingMemory(memory_file=memory_file)
    for tag in ("a", "b"):
        for i in range(10):
            assert reloaded.recall("strategy", f"{tag}_{i}") is not None, (
                f"lost {tag}_{i}"
            )


def test_save_survives_wedged_lock_holder(tmp_path: Path, monkeypatch):
    """A wedged flock holder must not stall the campaign: acquisition
    is deadline-bounded and save() degrades to a logged skip (the
    store is additive best-effort — the next flush retries)."""
    import fcntl

    memory_file = tmp_path / "fuzzing_memory.json"
    mem = FuzzingMemory(memory_file=memory_file)
    mem.remember(_k("held"))

    monkeypatch.setattr(FuzzingMemory, "_LOCK_TIMEOUT_S", 0.2)
    lock_path = memory_file.with_name(memory_file.name + ".lock")
    with open(lock_path, "w", encoding="utf-8") as holder:
        fcntl.flock(holder.fileno(), fcntl.LOCK_EX)
        start = time.monotonic()
        mem.save()  # must return, not hang
        assert time.monotonic() - start < 5.0


def test_malformed_shared_crash_pattern_reads_as_no_data(tmp_path: Path):
    """Shared-file entries are other processes' writes: a non-dict
    value or non-int counters must read as no-data, never raise into
    the crash-analysis path."""
    mem = FuzzingMemory(memory_file=tmp_path / "m.json")
    mem.remember(FuzzingKnowledge(
        knowledge_type="crash_pattern",
        key="SIGSEGV_f",
        value="junk-not-a-dict",
        # Intentionally ill-typed: a non-numeric confidence is exactly
        # the hostile shared-file shape under test.
        confidence="high",  # type: ignore[arg-type]
    ))
    prob = mem.is_crash_likely_exploitable("SIGSEGV", "f")
    assert isinstance(prob, float)
    assert 0.0 <= prob <= 1.0

    mem.remember(FuzzingKnowledge(
        knowledge_type="crash_pattern",
        key="SIGSEGV_g",
        value={"total_count": "NaN", "exploitable_count": None},
    ))
    # Both directions: recording over the malformed entry repairs it…
    mem.record_crash_pattern("SIGSEGV", "g", "hash", exploitable=True)
    prob = mem.is_crash_likely_exploitable("SIGSEGV", "g")
    assert 0.0 <= prob <= 1.0
    # …and recording over the non-dict entry does not raise either.
    mem.record_crash_pattern("SIGSEGV", "f", "hash", exploitable=False)


def test_campaign_merge_dedupes_identical_records(tmp_path: Path):
    """Pin the union semantics across the canonical-key rewrite:
    identical campaign dicts collapse, distinct ones survive."""
    memory_file = tmp_path / "m.json"
    first = FuzzingMemory(memory_file=memory_file)
    first.record_campaign({"binary": "a", "runs": 1})
    second = FuzzingMemory(memory_file=memory_file)
    second.campaigns = list(first.campaigns)  # identical records
    second.campaigns.append({"binary": "b", "runs": 2})
    second.save()
    reloaded = FuzzingMemory(memory_file=memory_file)
    binaries = sorted(str(c.get("binary")) for c in reloaded.campaigns)
    assert binaries == ["a", "b"]
