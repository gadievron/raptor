"""Cache tests for ``LLMClient.generate_structured``.

The cache infrastructure existed for unstructured ``generate()`` since
day one, but ``generate_structured()`` bypassed it — every consumer
that asks for structured JSON paid the full provider round-trip on
every repeated call. These tests cover the wiring in
``core/llm/client.py`` that closes that gap.

Each test stubs ``LLMClient`` with a fake provider so we can count
calls, then exercises the cache via the real public API
(``client.generate_structured``).
"""

from __future__ import annotations

from pathlib import Path

from core.testing import (
    FakeStructuredProvider,
    install_provider,
    make_test_client,
)

# Shared scaffolding (core/testing) under this suite's historical
# local names — the definitions used to live here and had already
# been copy-drifted into sibling suites.
_FakeProvider = FakeStructuredProvider
_client = make_test_client
_install_provider = install_provider


# ---------------------------------------------------------------------------


def test_repeat_call_is_served_from_cache(tmp_path: Path) -> None:
    """Same prompt + schema → provider invoked exactly once across two
    calls. Second call returns ``cached=True`` with zero cost."""
    client = _client(tmp_path)
    fake = _FakeProvider({"verdict": "safe"}, raw='{"verdict":"safe"}')
    _install_provider(client, fake)

    schema = {"type": "object", "properties": {"verdict": {"type": "string"}}}
    r1 = client.generate_structured("Is this safe?", schema)
    r2 = client.generate_structured("Is this safe?", schema)

    assert fake.calls == 1, "expected provider to be hit only once"
    assert r1.cached is False
    assert r2.cached is True
    assert r2.cost == 0.0
    assert r2.tokens_used == 0
    assert r1.result == r2.result == {"verdict": "safe"}
    assert r1.raw == r2.raw == '{"verdict":"safe"}'


def test_different_schema_does_not_collide(tmp_path: Path) -> None:
    """Same prompt with two different schemas → provider invoked twice.
    A naïve implementation that hashes only the prompt would serve the
    wrong shape on the second call; this guards against that."""
    client = _client(tmp_path)
    fake = _FakeProvider({"answer": "yes"})
    _install_provider(client, fake)

    schema_a = {"type": "object", "properties": {"answer": {"type": "string"}}}
    schema_b = {"type": "object", "properties": {"answer": {"type": "boolean"}}}

    client.generate_structured("Same prompt", schema_a)
    client.generate_structured("Same prompt", schema_b)

    assert fake.calls == 2


def test_schema_key_order_does_not_affect_cache(tmp_path: Path) -> None:
    """Two schemas that differ only in dict insertion order must hash
    to the same key — otherwise consumers that build schemas from
    keyword args would get spurious misses."""
    client = _client(tmp_path)
    # Result must conform to the schema below — the strict schema floor
    # rejects responses carrying fields outside the declared properties.
    fake = _FakeProvider({"a": "v"})
    _install_provider(client, fake)

    schema_1 = {"type": "object", "properties": {"a": {"type": "string"},
                                                  "b": {"type": "string"}}}
    schema_2 = {"properties": {"b": {"type": "string"},
                               "a": {"type": "string"}}, "type": "object"}

    client.generate_structured("p", schema_1)
    client.generate_structured("p", schema_2)

    assert fake.calls == 1


def test_different_system_prompt_does_not_collide(tmp_path: Path) -> None:
    """system_prompt is part of the cache key — changing it must miss."""
    client = _client(tmp_path)
    fake = _FakeProvider({"k": "v"})
    _install_provider(client, fake)
    schema = {"type": "object"}

    client.generate_structured("user", schema, system_prompt="sys-A")
    client.generate_structured("user", schema, system_prompt="sys-B")

    assert fake.calls == 2


def test_caching_disabled_skips_persistence(tmp_path: Path) -> None:
    """With ``enable_caching=False`` no cache file is written and every
    call re-invokes the provider."""
    client = _client(tmp_path, enable_caching=False)
    fake = _FakeProvider({"k": "v"})
    _install_provider(client, fake)
    schema = {"type": "object"}

    client.generate_structured("p", schema)
    client.generate_structured("p", schema)

    assert fake.calls == 2
    # Cache dir is set but never created when caching is off.
    if client.config.cache_dir.exists():
        assert not list(client.config.cache_dir.iterdir())


def test_cache_file_lives_under_structured_prefix(tmp_path: Path) -> None:
    """Structured cache entries are filed under a ``structured-`` prefix
    so ops can grep them and so they can't collide with the unstructured
    cache namespace if both happen to compute the same hex digest."""
    client = _client(tmp_path)
    fake = _FakeProvider({"k": "v"})
    _install_provider(client, fake)

    client.generate_structured("p", {"type": "object"})

    files = list(client.config.cache_dir.glob("structured-*.json"))
    assert len(files) == 1


def test_corrupt_cache_falls_through_to_provider(tmp_path: Path) -> None:
    """A truncated/corrupt cache entry must be treated as a miss
    rather than crashing the call. ``core.json.load_json`` already
    swallows JSON errors; we additionally guard against entries that
    are valid JSON but missing the required fields (e.g. an interrupted
    writer that landed half-formed data)."""
    client = _client(tmp_path)
    fake = _FakeProvider({"k": "v"})
    _install_provider(client, fake)
    schema = {"type": "object"}

    # Prime the cache by running once.
    client.generate_structured("p", schema)
    cache_files = list(client.config.cache_dir.glob("structured-*.json"))
    assert len(cache_files) == 1

    # Mangle the file: drop the "result" key so the entry is partial.
    cache_files[0].write_text('{"raw": "x"}', encoding="utf-8")

    # Next call should re-invoke the provider rather than blow up.
    client.generate_structured("p", schema)
    assert fake.calls == 2


def test_unstructured_cache_remains_untouched(tmp_path: Path) -> None:
    """Sanity: the new structured cache helpers must not have broken
    the existing ``generate()`` cache path (no shared file names, no
    shared keys). Tests the negative — a structured call leaves no
    file that ``generate()`` would treat as its own."""
    client = _client(tmp_path)
    fake = _FakeProvider({"k": "v"})
    _install_provider(client, fake)

    client.generate_structured("p", {"type": "object"})

    # Files generate() writes have no prefix; ours have ``structured-``.
    plain = [p for p in client.config.cache_dir.iterdir()
             if not p.name.startswith("structured-")]
    assert plain == []


# ---------------------------------------------------------------------------
# Concern #1: kwargs are part of the cache key
# ---------------------------------------------------------------------------


def test_kwargs_partition_cache(tmp_path: Path) -> None:
    """Two calls that differ only in a non-model_config kwarg
    (e.g. ``temperature``) must miss against each other. Without this
    they'd collide and the second caller would silently get the first
    caller's result, breaking determinism the moment provider impls
    grow kwargs support."""
    client = _client(tmp_path)
    fake = _FakeProvider({"k": "v"})
    _install_provider(client, fake)

    client.generate_structured("p", {"type": "object"}, temperature=0.0)
    client.generate_structured("p", {"type": "object"}, temperature=0.7)

    assert fake.calls == 2


class _RecordingHandler:
    """Tiny inline log handler. RaptorLogger sets propagate=False on
    its 'raptor' logger, so pytest's caplog (which hooks the root
    logger) never sees these records — attaching a handler directly
    is the cheapest workaround."""

    def __init__(self):
        self.records: list = []

    def __enter__(self):
        import logging
        self._h = logging.Handler()
        self._h.handle = lambda r: (self.records.append(r), True)[1]
        self._lg = logging.getLogger("raptor")
        self._lg.addHandler(self._h)
        return self

    def __exit__(self, *exc):
        self._lg.removeHandler(self._h)
        return False

    def messages(self):
        return [r.getMessage() for r in self.records]


def test_kwargs_plumbed_to_provider(tmp_path: Path) -> None:
    """Caller-supplied generation kwargs (notably ``temperature``)
    must reach the provider's ``generate_structured`` call — pre-fix
    (batch 331) the client warned and silently dropped them, leaving
    every DispatchTask's per-task temperature ineffective on the
    structured path while appearing to be honoured on the freeform
    path."""
    client = _client(tmp_path)
    fake = _FakeProvider({"k": "v"})
    _install_provider(client, fake)

    client.generate_structured("p", {"type": "object"}, temperature=0.5)

    assert fake.last_kwargs.get("temperature") == 0.5


def test_no_warning_when_kwargs_empty(tmp_path: Path) -> None:
    """Plain calls (no kwargs) must not produce the noisy warning —
    consumers calling correctly should see clean logs."""
    client = _client(tmp_path)
    fake = _FakeProvider({"k": "v"})
    _install_provider(client, fake)

    with _RecordingHandler() as cap:
        client.generate_structured("p", {"type": "object"})

    msgs = cap.messages()
    assert not any("ignored" in m for m in msgs), msgs


# ---------------------------------------------------------------------------
# Concern #2: per-key lock dedupes concurrent identical calls
# ---------------------------------------------------------------------------


def test_concurrent_same_key_dedupes_to_one_provider_call(
    tmp_path: Path,
) -> None:
    """Eight threads racing on the same (prompt, schema) must result
    in exactly one provider call: the first arrival pays, the others
    serialise on the per-key lock and observe its freshly-written
    cache entry on their own check."""
    import threading
    client = _client(tmp_path)
    fake = _FakeProvider({"verdict": "safe"})
    _install_provider(client, fake)

    schema = {"type": "object"}
    barrier = threading.Barrier(8)
    results: list = []

    def worker():
        barrier.wait()                       # release all 8 at once
        results.append(client.generate_structured("p", schema))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert fake.calls == 1, (
        f"expected dedup to 1 call, got {fake.calls}"
    )
    cached = sum(1 for r in results if r.cached)
    fresh = sum(1 for r in results if not r.cached)
    assert fresh == 1 and cached == 7
    assert all(r.result == {"verdict": "safe"} for r in results)


def test_concurrent_distinct_keys_run_in_parallel(tmp_path: Path) -> None:
    """The per-key lock must NOT serialise distinct keys against each
    other — that would be a regression on parallelism. Eight different
    prompts → eight provider calls, no blocking."""
    import threading
    client = _client(tmp_path)
    fake = _FakeProvider({"k": "v"})
    _install_provider(client, fake)

    schema = {"type": "object"}
    barrier = threading.Barrier(8)

    def worker(i: int):
        barrier.wait()
        client.generate_structured(f"distinct-prompt-{i}", schema)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert fake.calls == 8


# ---------------------------------------------------------------------------
# Concern #3: TTL + max-entries eviction
# ---------------------------------------------------------------------------


def test_ttl_expired_entry_treated_as_miss(tmp_path: Path) -> None:
    """An entry whose ``timestamp`` is older than ``cache_ttl_seconds``
    must miss on read so the provider is re-queried. We back-date the
    on-disk file rather than time.sleep'ing to keep the test fast."""
    client = _client(tmp_path, cache_ttl_seconds=60.0)
    fake = _FakeProvider({"k": "v"})
    _install_provider(client, fake)

    client.generate_structured("p", {"type": "object"})
    assert fake.calls == 1

    # Back-date the cache entry to 2 minutes ago.
    import json
    import time
    cache_files = list(client.config.cache_dir.glob("structured-*.json"))
    assert len(cache_files) == 1
    data = json.loads(cache_files[0].read_text(encoding="utf-8"))
    data["timestamp"] = time.monotonic() - 120
    cache_files[0].write_text(json.dumps(data), encoding="utf-8")

    client.generate_structured("p", {"type": "object"})
    assert fake.calls == 2, "stale entry should have forced a refetch"


def test_ttl_unset_keeps_entries_indefinitely(tmp_path: Path) -> None:
    """No TTL configured → an entry from epoch 0 still serves a hit.
    Defends the no-TTL path so operators aren't surprised by hidden
    expiry."""
    import json
    client = _client(tmp_path, cache_ttl_seconds=None)
    fake = _FakeProvider({"k": "v"})
    _install_provider(client, fake)

    client.generate_structured("p", {"type": "object"})
    cache_files = list(client.config.cache_dir.glob("structured-*.json"))
    data = json.loads(cache_files[0].read_text(encoding="utf-8"))
    data["timestamp"] = 0.0
    cache_files[0].write_text(json.dumps(data), encoding="utf-8")

    fake.calls = 0
    r = client.generate_structured("p", {"type": "object"})
    assert fake.calls == 0
    assert r.cached is True


def test_entries_without_timestamp_serve_as_fresh(tmp_path: Path) -> None:
    """A pre-existing cache entry that lacks a ``timestamp`` field
    (written by an older code version) must not be evicted en masse on
    upgrade — we treat it as fresh and let it serve. TTL only applies
    going forward."""
    import json
    client = _client(tmp_path, cache_ttl_seconds=1.0)
    fake = _FakeProvider({"k": "v"})
    _install_provider(client, fake)

    client.generate_structured("p", {"type": "object"})
    cache_files = list(client.config.cache_dir.glob("structured-*.json"))
    data = json.loads(cache_files[0].read_text(encoding="utf-8"))
    del data["timestamp"]
    cache_files[0].write_text(json.dumps(data), encoding="utf-8")

    fake.calls = 0
    r = client.generate_structured("p", {"type": "object"})
    assert fake.calls == 0
    assert r.cached is True


def test_eviction_drops_oldest_when_over_cap(tmp_path: Path) -> None:
    """Save N+overflow entries with cache_max_entries=N → directory
    settles at exactly N files, with the oldest evicted."""
    import time
    client = _client(tmp_path, cache_max_entries=5)
    fake = _FakeProvider({"k": "v"})
    _install_provider(client, fake)

    schema = {"type": "object"}
    # 8 distinct entries → after eviction we should keep 5.
    # time.sleep between writes so mtimes are distinct enough that
    # "oldest" is unambiguous.
    for i in range(8):
        client.generate_structured(f"prompt-{i}", schema)
        time.sleep(0.01)

    files = list(client.config.cache_dir.glob("*.json"))
    assert len(files) == 5, f"expected 5 entries after eviction, got {len(files)}"


def test_eviction_disabled_when_cap_unset(tmp_path: Path) -> None:
    """No cap → cache grows unbounded. Defends the default behaviour
    (no surprise eviction for operators who haven't opted in)."""
    client = _client(tmp_path, cache_max_entries=None)
    fake = _FakeProvider({"k": "v"})
    _install_provider(client, fake)

    for i in range(20):
        client.generate_structured(f"p-{i}", {"type": "object"})

    files = list(client.config.cache_dir.glob("*.json"))
    assert len(files) == 20


def test_cache_cap_defaults_to_bounded():
    """The config default must bound the cache: unbounded growth is
    opt-in (cache_max_entries=None), not the default. Pre-fix the
    default was None and out/llm_cache grew for the life of the
    install."""
    from core.llm.config import LLMConfig
    cfg = LLMConfig()
    assert cfg.cache_max_entries is not None
    assert cfg.cache_max_entries > 0


class TestCacheTtlDefault:
    """TTL defaults to 24h (operator decision 2026-08-15: most targets
    aren't re-audited across days, and the cache key already pins the
    model name — the TTL guards same-name behaviour drift)."""

    def test_default_is_24h(self, monkeypatch):
        monkeypatch.delenv("RAPTOR_LLM_CACHE_TTL_S", raising=False)
        from core.llm.config import LLMConfig
        assert LLMConfig().cache_ttl_seconds == 86_400.0

    def test_env_overrides_seconds(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_LLM_CACHE_TTL_S", "3600")
        from core.llm.config import LLMConfig
        assert LLMConfig().cache_ttl_seconds == 3600.0

    def test_env_none_disables_expiry(self, monkeypatch):
        for raw in ("none", "off", "0", "-1"):
            monkeypatch.setenv("RAPTOR_LLM_CACHE_TTL_S", raw)
            from core.llm.config import LLMConfig
            assert LLMConfig().cache_ttl_seconds is None, raw

    def test_garbled_env_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_LLM_CACHE_TTL_S", "tomorrow")
        from core.llm.config import LLMConfig
        assert LLMConfig().cache_ttl_seconds == 86_400.0
