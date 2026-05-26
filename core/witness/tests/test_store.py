"""Tests for ``core.witness.store.WitnessStore``.

Pin the contract: put / get / has / list semantics, dedup by hash,
hash-mismatch rejection, tolerant load on malformed manifests.
"""

from __future__ import annotations

import json

import pytest

from core.witness.store import WitnessStore, WitnessStoreError
from core.witness.types import (
    Witness,
    WitnessOutcome,
    WitnessSource,
    compute_bytes_hash,
)


def _make_witness(data: bytes, source: WitnessSource = WitnessSource.FUZZ):
    return Witness(
        bytes_hash=compute_bytes_hash(data),
        source=source,
        observed_outcome=WitnessOutcome.EXIT_SIGNAL,
    )


# ----------------------------------------------------------------------
# Put / get round-trip
# ----------------------------------------------------------------------


def test_put_then_get_witness_and_bytes(tmp_path):
    store = WitnessStore(tmp_path)
    data = b"trigger payload"
    w = _make_witness(data)

    store.put(w, data)
    loaded_w = store.get_witness(w.bytes_hash)
    loaded_bytes = store.get_bytes(w.bytes_hash)

    assert loaded_w.bytes_hash == w.bytes_hash
    assert loaded_w.source == w.source
    assert loaded_bytes == data


def test_put_stamps_bytes_len_if_default(tmp_path):
    """Producers that forget to set bytes_len get it filled in
    from the actual data length."""
    store = WitnessStore(tmp_path)
    data = b"A" * 200
    w = _make_witness(data)
    assert w.bytes_len == 0  # default
    store.put(w, data)
    loaded = store.get_witness(w.bytes_hash)
    assert loaded.bytes_len == 200


def test_put_creates_directories_lazily(tmp_path):
    """Constructing a store doesn't create dirs; first put does."""
    root = tmp_path / "new" / "deep" / "path"
    store = WitnessStore(root)
    assert not (root / "manifests").exists()
    assert not (root / "blobs").exists()
    store.put(_make_witness(b"data"), b"data")
    assert (root / "manifests").is_dir()
    assert (root / "blobs").is_dir()


# ----------------------------------------------------------------------
# Hash mismatch rejection
# ----------------------------------------------------------------------


def test_put_rejects_hash_mismatch(tmp_path):
    """Storing a witness whose hash doesn't match the data raises.
    Catches the common producer bug of computing hash on a
    transformed copy of the bytes."""
    store = WitnessStore(tmp_path)
    data = b"actual data"
    w = Witness(
        bytes_hash=compute_bytes_hash(b"different data"),
        source=WitnessSource.FUZZ,
        observed_outcome=WitnessOutcome.EXIT_SIGNAL,
    )
    with pytest.raises(WitnessStoreError, match="does not match"):
        store.put(w, data)


# ----------------------------------------------------------------------
# Existence check + missing-blob handling
# ----------------------------------------------------------------------


def test_has_after_put(tmp_path):
    store = WitnessStore(tmp_path)
    data = b"x"
    w = _make_witness(data)
    assert not store.has(w.bytes_hash)
    store.put(w, data)
    assert store.has(w.bytes_hash)


def test_get_missing_witness_raises(tmp_path):
    store = WitnessStore(tmp_path)
    with pytest.raises(WitnessStoreError, match="manifest not found"):
        store.get_witness("a" * 64)


def test_get_missing_bytes_raises(tmp_path):
    store = WitnessStore(tmp_path)
    with pytest.raises(WitnessStoreError, match="blob not found"):
        store.get_bytes("a" * 64)


def test_blob_path_returns_none_for_missing(tmp_path):
    """``blob_path`` is the soft-lookup variant — returns None on
    miss rather than raising. Useful for the "if we have it, use
    it; otherwise skip" pattern."""
    store = WitnessStore(tmp_path)
    assert store.blob_path("a" * 64) is None
    data = b"present"
    w = _make_witness(data)
    store.put(w, data)
    p = store.blob_path(w.bytes_hash)
    assert p is not None
    assert p.is_file()
    assert p.read_bytes() == data


# ----------------------------------------------------------------------
# Dedup on identical bytes
# ----------------------------------------------------------------------


def test_dedup_blob_across_different_witnesses(tmp_path):
    """Same bytes seen by two pipelines → single blob, two manifests.
    Wait — same hash means single manifest (overwrites). Verify the
    blob isn't rewritten and the most-recent manifest wins."""
    store = WitnessStore(tmp_path)
    data = b"same bytes"

    w1 = Witness(
        bytes_hash=compute_bytes_hash(data),
        source=WitnessSource.FUZZ,
        observed_outcome=WitnessOutcome.EXIT_SIGNAL,
        produced_by="afl++",
    )
    w2 = Witness(
        bytes_hash=compute_bytes_hash(data),
        source=WitnessSource.CRASH_REPLAY,
        observed_outcome=WitnessOutcome.SANITIZER_REPORT,
        produced_by="rr/replay",
    )

    store.put(w1, data)
    blob_path = tmp_path / "blobs" / f"{w1.bytes_hash}.bin"
    mtime_after_w1 = blob_path.stat().st_mtime

    store.put(w2, data)
    # Blob not rewritten (same content); manifest now reflects w2.
    assert blob_path.stat().st_mtime == mtime_after_w1
    loaded = store.get_witness(w1.bytes_hash)
    assert loaded.source == WitnessSource.CRASH_REPLAY  # w2 won
    assert loaded.produced_by == "rr/replay"


# ----------------------------------------------------------------------
# list_witnesses
# ----------------------------------------------------------------------


def test_list_witnesses_on_empty_store(tmp_path):
    store = WitnessStore(tmp_path)
    assert list(store.list_witnesses()) == []


def test_list_witnesses_returns_all(tmp_path):
    store = WitnessStore(tmp_path)
    pairs = [(f"data-{i}".encode(), i) for i in range(5)]
    for data, _i in pairs:
        store.put(_make_witness(data), data)
    listed = list(store.list_witnesses())
    assert len(listed) == 5
    hashes = {w.bytes_hash for w in listed}
    expected = {compute_bytes_hash(d) for d, _ in pairs}
    assert hashes == expected


def test_list_witnesses_skips_malformed_manifest(tmp_path):
    """Malformed JSON shouldn't abort enumeration — log a warning
    and skip. The store's contract is "load all valid records,"
    not "fail fast on the first bad one."""
    store = WitnessStore(tmp_path)
    # Plant one valid + one malformed manifest.
    data = b"valid"
    store.put(_make_witness(data), data)
    malformed = tmp_path / "manifests" / "deadbeef.json"
    malformed.write_text("{ this is not json")

    listed = list(store.list_witnesses())
    assert len(listed) == 1
    assert listed[0].bytes_hash == compute_bytes_hash(data)


# ----------------------------------------------------------------------
# Idempotency / overwrite semantics
# ----------------------------------------------------------------------


def test_put_overwrites_manifest_idempotent_on_blob(tmp_path):
    """Re-putting the same (hash, data, witness) is a no-op for the
    blob and a manifest-rewrite. Useful for retry-safe pipelines."""
    store = WitnessStore(tmp_path)
    data = b"retry-safe"
    w = _make_witness(data)
    store.put(w, data)
    store.put(w, data)  # second put
    loaded = store.get_witness(w.bytes_hash)
    assert loaded.bytes_hash == w.bytes_hash


def test_manifest_is_valid_json(tmp_path):
    """The persisted manifest is human-readable JSON — operators
    can inspect it without a special loader. Worth pinning so a
    future refactor doesn't silently switch to pickle or msgpack."""
    store = WitnessStore(tmp_path)
    data = b"inspectable"
    w = _make_witness(data)
    store.put(w, data)
    manifest_path = tmp_path / "manifests" / f"{w.bytes_hash}.json"
    parsed = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert parsed["bytes_hash"] == w.bytes_hash
    assert parsed["source"] == "fuzz"


# ----------------------------------------------------------------------
# Defensive checks added in the stacked fix on top of #579
# ----------------------------------------------------------------------


def test_put_rejects_bytes_len_mismatch(tmp_path):
    """Caller-supplied ``bytes_len`` that disagrees with
    ``len(data)`` is silent corruption of the manifest if not
    caught — downstream consumers trust this field. Reject with a
    clear error pointing at the producer."""
    store = WitnessStore(tmp_path)
    data = b"actual data"
    w = Witness(
        bytes_hash=compute_bytes_hash(data),
        source=WitnessSource.FUZZ,
        observed_outcome=WitnessOutcome.EXIT_SIGNAL,
        bytes_len=9999,  # caller lied
    )
    with pytest.raises(WitnessStoreError, match="bytes_len"):
        store.put(w, data)


def test_put_accepts_bytes_len_equal_to_data_length(tmp_path):
    """Caller-supplied ``bytes_len`` that DOES match is fine — only
    the mismatch path raises."""
    store = WitnessStore(tmp_path)
    data = b"actual data"
    w = Witness(
        bytes_hash=compute_bytes_hash(data),
        source=WitnessSource.FUZZ,
        observed_outcome=WitnessOutcome.EXIT_SIGNAL,
        bytes_len=len(data),  # matches
    )
    store.put(w, data)  # must not raise
    loaded = store.get_witness(w.bytes_hash)
    assert loaded.bytes_len == len(data)


def test_put_rejects_non_json_outcome_detail(tmp_path):
    """outcome_detail with a non-JSON-safe value (Path, datetime,
    bytes, custom class) is rejected with a clear error BEFORE the
    blob is written. Pre-fix the blob landed first and the manifest
    write failed with a confusing ``TypeError`` from json.dumps,
    leaving an orphan blob."""
    store = WitnessStore(tmp_path)
    data = b"x"
    w = Witness(
        bytes_hash=compute_bytes_hash(data),
        source=WitnessSource.FUZZ,
        observed_outcome=WitnessOutcome.EXIT_SIGNAL,
        outcome_detail={"path_obj": tmp_path},  # Path is not JSON-safe
    )
    with pytest.raises(WitnessStoreError, match="JSON-serialisable"):
        store.put(w, data)
    # Confirm no orphan blob landed.
    blobs_dir = tmp_path / "blobs"
    if blobs_dir.is_dir():
        assert list(blobs_dir.iterdir()) == [], (
            "non-JSON failure left an orphan blob behind"
        )


def test_put_atomic_blob_write_no_tmp_residue_on_success(tmp_path):
    """Successful blob writes go through .tmp + os.replace — verify
    no .tmp residue lingers after a clean put. (Failure mode for
    atomic-write is hard to test without crash injection; this
    pins the happy-path cleanup.)"""
    store = WitnessStore(tmp_path)
    data = b"atomic"
    w = _make_witness(data)
    store.put(w, data)
    blobs_dir = tmp_path / "blobs"
    tmp_files = list(blobs_dir.glob("*.tmp"))
    assert tmp_files == [], f"residue: {tmp_files}"


def test_put_atomic_manifest_write_no_tmp_residue_on_success(tmp_path):
    """Same as above for manifests."""
    store = WitnessStore(tmp_path)
    data = b"atomic-manifest"
    w = _make_witness(data)
    store.put(w, data)
    manifests_dir = tmp_path / "manifests"
    tmp_files = list(manifests_dir.glob("*.tmp"))
    assert tmp_files == [], f"residue: {tmp_files}"


def test_compute_bytes_hash_importable_from_init(tmp_path):
    """``compute_bytes_hash`` is part of the public API — consumers
    should import it from ``core.witness``, not from the private
    ``core.witness.types`` path. Pre-fix the symbol existed but
    wasn't re-exported, forcing the awkward import."""
    from core.witness import compute_bytes_hash as imported
    # Sanity: same function as the types-module version
    from core.witness.types import compute_bytes_hash as direct
    assert imported is direct


def test_witness_store_error_importable_from_init(tmp_path):
    """Likewise for ``WitnessStoreError`` — callers that want to
    catch store-specific errors shouldn't reach into the
    submodule."""
    from core.witness import WitnessStoreError as imported
    from core.witness.store import WitnessStoreError as direct
    assert imported is direct


def test_concurrent_same_hash_writes_do_not_race(tmp_path):
    """N threads writing the SAME bytes concurrently must all
    succeed. Pre-fix the atomic write used a shared ``.bin.tmp`` /
    ``.json.tmp`` suffix per blob; concurrent writers raced on
    that file and ``os.replace`` raised ``FileNotFoundError`` for
    the losers (the first ``replace`` consumed the shared tempfile).
    Per-(pid, thread) suffix on the tempfile name fixed it.

    PR E surfaced this: LLM exploits with identical bytes across
    findings are realistic and could trigger the race once
    crash_agent or a future caller goes multi-threaded. The end
    state was always correct (dedup-by-hash works); only the
    losing callers' exceptions were the bug.
    """
    import threading
    N = 16
    shared_bytes = b"// identical exploit text across findings\n"
    shared_hash = compute_bytes_hash(shared_bytes)
    store = WitnessStore(tmp_path / "witnesses")
    errors = []
    barrier = threading.Barrier(N)

    def worker(tid):
        try:
            barrier.wait()
            w = Witness(
                bytes_hash=shared_hash,
                bytes_len=len(shared_bytes),
                source=WitnessSource.LLM_EMIT_RUN,
                observed_outcome=WitnessOutcome.NOT_RUN,
                outcome_detail={"finding_id": f"F-{tid}"},
            )
            store.put(w, shared_bytes)
        except Exception as e:  # noqa: BLE001
            errors.append((tid, type(e).__name__, str(e)))

    threads = [
        threading.Thread(target=worker, args=(i,)) for i in range(N)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"concurrent put() raised on {len(errors)}/{N} threads"
    # End state: one blob, one manifest (last-write-wins on outcome_detail)
    blobs = list((tmp_path / "witnesses" / "blobs").glob("*"))
    manifests = list(
        (tmp_path / "witnesses" / "manifests").glob("*.json")
    )
    assert len(blobs) == 1
    assert len(manifests) == 1
    loaded = store.get_witness(shared_hash)
    assert loaded.outcome_detail["finding_id"].startswith("F-")


def test_concurrent_distinct_hash_writes_succeed(tmp_path):
    """Distinct hashes from concurrent writers: also must succeed.
    This was already safe pre-fix (each writer's hash was unique
    so tempfile names didn't collide) — pin it as a regression
    guard."""
    import threading
    N = 8
    PER = 20
    store = WitnessStore(tmp_path / "witnesses")
    errors = []
    barrier = threading.Barrier(N)

    def worker(tid):
        try:
            barrier.wait()
            for i in range(PER):
                data = f"thread-{tid}-write-{i}".encode()
                w = Witness(
                    bytes_hash=compute_bytes_hash(data),
                    bytes_len=len(data),
                    source=WitnessSource.LLM_EMIT_RUN,
                    observed_outcome=WitnessOutcome.NOT_RUN,
                    outcome_detail={"finding_id": f"F-{tid}-{i}"},
                )
                store.put(w, data)
        except Exception as e:  # noqa: BLE001
            errors.append((tid, type(e).__name__, str(e)))

    threads = [
        threading.Thread(target=worker, args=(i,)) for i in range(N)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    blobs = list((tmp_path / "witnesses" / "blobs").glob("*"))
    manifests = list(
        (tmp_path / "witnesses" / "manifests").glob("*.json")
    )
    assert len(blobs) == N * PER
    assert len(manifests) == N * PER
