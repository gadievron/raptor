"""Tests for core.analysis._reach_cache.

Covers fingerprint stability, miss/hit round-trips, corruption
handling, and auto-disable on inventories that lack per-file
sha256.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from core.analysis import _reach_cache
from core.analysis.reachability import (
    InternalFunction,
    _AdjacencyIndex,
    _get_or_build_index,
)


@pytest.fixture(autouse=True)
def _redirect_cache(tmp_path: Path, monkeypatch):
    """Every test gets a fresh cache dir under tmp_path so they
    don't share state or pollute the user's real cache."""
    cache_dir = tmp_path / "reach"
    monkeypatch.setattr(_reach_cache, "_CACHE_DIR", cache_dir)
    yield cache_dir


def _make_inventory(*files: tuple[str, str, list]) -> Dict[str, Any]:
    """Build a small inventory dict with sha256 populated.

    Each entry is ``(path, sha256, items_list)``.
    """
    return {
        "files": [
            {"path": p, "sha256": s, "items": items}
            for (p, s, items) in files
        ],
    }


def _item(name: str, line: int) -> Dict[str, Any]:
    return {"name": name, "kind": "function", "line_start": line}


# ---------------------------------------------------------------------------
# Fingerprint stability
# ---------------------------------------------------------------------------

def test_fingerprint_stable_across_identical_inventories():
    inv1 = _make_inventory(("a.py", "deadbeef", [_item("f", 1)]))
    inv2 = _make_inventory(("a.py", "deadbeef", [_item("f", 1)]))
    fp1 = _reach_cache.compute_fingerprint(inv1)
    fp2 = _reach_cache.compute_fingerprint(inv2)
    assert fp1 == fp2 and fp1 is not None


def test_fingerprint_changes_on_sha_change():
    inv1 = _make_inventory(("a.py", "deadbeef", []))
    inv2 = _make_inventory(("a.py", "feedface", []))
    assert _reach_cache.compute_fingerprint(inv1) \
        != _reach_cache.compute_fingerprint(inv2)


def test_fingerprint_changes_on_path_change():
    inv1 = _make_inventory(("a.py", "deadbeef", []))
    inv2 = _make_inventory(("b.py", "deadbeef", []))
    assert _reach_cache.compute_fingerprint(inv1) \
        != _reach_cache.compute_fingerprint(inv2)


def test_fingerprint_stable_under_file_reorder():
    """The function sorts file rows by path so dict-insertion-order
    differences don't change the fingerprint."""
    inv1 = _make_inventory(
        ("a.py", "01", []), ("b.py", "02", []),
    )
    inv2 = _make_inventory(
        ("b.py", "02", []), ("a.py", "01", []),
    )
    assert _reach_cache.compute_fingerprint(inv1) \
        == _reach_cache.compute_fingerprint(inv2)


def test_fingerprint_none_when_sha_missing():
    inv = {"files": [{"path": "a.py", "items": []}]}
    assert _reach_cache.compute_fingerprint(inv) is None


def test_fingerprint_none_on_empty_inventory():
    assert _reach_cache.compute_fingerprint({"files": []}) is None
    assert _reach_cache.compute_fingerprint({}) is None


# ---------------------------------------------------------------------------
# Load / save round-trip
# ---------------------------------------------------------------------------

def test_save_then_load_round_trips():
    fp = "a" * 64  # 64 lowercase hex chars — valid SHA-256 shape
    idx = _AdjacencyIndex()
    fn = InternalFunction(file_path="a.py", name="f", line=1)
    idx.definitions[("a.py", "f")] = {fn}

    _reach_cache.save_index(fp, idx)
    restored = _reach_cache.load_index(fp)
    assert restored is not None
    assert restored.definitions == {("a.py", "f"): {fn}}


def test_load_miss_when_file_absent():
    fp = "b" * 64
    assert _reach_cache.load_index(fp) is None


def test_load_returns_none_for_none_fingerprint():
    """When the inventory can't be fingerprinted, the loader is a
    no-op. The substrate uses this to auto-disable for tests."""
    assert _reach_cache.load_index(None) is None


def test_save_with_none_fingerprint_is_a_noop(tmp_path):
    """save_index(None, ...) must not create the cache dir."""
    _reach_cache.save_index(None, _AdjacencyIndex())
    # The dir shouldn't have been created — fingerprint=None is the
    # "this inventory is uncacheable" signal.
    assert not _reach_cache._CACHE_DIR.exists()


# ---------------------------------------------------------------------------
# Corruption / format-skew handling
# ---------------------------------------------------------------------------

def test_load_treats_wrong_magic_as_miss(tmp_path):
    fp = "c" * 64
    path = _reach_cache._cache_path_for(fp)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"NOT-THE-RAPTOR-MAGIC\nrubbish")
    assert _reach_cache.load_index(fp) is None


def test_load_treats_corrupt_pickle_as_miss(tmp_path):
    fp = "c" * 64
    path = _reach_cache._cache_path_for(fp)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Valid magic, garbage pickle payload.
    path.write_bytes(_reach_cache._HEADER_MAGIC + b"\x00\x01\x02\x03")
    assert _reach_cache.load_index(fp) is None


# ---------------------------------------------------------------------------
# clear_cache
# ---------------------------------------------------------------------------

def test_clear_cache_removes_entries():
    for fp in ("1" * 64, "2" * 64, "3" * 64):
        _reach_cache.save_index(fp, _AdjacencyIndex())
    n = _reach_cache.clear_cache()
    assert n == 3


def test_clear_cache_returns_zero_for_cold_cache():
    assert _reach_cache.clear_cache() == 0


# ---------------------------------------------------------------------------
# Integration with _get_or_build_index
# ---------------------------------------------------------------------------

def test_index_is_persisted_on_first_build():
    inv = _make_inventory(("src.py", "abc123", [_item("foo", 1)]))
    # Fresh build — should write to disk.
    _get_or_build_index(inv, exclude_test_files=False)
    fp = _reach_cache.compute_fingerprint(inv)
    path = _reach_cache._cache_path_for(fp)
    assert path.exists()


def test_second_process_loads_from_disk(monkeypatch):
    """Simulate a second-process cold start: build the index, clear
    the in-process cache, build again with the same inventory dict
    by id — the second call should pull from disk."""
    inv = _make_inventory(("src.py", "deadbeef", [_item("foo", 1)]))
    idx1 = _get_or_build_index(inv, exclude_test_files=False)

    # Wipe in-process cache to simulate a fresh process. The disk
    # cache survives.
    from core.analysis import reachability
    monkeypatch.setattr(reachability, "_INDEX_CACHE", {})

    idx2 = _get_or_build_index(inv, exclude_test_files=False)
    # Same definitions — both indices were built over the same inventory.
    assert idx1.definitions == idx2.definitions


def test_inventory_without_sha_disables_persistent_cache():
    """Test fixtures often lack per-file sha256. The in-process
    cache should still work but the disk cache should be a no-op."""
    inv = {"files": [{"path": "src.py", "items": [_item("f", 1)]}]}
    _get_or_build_index(inv, exclude_test_files=False)
    # No fingerprint → no cache dir created.
    assert not _reach_cache._CACHE_DIR.exists()


def test_invalid_fingerprint_rejected_no_path_construction():
    """Defense in depth: ``_cache_path_for`` must reject non-hex
    or wrong-length fingerprints rather than constructing a path
    that could escape the cache root."""
    bad = ["../../etc/passwd", "x" * 64, "a" * 63, "A" * 64, "", None]
    for fp in bad:
        assert _reach_cache._cache_path_for(fp) is None


def test_load_refuses_foreign_uid(tmp_path, monkeypatch):
    """Cache file owned by another UID must not be unpickled —
    container-build + run-as-other-user scenario."""
    fp = "d" * 64
    idx = _AdjacencyIndex()
    _reach_cache.save_index(fp, idx)
    path = _reach_cache._cache_path_for(fp)
    assert path.exists()

    # Simulate foreign-owned file by mocking os.getuid() to a
    # value that differs from the file's actual uid.
    import os
    real_uid = os.stat(path).st_uid
    foreign_uid = real_uid + 12345
    monkeypatch.setattr(os, "getuid", lambda: foreign_uid)

    result = _reach_cache.load_index(fp)
    assert result is None, "load_index must refuse foreign-owned cache file"


def test_load_refuses_world_writable_cache_file(tmp_path):
    """Cache file with group/world write bits set must not be
    unpickled — a less-privileged process or a misconfigured
    umask could plant a poisoned pickle."""
    import os
    fp = "e" * 64
    _reach_cache.save_index(fp, _AdjacencyIndex())
    path = _reach_cache._cache_path_for(fp)
    # Make world-writable
    os.chmod(path, 0o666)
    result = _reach_cache.load_index(fp)
    assert result is None, "load_index must refuse world-writable cache"


def test_load_refuses_symlink(tmp_path):
    """Symlink at cache path is suspicious — refuse to follow,
    even if the target is the user's own."""
    import os
    real_fp = "0" * 64
    link_fp = "9" * 64
    _reach_cache.save_index(real_fp, _AdjacencyIndex())
    real_path = _reach_cache._cache_path_for(real_fp)
    assert real_path.exists()
    link_path = _reach_cache._cache_path_for(link_fp)
    os.symlink(real_path, link_path)
    result = _reach_cache.load_index(link_fp)
    assert result is None, "load_index must refuse to follow a symlink at cache path"


def test_load_does_not_execute_pickle_payload(tmp_path):
    """Direct anti-RCE check: even if an attacker plants a file
    with the correct magic + a malicious pickle, the UID/perms
    gate must block it before pickle.loads runs."""
    import pickle
    import os
    canary = tmp_path / "canary"

    class Exploit:
        def __reduce__(self):
            return (canary.write_text, ("PWNED",))

    fp = "8" * 64
    cache = _reach_cache._CACHE_DIR
    cache.mkdir(parents=True, exist_ok=True)
    path = _reach_cache._cache_path_for(fp)
    with open(path, "wb") as f:
        f.write(_reach_cache._HEADER_MAGIC + pickle.dumps(Exploit()))
    # Make it foreign-UID-looking by setting world-writable mode
    # (triggers the perms gate).
    os.chmod(path, 0o666)

    result = _reach_cache.load_index(fp)
    assert result is None
    assert not canary.exists(), "pickle payload executed despite gate"


def test_cache_file_permissions_are_0600(tmp_path):
    import stat as _stat
    fp = "f" * 64  # valid hex
    _reach_cache.save_index(fp, _AdjacencyIndex())
    path = _reach_cache._cache_path_for(fp)
    mode = _stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600


# ---------------------------------------------------------------------------
# Data-only format: restored bytes are never executed
# ---------------------------------------------------------------------------

def test_gate_passing_pickle_payload_is_never_executed(tmp_path):
    """A poisoned entry that passes EVERY open-time gate (own UID,
    mode 0600, regular file, size ok, correct magic) must still be a
    cache miss, not code execution. Open-time gates cannot
    authenticate the restored bytes — a poisoned cache restored from
    an archive by the operator or CI arrives with clean metadata —
    so the format itself must be data-only."""
    import os
    import pickle

    canary = tmp_path / "canary"

    class Exploit:
        def __reduce__(self):
            return (canary.write_text, ("PWNED",))

    fp = "7" * 64
    cache = _reach_cache._CACHE_DIR
    cache.mkdir(parents=True, exist_ok=True)
    os.chmod(cache, 0o700)
    path = _reach_cache._cache_path_for(fp)
    with open(path, "wb") as f:
        f.write(_reach_cache._HEADER_MAGIC + pickle.dumps(Exploit()))
    os.chmod(path, 0o600)  # every gate green

    result = _reach_cache.load_index(fp)
    assert not canary.exists(), (
        "cache payload was executed despite passing the metadata gates"
    )
    assert result is None


def test_full_index_round_trips_every_field():
    """The data-only codec must round-trip every _AdjacencyIndex
    field with identical values."""
    from core.analysis.reachability import ExternalFunction

    fn_a = InternalFunction(file_path="a.py", name="f", line=3)
    fn_b = InternalFunction(file_path="b.py", name="g", line=7)
    ext = ExternalFunction(qualified_name="os.path.join")

    idx = _AdjacencyIndex(
        forward={fn_a: {fn_b, ext}},
        reverse={ext: {fn_a}, fn_b: {fn_a}},
        uncertain_callers_by_tail={"g": {(fn_a, "wildcard-import")}},
        method_match={"g": {(fn_a, "Cls"), (fn_b, None)}},
        uncertain_callees={fn_a: {"pkg.mod.h"}},
        has_method_dispatch={fn_a: True, fn_b: False},
        definitions={("a.py", "f"): {fn_a}, ("b.py", "g"): {fn_b}},
        class_of_method={fn_b: "Cls"},
        class_bases={("b.py", "Cls"): ("Base", "Mixin")},
        override_methods={("Cls", "g")},
        framework_callable={fn_a},
        framework_registered={fn_b},
        qualified_to_internal={"pkg.b.Cls.g": fn_b},
        call_lines={(fn_a, fn_b): (12, 27), (fn_a, ext): (4,)},
        test_paths=frozenset({"tests/test_a.py"}),
    )

    fp = "6" * 64
    _reach_cache.save_index(fp, idx)
    restored = _reach_cache.load_index(fp)
    assert restored is not None
    for field_name in (
        "forward", "reverse", "uncertain_callers_by_tail",
        "method_match", "uncertain_callees", "has_method_dispatch",
        "definitions", "class_of_method", "class_bases",
        "override_methods", "framework_callable",
        "framework_registered", "qualified_to_internal",
        "call_lines", "test_paths",
    ):
        assert getattr(restored, field_name) == getattr(idx, field_name), (
            f"field {field_name} did not round-trip"
        )


def test_malformed_json_shapes_are_misses():
    """Parseable JSON with wrong shapes must degrade to a miss, not
    surface a typed index that crashes consumers later."""
    fp = "5" * 64
    path_dir = _reach_cache._CACHE_DIR
    path_dir.mkdir(parents=True, exist_ok=True)
    path = _reach_cache._cache_path_for(fp)
    for payload in (
        b"[]",                                # not an object
        b'{"forward": 3}',                    # field not a list
        b'{"forward": [[["a.py","f","x"], []]]}',  # line not an int
        b'{"definitions": [["a.py", "f", ["notanode"]]]}',
    ):
        path.write_bytes(_reach_cache._HEADER_MAGIC + payload)
        import os
        os.chmod(path, 0o600)
        assert _reach_cache.load_index(fp) is None, payload


def test_deeply_nested_json_is_a_miss_not_a_crash():
    """~200KB of ``[[[[…`` under all gates raises RecursionError from
    json.loads — must be a cache miss (fail-to-miss), never an
    exception escaping into the consuming reachability pipeline."""
    import os

    fp = "6" * 64
    _reach_cache._CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = _reach_cache._cache_path_for(fp)
    path.write_bytes(_reach_cache._HEADER_MAGIC + b"[" * 200_000)
    os.chmod(path, 0o600)
    assert _reach_cache.load_index(fp) is None


def test_empty_object_under_valid_magic_is_a_miss():
    """``{}`` decodes as a fully-valid EMPTY index (every field
    optional) — a same-uid poisoning shape. save_index always writes
    every field, so a document without them is foreign → miss."""
    import os

    fp = "7" * 64
    _reach_cache._CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = _reach_cache._cache_path_for(fp)
    path.write_bytes(_reach_cache._HEADER_MAGIC + b"{}")
    os.chmod(path, 0o600)
    assert _reach_cache.load_index(fp) is None


def test_dangling_symlink_does_not_jam_eviction(monkeypatch):
    """One dangling ``.pickle`` symlink made the stat-based eviction
    sort raise and return silently — the entry cap was then never
    enforced again. lstat + per-entry fallback keeps eviction live."""
    import os

    monkeypatch.setattr(_reach_cache, "_MAX_CACHE_ENTRIES", 3)
    _reach_cache._CACHE_DIR.mkdir(parents=True, exist_ok=True)
    for i in range(5):
        p = _reach_cache._CACHE_DIR / (f"{i}" * 64 + ".json")
        p.write_bytes(_reach_cache._HEADER_MAGIC + b"{}")
        os.utime(p, (1000 + i, 1000 + i))
    dangling = _reach_cache._CACHE_DIR / "stale.pickle"
    dangling.symlink_to(_reach_cache._CACHE_DIR / "no-such-target")
    _reach_cache._evict_oldest()
    remaining = _reach_cache._cache_entries()
    assert len(remaining) <= 3, [p.name for p in remaining]
