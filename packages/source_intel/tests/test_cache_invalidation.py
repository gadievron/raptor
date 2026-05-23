"""Tests for the source_intel process-cache invalidation paths.

Closes gap #4 from SOURCE_INTEL_ARC_STATUS.md: ``_INVENTORY_BY_TARGET``
(in ``analyze.py``) and ``_SI_RESULT_CACHE`` (in ``source_intel_inject.py``)
are process-globals. Signature-based auto-invalidation now drops stale
entries on lookup, and an explicit ``clear_all_source_intel_caches()``
helper gives orchestrators a public reset lever.

Tests use the real filesystem (``tmp_path``) so the signature compute
exercises its actual walk, not a mock.
"""

from __future__ import annotations

import time
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from packages.source_intel import (
    clear_all_source_intel_caches,
    clear_inventory_cache,
)
from packages.source_intel.analyze import (
    _INVENTORY_BY_TARGET,
    _lookup_cached_inventory,
    _register_inventory,
)
from packages.source_intel.cache import compute_target_signature


@pytest.fixture(autouse=True)
def _reset_caches():
    """Clear both caches before + after every test."""
    clear_all_source_intel_caches()
    yield
    clear_all_source_intel_caches()


# =====================================================================
# compute_target_signature — the substrate
# =====================================================================

def _make_c_file(d: Path, name: str, content: str = "int x;") -> Path:
    p = d / name
    p.write_text(content)
    return p


def test_signature_stable_across_identical_calls(tmp_path):
    _make_c_file(tmp_path, "a.c")
    s1 = compute_target_signature(tmp_path)
    s2 = compute_target_signature(tmp_path)
    assert s1 == s2 and len(s1) == 64  # sha256 hex


def test_signature_changes_when_file_content_changes(tmp_path):
    _make_c_file(tmp_path, "a.c", "int x;")
    s1 = compute_target_signature(tmp_path)
    # mtime resolution on most filesystems is microseconds, but file
    # size MUST change for our cheap signature to catch a same-byte-
    # count edit on a sub-microsecond write. Use a longer write so
    # the size delta carries the signal regardless of mtime granularity.
    time.sleep(0.01)
    _make_c_file(tmp_path, "a.c", "int x; int y; int z;")
    s2 = compute_target_signature(tmp_path)
    assert s1 != s2


def test_signature_changes_when_file_added(tmp_path):
    _make_c_file(tmp_path, "a.c")
    s1 = compute_target_signature(tmp_path)
    _make_c_file(tmp_path, "b.c")
    s2 = compute_target_signature(tmp_path)
    assert s1 != s2


def test_signature_changes_when_build_marker_added(tmp_path):
    _make_c_file(tmp_path, "a.c")
    s1 = compute_target_signature(tmp_path)
    (tmp_path / "Makefile").write_text("all:\n\techo hi\n")
    s2 = compute_target_signature(tmp_path)
    assert s1 != s2


def test_signature_missing_target_returns_sentinel(tmp_path):
    nonexistent = tmp_path / "does-not-exist"
    assert compute_target_signature(nonexistent) == "missing"


def test_signature_ignores_non_c_files(tmp_path):
    _make_c_file(tmp_path, "a.c")
    s1 = compute_target_signature(tmp_path)
    (tmp_path / "README.md").write_text("not C")
    (tmp_path / "data.txt").write_text("not C")
    s2 = compute_target_signature(tmp_path)
    assert s1 == s2


# =====================================================================
# _INVENTORY_BY_TARGET — auto-invalidation
# =====================================================================

def test_inventory_cache_hit_when_target_unchanged(tmp_path):
    _make_c_file(tmp_path, "a.c")
    sentinel = SimpleNamespace(label="inv-v1")
    _register_inventory(tmp_path, sentinel)
    fp = str(tmp_path / "a.c")
    inv, _ = _lookup_cached_inventory(fp)
    assert inv is sentinel


def test_inventory_cache_invalidates_when_target_changes(tmp_path):
    _make_c_file(tmp_path, "a.c", "int x;")
    sentinel = SimpleNamespace(label="inv-v1")
    _register_inventory(tmp_path, sentinel)

    # Mutate target — signature should differ on next lookup.
    time.sleep(0.01)
    _make_c_file(tmp_path, "a.c", "int x; int y; int z;")

    fp = str(tmp_path / "a.c")
    inv, _ = _lookup_cached_inventory(fp)
    assert inv is None, "stale inventory must not win lookup"
    # Stale entry should be popped during the lookup (no growth).
    assert str(tmp_path.resolve()) not in _INVENTORY_BY_TARGET


def test_inventory_cache_invalidates_when_file_added(tmp_path):
    _make_c_file(tmp_path, "a.c")
    sentinel = SimpleNamespace(label="inv-v1")
    _register_inventory(tmp_path, sentinel)
    _make_c_file(tmp_path, "b.c")
    inv, _ = _lookup_cached_inventory(str(tmp_path / "a.c"))
    assert inv is None


def test_clear_inventory_cache_drops_all_entries(tmp_path):
    _make_c_file(tmp_path, "a.c")
    _register_inventory(tmp_path, SimpleNamespace())
    assert _INVENTORY_BY_TARGET  # populated
    clear_inventory_cache()
    assert not _INVENTORY_BY_TARGET  # empty


# =====================================================================
# _SI_RESULT_CACHE — auto-invalidation
# =====================================================================

def test_si_result_cache_invalidates_on_target_change(tmp_path):
    """``prepare_source_intel`` called twice on the same path with a
    content change in between must trigger a re-analyze, not reuse
    the stale result."""
    from packages.llm_analysis import source_intel_inject as inj

    _make_c_file(tmp_path, "a.c", "int x;")
    calls = []

    def _spy(target):
        calls.append(compute_target_signature(target))
        return SimpleNamespace(is_skipped=False, attributes=(), aborts=())

    with mock.patch.object(inj, "_analyze", side_effect=_spy):
        inj.prepare_source_intel(tmp_path)
        # No change → second call must be a no-op (signature unchanged).
        inj.prepare_source_intel(tmp_path)
        assert len(calls) == 1, "second call on unchanged tree should hit cache"

        # Mutate → second prepare must re-invoke _analyze.
        time.sleep(0.01)
        _make_c_file(tmp_path, "a.c", "int x; int y;")
        inj.prepare_source_intel(tmp_path)
        assert len(calls) == 2, "second call on changed tree should miss cache"
        assert calls[0] != calls[1], "signatures should differ pre/post edit"


def test_si_result_cache_returns_empty_on_stale_evidence_lookup(tmp_path):
    """``evidence_blocks_for_finding`` finds a cached entry but the
    target has shifted since prepare. The stale entry must be dropped
    and the call must return an empty tuple (orchestrator can re-prepare)."""
    from packages.llm_analysis import source_intel_inject as inj
    from packages.source_intel.analyze import (
        AttributeEvidence, KIND_NORETURN, SourceIntelResult,
    )

    fp = _make_c_file(tmp_path, "a.c", "int x;")
    result = SourceIntelResult(
        target=str(tmp_path),
        attributes=(
            AttributeEvidence(
                kind=KIND_NORETURN,
                function_name="panic",
                location=(str(fp), 1),
                match_source="literal",
                raw_match="noreturn",
            ),
        ),
    )
    with mock.patch.object(inj, "_analyze", return_value=result):
        inj.prepare_source_intel(tmp_path)

    # Mutate target → stale.
    time.sleep(0.01)
    _make_c_file(tmp_path, "a.c", "int x; int y; int z;")

    finding = {
        "rule_id": "cpp/null-dereference",
        "file_path": str(fp),
        "start_line": 1,
        "end_line": 1,
        "repo_path": str(tmp_path),
        "function": "panic",
    }
    out = inj.evidence_blocks_for_finding(finding)
    assert out == ()  # stale → miss
    # And the stale entry must have been dropped from the cache.
    assert str(tmp_path.resolve()) not in inj._SI_RESULT_CACHE


# =====================================================================
# clear_all_source_intel_caches — top-level orchestrator hook
# =====================================================================

def test_clear_all_drops_both_caches(tmp_path):
    """One call clears the inventory cache AND the si-result cache."""
    from packages.llm_analysis import source_intel_inject as inj
    _make_c_file(tmp_path, "a.c")
    _register_inventory(tmp_path, SimpleNamespace())
    # Manually populate _SI_RESULT_CACHE via prepare with a mocked analyze
    with mock.patch.object(
        inj, "_analyze",
        return_value=SimpleNamespace(is_skipped=False, attributes=(), aborts=()),
    ):
        inj.prepare_source_intel(tmp_path)

    assert _INVENTORY_BY_TARGET
    assert inj._SI_RESULT_CACHE

    clear_all_source_intel_caches()

    assert not _INVENTORY_BY_TARGET
    assert not inj._SI_RESULT_CACHE


def test_clear_all_safe_when_inject_module_unavailable(tmp_path):
    """``clear_all_source_intel_caches`` must tolerate ImportError on
    the inject module path — packages.llm_analysis is optional."""
    _make_c_file(tmp_path, "a.c")
    _register_inventory(tmp_path, SimpleNamespace())

    # Simulate ImportError by patching the import inside the helper.
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "packages.llm_analysis.source_intel_inject":
            raise ImportError("simulated minimal-install")
        return real_import(name, *args, **kwargs)

    with mock.patch.object(builtins, "__import__", side_effect=fake_import):
        clear_all_source_intel_caches()  # must not raise

    assert not _INVENTORY_BY_TARGET  # inventory clear still ran


# =====================================================================
# Concurrency — gap #5
# =====================================================================

def test_concurrent_register_lookup_no_raise(tmp_path):
    """Hammer ``_register_inventory`` and ``_lookup_cached_inventory``
    from multiple threads. The status doc flagged a "likely benign"
    race; the locks added in gap #5 should make it formally benign.
    Any unhandled exception, dict-mutated-during-iteration, or torn
    read would surface as a failed thread or a None vs sentinel
    inversion. None of the threads should raise."""
    import threading

    _make_c_file(tmp_path, "a.c")
    sentinel = SimpleNamespace(label="inv-v1")
    fp = str(tmp_path / "a.c")
    stop = threading.Event()
    errors: list[BaseException] = []
    errors_lock = threading.Lock()

    def writer():
        try:
            while not stop.is_set():
                _register_inventory(tmp_path, sentinel)
        except BaseException as e:  # noqa: BLE001
            with errors_lock:
                errors.append(e)

    def reader():
        try:
            while not stop.is_set():
                inv, _ = _lookup_cached_inventory(fp)
                # During the race window, inv may be sentinel or None
                # (if the entry was popped due to stale signature in a
                # concurrent step). Both are valid; what's NOT valid is
                # a partially-constructed/corrupt object. Sanity-check
                # the type.
                assert inv is None or inv is sentinel
        except BaseException as e:  # noqa: BLE001
            with errors_lock:
                errors.append(e)

    threads = (
        [threading.Thread(target=writer) for _ in range(3)]
        + [threading.Thread(target=reader) for _ in range(5)]
    )
    for t in threads:
        t.start()
    # Short burst is enough — even ~10k iter pairs per thread
    # surface a torn dict reliably under the GIL on a multi-core box.
    time.sleep(0.3)
    stop.set()
    for t in threads:
        t.join(timeout=5.0)
        assert not t.is_alive(), "thread didn't exit — possible deadlock"
    assert errors == [], f"thread(s) raised: {errors}"
