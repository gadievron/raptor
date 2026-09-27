"""CPG cache slot concurrency: lock, atomic promote, torn-read close.

Pre-fix, two sessions missing the same slot built directly into it
concurrently (interleaved c2cpg output in one cpg.bin), a reader could
validate the OLD manifest against a NEW mid-promote cpg.bin, and a
failed rebuild clobbered a previously-good slot before failing.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from types import SimpleNamespace

from packages.joern import runner as runner_mod
from packages.joern.runner import (
    _CPG_BUILD_DIR_MAX_AGE_S,
    _CPG_BUILD_DIR_PREFIX,
    _CPG_SLOT_UNSCOPED,
    _sweep_stale_cpg_build_dirs,
    _target_content_hash,
    _write_cpg_manifest,
    build_cpg_cached,
    load_cached_cpg,
)


def _valid_cpg_bytes(methods: int = 5) -> bytes:
    """Minimal structurally-valid cpg.bin (flatgraph JSON tail)."""
    return b"FLATGRAPH" + json.dumps({
        "version": 1,
        "nodes": [{"nodeLabel": "METHOD", "nnodes": methods}],
    }).encode()


def _make_target(tmp_path: Path, name: str = "src") -> Path:
    target = tmp_path / name
    target.mkdir()
    (target / "a.c").write_text("int main() {}")
    return target


def _scratch_dirs(cache: Path) -> list[Path]:
    return [d for d in cache.iterdir()
            if d.name.startswith(_CPG_BUILD_DIR_PREFIX)]


class TestBuildIsPrivateThenPromoted:
    def test_build_output_is_scratch_and_promote_is_complete(self, tmp_path):
        target = _make_target(tmp_path)
        cache = tmp_path / "cache"
        seen: dict = {}

        def fake_runner(cmd, **kw):
            out = Path(cmd[cmd.index("--output") + 1])
            seen["build_dir"] = out.parent
            out.write_bytes(_valid_cpg_bytes())
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        result = build_cpg_cached(
            target, cache, subprocess_runner=fake_runner)

        # The build never touched the slot: it ran in hidden scratch
        # under the cache dir (same filesystem, so the promote below
        # is an atomic rename).
        assert seen["build_dir"].name.startswith(_CPG_BUILD_DIR_PREFIX)
        assert seen["build_dir"].parent == cache
        # Promote is complete: slot holds cpg.bin + manifest, the
        # handle points at the SLOT copy, scratch is gone.
        slot = cache / _CPG_SLOT_UNSCOPED
        assert result.path == slot / "cpg.bin"
        assert result.path.exists()
        assert (slot / "manifest.json").exists()
        assert _scratch_dirs(cache) == []
        # And the promoted graph round-trips as a cache hit.
        assert load_cached_cpg(target, cache) is not None

    def test_failed_build_leaves_previous_slot_intact(self, tmp_path):
        # Pre-fix the build wrote INTO the slot, so a failed rebuild
        # destroyed a previously-good graph before failing. Now the
        # slot is untouched until a verified build is promoted.
        target = _make_target(tmp_path)
        cache = tmp_path / "cache"
        slot = cache / _CPG_SLOT_UNSCOPED
        slot.mkdir(parents=True)
        old_bytes = _valid_cpg_bytes(methods=7)
        (slot / "cpg.bin").write_bytes(old_bytes)
        _write_cpg_manifest(slot, target, "stale-hash", {"c"}, 100)
        old_manifest = (slot / "manifest.json").read_text()

        def failing_runner(cmd, **kw):
            return SimpleNamespace(returncode=1, stdout="", stderr="boom")

        result = build_cpg_cached(
            target, cache, subprocess_runner=failing_runner)
        # joern-parse exited nonzero without producing output: the
        # handle is unusable (no file) whatever build_failed says.
        assert result.build_failed or not result.path.exists()
        assert (slot / "cpg.bin").read_bytes() == old_bytes
        assert (slot / "manifest.json").read_text() == old_manifest
        assert _scratch_dirs(cache) == []

    def test_unverifiable_build_kept_in_scratch_not_cached(self, tmp_path):
        # No parseable flatgraph tail: the run still uses the build
        # (handle points into scratch; cleanup_cpg removes it), but
        # nothing is promoted — the next run rebuilds.
        target = _make_target(tmp_path)
        cache = tmp_path / "cache"

        def garbage_runner(cmd, **kw):
            out = Path(cmd[cmd.index("--output") + 1])
            out.write_bytes(b"not a flatgraph")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        result = build_cpg_cached(
            target, cache, subprocess_runner=garbage_runner)
        assert not result.build_failed
        assert result.path.exists()
        assert result.path.parent.name.startswith(_CPG_BUILD_DIR_PREFIX)
        assert not (cache / _CPG_SLOT_UNSCOPED / "manifest.json").exists()


class TestSlotLockSerialises:
    def test_concurrent_same_target_builds_pay_one_build(self, tmp_path):
        # Two sessions miss the same slot at once. The slot lock
        # serialises them and the loser's double-checked reload turns
        # its miss into a hit — exactly ONE build runs.
        target = _make_target(tmp_path)
        cache = tmp_path / "cache"
        build_started = threading.Event()
        release_build = threading.Event()
        build_count = 0
        count_lock = threading.Lock()

        def slow_runner(cmd, **kw):
            nonlocal build_count
            with count_lock:
                build_count += 1
            build_started.set()
            release_build.wait(timeout=30)
            out = Path(cmd[cmd.index("--output") + 1])
            out.write_bytes(_valid_cpg_bytes())
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        results: list = []

        def worker():
            results.append(build_cpg_cached(
                target, cache, subprocess_runner=slow_runner))

        t1 = threading.Thread(target=worker)
        t1.start()
        assert build_started.wait(timeout=30)
        t2 = threading.Thread(target=worker)
        t2.start()  # queues on the slot lock while t1 builds
        release_build.set()
        t1.join(timeout=60)
        t2.join(timeout=60)
        assert len(results) == 2
        assert build_count == 1
        slot_cpg = cache / _CPG_SLOT_UNSCOPED / "cpg.bin"
        for r in results:
            assert not r.build_failed
            assert r.path == slot_cpg


class TestReaderTornReadClose:
    def test_manifest_change_during_validation_is_a_miss(self, tmp_path,
                                                         monkeypatch):
        # A concurrent promote lands between this reader's manifest
        # snapshot and its return: the snapshot no longer describes
        # the bytes on disk, so the reader must miss, not serve a
        # graph validated against the wrong manifest.
        target = _make_target(tmp_path)
        cache = tmp_path / "cache"
        slot = cache / _CPG_SLOT_UNSCOPED
        slot.mkdir(parents=True)
        (slot / "cpg.bin").write_bytes(_valid_cpg_bytes())
        _write_cpg_manifest(
            slot, target, _target_content_hash(target), {"c"}, 100)

        real_probe = runner_mod.cpg_method_count

        def racing_probe(path):
            # Simulate a sibling's promote mid-validation: new bytes,
            # new manifest.
            (slot / "cpg.bin").write_bytes(_valid_cpg_bytes(methods=9))
            _write_cpg_manifest(
                slot, target, _target_content_hash(target), {"c"}, 999)
            return real_probe(path)

        monkeypatch.setattr(runner_mod, "cpg_method_count", racing_probe)
        assert load_cached_cpg(target, cache) is None
        # Quiescent slot still serves (the re-read is not a stricter
        # freshness rule, only a torn-read close).
        monkeypatch.setattr(runner_mod, "cpg_method_count", real_probe)
        assert load_cached_cpg(target, cache) is not None


class TestStaleScratchSweep:
    def test_old_scratch_removed_fresh_kept(self, tmp_path):
        cache = tmp_path / "cache"
        cache.mkdir()
        old = cache / f"{_CPG_BUILD_DIR_PREFIX}dead"
        old.mkdir()
        (old / "cpg.bin").write_bytes(b"x")
        past = 1_000_000.0
        os.utime(old, (past, past))
        fresh = cache / f"{_CPG_BUILD_DIR_PREFIX}live"
        fresh.mkdir()  # mtime = now, could be a LIVE sibling's build
        slot = cache / _CPG_SLOT_UNSCOPED
        slot.mkdir()
        os.utime(slot, (past, past))  # old but not scratch — exempt

        _sweep_stale_cpg_build_dirs(cache)
        assert not old.exists()      # orphaned crash debris reclaimed
        assert fresh.exists()        # in-progress build untouched
        assert slot.exists()         # slots are never sweep targets

    def test_boundary_is_two_directional(self, tmp_path):
        # _CPG_BUILD_DIR_MAX_AGE_S is churn-prone: too low sweeps a
        # live sibling's multi-hour build mid-write, too high strands
        # multi-GB debris. Pin both sides of the boundary.
        cache = tmp_path / "cache"
        cache.mkdir()
        import time as _time
        now = _time.time()
        just_under = cache / f"{_CPG_BUILD_DIR_PREFIX}under"
        just_under.mkdir()
        t_under = now - (_CPG_BUILD_DIR_MAX_AGE_S - 3600)
        os.utime(just_under, (t_under, t_under))
        just_over = cache / f"{_CPG_BUILD_DIR_PREFIX}over"
        just_over.mkdir()
        t_over = now - (_CPG_BUILD_DIR_MAX_AGE_S + 3600)
        os.utime(just_over, (t_over, t_over))
        _sweep_stale_cpg_build_dirs(cache)
        assert just_under.exists()
        assert not just_over.exists()

    def test_symlinked_scratch_never_removed_through(self, tmp_path):
        cache = tmp_path / "cache"
        cache.mkdir()
        victim = tmp_path / "victim"
        victim.mkdir()
        (victim / "keep.txt").write_text("x")
        link = cache / f"{_CPG_BUILD_DIR_PREFIX}link"
        link.symlink_to(victim)
        os.utime(link, (1, 1), follow_symlinks=False)
        _sweep_stale_cpg_build_dirs(cache)
        assert (victim / "keep.txt").exists()
