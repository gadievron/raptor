"""Per-scope CPG cache slots and the scope cache-semantics contract.

Consumers key on their OWN scope: an unscoped consumer must refuse a
scoped graph and vice versa; distinct scopes never share a slot; the
legacy single-slot layout keeps loading as the unscoped key; retained
scoped slots are bounded.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

from packages.joern.runner import (
    _CPG_SCOPED_SLOTS_KEEP,
    _CPG_SLOT_SCOPED_PREFIX,
    _CPG_SLOT_UNSCOPED,
    _prune_scoped_cpg_slots,
    _target_content_hash,
    _write_cpg_manifest,
    build_cpg_cached,
    cpg_cache_slot_name,
    load_cached_cpg,
)


def _valid_cpg_bytes(methods: int = 5) -> bytes:
    """Minimal structurally-valid cpg.bin (flatgraph JSON tail)."""
    return b"FLATGRAPH" + json.dumps({
        "version": 1,
        "nodes": [{"nodeLabel": "METHOD", "nnodes": methods}],
    }).encode()


def _seed_slot(cache: Path, slot: str, target: Path,
               content_hash: str, scope_exclude_dirs=()) -> Path:
    cpg_dir = cache / slot
    cpg_dir.mkdir(parents=True, exist_ok=True)
    (cpg_dir / "cpg.bin").write_bytes(_valid_cpg_bytes())
    _write_cpg_manifest(
        cpg_dir, target, content_hash, {"c"}, 100,
        scope_exclude_dirs=scope_exclude_dirs,
    )
    return cpg_dir


class TestSlotNaming:
    def test_unscoped_is_legacy_slot(self):
        assert cpg_cache_slot_name(()) == _CPG_SLOT_UNSCOPED

    def test_scoped_slot_is_deterministic_and_order_free(self, tmp_path):
        a = tmp_path / "a"
        b = tmp_path / "b"
        a.mkdir()
        b.mkdir()
        one = cpg_cache_slot_name((str(a), str(b)))
        two = cpg_cache_slot_name((str(b), str(a)))
        assert one == two
        assert one.startswith(_CPG_SLOT_SCOPED_PREFIX)

    def test_distinct_scopes_distinct_slots(self, tmp_path):
        a = tmp_path / "a"
        b = tmp_path / "b"
        a.mkdir()
        b.mkdir()
        assert cpg_cache_slot_name((str(a),)) != cpg_cache_slot_name((str(b),))


class TestScopeContract:
    def test_legacy_slot_still_loads_for_unscoped_consumer(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        (target / "a.c").write_text("int main() {}")
        cache = tmp_path / "cache"
        _seed_slot(cache, _CPG_SLOT_UNSCOPED, target,
                   _target_content_hash(target))
        assert load_cached_cpg(target, cache) is not None

    def test_unscoped_consumer_refuses_scoped_graph(self, tmp_path):
        # A scoped manifest sitting in the legacy slot (or any slot
        # the consumer resolves) must be refused, not served.
        target = tmp_path / "src"
        target.mkdir()
        (target / "a.c").write_text("int main() {}")
        skip = target / "vendor_tree"
        skip.mkdir()
        cache = tmp_path / "cache"
        _seed_slot(
            cache, _CPG_SLOT_UNSCOPED, target,
            _target_content_hash(target),
            scope_exclude_dirs=(str(skip),),
        )
        assert load_cached_cpg(target, cache) is None

    def test_scoped_consumer_refuses_unscoped_slot_and_uses_own(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        (target / "a.c").write_text("int main() {}")
        skip = target / "outofscope"
        skip.mkdir()
        (skip / "b.c").write_text("int f() {}")
        scope = (str(skip),)
        cache = tmp_path / "cache"
        # Fresh unscoped graph exists — the scoped consumer must not
        # adopt it.
        _seed_slot(cache, _CPG_SLOT_UNSCOPED, target,
                   _target_content_hash(target))
        assert load_cached_cpg(
            target, cache, scope_exclude_dirs=scope) is None
        # Its own slot serves it.
        _seed_slot(
            cache, cpg_cache_slot_name(scope), target,
            _target_content_hash(target, exclude_dirs=scope),
            scope_exclude_dirs=scope,
        )
        got = load_cached_cpg(target, cache, scope_exclude_dirs=scope)
        assert got is not None
        assert got.path.parent.name == cpg_cache_slot_name(scope)

    def test_scope_joins_content_key(self, tmp_path):
        # An edit INSIDE the scope complement must not stale the
        # scoped graph (it was never part of its coverage).
        target = tmp_path / "src"
        target.mkdir()
        (target / "a.c").write_text("int main() {}")
        skip = target / "outofscope"
        skip.mkdir()
        (skip / "b.c").write_text("int f() {}")
        scope = (str(skip),)
        cache = tmp_path / "cache"
        _seed_slot(
            cache, cpg_cache_slot_name(scope), target,
            _target_content_hash(target, exclude_dirs=scope),
            scope_exclude_dirs=scope,
        )
        (skip / "b.c").write_text("int f() { return 1; }")
        assert load_cached_cpg(
            target, cache, scope_exclude_dirs=scope) is not None
        # An in-scope edit still stales it.
        (target / "a.c").write_text("int main() { return 1; }")
        assert load_cached_cpg(
            target, cache, scope_exclude_dirs=scope) is None


class TestBuildCpgCachedScoped:
    def test_scoped_cache_hit_no_build(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        (target / "a.c").write_text("int main() {}")
        skip = target / "outofscope"
        skip.mkdir()
        scope = (str(skip),)
        cache = tmp_path / "cache"
        _seed_slot(
            cache, cpg_cache_slot_name(scope), target,
            _target_content_hash(target, exclude_dirs=scope),
            scope_exclude_dirs=scope,
        )
        calls = []

        def fake_runner(cmd, **kw):
            calls.append(cmd)
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        result = build_cpg_cached(
            target, cache, subprocess_runner=fake_runner,
            scope_exclude_dirs=scope,
        )
        assert result.path.parent.name == cpg_cache_slot_name(scope)
        assert calls == []

    def test_scoped_build_passes_excludes_and_writes_slot(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        (target / "a.c").write_text("int main() {}")
        skip = target / "outofscope"
        skip.mkdir()
        scope = (str(skip),)
        cache = tmp_path / "cache"
        seen: dict = {}

        def fake_runner(cmd, **kw):
            seen["cmd"] = list(cmd)
            out = Path(cmd[cmd.index("--output") + 1])
            out.write_bytes(_valid_cpg_bytes())
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        result = build_cpg_cached(
            target, cache, subprocess_runner=fake_runner,
            scope_exclude_dirs=scope,
        )
        slot = cpg_cache_slot_name(scope)
        assert result.path.parent.name == slot
        assert str(skip.resolve()) in seen["cmd"]  # --exclude parity
        manifest = json.loads((cache / slot / "manifest.json").read_text())
        assert manifest["scope_exclude_dirs"] == [str(skip.resolve())]


class TestScopedSlotPruning:
    def test_keeps_newest_n_and_active_and_unscoped(self, tmp_path):
        cache = tmp_path
        (cache / _CPG_SLOT_UNSCOPED).mkdir()
        names = []
        for i in range(_CPG_SCOPED_SLOTS_KEEP + 3):
            d = cache / f"{_CPG_SLOT_SCOPED_PREFIX}{i:012x}"
            d.mkdir()
            os.utime(d, (1000 + i, 1000 + i))
            names.append(d.name)
        active = names[0]  # oldest — active must survive regardless
        _prune_scoped_cpg_slots(cache, active_slot=active)
        remaining = {d.name for d in cache.iterdir()}
        assert _CPG_SLOT_UNSCOPED in remaining
        assert active in remaining
        scoped_left = [
            n for n in remaining if n.startswith(_CPG_SLOT_SCOPED_PREFIX)
        ]
        assert len(scoped_left) <= _CPG_SCOPED_SLOTS_KEEP + 1
        # Newest N all survive.
        for n in names[-_CPG_SCOPED_SLOTS_KEEP:]:
            assert n in remaining

    def test_symlink_slot_never_removed_through(self, tmp_path):
        cache = tmp_path / "cache"
        cache.mkdir()
        victim = tmp_path / "victim"
        victim.mkdir()
        (victim / "keep.txt").write_text("x")
        for i in range(_CPG_SCOPED_SLOTS_KEEP + 2):
            d = cache / f"{_CPG_SLOT_SCOPED_PREFIX}{i:012x}"
            d.mkdir()
            os.utime(d, (2000 + i, 2000 + i))
        link = cache / f"{_CPG_SLOT_SCOPED_PREFIX}{'f' * 12}"
        link.symlink_to(victim)
        os.utime(link, (1, 1), follow_symlinks=False)
        _prune_scoped_cpg_slots(cache, active_slot="none")
        assert (victim / "keep.txt").exists()

    def test_cache_hit_bumps_slot_recency(self, tmp_path):
        # Prune orders by slot mtime; without the hit-time recency
        # bump a frequently-HIT old slot would evict before a
        # never-read newer one.
        target = tmp_path / "src"
        target.mkdir()
        (target / "a.c").write_text("int main() {}")
        skip = target / "outofscope"
        skip.mkdir()
        scope = (str(skip),)
        cache = tmp_path / "cache"
        hot = _seed_slot(
            cache, cpg_cache_slot_name(scope), target,
            _target_content_hash(target, exclude_dirs=scope),
            scope_exclude_dirs=scope,
        )
        os.utime(hot, (1000, 1000))  # oldest by build time
        cold_names = []
        for i in range(_CPG_SCOPED_SLOTS_KEEP):
            d = cache / f"{_CPG_SLOT_SCOPED_PREFIX}{i:012x}"
            d.mkdir()
            os.utime(d, (2000 + i, 2000 + i))
            cold_names.append(d.name)
        # The hit refreshes recency to now.
        assert load_cached_cpg(
            target, cache, scope_exclude_dirs=scope) is not None
        _prune_scoped_cpg_slots(cache, active_slot=cold_names[-1])
        remaining = {d.name for d in cache.iterdir()}
        assert hot.name in remaining           # protected by the hit
        assert cold_names[0] not in remaining  # oldest unhit evicted
