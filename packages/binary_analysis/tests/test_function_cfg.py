"""Tests for per-function basic-block CFG extraction.

r2-free: exercises the ``afbj``-JSON parser, the ``BasicBlockCFG``
Graph-protocol adapter (including feeding it to the live dominator and
CFG-metric consumers), and the per-build-id on-disk cache — all without
radare2 installed.
"""

import json
from pathlib import Path

import pytest

from core.analysis.cfg_metrics import cyclomatic_number
from core.analysis.dominators import build_dom_tree
from packages.binary_analysis import function_cfg
from packages.binary_analysis.function_cfg import (
    BasicBlockCFG,
    load_cached_cfgs,
    parse_afbj,
    save_cached_cfgs,
)


# ---------------------------------------------------------------------------
# parse_afbj
# ---------------------------------------------------------------------------

class TestParseAfbj:
    def test_empty_and_garbage(self):
        assert parse_afbj([]).adjacency == {}
        assert parse_afbj(None).adjacency == {}
        assert parse_afbj([42, "x", None]).adjacency == {}

    def test_straight_line_single_block(self):
        cfg = parse_afbj([{"addr": 0x1000, "size": 16}], entry_addr=0x1000)
        assert cfg.block_count == 1
        assert cfg.edge_count == 0
        assert cfg.entry == 0x1000

    def test_conditional_branch_jump_and_fail(self):
        blocks = [
            {"addr": 0x10, "jump": 0x30, "fail": 0x20},  # if
            {"addr": 0x20, "jump": 0x30},                # then -> join
            {"addr": 0x30},                              # join
        ]
        cfg = parse_afbj(blocks, entry_addr=0x10)
        assert set(cfg.successors(0x10)) == {0x20, 0x30}
        assert cfg.successors(0x20) == [0x30]
        assert cfg.successors(0x30) == []
        assert cfg.edge_count == 3

    def test_drops_edges_leaving_the_function(self):
        # jump to 0x999 (a tail call / other function) is not a block here.
        blocks = [{"addr": 0x10, "jump": 0x999, "fail": 0x20},
                  {"addr": 0x20}]
        cfg = parse_afbj(blocks, entry_addr=0x10)
        assert cfg.successors(0x10) == [0x20]  # 0x999 dropped

    def test_keeps_self_loop(self):
        # A block branching to itself is real control flow (single-block
        # spin loop) and must survive extraction.
        blocks = [{"addr": 0x10, "jump": 0x10, "fail": 0x20}, {"addr": 0x20}]
        cfg = parse_afbj(blocks, entry_addr=0x10)
        assert set(cfg.successors(0x10)) == {0x10, 0x20}

    def test_single_block_spin_loop_cyclomatic_is_one(self):
        # McCabe regression: while(1); compiles to one block jumping to
        # itself. Dropping the self-edge under-reported cyclomatic as 0.
        cfg = parse_afbj([{"addr": 0x10, "jump": 0x10}], entry_addr=0x10)
        assert cfg.successors(0x10) == [0x10]
        assert cyclomatic_number(cfg) == 1

    def test_offset_key_fallback(self):
        # Some r2 builds key the block address as "offset".
        cfg = parse_afbj([{"offset": 0x10, "jump": 0x20},
                          {"offset": 0x20}], entry_addr=0x10)
        assert cfg.block_count == 2
        assert cfg.successors(0x10) == [0x20]

    def test_switch_cases_parsed(self):
        blocks = [
            {"addr": 0x10, "switch_op": {"cases": [
                {"jump": 0x20}, {"jump": 0x30}, {"jump": 0x40}]}},
            {"addr": 0x20}, {"addr": 0x30}, {"addr": 0x40},
        ]
        cfg = parse_afbj(blocks, entry_addr=0x10)
        assert set(cfg.successors(0x10)) == {0x20, 0x30, 0x40}

    def test_bare_case_list_parsed(self):
        # r2 sometimes exposes case targets as a bare list on the block.
        blocks = [{"addr": 0x10, "cases": [0x20, {"addr": 0x30}]},
                  {"addr": 0x20}, {"addr": 0x30}]
        cfg = parse_afbj(blocks, entry_addr=0x10)
        assert set(cfg.successors(0x10)) == {0x20, 0x30}

    def test_entry_falls_back_to_min_addr(self):
        cfg = parse_afbj([{"addr": 0x50}, {"addr": 0x10}, {"addr": 0x30}])
        assert cfg.entry == 0x10

    def test_entry_none_on_empty(self):
        assert parse_afbj([]).entry is None

    def test_duplicate_out_edges_deduped(self):
        cfg = parse_afbj([{"addr": 0x10, "jump": 0x20, "fail": 0x20},
                          {"addr": 0x20}], entry_addr=0x10)
        assert cfg.successors(0x10) == [0x20]

    def test_duplicate_block_records_first_wins(self):
        cfg = parse_afbj([{"addr": 0x10, "jump": 0x20},
                          {"addr": 0x10, "jump": 0x30},
                          {"addr": 0x20}, {"addr": 0x30}], entry_addr=0x10)
        # Both records contribute edges to the same block; no crash, no
        # duplicate node.
        assert cfg.block_count == 3
        assert set(cfg.successors(0x10)) == {0x20, 0x30}

    def test_duplicate_block_records_dedupe_shared_edges(self):
        # A hostile listing repeating the same record must not inflate
        # the edge set — dedup spans records, not just within one.
        cfg = parse_afbj([{"addr": 0x10, "jump": 0x20},
                          {"addr": 0x10, "jump": 0x20},
                          {"addr": 0x20}], entry_addr=0x10)
        assert cfg.successors(0x10) == [0x20]
        assert cfg.edge_count == 1

    def test_bool_addresses_rejected(self):
        # bool is an int subclass; a hostile {"addr": true} must not
        # materialise as block address 1.
        cfg = parse_afbj([{"addr": True, "jump": False},
                          {"addr": 0x10, "jump": True}], entry_addr=0x10)
        assert cfg.nodes() == [0x10]
        assert cfg.successors(0x10) == []

    def test_malformed_switch_shapes_ignored(self):
        blocks = [
            {"addr": 0x10, "switch_op": "not-a-dict"},
            {"addr": 0x20, "switch_op": {"cases": "not-a-list"}},
            {"addr": 0x30, "cases": [None, "x", {"jump": "y"}, 2.5]},
        ]
        cfg = parse_afbj(blocks, entry_addr=0x10)
        assert cfg.block_count == 3
        assert cfg.edge_count == 0


# ---------------------------------------------------------------------------
# BasicBlockCFG as a Graph — feeds the live consumers
# ---------------------------------------------------------------------------

class TestAdapterFeedsConsumers:
    def test_diamond_dominators(self):
        # if/else diamond: the branch head dominates everything; neither
        # arm dominates the join.
        blocks = [
            {"addr": 0, "jump": 1, "fail": 2},
            {"addr": 1, "jump": 3},
            {"addr": 2, "jump": 3},
            {"addr": 3},
        ]
        cfg = parse_afbj(blocks, entry_addr=0)
        dom = build_dom_tree(cfg)
        assert dom.idom(3) == 0
        assert dom.dominates(0, 3)
        assert not dom.dominates(1, 3)

    def test_loop_dominators_and_cyclomatic(self):
        # while loop: head -> {body, exit}; body -> head.
        blocks = [
            {"addr": 0, "jump": 1},
            {"addr": 1, "jump": 2, "fail": 3},  # head
            {"addr": 2, "jump": 1},             # body -> head (back edge)
            {"addr": 3},                        # exit
        ]
        cfg = parse_afbj(blocks, entry_addr=0)
        dom = build_dom_tree(cfg)
        assert dom.idom(2) == 1
        assert dom.idom(3) == 1
        assert cyclomatic_number(cfg) == 1

    def test_nodes_and_successors(self):
        cfg = BasicBlockCFG(entry=0, adjacency={0: [1], 1: []})
        assert set(cfg.nodes()) == {0, 1}
        assert cfg.successors(0) == [1]
        assert cfg.successors(99) == []
        assert cfg.block_count == 2 and cfg.edge_count == 1


# ---------------------------------------------------------------------------
# Per-build-id cache
# ---------------------------------------------------------------------------

@pytest.fixture
def cache_dir(tmp_path, monkeypatch):
    d = tmp_path / "cfg-cache"
    monkeypatch.setattr(function_cfg, "_cache_dir", lambda: d)
    return d


def _make_binary(tmp_path, name, content=b"\x7fELF not-a-real-binary"):
    p = tmp_path / name
    p.write_bytes(content)
    return p


class TestCache:
    def test_round_trip(self, tmp_path, cache_dir):
        binary = _make_binary(tmp_path, "a.bin")
        cfgs = {0x10: BasicBlockCFG(entry=0x10, adjacency={0x10: [0x20], 0x20: []})}
        save_cached_cfgs(binary, cfgs)
        loaded = load_cached_cfgs(binary)
        assert loaded is not None
        assert set(loaded) == {0x10}
        assert loaded[0x10].entry == 0x10
        assert loaded[0x10].adjacency == {0x10: [0x20], 0x20: []}

    def test_self_loop_survives_round_trip(self, tmp_path, cache_dir):
        binary = _make_binary(tmp_path, "spin.bin")
        cfgs = {0x10: BasicBlockCFG(entry=0x10, adjacency={0x10: [0x10]})}
        save_cached_cfgs(binary, cfgs)
        loaded = load_cached_cfgs(binary)
        assert loaded is not None
        assert loaded[0x10].adjacency == {0x10: [0x10]}
        assert cyclomatic_number(loaded[0x10]) == 1

    def test_miss_when_absent(self, tmp_path, cache_dir):
        assert load_cached_cfgs(_make_binary(tmp_path, "nope.bin")) is None

    def test_version_mismatch_is_miss(self, tmp_path, cache_dir):
        binary = _make_binary(tmp_path, "v.bin")
        save_cached_cfgs(binary, {0x1: BasicBlockCFG(entry=0x1, adjacency={0x1: []})})
        # Corrupt the version on disk.
        cache_file = next(cache_dir.glob("*.json"))
        payload = json.loads(cache_file.read_text())
        payload["version"] = 999
        cache_file.write_text(json.dumps(payload))
        assert load_cached_cfgs(binary) is None

    def test_build_id_collision_is_miss(self, tmp_path, cache_dir):
        # Two files with identical content share a cache key; loading the
        # second must detect the binary_path mismatch and refuse.
        same = b"\x7fELF identical-content"
        a = _make_binary(tmp_path, "a.bin", same)
        b = _make_binary(tmp_path, "b.bin", same)
        save_cached_cfgs(a, {0x1: BasicBlockCFG(entry=0x1, adjacency={0x1: []})})
        assert load_cached_cfgs(b) is None      # collision guard
        assert load_cached_cfgs(a) is not None  # original still hits

    def test_missing_binary_path_field_is_miss(self, tmp_path, cache_dir):
        # A payload with the collision-guard field stripped must be
        # treated as a miss, not trusted.
        binary = _make_binary(tmp_path, "strip.bin")
        save_cached_cfgs(binary, {0x1: BasicBlockCFG(entry=0x1, adjacency={0x1: []})})
        cache_file = next(cache_dir.glob("*.json"))
        payload = json.loads(cache_file.read_text())
        del payload["binary_path"]
        cache_file.write_text(json.dumps(payload))
        assert load_cached_cfgs(binary) is None

    def test_malformed_payloads_are_misses(self, tmp_path, cache_dir):
        binary = _make_binary(tmp_path, "m.bin")
        save_cached_cfgs(binary, {0x1: BasicBlockCFG(entry=0x1, adjacency={0x1: []})})
        cache_file = next(cache_dir.glob("*.json"))

        def _payload(cfgs):
            return json.dumps(
                {"version": 1, "binary_path": str(binary), "cfgs": cfgs})

        for garbage in (
            "not json at all",
            json.dumps([1, 2, 3]),
            # version smuggling: bool is an int subclass and True == 1.
            json.dumps({"version": True, "binary_path": str(binary),
                        "cfgs": {}}),
            _payload("not-a-dict"),
            _payload({"xyz": {"entry": None, "adjacency": {"a": ["b"]}}}),
            _payload({"16": {"entry": "0x10", "adjacency": {}}}),
            _payload({"16": ["not", "a", "dict"]}),
            # bool entry (the coercion _is_addr exists to reject).
            _payload({"16": {"entry": True, "adjacency": {"16": []}}}),
            # string successors would iterate char-wise under int().
            _payload({"16": {"entry": 16, "adjacency": {"16": "123"}}}),
            # float / bool targets must not truncate-coerce.
            _payload({"16": {"entry": 16, "adjacency": {"16": [1.9]}}}),
            _payload({"16": {"entry": 16, "adjacency": {"16": [True]}}}),
            # non-canonical int keys ("1_0" == 10 under int()).
            _payload({"1_0": {"entry": None, "adjacency": {}}}),
            # parser invariants: targets and entry must be member blocks.
            _payload({"16": {"entry": 16, "adjacency": {"16": [99]}}}),
            _payload({"16": {"entry": 99, "adjacency": {"16": []}}}),
        ):
            cache_file.write_text(garbage)
            assert load_cached_cfgs(binary) is None

    def test_deeply_nested_cache_json_is_a_miss(self, tmp_path, cache_dir):
        # json.loads raises RecursionError on deep nesting; a tampered
        # cache file must read as a miss, not abort the analysis run.
        binary = _make_binary(tmp_path, "deep.bin")
        save_cached_cfgs(binary, {0x1: BasicBlockCFG(entry=0x1, adjacency={0x1: []})})
        cache_file = next(cache_dir.glob("*.json"))
        cache_file.write_text("[" * 100_000 + "]" * 100_000)
        assert load_cached_cfgs(binary) is None

    def test_save_never_raises_on_unwritable_dir(self, tmp_path, cache_dir, monkeypatch):
        binary = _make_binary(tmp_path, "w.bin")
        monkeypatch.setattr(
            function_cfg, "_cache_dir",
            lambda: tmp_path / "w.bin" / "not-a-dir")  # parent is a file
        save_cached_cfgs(binary, {0x1: BasicBlockCFG(entry=0x1, adjacency={})})
        # Best-effort: no exception is the assertion.


class TestCacheWriteSubstrate:
    def test_save_routes_through_atomic_save_json(
        self, tmp_path, cache_dir,
    ):
        """Cache saves must go through core.json.save_json — the
        hand-rolled predecessor used a CONSTANT `.json.tmp` sidecar
        per key, racing concurrent saves on the same tempfile."""
        from unittest.mock import patch

        import core.json as core_json

        real_save = core_json.save_json
        calls = []

        def spy(path, data, *args, **kwargs):
            calls.append(path)
            return real_save(path, data, *args, **kwargs)

        binary = _make_binary(tmp_path, "atomic.bin")
        cfgs = {0x10: BasicBlockCFG(entry=0x10, adjacency={0x10: []})}
        with patch.object(core_json, "save_json", side_effect=spy):
            save_cached_cfgs(binary, cfgs)

        # The patch window is process-global: background work from
        # other components may legitimately route saves through the
        # same chokepoint while it is open, so count only writes into
        # this test's cache dir.
        cache_calls = [p for p in calls if Path(p).parent == cache_dir]
        assert len(cache_calls) == 1
        # No constant-name tempfile sidecar left (or racing) on disk.
        assert list(cache_dir.glob("*.json.tmp")) == []
        assert load_cached_cfgs(binary) is not None

    def test_content_sha_matches_core_hash(self, tmp_path):
        from core.hash import sha256_file

        from packages.binary_analysis.function_cfg import _content_sha

        binary = _make_binary(tmp_path, "hash.bin", b"some bytes")
        assert _content_sha(binary) == sha256_file(binary)
        assert _content_sha(tmp_path / "missing.bin") is None
