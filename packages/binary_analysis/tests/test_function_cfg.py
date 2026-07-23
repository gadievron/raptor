"""Tests for per-function basic-block CFG extraction (Phase 2).

r2-free: exercises the ``afbj``-JSON parser, the ``BasicBlockCFG``
Graph-protocol adapter (including feeding it to the path-homology core),
and the per-build-id on-disk cache — all without radare2 installed.
"""

import json

import pytest

from core.inventory.path_homology import betti
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
        assert cfg.successors(0x10) == [0x30, 0x20] or \
            set(cfg.successors(0x10)) == {0x20, 0x30}
        assert cfg.successors(0x20) == [0x30]
        assert cfg.successors(0x30) == []
        assert cfg.edge_count == 3

    def test_drops_edges_leaving_the_function(self):
        # jump to 0x999 (a tail call / other function) is not a block here.
        blocks = [{"addr": 0x10, "jump": 0x999, "fail": 0x20},
                  {"addr": 0x20}]
        cfg = parse_afbj(blocks, entry_addr=0x10)
        assert cfg.successors(0x10) == [0x20]  # 0x999 dropped

    def test_drops_self_loop(self):
        blocks = [{"addr": 0x10, "jump": 0x10, "fail": 0x20}, {"addr": 0x20}]
        cfg = parse_afbj(blocks, entry_addr=0x10)
        assert cfg.successors(0x10) == [0x20]

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

    def test_entry_falls_back_to_min_addr(self):
        cfg = parse_afbj([{"addr": 0x50}, {"addr": 0x10}, {"addr": 0x30}])
        assert cfg.entry == 0x10

    def test_duplicate_out_edges_deduped(self):
        cfg = parse_afbj([{"addr": 0x10, "jump": 0x20, "fail": 0x20},
                          {"addr": 0x20}], entry_addr=0x10)
        assert cfg.successors(0x10) == [0x20]


# ---------------------------------------------------------------------------
# BasicBlockCFG as a Graph — feeds path homology
# ---------------------------------------------------------------------------

class TestAdapterFeedsHomology:
    def test_diamond_is_path_contractible(self):
        # if/else diamond: β_1 = 0 (path homology fills the square).
        blocks = [
            {"addr": 0, "jump": 1, "fail": 2},
            {"addr": 1, "jump": 3},
            {"addr": 2, "jump": 3},
            {"addr": 3},
        ]
        cfg = parse_afbj(blocks, entry_addr=0)
        r = betti(cfg, max_dim=2)
        assert r.b0 == 1 and r.b1 == 0

    def test_loop_has_one_cycle(self):
        # while loop: head -> {body, exit}; body -> head.
        blocks = [
            {"addr": 0, "jump": 1},
            {"addr": 1, "jump": 2, "fail": 3},  # head
            {"addr": 2, "jump": 1},             # body -> head (back edge)
            {"addr": 3},                        # exit
        ]
        cfg = parse_afbj(blocks, entry_addr=0)
        r = betti(cfg, max_dim=2)
        assert r.b0 == 1 and r.b1 == 1

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
