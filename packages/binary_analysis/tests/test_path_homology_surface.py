"""Tests for the path-homology surface in binary analysis (Phase 3).

r2-free: builds a BinaryContextMap whose functions carry basic-block
CFGs (via function_cfg.parse_afbj), then exercises compute_path_homology,
the homology_report helper, and to_dict surfacing — no radare2 needed.
"""

from pathlib import Path

from packages.binary_analysis.function_cfg import parse_afbj
from packages.binary_analysis.radare2_understand import (
    _BETTI_BONUS_CAP,
    BinaryContextMap,
    FunctionInfo,
    betti_priority_bonus,
    compute_path_homology,
    homology_report,
)


# Basic-block CFG shapes (afbj-style records) ------------------------------

_DIAMOND = [  # if/else: β_1 = 0 (path homology fills the square)
    {"addr": 0, "jump": 1, "fail": 2},
    {"addr": 1, "jump": 3},
    {"addr": 2, "jump": 3},
    {"addr": 3},
]
_LOOP = [  # while loop: β_1 = 1, β_2 = 0
    {"addr": 0, "jump": 1},
    {"addr": 1, "jump": 2, "fail": 3},
    {"addr": 2, "jump": 1},
    {"addr": 3},
]
# K_{2,2,2} layered as basic blocks → β_2 = 1 (irreducible).
_IRREDUCIBLE = [
    {"addr": 0, "jump": 2, "fail": 3},
    {"addr": 1, "jump": 2, "fail": 3},
    {"addr": 2, "jump": 4, "fail": 5},
    {"addr": 3, "jump": 4, "fail": 5},
    {"addr": 4},
    {"addr": 5},
]


def _fn(name, addr, blocks):
    f = FunctionInfo(name=name, address=addr)
    f.basic_block_cfg = parse_afbj(blocks, entry_addr=addr)
    return f


def _ctx(fns):
    ctx = BinaryContextMap(binary_path=Path("/tmp/x.bin"))
    ctx.interesting_functions = fns
    return ctx


class TestComputePathHomology:
    def test_loop_and_diamond_betti(self):
        ctx = _ctx([_fn("loop", 0x10, _LOOP), _fn("diamond", 0x20, _DIAMOND)])
        n = compute_path_homology(ctx)
        assert n == 2
        loop, diamond = ctx.interesting_functions
        assert loop.path_betti[1] == 1          # one genuine cycle
        assert diamond.path_betti[1] == 0       # filled commutative square
        assert loop.decompiler_low_confidence is False
        assert diamond.decompiler_low_confidence is False

    def test_irreducible_sets_low_confidence(self):
        ctx = _ctx([_fn("gnarly", 0x30, _IRREDUCIBLE)])
        compute_path_homology(ctx)
        fn = ctx.interesting_functions[0]
        assert fn.path_betti[2] == 1            # β_2 > 0 ⇒ irreducible
        assert fn.decompiler_low_confidence is True
        # And a context note flags it for the operator.
        assert any("irreducible control flow" in note for note in ctx.notes)

    def test_cyclomatic_reported(self):
        ctx = _ctx([_fn("loop", 0x10, _LOOP)])
        compute_path_homology(ctx)
        # while loop: 4 blocks, edges 0->1,1->2,1->3,2->1 = 4; 4-4+1 = 1.
        assert ctx.interesting_functions[0].cyclomatic == 1

    def test_function_without_cfg_is_skipped(self):
        f = FunctionInfo(name="no_cfg", address=0x99)  # basic_block_cfg=None
        ctx = _ctx([f])
        assert compute_path_homology(ctx) == 0
        assert f.path_betti is None
        assert f.decompiler_low_confidence is False


class TestHomologyReport:
    def test_none_before_compute(self):
        assert homology_report(FunctionInfo(name="x", address=0)) is None

    def test_shape_after_compute(self):
        ctx = _ctx([_fn("gnarly", 0x30, _IRREDUCIBLE)])
        compute_path_homology(ctx)
        rep = homology_report(ctx.interesting_functions[0])
        assert set(rep) == {
            "path_betti", "path_betti_complete",
            "cyclomatic", "decompiler_low_confidence",
        }
        assert rep["decompiler_low_confidence"] is True


class TestBettiPriorityBonus:
    def test_zero_without_homology(self):
        # Default runs (no path_betti) get no bonus → ranking unchanged.
        assert betti_priority_bonus(FunctionInfo(name="x", address=0)) == 0

    def test_zero_for_truncated_vector(self):
        f = FunctionInfo(name="t", address=0)
        f.path_betti = [1]  # only β_0; β_1 unknown, not 0
        assert betti_priority_bonus(f) == 0

    def test_uses_beta1(self):
        f = FunctionInfo(name="c", address=0)
        f.path_betti = [1, 3, 0]
        assert betti_priority_bonus(f) == 3

    def test_capped(self):
        f = FunctionInfo(name="big", address=0)
        f.path_betti = [1, 999, 0]
        assert betti_priority_bonus(f) == _BETTI_BONUS_CAP


class TestToDictSurfacing:
    def test_fields_absent_by_default(self):
        ctx = _ctx([FunctionInfo(name="plain", address=0x1)])
        d = ctx.to_dict()
        fn = d["interesting_functions"][0]
        assert "path_betti" not in fn
        assert "decompiler_low_confidence" not in fn

    def test_fields_present_after_compute(self):
        ctx = _ctx([_fn("gnarly", 0x30, _IRREDUCIBLE)])
        compute_path_homology(ctx)
        d = ctx.to_dict()
        fn = d["interesting_functions"][0]
        assert fn["path_betti"][2] == 1
        assert fn["decompiler_low_confidence"] is True
        assert fn["cyclomatic"] is not None
        assert fn["path_betti_complete"] is True
