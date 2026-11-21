"""Hijack-site attribution and register-constraint honesty.

The overflow-witness primitive proves input controls PC — it does NOT
prove the hypothesised function is the vulnerable one. These tests pin
the attribution substrate (`_hijack_sites`) and the two S-class honesty
fixes: register-constraint names are vetted loudly up front, and states
skipped for constraint-application failure never ground an
"unsatisfiable" exhausted verdict.

Pure-fake tests only — the real-angr end-to-end paths live in
test_overflow.py.
"""
from __future__ import annotations

import pytest

from core.symbolic._overflow import (
    _hijack_sites,
    _try_solve_pc,
    _unknown_register_names,
)


class _Symbol:
    def __init__(self, name: str, rebased_addr: int, size: int):
        self.name = name
        self.rebased_addr = rebased_addr
        self.size = size


class _Loader:
    def __init__(self, symbols: list):
        self._symbols = sorted(symbols, key=lambda s: s.rebased_addr)

    def find_symbol(self, addr: int, fuzzy: bool = False):
        best = None
        for sym in self._symbols:
            if sym.rebased_addr <= addr:
                best = sym
        return best


class _Project:
    def __init__(self, loader: _Loader):
        self.loader = loader


class _History:
    def __init__(self, bbl_addrs: list):
        self.bbl_addrs = bbl_addrs


class _State:
    def __init__(self, bbl_addrs: list, symbols: list):
        self.history = _History(bbl_addrs)
        self.project = _Project(_Loader(symbols))


class TestHijackSites:
    def test_contained_address_attributed(self):
        state = _State([0x1010], [_Symbol("vuln", 0x1000, 0x40)])
        sites = _hijack_sites(state)
        assert sites == [{"address": 0x1010, "symbol": "vuln"}]

    def test_address_beyond_symbol_extent_unattributed(self):
        # fuzzy lookup returns the nearest PRECEDING symbol; an address
        # past its sized extent (glue / stripped region) must not
        # inherit the name — that would be false attribution.
        state = _State([0x2000], [_Symbol("vuln", 0x1000, 0x40)])
        sites = _hijack_sites(state)
        assert sites == [{"address": 0x2000, "symbol": None}]

    def test_zero_size_symbol_never_attributes(self):
        state = _State([0x1010], [_Symbol("vuln", 0x1000, 0)])
        assert _hijack_sites(state)[0]["symbol"] is None

    def test_most_recent_first_and_bounded(self):
        syms = [
            _Symbol("a", 0x1000, 0x10), _Symbol("b", 0x2000, 0x10),
            _Symbol("c", 0x3000, 0x10), _Symbol("d", 0x4000, 0x10),
        ]
        state = _State([0x1000, 0x2000, 0x3000, 0x4000], syms)
        names = [s["symbol"] for s in _hijack_sites(state)]
        # last block (the frame that leaked control) comes first;
        # the window is bounded, so the oldest block drops off.
        assert names == ["d", "c", "b"]

    def test_no_history_yields_no_attribution(self):
        class _Bare:
            pass

        assert _hijack_sites(_Bare()) == []


class TestUnknownRegisterNames:
    class _Arch:
        registers = {"rdi": (72, 8), "rsi": (64, 8)}

    class _Proj:
        pass

    def test_known_names_pass(self):
        proj = self._Proj()
        proj.arch = self._Arch()
        assert _unknown_register_names(proj, {"rdi": 1}) is None

    def test_unknown_names_reported_sorted(self):
        proj = self._Proj()
        proj.arch = self._Arch()
        bad = _unknown_register_names(proj, {"zdi": 1, "adi": 2})
        assert bad == ["adi", "zdi"]

    def test_unvettable_arch_defers_to_per_state(self):
        class _NoRegs:
            @property
            def registers(self):
                raise RuntimeError("exotic arch")

        proj = self._Proj()
        proj.arch = _NoRegs()
        assert _unknown_register_names(proj, {"rdi": 1}) is None


class _FakeRegs:
    pc = 0x1000


class _FakeSolver:
    def add(self, constraint) -> None:
        pass


class _FakePosix:
    def dumps(self, fd: int) -> bytes:
        return b"AAAA"


class _FakeSolveState:
    """Just enough surface for _try_solve_pc's constraint loop."""

    def __init__(self):
        self.regs = _FakeRegs()
        self.solver = _FakeSolver()
        self.posix = _FakePosix()

    def copy(self) -> "_FakeSolveState":
        return self

    def satisfiable(self) -> bool:
        return True


class TestConstraintFailureRecording:
    def test_unconstrainable_register_skip_is_recorded(self):
        # The state exists and was never solver-checked; the skip must
        # be visible to the caller so the exhausted path cannot read
        # it as an unsatisfiability proof.
        failures: list = []
        solved = _try_solve_pc(
            [_FakeSolveState()], 0x1000, 4096,
            register_constraints={"no_such_reg": 7},
            constraint_failures=failures,
        )
        assert solved is None
        assert failures == ["no_such_reg"]

    def test_recorder_untouched_when_constraints_apply(self):
        failures: list = []

        class _AttrRegs(_FakeRegs):
            rdi = 0

        state = _FakeSolveState()
        state.regs = _AttrRegs()
        # history/arch fakes are absent: the snapshot helpers degrade
        # to empty sections rather than failing the solve.
        solved = _try_solve_pc(
            [state], 0x1000, 4096,
            register_constraints={"rdi": 7},
            constraint_failures=failures,
        )
        assert solved is not None
        data, snapshot = solved
        assert data == b"AAAA"
        assert snapshot["hijack_sites"] == []
        assert failures == []


@pytest.mark.slow  # launches the sandboxed angr worker
def test_unknown_register_name_is_loud_caller_error(tmp_path):
    """A typo'd register name used to skip EVERY state silently and
    the exhausted path then reported "unsatisfiable" — a false
    refutation flavour. It must surface as a caller error instead."""
    pytest.importorskip("angr")
    from core.symbolic import find_overflow_reaching_input, load_binary
    from core.symbolic.tests.conftest import (
        OVERFLOW_MARKER_SOURCE,
        compile_fixture,
    )

    binary = compile_fixture(tmp_path, OVERFLOW_MARKER_SOURCE)
    info = load_binary(binary)
    result = find_overflow_reaching_input(
        binary, target_address=info.symbols["win"], timeout=60.0,
        register_constraints={"not_a_register": 1},
    )
    assert not result.succeeded
    assert "not_a_register" in result.reason
    assert "caller error" in result.reason
    assert "unsatisfiable" not in result.reason
