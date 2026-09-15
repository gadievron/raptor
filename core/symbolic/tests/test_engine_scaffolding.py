"""Scaffolding-contract pins for the five symbolic engines.

Every engine (`_reach`, `_overflow`, `_constraints`, `_fmtstr`,
`_heap_mismatch`) exposes the same public-wrapper scaffolding:

  * an availability gate that answers WITHOUT spawning a child when
    angr is absent (the impl's re-gate produces the descriptive
    ``unavailable_result``), and
  * a :func:`core.symbolic._isolate.run_isolated` dispatch — impl
    module + function BY NAME, kwargs verbatim, the caller's timeout
    — when angr is present.

These tests pin that contract per engine, parametrized, so shared
scaffolding cannot drift one engine's gate ordering, dispatch
target, or forwarded arguments without a test catching it. They
work through the import seams only (``_availability._probe`` and
``_isolate.run_isolated``), so both sides of the gate are pinned on
any host, with or without angr installed.
"""
from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any, Callable
from unittest.mock import patch

import pytest

from core.symbolic._availability import clear_probe_cache
from core.symbolic._types import SymbolicResult


def _kwargs_reach(binary: Path) -> dict[str, Any]:
    return {
        "binary_path": binary,
        "target_address": 0x400000,
        "timeout": 7.5,
        "max_input_bytes": 4096,
        "avoid_addresses": None,
    }


def _kwargs_overflow(binary: Path) -> dict[str, Any]:
    return {
        "binary_path": binary,
        "target_address": 0x400000,
        "timeout": 7.5,
        "max_input_bytes": 4096,
        "register_constraints": None,
    }


def _kwargs_constraints(binary: Path) -> dict[str, Any]:
    return {
        "binary_path": binary,
        "target_address": 0x400000,
        "max_paths": 3,
        "timeout": 7.5,
        "max_input_bytes": 128,
    }


def _kwargs_fmtstr(binary: Path) -> dict[str, Any]:
    return {
        "binary_path": binary,
        "sink_addr": 0x400000,
        "fmt_arg_index": 1,
        "num_slots": 20,
        "timeout": 7.5,
        "max_input_bytes": 128,
    }


def _kwargs_heap(binary: Path) -> dict[str, Any]:
    return {
        "binary_path": binary,
        "target_address": 0x400000,
        "timeout": 7.5,
        "max_input_bytes": 4096,
    }


#: (public name, impl module, impl name, kwargs builder). The impl
#: module + name pair is the exact string pair the wrapper hands to
#: run_isolated — the child imports the impl by these names.
ENGINES: list[tuple[str, str, str, Callable[[Path], dict[str, Any]]]] = [
    (
        "find_reaching_input",
        "core.symbolic._reach",
        "_find_reaching_input_impl",
        _kwargs_reach,
    ),
    (
        "find_overflow_reaching_input",
        "core.symbolic._overflow",
        "_find_overflow_reaching_input_impl",
        _kwargs_overflow,
    ),
    (
        "extract_path_constraints",
        "core.symbolic._constraints",
        "_extract_path_constraints_impl",
        _kwargs_constraints,
    ),
    (
        "discover_fmtstr_slots",
        "core.symbolic._fmtstr",
        "_discover_fmtstr_slots_impl",
        _kwargs_fmtstr,
    ),
    (
        "find_heap_mismatch_witness",
        "core.symbolic._heap_mismatch",
        "_find_heap_mismatch_impl",
        _kwargs_heap,
    ),
]

_ENGINE_IDS = [e[0] for e in ENGINES]


def _public_fn(public_name: str, impl_module: str) -> Callable[..., Any]:
    """Resolve the public wrapper from its OWN module (not the
    package re-export) so the pin holds even for primitives the
    package ``__init__`` does not re-export (heap-mismatch)."""
    return getattr(importlib.import_module(impl_module), public_name)


@pytest.fixture()
def dummy_binary(tmp_path: Path) -> Path:
    binary = tmp_path / "dummy"
    binary.write_bytes(b"\x7fELFdummy")
    return binary


@pytest.mark.parametrize(
    ("public_name", "impl_module", "impl_name", "kwargs_builder"),
    ENGINES, ids=_ENGINE_IDS,
)
def test_availability_gate_answers_without_spawning(
    public_name: str,
    impl_module: str,
    impl_name: str,
    kwargs_builder: Callable[[Path], dict[str, Any]],
    dummy_binary: Path,
):
    """Angr absent: the wrapper must answer in-process via the impl's
    re-gate — descriptive unavailable result, correct primitive name,
    and NO child spawn (run_isolated never consulted)."""
    fn = _public_fn(public_name, impl_module)
    spawns: list[Any] = []

    def _no_spawn(*args: Any, **kwargs: Any) -> SymbolicResult:
        spawns.append((args, kwargs))
        raise AssertionError("run_isolated must not be called")

    with patch(
        "core.symbolic._availability._probe",
        side_effect=lambda name, module: False,
    ), patch(
        "core.symbolic._isolate.run_isolated", side_effect=_no_spawn,
    ):
        clear_probe_cache()
        try:
            result = fn(**kwargs_builder(dummy_binary))
        finally:
            clear_probe_cache()

    assert spawns == []
    assert result.succeeded is False
    assert "angr" in result.reason
    assert result.metadata.get("unavailable_dep") == "angr"
    assert result.metadata.get("primitive") == public_name


@pytest.mark.parametrize(
    ("public_name", "impl_module", "impl_name", "kwargs_builder"),
    ENGINES, ids=_ENGINE_IDS,
)
def test_isolation_dispatch_pins_module_impl_kwargs_timeout(
    public_name: str,
    impl_module: str,
    impl_name: str,
    kwargs_builder: Callable[[Path], dict[str, Any]],
    dummy_binary: Path,
):
    """Angr present: exactly one run_isolated dispatch, with the
    pinned (module, impl) name pair, the caller's kwargs verbatim,
    and the caller's timeout. The wrapper returns the child's result
    unchanged."""
    fn = _public_fn(public_name, impl_module)
    sentinel = SymbolicResult(
        succeeded=False, reason="sentinel", wall_seconds=0.0,
    )
    calls: list[tuple[Any, ...]] = []

    def _fake_run_isolated(
        module_name: str,
        func_name: str,
        kwargs: dict[str, Any],
        *,
        timeout: float,
    ) -> SymbolicResult:
        calls.append((module_name, func_name, kwargs, timeout))
        return sentinel

    call_kwargs = kwargs_builder(dummy_binary)
    with patch(
        "core.symbolic._availability._probe",
        side_effect=lambda name, module: True,
    ), patch(
        "core.symbolic._isolate.run_isolated",
        side_effect=_fake_run_isolated,
    ):
        clear_probe_cache()
        try:
            result = fn(**call_kwargs)
        finally:
            clear_probe_cache()

    assert result is sentinel
    assert len(calls) == 1
    module_name, func_name, forwarded, timeout = calls[0]
    assert module_name == impl_module
    assert func_name == impl_name
    assert forwarded == call_kwargs
    assert timeout == call_kwargs["timeout"]


@pytest.mark.parametrize(
    ("public_name", "impl_module", "impl_name", "kwargs_builder"),
    ENGINES, ids=_ENGINE_IDS,
)
def test_impl_regates_and_resolves_by_dispatch_names(
    public_name: str,
    impl_module: str,
    impl_name: str,
    kwargs_builder: Callable[[Path], dict[str, Any]],
    dummy_binary: Path,
):
    """The child-side contract: the impl must resolve by the exact
    (module, name) strings the dispatch sends, and must re-gate on
    availability itself — the child re-checks rather than trusting
    the parent's probe (import can fail in-child, e.g. under the
    symex sandbox)."""
    impl = getattr(importlib.import_module(impl_module), impl_name)

    with patch(
        "core.symbolic._availability._probe",
        side_effect=lambda name, module: False,
    ):
        clear_probe_cache()
        try:
            result = impl(**kwargs_builder(dummy_binary))
        finally:
            clear_probe_cache()

    assert result.succeeded is False
    assert result.metadata.get("unavailable_dep") == "angr"
    assert result.metadata.get("primitive") == public_name


# ---------------------------------------------------------------------------
# Cap-abort honesty: a state-explosion prune is never "explored fully"
# ---------------------------------------------------------------------------
# budget_step's active-cap arm silently moved ALL active states to
# deadended; unfound_result then reported the engine's no_path_reason
# ("no path to target" / "explored fully; ...") — refutation-grade
# language for an exploration aborted at the state ceiling. The step
# object now records the abort and unfound_result reports it.


class _FakeStash(list):
    pass


class _FakeSimgr:
    def __init__(self, n_active: int) -> None:
        self.active = _FakeStash(range(n_active))
        self.moves: list = []

    def move(self, from_stash: str, to_stash: str):
        self.moves.append((from_stash, to_stash))
        return self


def test_cap_abort_reported_as_state_explosion():
    import time

    from core.symbolic import _engine

    step = _engine.budget_step(time.monotonic() + 100, max_active=2)
    step(_FakeSimgr(3))
    assert step.cap_aborted is True
    r = _engine.unfound_result(
        deadline=time.monotonic() + 100, wall=1.0, states=3,
        timeout_reason="timeout", no_path_reason="no path to target",
        metadata={}, step=step,
    )
    assert "state explosion" in r.reason
    assert "not exhaustive" in r.reason
    assert r.metadata.get("cap_aborted") is True


def test_full_exploration_keeps_no_path_reason():
    import time

    from core.symbolic import _engine

    step = _engine.budget_step(time.monotonic() + 100, max_active=8)
    step(_FakeSimgr(2))  # under the cap — no abort
    assert step.cap_aborted is False
    r = _engine.unfound_result(
        deadline=time.monotonic() + 100, wall=1.0, states=2,
        timeout_reason="timeout", no_path_reason="no path to target",
        metadata={}, step=step,
    )
    assert r.reason == "no path to target"
    assert "cap_aborted" not in r.metadata


def test_timeout_reason_wins_over_cap_abort():
    import time

    from core.symbolic import _engine

    step = _engine.budget_step(time.monotonic() - 1, max_active=2)
    step.cap_aborted = True
    r = _engine.unfound_result(
        deadline=time.monotonic() - 1, wall=9.0, states=3,
        timeout_reason="timeout after 9.0s", no_path_reason="no path",
        metadata={}, step=step,
    )
    assert r.reason == "timeout after 9.0s"


# ---------------------------------------------------------------------------
# Errored-stash honesty: errored states are pruned exploration, not
# "explored fully" — and they count as states.
# ---------------------------------------------------------------------------


class _FakeErroredSimgr:
    def __init__(self, n_errored: int, stashes=None) -> None:
        self.errored = list(range(n_errored))
        self.stashes = stashes or {"active": [], "deadended": []}


def test_errored_states_qualify_no_path_reason():
    import time

    from core.symbolic import _engine

    r = _engine.unfound_result(
        deadline=time.monotonic() + 100, wall=1.0, states=0,
        timeout_reason="timeout", no_path_reason="no path to target",
        metadata={}, step=None, simgr=_FakeErroredSimgr(3),
    )
    assert "no path to target" in r.reason
    assert "errored on 3 state(s)" in r.reason
    assert "not exhaustive" in r.reason
    assert r.metadata.get("errored_states") == 3


def test_no_errored_states_keeps_bare_no_path_reason():
    import time

    from core.symbolic import _engine

    r = _engine.unfound_result(
        deadline=time.monotonic() + 100, wall=1.0, states=0,
        timeout_reason="timeout", no_path_reason="no path to target",
        metadata={}, step=None, simgr=_FakeErroredSimgr(0),
    )
    assert r.reason == "no path to target"
    assert "errored_states" not in r.metadata


def test_errored_states_recorded_even_on_timeout():
    import time

    from core.symbolic import _engine

    r = _engine.unfound_result(
        deadline=time.monotonic() - 1, wall=9.0, states=0,
        timeout_reason="timeout after 9.0s", no_path_reason="no path",
        metadata={}, step=None, simgr=_FakeErroredSimgr(2),
    )
    assert r.reason == "timeout after 9.0s"
    assert r.metadata.get("errored_states") == 2


def test_count_states_includes_errored():
    from core.symbolic import _engine

    sg = _FakeErroredSimgr(4, stashes={"active": [1], "deadended": [1, 2]})
    assert _engine.count_states(sg) == 7
    assert _engine.count_states(_FakeErroredSimgr(2)) == 2


def test_errored_suffix_wording():
    from core.symbolic import _engine

    assert _engine.errored_suffix(_FakeErroredSimgr(0)) == ""
    s = _engine.errored_suffix(_FakeErroredSimgr(1))
    assert "errored on 1 state(s)" in s and "not exhaustive" in s


class _FakeUnconstrainedSimgr:
    def __init__(self, n_unconstrained: int) -> None:
        self.errored = []
        self.unconstrained = list(range(n_unconstrained))


def test_unconstrained_stash_qualifies_no_path_reason():
    """An engine running save_unconstrained=True that still finds no
    path but holds unconstrained states explored a PRUNED space —
    the negative must carry the qualifier (the save_unconstrained=
    False engines' invisible drop is documented as out of scope)."""
    import time

    from core.symbolic import _engine

    r = _engine.unfound_result(
        deadline=time.monotonic() + 100, wall=1.0, states=0,
        timeout_reason="timeout", no_path_reason="explored fully",
        metadata={}, step=None, simgr=_FakeUnconstrainedSimgr(2),
    )
    assert "explored fully" in r.reason
    assert "2 state(s) went unconstrained" in r.reason
    assert "not exhaustive" in r.reason
    assert r.metadata.get("unconstrained_states") == 2
