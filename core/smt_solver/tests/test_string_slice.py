"""Native finite-language controls for the source-free slice model."""
from dataclasses import replace
from itertools import product

import pytest

from core.smt_solver import string_slice as ss
from core.smt_solver.session import query_budget

_requires_z3 = pytest.mark.skipif(ss.z3 is None, reason="z3-solver not installed")
_BASE = ss.AsciiRepeatDomain(((97, 98),), 0, False, 3)


def _native_language(alphabet, minimum, suffix, maximum):
    words = set()
    for size in range(minimum, maximum + 1):
        for chars in product(alphabet, repeat=size):
            word = "".join(chars)
            words.add(word)
            if suffix and len(word) < maximum:
                words.add(word + "\n")
    return words


@_requires_z3
@pytest.mark.parametrize("alphabet", [("a", "b"), ("a", "\n"), ("a", ".")])
@pytest.mark.parametrize("minimum,suffix", [(0, False), (0, True), (1, False), (1, True)])
@pytest.mark.parametrize("start,stop", [(None, None), (None, -1), (1, None), (0, 0), (7, -5), (1, -1)])
@pytest.mark.parametrize("bad", [10, 97])
def test_model_matches_exhaustive_native_language(alphabet, minimum, suffix, start, stop, bad):
    domain = ss.AsciiRepeatDomain(tuple((ord(c), ord(c)) for c in alphabet), minimum, suffix, 3)
    operation = ss.PythonEdgeSlice(start, stop)
    words = _native_language(alphabet, minimum, suffix, 3)
    witnesses = {word for word in words if chr(bad) in word[start:stop]}
    result = ss.prove_slice_property(domain, operation, (bad,))
    assert result.status == ("counterexample" if witnesses else "excluded"), result
    assert result.assumptions and "conditional" in result.assumptions[-1]
    if witnesses:
        assert result.input_value in witnesses
        assert result.output_value == result.input_value[start:stop]
        assert chr(bad) in result.output_value
    else:
        assert result.input_value is result.output_value is None


@_requires_z3
def test_terminal_lf_is_removed_only_in_the_correct_direction():
    domain = ss.AsciiRepeatDomain(((97, 122),), 1, True, 32)
    assert ss.prove_slice_property(domain, ss.PythonEdgeSlice(stop=-1), (10,)).status == "excluded"
    result = ss.prove_slice_property(domain, ss.PythonEdgeSlice(start=1), (10,))
    assert result.status == "counterexample"
    assert result.input_value.endswith("\n") and result.output_value.endswith("\n")


@_requires_z3
@pytest.mark.parametrize("maximum", [0, 1, 128])
def test_zero_and_admission_boundary_lengths(maximum):
    domain = ss.AsciiRepeatDomain(((97, 97),), 0, True, maximum)
    result = ss.prove_slice_property(domain, ss.PythonEdgeSlice(stop=0), (97, 10))
    assert result.status == "excluded"
    if maximum:
        assert ss.prove_slice_property(domain, ss.PythonEdgeSlice(), (10,)).status == "counterexample"


@_requires_z3
def test_suffix_is_optional_when_lf_also_belongs_to_the_body_alphabet():
    domain = ss.AsciiRepeatDomain(((10, 10),), 1, True, 1)
    result = ss.prove_slice_property(domain, ss.PythonEdgeSlice(), (10,))
    assert result.status == "counterexample"
    assert result.input_value == result.output_value == "\n"
    outside_alphabet = replace(domain, intervals=((97, 97),))
    assert ss.prove_slice_property(outside_alphabet, ss.PythonEdgeSlice(), (10,)).status == "excluded"


@_requires_z3
def test_huge_indices_are_clipped_without_native_integer_coercion():
    domain = ss.AsciiRepeatDomain(((97, 97),), 0, False, 3)
    for operation in (ss.PythonEdgeSlice(start=10**5000), ss.PythonEdgeSlice(stop=-(10**5000))):
        result = ss.prove_slice_property(domain, operation, (97,))
        assert result.status == "excluded"


@pytest.mark.parametrize("domain,operation,forbidden,timeout", [
    (None, ss.PythonEdgeSlice(), (97,), 100),
    (_BASE, None, (97,), 100),
    (replace(_BASE, intervals=[]), ss.PythonEdgeSlice(), (97,), 100),
    (replace(_BASE, intervals=()), ss.PythonEdgeSlice(), (97,), 100),
    (replace(_BASE, intervals=((97,),)), ss.PythonEdgeSlice(), (97,), 100),
    (replace(_BASE, intervals=((True, 97),)), ss.PythonEdgeSlice(), (97,), 100),
    (replace(_BASE, intervals=((98, 97),)), ss.PythonEdgeSlice(), (97,), 100),
    (replace(_BASE, intervals=((0, 128),)), ss.PythonEdgeSlice(), (97,), 100),
    (replace(_BASE, minimum_repetitions=True), ss.PythonEdgeSlice(), (97,), 100),
    (replace(_BASE, minimum_repetitions=2), ss.PythonEdgeSlice(), (97,), 100),
    (replace(_BASE, optional_final_lf=1), ss.PythonEdgeSlice(), (97,), 100),
    (replace(_BASE, source_max_length=True), ss.PythonEdgeSlice(), (97,), 100),
    (replace(_BASE, source_max_length=129), ss.PythonEdgeSlice(), (97,), 100),
    (replace(_BASE, source_max_length=-1), ss.PythonEdgeSlice(), (97,), 100),
    (replace(_BASE, source_max_length=0, minimum_repetitions=1), ss.PythonEdgeSlice(), (97,), 100),
    (_BASE, ss.PythonEdgeSlice(start=-1), (97,), 100),
    (_BASE, ss.PythonEdgeSlice(start=True), (97,), 100),
    (_BASE, ss.PythonEdgeSlice(stop=1), (97,), 100),
    (_BASE, ss.PythonEdgeSlice(stop=False), (97,), 100),
    (_BASE, ss.PythonEdgeSlice(), (), 100),
    (_BASE, ss.PythonEdgeSlice(), [97], 100),
    (_BASE, ss.PythonEdgeSlice(), (True,), 100),
    (_BASE, ss.PythonEdgeSlice(), (128,), 100),
    (_BASE, ss.PythonEdgeSlice(), (97,), False),
    (_BASE, ss.PythonEdgeSlice(), (97,), 0),
])
def test_invalid_ir_never_reaches_the_solver(monkeypatch, domain, operation, forbidden, timeout):
    def unexpected_solver(**_kwargs):
        raise AssertionError("invalid IR must not construct a solver")
    monkeypatch.setattr(ss, "new_solver", unexpected_solver)
    result = ss.prove_slice_property(domain, operation, forbidden, timeout_ms=timeout)
    assert result.status == "unsupported"
    assert result.input_value is result.output_value is None


def test_missing_z3_is_unsupported(monkeypatch):
    monkeypatch.setattr(ss, "z3", None)
    result = ss.prove_slice_property(_BASE, ss.PythonEdgeSlice(), (97,))
    assert result.status == "unsupported"
    assert "unavailable" in result.reason


@_requires_z3
def test_expired_shared_budget_returns_unknown_without_a_witness():
    with query_budget(0):
        result = ss.prove_slice_property(_BASE, ss.PythonEdgeSlice(), (97,))
    assert result.status == "unknown"
    assert "budget" in result.reason
    assert result.input_value is result.output_value is None
    assert ss.prove_slice_property(_BASE, ss.PythonEdgeSlice(), (97,)).status == "counterexample"


@_requires_z3
def test_native_unknown_does_not_read_a_model(monkeypatch):
    monkeypatch.setattr(ss, "check_solver", lambda solver: ss.z3.unknown)
    monkeypatch.setattr(ss, "solver_reason_unknown", lambda solver: "injected unknown")
    result = ss.prove_slice_property(_BASE, ss.PythonEdgeSlice(), (97,))
    assert result.status == "unknown" and result.reason == "injected unknown"
    assert result.input_value is result.output_value is None


@_requires_z3
def test_solver_failure_is_not_an_exclusion(monkeypatch):
    def fail(solver):
        raise RuntimeError("owned injected failure")
    monkeypatch.setattr(ss, "check_solver", fail)
    result = ss.prove_slice_property(_BASE, ss.PythonEdgeSlice(), (97,))
    assert result.status == "unknown"
    assert result.input_value is result.output_value is None


@_requires_z3
def test_native_replay_failure_does_not_publish_a_witness(monkeypatch):
    monkeypatch.setattr(ss, "_replay_witness", lambda *_args: False)
    result = ss.prove_slice_property(_BASE, ss.PythonEdgeSlice(), (97,))
    assert result.status == "unknown" and "replay" in result.reason
    assert result.input_value is result.output_value is None


def test_native_replay_rejects_inconsistent_plain_witnesses():
    domain = ss.AsciiRepeatDomain(((97, 97),), 1, True, 3)
    operation = ss.PythonEdgeSlice(start=1)
    assert ss._replay_witness("a\n", "\n", domain, operation, (10,))
    assert not ss._replay_witness("a\n", "a", domain, operation, (10,))
    assert not ss._replay_witness(".\n", "\n", domain, operation, (10,))
    assert not ss._replay_witness("a\n", "\n", domain, operation, (46,))
    assert not ss._replay_witness("aaaa\n", "aaa\n", domain, operation, (10,))


@_requires_z3
def test_each_query_uses_a_private_context(monkeypatch):
    solvers = []
    original = ss.new_solver
    def capture(**kwargs):
        solver = original(**kwargs)
        solvers.append(solver)
        return solver
    monkeypatch.setattr(ss, "new_solver", capture)
    first = ss.prove_slice_property(_BASE, ss.PythonEdgeSlice(), (97,))
    second = ss.prove_slice_property(_BASE, ss.PythonEdgeSlice(stop=-3), (97,))
    assert first.status == "counterexample" and second.status == "excluded"
    assert solvers[0].ctx != solvers[1].ctx
    assert all(solver.ctx != ss.z3.main_ctx() for solver in solvers)
