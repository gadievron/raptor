"""Conditional ASCII language properties after constant Python edge slices.

This module models plain typed data, never scanned source or callable identity.
An excluded property is conditional on the declared input domain and exact
builtin string semantics. It is not a source or vulnerability certificate.
"""
from __future__ import annotations

from dataclasses import dataclass

from .availability import z3
from .session import check_solver, new_solver, solver_reason_unknown

_MAX_LENGTH = 128
_ASSUMPTIONS = (
    "exact builtin Python str with ASCII codepoints",
    "input belongs to the declared bounded repetition language",
    "constant edge slice with native Python clipping and step one",
    "conditional model only; source identity, types and reaching guards unverified",
)


@dataclass(frozen=True)
class AsciiRepeatDomain:
    intervals: tuple[tuple[int, int], ...]
    minimum_repetitions: int
    optional_final_lf: bool
    source_max_length: int


@dataclass(frozen=True)
class PythonEdgeSlice:
    start: int | None = None
    stop: int | None = None


@dataclass(frozen=True)
class SlicePropertyResult:
    status: str
    reason: str
    input_value: str | None = None
    output_value: str | None = None
    assumptions: tuple[str, ...] = _ASSUMPTIONS


def _invalid_request(domain, operation, forbidden, timeout_ms) -> str | None:
    if type(domain) is not AsciiRepeatDomain or type(operation) is not PythonEdgeSlice:
        return "expected exact bounded-domain and edge-slice records"
    if (type(domain.intervals) is not tuple or not domain.intervals
            or len(domain.intervals) > 128):
        return "ASCII alphabet requires one to 128 interval tuples"
    for interval in domain.intervals:
        if (type(interval) is not tuple or len(interval) != 2
                or any(type(endpoint) is not int for endpoint in interval)
                or not 0 <= interval[0] <= interval[1] <= 127):
            return "alphabet intervals require exact ASCII integer endpoints"
    if (type(domain.minimum_repetitions) is not int
            or domain.minimum_repetitions not in (0, 1)):
        return "minimum repetitions must be zero or one"
    if type(domain.optional_final_lf) is not bool:
        return "optional final LF must be a boolean"
    if (type(domain.source_max_length) is not int
            or not 0 <= domain.source_max_length <= _MAX_LENGTH):
        return "source length bound must be an integer between zero and 128"
    if domain.source_max_length < domain.minimum_repetitions:
        return "declared input language is empty under its length bound"
    if operation.start is not None and (
            type(operation.start) is not int or operation.start < 0):
        return "slice start must be None or a nonnegative integer"
    if operation.stop is not None and (
            type(operation.stop) is not int or operation.stop > 0):
        return "slice stop must be None or a nonpositive integer"
    if (type(forbidden) is not tuple or not forbidden or len(forbidden) > 128
            or any(type(code) is not int or not 0 <= code <= 127 for code in forbidden)):
        return "property requires one to 128 ASCII integer codepoints"
    if type(timeout_ms) is not int or timeout_ms <= 0:
        return "timeout must be a positive integer in milliseconds"
    return None


def _domain_accepts(value: str, domain: AsciiRepeatDomain) -> bool:
    def body_accepts(body: str) -> bool:
        return (len(body) >= domain.minimum_repetitions
                and all(any(low <= ord(char) <= high for low, high in domain.intervals)
                        for char in body))

    return (len(value) <= domain.source_max_length
            and (body_accepts(value)
                 or (domain.optional_final_lf and value.endswith("\n")
                     and body_accepts(value[:-1]))))


def _replay_witness(
    input_value: str, output_value: str, domain: AsciiRepeatDomain,
    operation: PythonEdgeSlice, forbidden_codepoints: tuple[int, ...],
) -> bool:
    """Independently check plain witness strings using native slice semantics."""
    return (type(input_value) is str and type(output_value) is str
            and all(ord(char) <= 127 for char in input_value)
            and _domain_accepts(input_value, domain)
            and input_value[operation.start:operation.stop] == output_value
            and any(ord(char) in forbidden_codepoints for char in output_value))


def prove_slice_property(
    domain: AsciiRepeatDomain, operation: PythonEdgeSlice,
    forbidden_codepoints: tuple[int, ...], *, timeout_ms: int = 2000,
) -> SlicePropertyResult:
    """Exclude or exhibit a forbidden output character under explicit premises.

    The length cap is an admission limit, never a truncation of a larger
    domain. A nonempty alphabet and max >= minimum ensure habitation without
    an extra solver query; unsupported empty domains cannot prove vacuity.
    SAT witnesses undergo independent native replay. Unknown and failures
    carry no witness or exclusion claim.
    """
    invalid = _invalid_request(domain, operation, forbidden_codepoints, timeout_ms)
    if invalid:
        return SlicePropertyResult("unsupported", invalid)
    if z3 is None:
        return SlicePropertyResult("unsupported", "z3-solver is unavailable")
    try:
        ctx = z3.Context()
        solver = new_solver(timeout_ms=timeout_ms, ctx=ctx)
        length = z3.Int("input_length", ctx=ctx)
        suffix = z3.Bool("final_lf", ctx=ctx)
        maximum = domain.source_max_length
        chars = [z3.Int(f"input_{index}", ctx=ctx) for index in range(maximum)]
        body_length = z3.If(suffix, length - 1, length)
        solver.add(length >= 0, length <= maximum,
                   body_length >= domain.minimum_repetitions)
        if not domain.optional_final_lf:
            solver.add(z3.Not(suffix))
        for index, char in enumerate(chars):
            solver.add(char >= 0, char <= 127)
            alphabet = z3.Or(*[z3.And(char >= low, char <= high)
                               for low, high in domain.intervals])
            solver.add(z3.Implies(index < body_length, alphabet))
            solver.add(z3.Implies(z3.And(suffix, index == length - 1), char == 10))
        # Clamping constants to the declared finite domain preserves Python
        # clipping, including huge indices, without huge native numerals.
        start = min(operation.start or 0, maximum)
        if operation.stop is None:
            end = length
        else:
            distance = min(-operation.stop, maximum)
            end = z3.If(length - distance > 0, length - distance, 0)
            if operation.stop == 0:
                end = z3.IntVal(0, ctx=ctx)
        bad_positions = [
            z3.And(index >= start, index < end,
                   z3.Or(*[char == code for code in forbidden_codepoints]))
            for index, char in enumerate(chars)
        ]
        bad_output = (z3.Or(*bad_positions) if bad_positions
                      else z3.BoolVal(False, ctx=ctx))
        solver.add(bad_output)
        verdict = check_solver(solver)
        if verdict == z3.unsat:
            return SlicePropertyResult("excluded", "forbidden output characters excluded by the bounded model")
        if verdict != z3.sat:
            return SlicePropertyResult("unknown", solver_reason_unknown(solver))
        model = solver.model()
        count = model.eval(length, model_completion=True).as_long()
        if not 0 <= count <= maximum:
            return SlicePropertyResult("unknown", "solver witness has an invalid input length")
        codes = [model.eval(char, model_completion=True).as_long() for char in chars[:count]]
        if any(not 0 <= code <= 127 for code in codes):
            return SlicePropertyResult("unknown", "solver witness has non-ASCII input")
        input_value = "".join(chr(code) for code in codes)
        output_value = input_value[operation.start:operation.stop]
        if not _replay_witness(input_value, output_value, domain, operation, forbidden_codepoints):
            return SlicePropertyResult("unknown", "solver witness failed independent native replay")
        return SlicePropertyResult("counterexample", "bounded-model witness replayed with native slicing",
                                   input_value, output_value)
    except Exception as exc:  # noqa: BLE001 — failed optional SMT diagnostics cannot certify
        return SlicePropertyResult("unknown", f"slice solver failed ({type(exc).__name__})")
