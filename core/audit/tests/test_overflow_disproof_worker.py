"""Auxiliary overflow checks share the confined JSON worker, including prefixes."""

from copy import deepcopy

import pytest

from core.audit import condition_smt as smt
from core.audit import overflow_disproof as worker

PREFIX_SAFE = "unsigned Read(unsigned Count, unsigned Step) { unsigned half = Count / 2; if(Count <= 10 && Step <= 10) return Count + Step; return half; }"

HYPOTHESIS = "integer overflow in `Count + Step`"
SAFE = "unsigned Read(unsigned Count, unsigned Step) { if(Count <= 10 && Step <= 10) return Count + Step; return 0; }"
UNSAFE = "unsigned Read(unsigned Count, unsigned Step) { if(Count >= 1) return Count + Step; return 0; }"


def call(source=SAFE, **kwargs):
    return smt.disprove_integer_overflow(
        HYPOTHESIS,
        source,
        file_path="record.c",
        function_name="Read",
        integer_abi="lp64",
        **kwargs,
    )


def receipt(args, state=True):
    return {
        "binding": worker._binding(args),
        "result": {
            "hypothesis_class": "integer_overflow",
            "disproved": state,
            "reasoning": "checked the bound operation",
            "error": "",
            "witness": {"Count": 4294967295, "Step": 1} if state is False else None,
        },
    }


@pytest.mark.parametrize(
    "source,state",
    [
        (SAFE, True),
        (UNSAFE, False),
        (PREFIX_SAFE, True),
        ("unsigned Read(unsigned Count, unsigned Step) { return Count + Step; }", None),
    ],
    ids=["safe", "overflow", "prefix-division", "unconstrained"],
)
def test_source_and_solver_work_happens_only_inside_dispatch(
    monkeypatch, source, state
):
    pytest.importorskip("z3")
    pytest.importorskip("tree_sitter_c")
    from core.audit import arithmetic_operation, arithmetic_prefix_obligations
    from packages.exploit_feasibility import smt_verbs

    # Semantic assertions must not depend on host contention at 100 ms.
    monkeypatch.setattr(arithmetic_prefix_obligations, "_BUDGET_MS", 5000)
    original = arithmetic_operation.bind_arithmetic_operation
    inside = False
    calls = []
    native_calls = []
    original_prefix = arithmetic_prefix_obligations.check_solver
    original_overflow = smt_verbs.check_overflow

    def prefix(*args, **kwargs):
        assert inside, "prefix solver must not run in the parent"
        native_calls.append("prefix")
        return original_prefix(*args, **kwargs)

    def overflow(*args, **kwargs):
        assert inside, "overflow solver must not run in the parent"
        native_calls.append("overflow")
        return original_overflow(*args, **kwargs)

    def bind(*args, **kwargs):
        assert inside, "source binder must not run in the parent"
        return original(*args, **kwargs)

    def dispatch(tag, args):
        nonlocal inside
        assert tag == "overflow_disproof"
        calls.append(tag)
        inside = True
        try:
            return smt._z3_dispatch_json({"tag": tag, "args": args})
        finally:
            inside = False

    monkeypatch.setattr(arithmetic_prefix_obligations, "check_solver", prefix)
    monkeypatch.setattr(smt_verbs, "check_overflow", overflow)
    monkeypatch.setattr(arithmetic_operation, "bind_arithmetic_operation", bind)
    monkeypatch.setattr(smt, "_run_z3_child", dispatch)
    result = call(source)
    assert result.disproved is state, result
    assert calls == ["overflow_disproof"]
    if source == PREFIX_SAFE:
        assert "prefix" in native_calls and "overflow" in native_calls
    assert bool(result.witness) is (state is False)


@pytest.mark.parametrize(
    "field",
    [
        "hypothesis",
        "source_context",
        "var_types",
        "file_path",
        "function_name",
        "integer_abi",
    ],
)
def test_reply_for_different_request_cannot_disprove(monkeypatch, field):
    monkeypatch.setattr(smt, "_z3_importable", lambda: True)

    def dispatch(tag, args):
        other = deepcopy(args)
        changes = {
            "hypothesis": HYPOTHESIS + " elsewhere",
            "source_context": SAFE + "\n",
            "var_types": {"Count": "unsigned"},
            "file_path": "other.c",
            "function_name": "Other",
            "integer_abi": worker.integer_abi_record("ilp32"),
        }
        other[field] = changes[field]
        return receipt(other)

    monkeypatch.setattr(smt, "_run_z3_child", dispatch)
    result = call()
    assert result.disproved is None
    assert result.witness is None


@pytest.mark.parametrize(
    "case",
    [
        "missing",
        "version",
        "source-contract",
        "class",
        "state-int",
        "state-string",
        "error",
        "reason",
        "extra",
        "safe-witness",
        "sat-no-witness",
        "sat-bool",
        "sat-float",
        "sat-range",
    ],
)
def test_malformed_or_stale_reply_is_inconclusive(monkeypatch, case):
    monkeypatch.setattr(smt, "_z3_importable", lambda: True)

    def dispatch(tag, args):
        out = receipt(args)
        result = out["result"]
        if case == "missing":
            return None
        if case == "version":
            out["binding"]["query_contract"] = "old"
        elif case == "source-contract":
            out["binding"]["source_contract"]["query_contract"] = "old"
        elif case == "class":
            result["hypothesis_class"] = "other"
        elif case == "state-int":
            result["disproved"] = 1
        elif case == "state-string":
            result["disproved"] = "true"
        elif case == "error":
            result["error"] = "timeout"
        elif case == "reason":
            result["reasoning"] = ""
        elif case == "extra":
            result["unexpected"] = True
        elif case == "safe-witness":
            result["witness"] = {"Count": 0}
        else:
            result["disproved"] = False
            result["witness"] = {
                "sat-no-witness": None,
                "sat-bool": {"Count": True},
                "sat-float": {"Count": 1.5},
                "sat-range": {"Count": 1 << 64},
            }[case]
        return out

    monkeypatch.setattr(smt, "_run_z3_child", dispatch)
    result = call()
    assert result.disproved is None
    assert result.witness is None


@pytest.mark.parametrize(
    "changes",
    [
        dict(source_context="x" * 65537),
        dict(source_context="\ud800"),
        dict(hypothesis="x" * 8193),
        dict(var_types={"Count": 32}),
        dict(var_types={"x" * 257: "int"}),
        dict(integer_abi=None),
        dict(function_name=None),
        dict(file_path=""),
    ],
    ids=[
        "source-budget",
        "unicode",
        "claim-budget",
        "hint-type",
        "hint-budget",
        "abi",
        "scope",
        "file",
    ],
)
def test_invalid_requests_do_not_start_worker(monkeypatch, changes):
    monkeypatch.setattr(smt, "_z3_importable", lambda: True)

    def forbidden(*args, **kwargs):
        pytest.fail("invalid request started a worker")

    monkeypatch.setattr(smt, "_run_z3_child", forbidden)
    args = dict(
        hypothesis=HYPOTHESIS,
        source_context=SAFE,
        file_path="record.c",
        function_name="Read",
        integer_abi="lp64",
    )
    args.update(changes)
    assert smt.disprove_integer_overflow(**args).disproved is None


def test_valid_counterexample_is_snapshotted(monkeypatch):
    monkeypatch.setattr(smt, "_z3_importable", lambda: True)
    replies = []

    def dispatch(tag, args):
        out = receipt(args, False)
        replies.append(out)
        return out

    monkeypatch.setattr(smt, "_run_z3_child", dispatch)
    result = call()
    replies[0]["result"]["witness"]["Count"] = 0
    assert result.disproved is False
    assert result.witness["Count"] == 4294967295


def test_isolation_refusal_propagates_without_native_fallback(monkeypatch):
    from core.sandbox import SandboxSetupError

    monkeypatch.setattr(smt, "_z3_importable", lambda: True)

    def refuse(*args, **kwargs):
        raise SandboxSetupError("owned refusal")

    monkeypatch.setattr(smt, "_run_z3_child", refuse)
    with pytest.raises(SandboxSetupError, match="owned refusal"):
        call()


@pytest.mark.parametrize("args", [None, {}, {"hypothesis": HYPOTHESIS}])
def test_child_rejects_incomplete_protocol(args):
    assert worker.run_request(args) is None


@pytest.mark.slow
@pytest.mark.parametrize(
    "source,state",
    [(SAFE, True), (UNSAFE, False), (PREFIX_SAFE, True)],
    ids=["safe", "overflow", "prefix-division"],
)
def test_native_confined_overflow_disproof(source, state):
    pytest.importorskip("z3")
    pytest.importorskip("tree_sitter_c")
    result = call(source)
    assert result.disproved is state, result
    assert bool(result.witness) is (state is False)


@pytest.mark.slow
def test_native_qualified_cpp_frame_and_abi():
    pytest.importorskip("z3")
    pytest.importorskip("tree_sitter_cpp")
    source = "constexpr unsigned long Read(unsigned long Count, unsigned long Step) noexcept { if(Count <= 10 && Step <= 10) return Count + Step; return 0; }"
    result = smt.disprove_integer_overflow(
        HYPOTHESIS,
        source,
        file_path="record.cpp",
        function_name="Read",
        integer_abi="llp64",
    )
    assert result.disproved is True, result


@pytest.mark.parametrize("exit_mode", ["normal", "error", "interrupt"])
def test_unit_dispatch_fixture_restores_borrowed_transport(request, exit_mode):
    from contextlib import nullcontext

    from core.audit.tests.conftest import overflow_disproof_unit_worker

    original = smt._run_z3_child
    failure = {"error": RuntimeError, "interrupt": KeyboardInterrupt}.get(exit_mode)
    expected = (
        pytest.raises(failure, match="owned fixture exit") if failure else nullcontext()
    )
    with expected:
        with pytest.MonkeyPatch.context() as scope:
            overflow_disproof_unit_worker.__wrapped__(scope, request)
            assert smt._run_z3_child is not original
            if failure:
                raise failure("owned fixture exit")
    assert smt._run_z3_child is original
