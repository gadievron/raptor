"""JSON child protocol for the Z3/SMT verification layer."""

from __future__ import annotations

import pytest

from pathlib import Path

from core.audit.subproc_json import _CHILD_SCRIPT_PATH, run_json_child
from core.audit.sweep import SweepResult, smt_child_env


class TestChildScript:
    def test_no_pickle_in_protocol(self) -> None:
        """The child protocol must never unpickle — a compromised or
        crashed child hands back at worst malformed JSON."""
        src = Path(_CHILD_SCRIPT_PATH).read_text(encoding="utf-8")
        assert "pickle" not in src
        assert "json" in src

    def test_child_is_a_named_in_tree_script(self) -> None:
        """EDR coexistence: the child must be an on-disk script inside
        the RAPTOR tree executed by path — never a ``python -c`` blob
        (loader-shaped to endpoint-security heuristics)."""
        child = Path(_CHILD_SCRIPT_PATH)
        assert child.is_file()
        assert child.name == "_json_child.py"
        repo_root = Path(__file__).resolve().parents[3]
        assert repo_root in child.parents
        import inspect

        from core.audit import subproc_json
        src = inspect.getsource(subproc_json)
        assert '"-c"' not in src


class TestRunJsonChild:
    def test_round_trip_through_real_child(self) -> None:
        """Full spawn: the SMT verb adapter returns a SweepResult dict
        (inconclusive — no operands extractable; no solver needed)."""
        out = run_json_child(
            "core.audit.sweep:_run_smt_verb_inner_json",
            {
                "file_path": "f.c", "function_name": "f",
                "verb": "check-negative-bypass", "source": "int x;",
                "hypothesis": "nothing", "target_path": None,
            },
            env=smt_child_env(),
            timeout=30,
        )
        assert isinstance(out, dict)
        sr = SweepResult(**out)
        assert sr.outcome == "inconclusive"
        assert sr.tool == "smt"

    def test_child_exception_returns_none(self) -> None:
        out = run_json_child(
            "core.audit.subproc_json:does_not_exist",
            {},
            env=smt_child_env(),
            timeout=30,
        )
        assert out is None

    def test_timeout_returns_none(self) -> None:
        out = run_json_child(
            "time:sleep",
            5,
            env=smt_child_env(),
            timeout=1,
        )
        assert out is None

    def test_unserialisable_request_returns_none(self) -> None:
        out = run_json_child(
            "core.audit.sweep:_run_smt_verb_inner_json",
            {"bad": object()},
            env=smt_child_env(),
        )
        assert out is None


class TestZ3DispatchJson:
    def test_unknown_tag_returns_none(self) -> None:
        from core.audit.condition_smt import _z3_dispatch_json
        assert _z3_dispatch_json({"tag": "nope", "args": {}}) is None

    def test_path_feasibility_round_trip(self) -> None:
        pytest.importorskip("z3")
        from core.audit.condition_smt import (
            BoundsConstraint,
            _try_z3_path_feasibility,
        )
        contradiction = [
            BoundsConstraint("x", "<", 10, "x < 10"),
            BoundsConstraint("x", ">", 20, "x > 20"),
        ]
        result = _try_z3_path_feasibility(contradiction)
        assert result is not None
        feasible, reasoning, witness = result
        assert feasible is False
        assert "infeasible" in reasoning
        assert witness is None

    def test_signed_mismatch_round_trip(self) -> None:
        pytest.importorskip("z3")
        from core.audit.condition_smt import _try_z3_signed_mismatch
        result = _try_z3_signed_mismatch("n", "<", 100, 32)
        assert result is not None
        assert result.mismatch is True
        assert result.witness  # concrete int witness survives JSON

    def test_guard_sufficiency_round_trip(self) -> None:
        pytest.importorskip("z3")
        from core.audit.condition_smt import BoundsConstraint, _try_z3_check
        result = _try_z3_check(
            [BoundsConstraint("len", "<", 4096, "len < 4096")],
            256,
            "memcpy",
        )
        assert result is not None
        assert result[0] is True  # guard insufficient for 256-byte dst
        assert isinstance(result[2], dict)
