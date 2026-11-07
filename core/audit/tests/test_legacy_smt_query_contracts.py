"""Legacy audit queries retain budgets and distinguish unknown from proof."""

from dataclasses import asdict
from pathlib import Path
import subprocess
import sys

import pytest

z3 = pytest.importorskip("z3")

from core.audit import condition_smt as bridge  # noqa: E402
from core.smt_solver.session import query_budget  # noqa: E402


def test_parent_bridge_import_does_not_load_native_solver():
    root = str(Path(__file__).resolve().parents[3])
    script = (
        f"import sys; sys.path.insert(0, {root!r}); "
        "import core.audit.condition_smt; "
        "assert not any(name == 'z3' or name.startswith('z3.') for name in sys.modules)"
    )
    result = subprocess.run([sys.executable, "-I", "-c", script], capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr


def constraints():
    return [bridge.BoundsConstraint("Count", ">=", 0), bridge.BoundsConstraint("Other", ">=", 0)]


@pytest.mark.parametrize("query", [
    lambda: bridge._z3_overflow_check(constraints(), 4),
    lambda: bridge._z3_alloc_overflow_check(constraints()),
    lambda: bridge._z3_consistency_check(constraints()),
    lambda: bridge._z3_path_feasibility_check(constraints()),
    lambda: bridge._z3_signed_mismatch_check("Count", "<", 4, 8),
    lambda: bridge._z3_auth_bypass_check("Count > 0", ["check"]),
    lambda: bridge._z3_lock_discipline_check("Count > 0", "lock", 1),
    lambda: bridge._z3_resource_leak_check("Count > 0", "resource", "allocate", 1, 2),
    lambda: bridge._z3_integer_narrowing_check("Count", "uint16_t", "uint8_t", 1),
], ids=["copy", "allocation", "consistency", "path", "signedness", "auth", "lock", "resource", "narrowing"])
def test_expired_budget_never_queries_or_reads_native_models(monkeypatch, query):
    def forbidden(*args, **kwargs):
        pytest.fail("expired shared budget reached native query or model")
    monkeypatch.setattr(z3.Solver, "check", forbidden)
    monkeypatch.setattr(z3.Solver, "model", forbidden)
    with query_budget(0):
        result = query()
    if isinstance(result, tuple):
        assert result[0] is None and result[2] is None
        assert "inconclusive" in result[1]
    else:
        assert result.witness is None
        assert "UNSAT" not in result.reasoning


def test_unknown_narrowing_status_cannot_claim_unsat(monkeypatch):
    monkeypatch.setattr(z3.Solver, "check", lambda self: z3.unknown)
    monkeypatch.setattr(z3.Solver, "model", lambda self: pytest.fail("unknown has no model"))
    result = bridge._z3_integer_narrowing_check("Count", "uint16_t", "uint8_t", 3)
    assert result.solver_status == "unknown"
    assert result.witness is None
    assert "inconclusive" in result.reasoning and "UNSAT" not in result.reasoning
    assert bridge._result_from_child(bridge.IntegerNarrowingResult, asdict(result)).to_dict()["solver_status"] == "unknown"


@pytest.mark.parametrize("status", [None, "unknown", "unmodeled"])
def test_inconclusive_child_cannot_suppress_source_candidate(monkeypatch, status):
    pytest.importorskip("tree_sitter_c")
    monkeypatch.setattr(bridge, "_z3_importable", lambda: True)
    monkeypatch.setattr(bridge, "_run_z3_child", lambda *a, **k: asdict(
        bridge.IntegerNarrowingResult(solver_status=status)))
    result = bridge.check_integer_narrowing(
        "void Read(uint16_t Count) {\n uint8_t Small = Count;\n}",
        function_name="Read", language="c",
    )
    assert result.narrowing_found is True
    assert result.witness is None
    assert result.solver_status is None
    assert "without bounds check" in result.reasoning


@pytest.mark.parametrize("source,dest", [("ProjectType", "uint8_t"), ("uint16_t", "ProjectType"), (None, "uint8_t")])
def test_unsupported_types_do_not_invent_fallback_widths(monkeypatch, source, dest):
    monkeypatch.setattr("core.smt_solver.session.new_solver", lambda: pytest.fail("unmodeled type reached solver"))
    result = bridge._z3_integer_narrowing_check("Count", source, dest, 1)
    assert result.solver_status == "unmodeled"
    assert result.source_width == result.dest_width == 0
    assert result.witness is None


@pytest.mark.parametrize("source,dest,status", [("uint16_t", "uint8_t", "sat"), ("uint8_t", "uint8_t", "unsat")])
def test_genuine_narrowing_model_status_is_preserved(source, dest, status):
    result = bridge._z3_integer_narrowing_check("Count", source, dest, 1)
    assert result.solver_status == status
    assert result.narrowing_found is (status == "sat")
    if status == "sat":
        assert 255 < result.witness["Count"] < 65536


@pytest.mark.parametrize("status,found", [("sat", False), ("unsat", True)])
def test_inconsistent_child_status_is_not_a_verdict(monkeypatch, status, found):
    monkeypatch.setattr(bridge, "_z3_importable", lambda: True)
    monkeypatch.setattr(bridge, "_run_z3_child", lambda *a, **k: asdict(
        bridge.IntegerNarrowingResult(solver_status=status, narrowing_found=found)))
    assert bridge._try_z3_integer_narrowing("Count", "uint16_t", "uint8_t", 16, 8, 1) is None
