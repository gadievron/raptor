"""An infeasible candidate guard must not terminate a multi-site scan."""

import pytest

from core.audit import condition_smt as bridge


_CASES = {
    "auth": ("", "return 0;", "if (!capable(CAP_SYS_ADMIN))\n        return -1;",
             "check_auth_bypass", "_try_z3_auth_bypass", "bypass_found"),
    "lock": ("mutex_lock(&lock);", "return -1;", "mutex_unlock(&lock);",
             "check_lock_discipline", "_try_z3_lock_discipline", "violation_found"),
    "resource": ("void *buffer = malloc(16);", "return -1;", "free(buffer);",
                 "check_resource_leak", "_try_z3_resource_leak", "leak_found"),
}


def _exercise(monkeypatch, kind, second_guard, first_guard="Count < 0 && Count > 10"):
    pytest.importorskip("z3")
    setup, ret, cleanup, checker, seam, found = _CASES[kind]
    calls = []

    def native(*args):
        calls.append(args[0])
        if kind == "auth":
            return bridge._z3_auth_bypass_check(*args)
        if kind == "lock":
            # The worker request carries bypassed-unlock diagnostics; the
            # native predicate takes the guard, function and return line.
            return bridge._z3_lock_discipline_check(*args[:3])
        return bridge._z3_resource_leak_check(*args)

    monkeypatch.setattr(bridge, seam, native)
    source = (
        "int subject(int Count) {\n"
        f"    {setup}\n"
        f"    if ({first_guard})\n"
        f"        {ret}\n"
        f"    if ({second_guard})\n"
        f"        {ret}\n"
        f"    {cleanup}\n"
        "    return 0;\n"
        "}\n"
    )
    return getattr(bridge, checker)(source), calls, found


@pytest.mark.parametrize("kind", _CASES)
def test_infeasible_first_candidate_does_not_hide_later_witness(monkeypatch, kind):
    result, calls, found = _exercise(monkeypatch, kind, "Count == 1")
    assert getattr(result, found) is True
    assert result.witness == {"Count": 1}
    assert calls == ["(Count < 0 && Count > 10)", "(Count == 1)"]


@pytest.mark.parametrize("kind", _CASES)
def test_all_infeasible_candidates_remain_negative(monkeypatch, kind):
    result, calls, found = _exercise(monkeypatch, kind, "Count == 1 && Count == 2")
    assert getattr(result, found) is False
    assert result.witness is None
    assert calls == ["(Count < 0 && Count > 10)", "(Count == 1 && Count == 2)"]


@pytest.mark.parametrize("kind", _CASES)
def test_first_witness_is_retained_without_querying_later_sites(monkeypatch, kind):
    result, calls, found = _exercise(
        monkeypatch, kind, "Count == 1 && Count == 2", first_guard="Count == 3",
    )
    assert getattr(result, found) is True
    assert result.witness == {"Count": 3}
    assert calls == ["(Count == 3)"]
