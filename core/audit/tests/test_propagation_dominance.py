"""Tests for the constraint-propagation dominance resolver tier (P23).

The Joern query and the caller lookup are stubbed — no JVM, no CPG.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import core.audit.joern_verify as jv
import core.audit.propagation as prop
from core.audit.constraints import Constraint
from core.audit.propagation import (
    PropagationConfig,
    _try_joern_dominance_resolve,
    propagate_one_hop,
)
from core.audit.sweep import SweepResult


def _constraint(**kw):
    defaults = {
        "function": "copy_data",
        "file": "src/copy.c",
        "kind": "parameter",
        "target": "len",
        "rule": "len must be <= 1024",
        "violation": "stack overflow in fixed buf",
        "cwe": "CWE-120",
        "direction": "callers",
    }
    defaults.update(kw)
    return Constraint(**defaults)


_SENTINEL_SERVER = object()


def _config(server=_SENTINEL_SERVER, target=Path("/t")):
    return PropagationConfig(
        target_path=target,
        joern_server=server,
        inventory={},
    )


def _patch(monkeypatch, outcomes):
    """Stub get_callers + find_function_line + the dominance query.

    ``outcomes`` maps caller function name → SweepResult outcome.
    """
    monkeypatch.setattr(
        prop, "get_callers",
        lambda file, fn, line, inv: [
            (f"src/{name}.c", name, 10) for name in outcomes
        ],
    )
    monkeypatch.setattr(prop, "find_function_line", lambda *a, **kw: 5)

    calls = []

    def fake_check(**kwargs):
        calls.append(kwargs)
        name = kwargs["function_name"]
        return SweepResult(
            tool="joern",
            file_path=kwargs["file_path"],
            function_name=name,
            outcome=outcomes[name],
            rule_id="joern:guard-dominance",
        )

    monkeypatch.setattr(jv, "run_guard_dominance_check", fake_check)
    return calls


class TestDominanceResolve:
    def test_all_callers_guarded_refutes(self, monkeypatch):
        _patch(monkeypatch, {"caller_a": "refuted", "caller_b": "refuted"})
        result = _try_joern_dominance_resolve(_constraint(), _config(), {})
        assert result is not None
        assert result.resolved
        assert result.resolution == "refuted"
        assert result.resolver_used == "joern_dominance"

    def test_unguarded_caller_confirms(self, monkeypatch):
        _patch(monkeypatch, {"caller_a": "refuted", "caller_b": "confirmed"})
        result = _try_joern_dominance_resolve(_constraint(), _config(), {})
        assert result is not None
        assert result.resolution == "confirmed"
        assert result.resolver_used == "joern_dominance"

    def test_inconclusive_mix_falls_through(self, monkeypatch):
        _patch(monkeypatch, {"caller_a": "refuted", "caller_b": "inconclusive"})
        assert _try_joern_dominance_resolve(
            _constraint(), _config(), {},
        ) is None

    def test_no_server_disables_tier(self, monkeypatch):
        calls = _patch(monkeypatch, {"caller_a": "refuted"})
        assert _try_joern_dominance_resolve(
            _constraint(), _config(server=None), {},
        ) is None
        assert calls == []

    def test_no_target_path_disables_tier(self, monkeypatch):
        calls = _patch(monkeypatch, {"caller_a": "refuted"})
        assert _try_joern_dominance_resolve(
            _constraint(), _config(target=None), {},
        ) is None
        assert calls == []

    @pytest.mark.parametrize("kind", ["postcondition", "state", "ordering"])
    def test_non_guardable_kinds_skipped(self, monkeypatch, kind):
        calls = _patch(monkeypatch, {"caller_a": "refuted"})
        assert _try_joern_dominance_resolve(
            _constraint(kind=kind), _config(), {},
        ) is None
        assert calls == []

    def test_callee_direction_skipped(self, monkeypatch):
        calls = _patch(monkeypatch, {"caller_a": "refuted"})
        assert _try_joern_dominance_resolve(
            _constraint(direction="callees"), _config(), {},
        ) is None
        assert calls == []

    def test_invalid_identifier_skipped(self, monkeypatch):
        calls = _patch(monkeypatch, {"caller_a": "refuted"})
        assert _try_joern_dominance_resolve(
            _constraint(target="len; DROP"), _config(), {},
        ) is None
        assert calls == []

    def test_caller_probe_bounded(self, monkeypatch):
        outcomes = {f"caller_{i}": "refuted" for i in range(6)}
        calls = _patch(monkeypatch, outcomes)
        _try_joern_dominance_resolve(_constraint(), _config(), {})
        assert len(calls) == prop._DOMINANCE_MAX_CALLERS

    def test_query_exception_falls_through(self, monkeypatch):
        monkeypatch.setattr(
            prop, "get_callers",
            lambda *a, **kw: [("src/a.c", "caller_a", 10)],
        )
        monkeypatch.setattr(prop, "find_function_line", lambda *a, **kw: 5)

        def boom(**kwargs):
            raise RuntimeError("server died")

        monkeypatch.setattr(jv, "run_guard_dominance_check", boom)
        assert _try_joern_dominance_resolve(
            _constraint(), _config(), {},
        ) is None


class TestHopIntegration:
    def test_hop_resolves_via_dominance_tier(self, monkeypatch):
        _patch(monkeypatch, {"caller_a": "refuted"})
        counters = {"joern_dominance": type(
            "TC", (), {"confirmed": 0, "refuted": 0, "inconclusive": 0,
                       "errors": 0},
        )()}
        result = propagate_one_hop(
            _constraint(),
            checklist={},
            entry_points=set(),
            config=_config(),
            tier_counters=counters,
        )
        assert result.resolved
        assert result.resolver_used == "joern_dominance"
        assert counters["joern_dominance"].refuted == 1

    def test_config_default_has_no_server(self):
        assert PropagationConfig().joern_server is None
