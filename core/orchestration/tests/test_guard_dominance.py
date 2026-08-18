"""Tests for the shared guard-dominance channel (P23).

The Joern query is stubbed at the ``run_guard_dominance_check``
boundary — no JVM, no CPG, no target execution.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import core.audit.joern_verify as jv
from core.audit.sweep import SweepResult
from core.orchestration.guard_dominance import (
    acquire_warm_server,
    apply_to_findings,
    missing_check_binding,
    refute_finding,
)


def _finding(fid="FIND-0001", *, reasoning=None, cwe="CWE-120", **extra):
    f = {
        "id": fid,
        "file": "src/parse.c",
        "function": "parse_header",
        "line": 40,
        "vuln_type": "buffer_overflow",
        "status": "not_disproven",
        "cwe_id": cwe,
        "candidate_reasoning": (
            reasoning
            if reasoning is not None
            else "missing bounds check on `len` before memcpy"
        ),
    }
    f.update(extra)
    return f


def _attack_path(finding_id="FIND-0001", proximity=7):
    return {
        "id": "AP-1",
        "finding": finding_id,
        "steps": [],
        "proximity": proximity,
        "blockers": [],
        "status": "uncertain",
    }


def _sweep_result(outcome, **kw):
    return SweepResult(
        tool="joern",
        file_path="src/parse.c",
        function_name="parse_header",
        outcome=outcome,
        rule_id="joern:guard-dominance",
        **kw,
    )


def _patch_query(monkeypatch, outcome, **kw):
    calls = []

    def fake(**kwargs):
        calls.append(kwargs)
        return _sweep_result(outcome, **kw)

    monkeypatch.setattr(jv, "run_guard_dominance_check", fake)
    return calls


class TestBinding:
    def test_missing_check_claim_binds(self):
        binding = missing_check_binding(_finding())
        assert binding == ("len", "memcpy")

    def test_non_missing_check_claim_does_not_bind(self):
        f = _finding(reasoning="integer overflow in size calculation")
        assert missing_check_binding(f) is None

    def test_no_identifier_no_binding(self):
        f = _finding(reasoning="missing check before memcpy somewhere")
        assert missing_check_binding(f) is None


class TestRefuteFinding:
    def test_refuted_returns_receipt(self, monkeypatch):
        _patch_query(
            monkeypatch, "refuted",
            details={"reason": "a check on 'len' dominates every "
                               "'memcpy' call site",
                     "dominators": [{"guard_line": 12}]},
        )
        receipt = refute_finding(_finding(), Path("/t"), object())
        assert receipt is not None
        assert receipt["outcome"] == "refuted"
        assert "dominates" in receipt["reason"]
        assert receipt["dominators"] == [{"guard_line": 12}]

    def test_confirmed_returns_none(self, monkeypatch):
        _patch_query(monkeypatch, "confirmed", matches=[{"line": 44}])
        assert refute_finding(_finding(), Path("/t"), object()) is None

    def test_inconclusive_returns_none(self, monkeypatch):
        _patch_query(monkeypatch, "inconclusive")
        assert refute_finding(_finding(), Path("/t"), object()) is None

    def test_unbindable_returns_none_without_query(self, monkeypatch):
        calls = _patch_query(monkeypatch, "refuted")
        f = _finding(reasoning="use-after-free of ctx")
        assert refute_finding(f, Path("/t"), object()) is None
        assert calls == []


class TestApplyToFindings:
    def test_refuted_demotes_anchored_paths(self, monkeypatch):
        _patch_query(
            monkeypatch, "refuted",
            details={"reason": "dominating check on 'len'"},
        )
        finding = _finding()
        path = _attack_path()
        stats = apply_to_findings(
            [finding], [path], Path("/t"), object(),
        )
        assert stats == {"checked": 1, "refuted": 1, "corroborated": 0,
                         "demoted_paths": 1}
        assert finding["guard_dominance"]["outcome"] == "refuted"
        assert path["proximity"] == 1
        assert any(
            b.startswith("joern:guard-dominance") for b in path["blockers"]
        )
        # Never suppression: the path (with receipt) stays.
        assert path["status"] == "uncertain"

    def test_confirmed_records_corroboration(self, monkeypatch):
        _patch_query(monkeypatch, "confirmed", matches=[{"line": 44}])
        finding = _finding()
        path = _attack_path()
        stats = apply_to_findings([finding], [path], Path("/t"), object())
        assert stats["corroborated"] == 1
        assert finding["guard_dominance"]["outcome"] == "confirmed"
        assert finding["guard_dominance"]["unguarded"] == [{"line": 44}]
        assert path["proximity"] == 7  # untouched

    def test_inconclusive_records_nothing(self, monkeypatch):
        _patch_query(monkeypatch, "inconclusive")
        finding = _finding()
        stats = apply_to_findings([finding], [], Path("/t"), object())
        assert stats["checked"] == 1
        assert "guard_dominance" not in finding

    @pytest.mark.parametrize("mutate", [
        {"status": "disproven"},
        {"ruling": {"status": "ruled_out"}},
        {"manual_override": True},
        {"guard_dominance": {"outcome": "refuted"}},
    ])
    def test_out_of_play_findings_skipped(self, monkeypatch, mutate):
        calls = _patch_query(monkeypatch, "refuted")
        finding = _finding(**mutate)
        stats = apply_to_findings([finding], [], Path("/t"), object())
        assert stats["checked"] == 0
        assert calls == []

    def test_cap_bounds_queries(self, monkeypatch):
        calls = _patch_query(monkeypatch, "inconclusive")
        findings = [_finding(fid=f"FIND-{i:04d}") for i in range(5)]
        stats = apply_to_findings(
            findings, [], Path("/t"), object(), cap=2,
        )
        assert stats["checked"] == 2
        assert len(calls) == 2


class TestAcquireWarmServer:
    def test_none_when_joern_unavailable(self, monkeypatch, tmp_path):
        from packages.joern import prereqs
        monkeypatch.setattr(prereqs, "is_available", lambda: False)
        assert acquire_warm_server(tmp_path, tmp_path) is None

    def test_none_when_no_cached_cpg(self, monkeypatch, tmp_path):
        from packages.joern import prereqs, runner
        monkeypatch.setattr(prereqs, "is_available", lambda: True)
        monkeypatch.setattr(
            runner, "load_cached_cpg", lambda target, cache: None,
        )
        assert acquire_warm_server(tmp_path, tmp_path, tmp_path / "x") is None

    def test_starts_server_on_cache_hit(self, monkeypatch, tmp_path):
        import packages.joern.server as server_mod
        from packages.joern import prereqs, runner

        class FakeCPG:
            path = tmp_path / "cpg.bin"

        class FakeServer:
            started = False
            imported = None

            def start(self):
                FakeServer.started = True

            def import_cpg(self, path):
                FakeServer.imported = path
                return True

            def stop(self):
                pass

        monkeypatch.setattr(prereqs, "is_available", lambda: True)
        monkeypatch.setattr(
            runner, "load_cached_cpg",
            lambda target, cache: FakeCPG() if cache == tmp_path else None,
        )
        monkeypatch.setattr(server_mod, "JoernServer", FakeServer)
        server = acquire_warm_server(tmp_path / "repo", tmp_path)
        assert isinstance(server, FakeServer)
        assert FakeServer.started
        assert FakeServer.imported == FakeCPG.path
