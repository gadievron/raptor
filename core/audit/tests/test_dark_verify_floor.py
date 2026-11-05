"""Containment-floor refusals at the dark-verify seam.

The sandbox floor contract's verification-seam mapping: when the
sandbox refuses to execute a dark witness because the environment
cannot deliver the required containment tier (``SandboxFloorError``),
the verdict is about the ENVIRONMENT, not the hypothesis. The pass
records an error-shaped, structured ``unverifiable_environment``
verdict on that finding's record and re-raises (record-then-raise):
the refusal is host-deterministic, so one loud failure with one
surfaced record beats N benign-looking "error" rows.

Everything except the integration probe is faked — no LLM, no gcc,
no real sandbox spawn.
"""

from __future__ import annotations

import json
import sys
import time

import pytest

import core.audit.dark_verify as _dv
from core.audit.dark_verify import (
    DarkWitnessSpec,
    floor_refusal_result,
)
from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
    _run_dark_verification,
)
from core.sandbox.errors import SandboxFloorError, SandboxSetupError
from core.sandbox.tiers import ContainmentTier


def _outcome(file, function, status="dark", hypothesis=""):
    o = ReviewOutcome(
        file=file, function=function, status=status,
        body="suspected bug", hypothesis=hypothesis,
    )
    o.review_result = None
    o.evidence_tool = ""
    return o


def _result(outcomes):
    r = OrchestratorResult()
    r.outcomes = list(outcomes)
    for o in outcomes:
        if o.status == "dark":
            r.dormant += 1
    return r


def _floor_error(remedies: str = "install uidmap; re-run"):
    return SandboxFloorError(
        "sandbox containment floor violated",
        remedies,
        achievable=ContainmentTier.LANDLOCK_ONLY,
        floor=ContainmentTier.MOUNT_NS,
        setup_category="U",
    )


def _spec(finding_key: str = "math_util.py:divide") -> DarkWitnessSpec:
    return DarkWitnessSpec(
        finding_key=finding_key,
        file="math_util.py",
        function="divide",
        language="python",
    )


_WITNESS_JSON = json.dumps({
    "module_path": "math_util",
    "function": "divide",
    "args": [1, 0],
    "expected_exception": "ZeroDivisionError",
    "rationale": "dividing by zero",
})


def _dark_run_fixture(tmp_path, n_outcomes: int = 1):
    """A config + result pair whose outcomes all parse to executable
    witness specs (mirrors the positive-control fixture in
    test_postloop_budget_gating)."""
    src = tmp_path / "math_util.py"
    src.write_text("def divide(a, b):\n    return a / b\n", encoding="utf-8")
    config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
    outcomes = [
        _outcome("math_util.py", "divide", hypothesis="division by zero")
        for _ in range(n_outcomes)
    ]
    return config, _result(outcomes)


# ---------------------------------------------------------------------------
# floor_refusal_result — the module-owned verdict mapping
# ---------------------------------------------------------------------------


class TestFloorRefusalResult:
    def test_maps_to_error_verdict_with_structured_detail(self):
        res = floor_refusal_result(_spec(), "python", _floor_error())
        assert res.finding_key == "math_util.py:divide"
        assert res.verdict == "error"  # existing vocabulary, no new value
        assert res.language == "python"
        assert res.oracle_reliability == "unavailable"
        assert res.match_detail.startswith("unverifiable_environment:")
        assert "mount-ns required" in res.match_detail
        assert "landlock achievable" in res.match_detail
        assert "install uidmap; re-run" in res.match_detail
        assert "witness never executed" in res.match_detail

    def test_result_round_trips_through_to_dict(self):
        res = floor_refusal_result(_spec(), "c", _floor_error())
        json.dumps(res.to_dict())  # schema-compatible, JSON-safe

    def test_empty_remedies_fall_back_to_error_text(self):
        res = floor_refusal_result(_spec(), "c", _floor_error(remedies=""))
        assert "sandbox containment floor violated" in res.match_detail

    def test_rejects_non_floor_exceptions(self):
        with pytest.raises(TypeError):
            floor_refusal_result(
                _spec(), "c", SandboxSetupError("engage failed"),
            )
        with pytest.raises(TypeError):
            floor_refusal_result(_spec(), "c", ValueError("nope"))


# ---------------------------------------------------------------------------
# _run_dark_verification — record-then-raise
# ---------------------------------------------------------------------------


class TestDarkVerificationFloorRefusal:
    def test_refusal_records_verdict_then_raises(
            self, tmp_path, monkeypatch, caplog):
        config, result = _dark_run_fixture(tmp_path)

        def refusing_witness(spec, target_root, **kwargs):
            raise _floor_error()

        monkeypatch.setattr(_dv, "execute_witness", refusing_witness)
        with caplog.at_level("ERROR", logger="core.audit.orchestrator"), \
                pytest.raises(SandboxFloorError):
            _run_dark_verification(
                result, config, llm_client=lambda p, s: _WITNESS_JSON,
                start_time=time.monotonic(),
                include_diagnostics=True,
            )

        # The environment verdict landed on the finding's record.
        records = json.loads(
            (tmp_path / "dark-verify-results.json").read_text())
        assert len(records) == 1
        rec = records[0]
        assert rec["file"] == "math_util.py"
        assert rec["function"] == "divide"
        assert rec["verdict"] == "error"
        assert rec["match_detail"].startswith("unverifiable_environment:")
        assert "install uidmap; re-run" in rec["match_detail"]
        # An environment refusal is NOT a hypothesis verdict: the
        # outcome's status is untouched (neither confirmed nor
        # refuted), and the run counters don't move.
        assert rec["status"] == "dark"
        assert result.outcomes[0].status == "dark"
        assert result.findings == 0
        assert result.clean == 0
        # The one-line summary is surfaced from the structured payload.
        assert "execution(s) refused" in caplog.text
        assert "mount-ns required" in caplog.text

    def test_first_refusal_stops_the_pass(self, tmp_path, monkeypatch):
        """Host-deterministic refusal: one surfaced record, one LLM
        call — never one masked error per remaining outcome."""
        config, result = _dark_run_fixture(tmp_path, n_outcomes=3)
        llm_calls: list = []
        witness_calls: list = []

        def refusing_witness(spec, target_root, **kwargs):
            witness_calls.append(spec)
            raise _floor_error()

        monkeypatch.setattr(_dv, "execute_witness", refusing_witness)
        with pytest.raises(SandboxFloorError):
            _run_dark_verification(
                result, config,
                llm_client=lambda p, s: llm_calls.append(p) or _WITNESS_JSON,
                start_time=time.monotonic(),
                include_diagnostics=True,
            )
        assert len(llm_calls) == 1
        assert len(witness_calls) == 1
        records = json.loads(
            (tmp_path / "dark-verify-results.json").read_text())
        assert len(records) == 1

    def test_plain_setup_error_propagates_without_record(
            self, tmp_path, monkeypatch):
        """Only the typed floor subtype is mapped: a generic
        SandboxSetupError keeps its pre-existing BaseException flight
        path — it propagates and mints no record."""
        config, result = _dark_run_fixture(tmp_path)

        def failing_witness(spec, target_root, **kwargs):
            raise SandboxSetupError("engage failed", "fix the host")

        monkeypatch.setattr(_dv, "execute_witness", failing_witness)
        with pytest.raises(SandboxSetupError) as excinfo:
            _run_dark_verification(
                result, config, llm_client=lambda p, s: _WITNESS_JSON,
                start_time=time.monotonic(),
                include_diagnostics=True,
            )
        assert not isinstance(excinfo.value, SandboxFloorError)
        assert not (tmp_path / "dark-verify-results.json").exists()
        assert result.outcomes[0].status == "dark"

    def test_ordinary_exception_propagates_without_record(
            self, tmp_path, monkeypatch):
        """Non-sandbox exceptions from the witness step keep their
        pre-existing behaviour too (propagate; the caller's
        except-Exception wrapper owns them)."""
        config, result = _dark_run_fixture(tmp_path)

        def broken_witness(spec, target_root, **kwargs):
            raise ValueError("boom")

        monkeypatch.setattr(_dv, "execute_witness", broken_witness)
        with pytest.raises(ValueError):
            _run_dark_verification(
                result, config, llm_client=lambda p, s: _WITNESS_JSON,
                start_time=time.monotonic(),
                include_diagnostics=True,
            )
        assert not (tmp_path / "dark-verify-results.json").exists()

    def test_matched_prediction_remains_recorded_without_promotion(self, tmp_path):
        """Positive control: the arm sits around the real
        execute_witness without disturbing the confirm path."""
        config, result = _dark_run_fixture(tmp_path)
        _run_dark_verification(
            result, config, llm_client=lambda p, s: _WITNESS_JSON,
            start_time=time.monotonic(),
            include_diagnostics=True,
        )
        assert result.outcomes[0].status == "dark"
        records = json.loads(
            (tmp_path / "dark-verify-results.json").read_text())
        assert records[0]["verdict"] == "confirmed"


# ---------------------------------------------------------------------------
# Integration-shaped: a GENUINE floor refusal through the real entry
# contract (no fakes below the probe seam)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform != "linux", reason="linux probe seam")
def test_native_witness_genuine_floor_refusal_maps(tmp_path, monkeypatch):
    """Force the environmental userns-less shape (the B1 population:
    Docker default-seccomp / Ubuntu-24.04 hosts) and drive dark
    verify's native runner at it: the entry contract refuses with the
    typed floor error BEFORE any spawn, and the seam mapping produces
    the structured unverifiable-environment verdict from it."""
    import shutil

    from core.audit.dark_verify import _execute as _dvx
    from core.sandbox import context as _ctx
    from core.witness import refusal_detail

    monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", raising=False)
    monkeypatch.setattr(_ctx, "check_net_available", lambda: False)

    # Pre-flight (mirrors test_fresh_procfs_contract's environmental
    # probes): the same shape WITHOUT the contract must run on this
    # host, otherwise a refusal below is unattributable to the gate
    # under test.
    try:
        pre = _ctx.run(["true"], target=str(tmp_path),
                       output=str(tmp_path), timeout=60)
    except BaseException as e:  # noqa: BLE001 — includes SandboxSetupError
        pytest.skip(f"degraded lane unavailable on this host: {e}")
    if pre.returncode != 0:
        pytest.skip("degraded-lane pre-flight did not run cleanly")

    binary = tmp_path / "witness-bin"
    shutil.copy(shutil.which("true"), binary)
    spec = _spec("native.c:f")

    with pytest.raises(SandboxFloorError) as excinfo:
        _dvx._run_native_binary(
            spec, binary, tmp_path, timeout_s=5, lang="c",
        )
    detail = refusal_detail(excinfo.value)
    assert detail is not None
    assert detail["status"] == "unverifiable_environment"
    assert detail["floor"] == "mount-ns"
    assert detail["remedies"]  # operator-facing remedy text present
    refusal = floor_refusal_result(spec, "c", excinfo.value)
    assert refusal.verdict == "error"
    assert "unverifiable_environment" in refusal.match_detail
