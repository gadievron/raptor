"""Tests for the ``--execute-exploits`` path in ``CrashAnalysisAgent``.

The full end-to-end (compile → sandbox-run → witness write) is
covered by ``test_exploit_verify_execute.py`` (which needs gcc).
These tests focus on the wiring: that the agent calls
``compile_and_execute`` instead of ``compile_verify`` when the flag
is on, that the outcome flows into the Witness, that the executor
respects the gate combinations.

monkeypatched throughout — no real sandbox / gcc needed.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Optional


# packages/llm_analysis/tests/test_crash_agent_execute.py
#   parents[3] = repo root
REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from core.witness import WitnessOutcome  # noqa: E402
from packages.binary_analysis.crash_analyser import CrashContext  # noqa: E402
from packages.llm_analysis.crash_agent import CrashAnalysisAgent  # noqa: E402


def _make_crash_context(
    crash_id: str = "C0001",
    binary_path: Optional[Path] = None,
    source_location: str = "src/parser.c:42",
) -> CrashContext:
    return CrashContext(
        crash_id=crash_id,
        binary_path=binary_path or Path("/nonexistent"),
        input_file=Path("/nonexistent_input"),
        signal="11",
        crash_type="stack_overflow",
        source_location=source_location,
        exploit_code="// poc",
        exploit_compiled=None,
        exploit_compile_errors=[],
        intent_match=None,
    )


def _stub_agent(
    tmp_path: Path,
    binary: Path,
    execute_exploits: bool = True,
    execute_timeout: int = 5,
    execute_sanitizers=None,
):
    """Build a minimal agent that has just enough state for the
    execute + record helpers; bypasses the LLM-init constructor."""
    agent = SimpleNamespace(
        out_dir=tmp_path,
        binary=binary,
        record_witnesses=True,
        _witness_store=None,
        execute_exploits=execute_exploits,
        execute_timeout=execute_timeout,
        execute_sanitizers=execute_sanitizers,
    )
    agent._compile_and_execute_exploit = (
        CrashAnalysisAgent._compile_and_execute_exploit.__get__(
            agent, type(agent)
        )
    )
    agent._record_exploit_witness = (
        CrashAnalysisAgent._record_exploit_witness.__get__(
            agent, type(agent)
        )
    )
    agent._resolve_execute_outcome = (
        CrashAnalysisAgent._resolve_execute_outcome
    )
    return agent


# ----------------------------------------------------------------------
# _compile_and_execute_exploit threads outcome onto crash_context
# ----------------------------------------------------------------------


def test_compile_and_execute_writes_execute_fields(tmp_path, monkeypatch):
    """The helper must populate exploit_compiled + execute_outcome
    + execute_detail on the crash_context."""
    binary = tmp_path / "target"
    binary.write_bytes(b"ELF")
    agent = _stub_agent(tmp_path, binary)
    crash = _make_crash_context()

    captured_kwargs = {}

    def fake_compile_and_execute(
        exploit_code, target_file_path, artifact_id, **kwargs,
    ):
        captured_kwargs["target_file_path"] = target_file_path
        captured_kwargs["artifact_id"] = artifact_id
        captured_kwargs.update(kwargs)
        return (
            True, [], WitnessOutcome.EXIT_SIGNAL,
            {"signal": "SIGSEGV", "crashed": True},
        )

    import packages.llm_analysis.exploit_verify as ev_mod
    monkeypatch.setattr(
        ev_mod, "compile_and_execute", fake_compile_and_execute,
    )

    agent._compile_and_execute_exploit(crash, "// exploit\n")

    assert crash.exploit_compiled is True
    assert crash.execute_outcome == WitnessOutcome.EXIT_SIGNAL.value
    assert crash.execute_detail["signal"] == "SIGSEGV"
    assert crash.execute_detail["crashed"] is True
    # target_binary_path must flow through as self.binary
    assert captured_kwargs["target_binary_path"] == binary
    # timeout must be the agent's configured value
    assert captured_kwargs["timeout"] == 5
    # No sanitizers by default
    assert captured_kwargs.get("sanitizers") is None
    # source_location → target_file_path (strip line number)
    assert captured_kwargs["target_file_path"] == "src/parser.c"


def test_compile_and_execute_outcome_none_leaves_field_unset(
    tmp_path, monkeypatch,
):
    """When compile_and_execute returns outcome=None (compile
    failure, sandbox unavailable, etc.), execute_outcome stays
    None on the crash_context."""
    binary = tmp_path / "target"
    binary.write_bytes(b"ELF")
    agent = _stub_agent(tmp_path, binary)
    crash = _make_crash_context()

    def fake_compile_and_execute(*args, **kwargs):
        return False, ["error line 1"], None, {}

    import packages.llm_analysis.exploit_verify as ev_mod
    monkeypatch.setattr(
        ev_mod, "compile_and_execute", fake_compile_and_execute,
    )

    agent._compile_and_execute_exploit(crash, "// bad exploit\n")
    assert crash.exploit_compiled is False
    assert crash.exploit_compile_errors == ["error line 1"]
    assert crash.execute_outcome is None
    assert crash.execute_detail == {}


# ----------------------------------------------------------------------
# Witness recorder upgrades NOT_RUN → executed outcome
# ----------------------------------------------------------------------


def test_witness_records_executed_outcome(tmp_path, monkeypatch):
    """When execute_outcome is set on the crash context, the
    recorded Witness uses that outcome, not NOT_RUN."""
    binary = tmp_path / "target"
    binary.write_bytes(b"ELF")
    agent = _stub_agent(tmp_path, binary)
    crash = _make_crash_context()
    crash.execute_outcome = WitnessOutcome.SANITIZER_REPORT.value
    crash.execute_detail = {"sanitizer": "asan", "crashed": True}

    agent._record_exploit_witness(crash, "// exploit\n")

    from core.witness import WitnessStore
    store = WitnessStore(tmp_path / "witnesses")
    manifests = list(
        (tmp_path / "witnesses" / "manifests").glob("*.json")
    )
    assert len(manifests) == 1
    witness = store.get_witness(manifests[0].stem)
    assert witness.observed_outcome is WitnessOutcome.SANITIZER_REPORT
    assert witness.outcome_detail["sanitizer"] == "asan"
    assert witness.outcome_detail["crashed"] is True


def test_witness_keeps_not_run_when_executed_outcome_unset(
    tmp_path, monkeypatch,
):
    """When execute_outcome is None (operator didn't pass
    --execute-exploits or execution failed), the Witness stays
    NOT_RUN — the legacy behaviour."""
    binary = tmp_path / "target"
    binary.write_bytes(b"ELF")
    agent = _stub_agent(tmp_path, binary)
    crash = _make_crash_context()
    # execute_outcome stays default (None)

    agent._record_exploit_witness(crash, "// exploit\n")

    from core.witness import WitnessStore
    store = WitnessStore(tmp_path / "witnesses")
    manifests = list(
        (tmp_path / "witnesses" / "manifests").glob("*.json")
    )
    witness = store.get_witness(manifests[0].stem)
    assert witness.observed_outcome is WitnessOutcome.NOT_RUN
    assert "sanitizer" not in witness.outcome_detail
    assert "signal" not in witness.outcome_detail


def test_resolve_execute_outcome_known_values():
    assert (
        CrashAnalysisAgent._resolve_execute_outcome("exit_signal")
        is WitnessOutcome.EXIT_SIGNAL
    )
    assert (
        CrashAnalysisAgent._resolve_execute_outcome("sanitizer_report")
        is WitnessOutcome.SANITIZER_REPORT
    )
    assert (
        CrashAnalysisAgent._resolve_execute_outcome("no_obvious_effect")
        is WitnessOutcome.NO_OBVIOUS_EFFECT
    )


def test_resolve_execute_outcome_none_passes_through():
    assert CrashAnalysisAgent._resolve_execute_outcome(None) is None
    assert CrashAnalysisAgent._resolve_execute_outcome("") is None


def test_resolve_execute_outcome_unknown_string_to_unknown():
    """Defensive: future code path emitting an unrecognised
    string should not break the witness write."""
    assert (
        CrashAnalysisAgent._resolve_execute_outcome("future_outcome")
        is WitnessOutcome.UNKNOWN
    )


# ----------------------------------------------------------------------
# Gate combination semantics
# ----------------------------------------------------------------------


def test_constructor_defaults():
    """Default: execute_exploits=False (policy shift; opt-in only).
    execute_timeout=5 matches the long-dormant safe_test_exploit
    default. Inspected via signature rather than constructed,
    since the real constructor needs LLM credentials."""
    import inspect
    sig = inspect.signature(CrashAnalysisAgent.__init__)
    assert sig.parameters["execute_exploits"].default is False
    assert sig.parameters["execute_timeout"].default == 5
    assert sig.parameters["execute_sanitizers"].default is None


def test_execute_sanitizers_flows_to_compile_and_execute(
    tmp_path, monkeypatch,
):
    """``execute_sanitizers=['address']`` on the agent must reach
    ``compile_and_execute`` as ``sanitizers=['address']``."""
    binary = tmp_path / "target"
    binary.write_bytes(b"ELF")
    agent = _stub_agent(
        tmp_path, binary, execute_sanitizers=["address", "undefined"],
    )
    crash = _make_crash_context()

    captured_kwargs = {}

    def fake_compile_and_execute(
        exploit_code, target_file_path, artifact_id, **kwargs,
    ):
        captured_kwargs.update(kwargs)
        return True, [], WitnessOutcome.SANITIZER_REPORT, {
            "sanitizer": "asan", "crashed": True,
        }

    import packages.llm_analysis.exploit_verify as ev_mod
    monkeypatch.setattr(
        ev_mod, "compile_and_execute", fake_compile_and_execute,
    )

    agent._compile_and_execute_exploit(crash, "// exploit\n")

    assert captured_kwargs.get("sanitizers") == ["address", "undefined"]
    assert crash.execute_outcome == WitnessOutcome.SANITIZER_REPORT.value
    assert crash.execute_detail["sanitizer"] == "asan"
