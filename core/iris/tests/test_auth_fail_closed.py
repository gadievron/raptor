"""Persistent-401 fail-closed behaviour for the IRIS synthesis phases.

Regression for the fail-open observed on a >12 h audit whose dispatcher
token expired mid-run: iris-assumptions "returned" 0/6 batches and
iris.synthesise 0 assumptions — every batch's 401 was converted into an
empty/heuristic result and the phases reported success. On persistent
auth refusal the phase must ABORT with ``LLMAuthPersistentError``
instead of zero-filling.
"""

from __future__ import annotations

import json

import pytest

from core.iris.refine import refine_loop
from core.iris.specs import CandidateFunction, TaintSpec
from core.iris.synthesise import synthesise_assumptions, synthesise_specs
from core.llm.client import LLMAuthPersistentError

TOKEN_EXPIRED_MSG = (
    "All cloud models failed (tried 1 model(s)).\n"
    "Last error: Error code: 401 - "
    "{'error': 'token expired (age 45011.6s, ttl 28800s)'}\n"
    "→ Check API keys and network connectivity"
)
GENERIC_401_MSG = (
    "All cloud models failed (tried 2 model(s)).\n"
    "Last error: Error code: 401 - authentication_error: "
    "invalid x-api-key"
)


def _cand(fn="check_input", file="src/auth.py"):
    return CandidateFunction(
        function=fn, file=file, source=f"def {fn}(x):\n    return x\n",
    )


def _sink_spec(fn="exec_sql", file="src/db.py"):
    return TaintSpec(function=fn, file=file, role="sink")


class _RefusingLLM:
    """Bare-callable client whose every call fails like a dead token."""

    def __init__(self, message: str):
        self.message = message
        self.calls = 0

    def __call__(self, system, user):
        self.calls += 1
        raise RuntimeError(self.message)


class TestSpecSynthesisFailClosed:
    def test_token_expired_aborts_phase(self):
        llm = _RefusingLLM(TOKEN_EXPIRED_MSG)
        with pytest.raises(LLMAuthPersistentError) as exc_info:
            synthesise_specs([_cand()], llm)
        assert exc_info.value.phase == "iris-synth"
        assert "iris-synth" in str(exc_info.value)

    def test_tripped_tracker_stops_submitting_batches(self):
        # The explicit token-death signal trips on batch 1; batches
        # 2-5 must skip their LLM call entirely, then the phase raises.
        llm = _RefusingLLM(TOKEN_EXPIRED_MSG)
        cands = [_cand(fn=f"fn_{i}") for i in range(5)]
        with pytest.raises(LLMAuthPersistentError):
            synthesise_specs(cands, llm, max_batch=1)
        assert llm.calls == 1

    def test_three_consecutive_generic_401s_abort(self):
        llm = _RefusingLLM(GENERIC_401_MSG)
        cands = [_cand(fn=f"fn_{i}") for i in range(3)]
        with pytest.raises(LLMAuthPersistentError):
            synthesise_specs(cands, llm, max_batch=1)
        assert llm.calls == 3

    def test_below_threshold_keeps_degrade_semantics(self):
        # Two 401s are not yet "persistent": the pre-existing
        # heuristic-fallback contract holds and no abort fires.
        llm = _RefusingLLM(GENERIC_401_MSG)
        cands = [_cand(fn=f"fn_{i}") for i in range(2)]
        specs = synthesise_specs(cands, llm, max_batch=1)
        assert llm.calls == 2
        assert len(specs) == 2
        assert all(s.source == "heuristic" for s in specs)

    def test_non_auth_errors_keep_degrade_semantics(self):
        llm = _RefusingLLM("upstream error: ReadTimeout")
        cands = [_cand(fn=f"fn_{i}") for i in range(5)]
        specs = synthesise_specs(cands, llm, max_batch=1)
        assert llm.calls == 5
        assert len(specs) == 5
        assert all(s.source == "heuristic" for s in specs)


class TestAssumptionSynthesisFailClosed:
    def test_token_expired_aborts_phase(self):
        llm = _RefusingLLM(TOKEN_EXPIRED_MSG)
        with pytest.raises(LLMAuthPersistentError) as exc_info:
            synthesise_assumptions([_sink_spec()], llm)
        assert exc_info.value.phase == "iris-assumptions"
        assert "iris-assumptions" in str(exc_info.value)

    def test_generic_401s_abort_across_batches(self):
        llm = _RefusingLLM(GENERIC_401_MSG)
        # 3 batches of 20 sink specs each (_MAX_BATCH = 20).
        specs = [_sink_spec(fn=f"sink_{i:02d}") for i in range(60)]
        with pytest.raises(LLMAuthPersistentError):
            synthesise_assumptions(specs, llm)
        assert llm.calls == 3


class TestRefineLoopPropagation:
    """The refine loop's degrade-to-heuristic excepts must not swallow
    the typed phase abort."""

    def test_initial_synthesis_abort_propagates(self):
        llm = _RefusingLLM(TOKEN_EXPIRED_MSG)
        with pytest.raises(LLMAuthPersistentError):
            refine_loop([_cand()], llm, tool_runner=None)

    def test_assumption_leg_abort_propagates(self):
        class _SpecThenRefuse:
            def __init__(self):
                self.calls = 0

            def __call__(self, system, user):
                self.calls += 1
                if self.calls == 1:
                    return json.dumps([{
                        "function": "exec_sql",
                        "file": "src/db.py",
                        "role": "sink",
                        "taint_classes": ["sql"],
                        "confidence": 0.9,
                    }])
                raise RuntimeError(TOKEN_EXPIRED_MSG)

        llm = _SpecThenRefuse()
        with pytest.raises(LLMAuthPersistentError) as exc_info:
            refine_loop([_cand(fn="exec_sql")], llm, tool_runner=None)
        assert exc_info.value.phase == "iris-assumptions"
