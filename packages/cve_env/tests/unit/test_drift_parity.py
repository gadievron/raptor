"""Phase 1.A: drift-parity tests pinning prompt↔code contracts.

Each test locks one pair where a numeric / textual / structural fact must
agree between ``src/cve_env/agent/prompts.py`` (LLM-facing) and the runtime
that enforces it. Drift caused real bench losses — these prevent silent
re-divergence.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
pytest.importorskip("claude_agent_sdk")

import cve_env

# Derive the package source dir from the imported module — layout-independent
# (works for the standalone src/cve_env tree and the packages/cve_env/cve_env
# home under raptor without hardcoding nesting depth).
_PKG_ROOT = Path(cve_env.__file__).resolve().parent  # .../cve_env
PROMPTS_PATH = _PKG_ROOT / "agent" / "prompts.py"

@pytest.fixture(scope="module")
def prompt_text() -> str:
    return PROMPTS_PATH.read_text()

def test_nvd_lookup_threshold_parity(prompt_text: str) -> None:
    """``_NVD_LOOKUP_THRESHOLD = 2`` must be advertised verbatim in the prompt.

    Phase 35.4 guard short-circuits agents that re-research mid-CVE. Drift here
    means the agent doesn't know the cap and burns a turn on a no-op call.
    """
    from cve_env.agent.tools import _NVD_LOOKUP_THRESHOLD

    assert _NVD_LOOKUP_THRESHOLD == 2  # locked-in default; raise this with caution
    assert re.search(
        rf"nvd_lookup is capped at {_NVD_LOOKUP_THRESHOLD} calls",
        prompt_text,
    ), (
        f"prompts.py must mention the runtime cap "
        f"(nvd_lookup is capped at {_NVD_LOOKUP_THRESHOLD} calls). "
        f"If the threshold changes, update both at once."
    )

def test_functional_smoke_heuristic_parity(prompt_text: str) -> None:
    """The 3 active-vuln check types must all be advertised in the prompt."""
    from cve_env.tools.verify import _ACTIVE_PROBE_TYPES

    expected_types = frozenset({"http_request_check", "exec_check", "tcp_probe_check"})
    assert expected_types == _ACTIVE_PROBE_TYPES, (
        "Active vuln-types changed; update prompts.py + this lock-test."
    )

    for check_type in _ACTIVE_PROBE_TYPES:
        assert check_type in prompt_text, (
            f"Active check type {check_type!r} is missing from prompts.py. "
            f"Agent cannot use what it does not see (Phase 31.3 / Phase 63.2)."
        )

def test_p_invariants_named_in_prompt(prompt_text: str) -> None:
    """Named invariants P6/P14/P17/P18 must be referenced in the prompt.

    P-codes are the dockerfile_gen validators (apt-cap, digest-pinned base,
    no-privilege-escalation, loopback-only). When an agent reads a P-code in
    a validator error it must be able to look it up in the prompt.
    """
    expected = {"P6", "P14", "P17", "P18"}
    found = {code for code in expected if re.search(rf"\b{code}\b", prompt_text)}
    missing = expected - found
    assert not missing, (
        f"P-invariant codes missing from prompts.py: {sorted(missing)}. "
        f"Validators emit these; the prompt must explain them."
    )

def test_loop_exception_path_branch_parity() -> None:
    """``_classify_verify_outcome`` must be called both on the happy path
    AND the exception path (loop.py:225 + the relabel comment at 643/655)."""
    loop_text = (_PKG_ROOT / "agent" / "loop.py").read_text()
    classify_count = loop_text.count("_classify_verify_outcome")
    assert classify_count >= 2, (
        f"_classify_verify_outcome is referenced only "
        f"{classify_count} times in loop.py; both happy-path and "
        f"exception-path must call it (Phase 31.2 parity)."
    )

def test_refusal_two_systems_disjoint() -> None:
    """``_REFUSAL_SIGNATURES`` (string substrings) and ``_REFUSAL_PATTERNS``
    (regex compiled) target different surfaces; they must not cover the
    same shape with different mechanisms (existing test_refusals.py only
    checks ``len >= 8`` for SIGNATURES; disjointness is uncovered).
    """
    from cve_env.agent.llm import _REFUSAL_SIGNATURES
    from cve_env.agent.refusals import _REFUSAL_PATTERNS

    assert isinstance(_REFUSAL_SIGNATURES, tuple)
    assert isinstance(_REFUSAL_PATTERNS, tuple)
    assert all(isinstance(s, str) for s in _REFUSAL_SIGNATURES)
    assert all(hasattr(p, "search") for p in _REFUSAL_PATTERNS), (
        "_REFUSAL_PATTERNS must be a tuple of compiled regex; got non-Pattern."
    )
    sig_lower = {s.lower() for s in _REFUSAL_SIGNATURES}
    pat_sources_lower = {p.pattern.lower() for p in _REFUSAL_PATTERNS}
    overlap = sig_lower & pat_sources_lower
    assert not overlap, (
        f"_REFUSAL_SIGNATURES and _REFUSAL_PATTERNS overlap on: {overlap}. "
        f"They target different surfaces — keep disjoint or unify into one system."
    )
