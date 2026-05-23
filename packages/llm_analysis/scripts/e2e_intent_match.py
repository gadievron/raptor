#!/usr/bin/env python3
"""E2E script for the IntentMatchJudge v1 wiring.

Demonstrates the heuristic-first / LLM-tiebreak verdict path end-
to-end against a fake LLM provider that produces canned responses.

Scenarios:

1. 4/4 heuristics fire → ``matches`` without LLM call.
2. 0/4 fire → ``off_target`` without LLM call.
3. Ambiguous (1/4 fires) → LLM tiebreak → ``matches`` verdict.
4. Ambiguous → LLM tiebreak → ``off_target`` verdict.
5. Ambiguous → LLM tiebreak → ``uncertain`` verdict.
6. LLM raises mid-tiebreak → graceful fallback to ``uncertain``
   with the error captured in ``llm_error``.
7. No exploit_code → ``uncertain`` (nothing to judge).
8. Unknown CWE (no detector) → abstain on cwe_shape signal.

Run from the repo root:

    python3 packages/llm_analysis/scripts/e2e_intent_match.py
"""

from __future__ import annotations

import json
import logging
import os
import sys
from dataclasses import asdict
from pathlib import Path

# packages/llm_analysis/scripts/e2e_intent_match.py
#   parents[0] = scripts/
#   parents[1] = llm_analysis/
#   parents[2] = packages/
#   parents[3] = repo root
REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))
os.environ.setdefault("RAPTOR_DIR", str(REPO))

from packages.llm_analysis.intent_match import intent_match  # noqa: E402


# ---------------------------------------------------------------------------
# Fake LLM provider
# ---------------------------------------------------------------------------


class _FakeLLMResponse:
    def __init__(self, content: str, cost_usd: float = 0.002):
        self.content = content
        self.cost_usd = cost_usd


class FakeLLMProvider:
    """Stand-in for an LLM client. Queue of canned responses; pops
    one per ``.generate(...)`` call. The intent-match tiebreak
    invokes ``.generate(...)`` twice (describe + judge)."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def generate(self, prompt, system_prompt=None, task_type=None, **kw):
        self.calls.append({"prompt_len": len(prompt)})
        if not self._responses:
            raise RuntimeError("FakeLLMProvider exhausted")
        return self._responses.pop(0)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


# Buffer-overflow exploit that references the target file + function
# AND uses the Python-style ``"A" * N`` payload pattern the
# CWE-120 shape detector keys on.
EXPLOIT_BOF_TARGETED = '''\
# PoC for src/auth.c::check_password buffer overflow
import ctypes
payload = "A" * 200
lib = ctypes.CDLL("./target.so")
lib.check_password(payload.encode())
'''


# SQL-injection exploit (doesn't match the BOF finding).
EXPLOIT_SQL_OFF_TARGET = """\
import requests
payload = "x' UNION SELECT * FROM users--"
requests.get(f"http://example.com/search?q={payload}")
"""


# Ambiguous exploit — fires CWE-shape but nothing else.
EXPLOIT_AMBIGUOUS = """\
import socket
sock = socket.socket()
payload = b"A" * 256
sock.send(payload)
"""


def _hr(title: str) -> None:
    print()
    print("=" * 72)
    print(f"  {title}")
    print("=" * 72)


def _show(v) -> None:
    d = asdict(v)
    print(f"  verdict:    {d['verdict']}")
    print(f"  confidence: {d['confidence']:.2f}")
    print(f"  used_llm:   {d['used_llm']}")
    print(f"  cost_usd:   ${d['cost_usd']:.4f}")
    print(f"  signals:    {json.dumps(d['signals'], default=str)}")
    print(f"  reasoning:  {d['reasoning'][:200]}")
    if d.get("llm_error"):
        print(f"  llm_error:  {d['llm_error']}")


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------


def scenario_1_all_heuristics_fire() -> None:
    _hr("Scenario 1: 4/4 heuristics fire → matches without LLM")
    llm = FakeLLMProvider([])  # would raise if called
    v = intent_match(
        exploit_code=EXPLOIT_BOF_TARGETED,
        finding_file_path="src/auth.c",
        finding_function_name="check_password",
        finding_cwe="CWE-120",
        exploit_compile_errors=[
            "src/auth.c:42: error: stack-buffer-overflow"
        ],
        llm_client=llm,
    )
    _show(v)
    print(f"  llm calls: {len(llm.calls)} (must be 0)")


def scenario_2_no_heuristics() -> None:
    _hr("Scenario 2: 0/4 fire → off_target without LLM")
    llm = FakeLLMProvider([])
    v = intent_match(
        exploit_code=EXPLOIT_SQL_OFF_TARGET,
        finding_file_path="src/auth.c",
        finding_function_name="check_password",
        finding_cwe="CWE-120",
        llm_client=llm,
    )
    _show(v)
    print(f"  llm calls: {len(llm.calls)} (must be 0)")


def scenario_3_llm_matches() -> None:
    _hr("Scenario 3: ambiguous → LLM says matches")
    llm = FakeLLMProvider([
        _FakeLLMResponse(
            "The exploit constructs a 256-byte payload and sends it "
            "over a network socket, consistent with buffer-overflow "
            "exploitation of a network-facing service."
        ),
        _FakeLLMResponse(
            "matches: payload shape and target match the bug class"
        ),
    ])
    v = intent_match(
        exploit_code=EXPLOIT_AMBIGUOUS,
        finding_file_path="src/network_server.c",
        finding_function_name="handle_request",
        finding_cwe="CWE-120",
        llm_client=llm,
    )
    _show(v)
    print(f"  llm calls: {len(llm.calls)} (must be 2 — describe + judge)")


def scenario_4_llm_off_target() -> None:
    _hr("Scenario 4: ambiguous → LLM says off_target")
    llm = FakeLLMProvider([
        _FakeLLMResponse(
            "The exploit sends 256 bytes to a socket but the target "
            "bug is in file parsing, not network input."
        ),
        _FakeLLMResponse(
            "off_target: payload reaches wrong code path"
        ),
    ])
    v = intent_match(
        exploit_code=EXPLOIT_AMBIGUOUS,
        finding_file_path="src/network_server.c",
        finding_function_name="handle_request",
        finding_cwe="CWE-120",
        llm_client=llm,
    )
    _show(v)


def scenario_5_llm_uncertain() -> None:
    _hr("Scenario 5: ambiguous → LLM says uncertain")
    llm = FakeLLMProvider([
        _FakeLLMResponse("Exploit shape is generic."),
        _FakeLLMResponse(
            "uncertain: payload is consistent but not specifically aimed"
        ),
    ])
    v = intent_match(
        exploit_code=EXPLOIT_AMBIGUOUS,
        finding_file_path="src/network_server.c",
        finding_function_name="handle_request",
        finding_cwe="CWE-120",
        llm_client=llm,
    )
    _show(v)


def scenario_6_llm_raises() -> None:
    _hr("Scenario 6: LLM raises → uncertain with llm_error")

    class _Bomb:
        def generate(self, *a, **kw):
            raise RuntimeError("simulated LLM API timeout")

    v = intent_match(
        exploit_code=EXPLOIT_AMBIGUOUS,
        finding_file_path="src/network_server.c",
        finding_function_name="handle_request",
        finding_cwe="CWE-120",
        llm_client=_Bomb(),
    )
    _show(v)


def scenario_7_no_exploit() -> None:
    _hr("Scenario 7: no exploit_code → uncertain (nothing to judge)")
    v = intent_match(
        exploit_code="",
        finding_file_path="src/auth.c",
        finding_function_name="check_password",
        finding_cwe="CWE-120",
    )
    _show(v)


def scenario_8_unknown_cwe() -> None:
    _hr("Scenario 8: unknown CWE (no detector) → cwe_shape abstains")
    # File + function fire (2/3 evaluated since CWE-416 has no v1
    # detector and cwe_shape returns None). 2/3 = uncertain → LLM
    # tiebreak. Provide canned responses so the demo lands cleanly.
    llm = FakeLLMProvider([
        _FakeLLMResponse(
            "The exploit invokes a virtual call on a freed object — "
            "consistent with a use-after-free trigger pattern."
        ),
        _FakeLLMResponse(
            "matches: vtable-on-freed-object aimed at free_target"
        ),
    ])
    v = intent_match(
        exploit_code=(
            "// src/heap.c::free_target — trigger UAF\n"
            "free(obj); obj->vtable[0]();"
        ),
        finding_file_path="src/heap.c",
        finding_function_name="free_target",
        finding_cwe="CWE-416",  # no v1 detector → cwe_shape abstains
        llm_client=llm,
    )
    _show(v)
    print(f"  cwe_shape signal: {v.signals.get('cwe_shape')} (None = abstain)")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s] %(message)s",
    )

    scenario_1_all_heuristics_fire()
    scenario_2_no_heuristics()
    scenario_3_llm_matches()
    scenario_4_llm_off_target()
    scenario_5_llm_uncertain()
    scenario_6_llm_raises()
    scenario_7_no_exploit()
    scenario_8_unknown_cwe()

    return 0


if __name__ == "__main__":
    sys.exit(main())
