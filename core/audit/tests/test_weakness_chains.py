"""Weakness chain detection PoC tests.

Proves that two individually non-exploitable weaknesses on the same call
path can be composed into a vulnerability via the weakness-chain pipeline
wired into the SEC scanner.

Fixture pairs (C files under ``fixtures/chain-weaknesses/``):
- parse_content_length + process_body → buffer overflow
  (unbounded user length × fixed-size memcpy)
- handle_request + authenticate → auth bypass
  (user-controlled flags × legacy compat path skips auth check)

Disconnected weaknesses (no call-graph edge, no flow trace) must NOT
appear as candidates.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.audit.chain_detector import (
    evaluate_weakness_chains,
    find_weakness_chain_candidates,
)


# ── Minimal ReviewOutcome stub ──────────────────────────────────────

@dataclass
class _Outcome:
    file: str
    function: str
    status: str
    body: str
    hypothesis: str = ""
    evidence_tool: str = ""
    review_result: dict[str, Any] | None = None


# ── Fixture helpers ─────────────────────────────────────────────────

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "chain-weaknesses"


def _make_weakness(
    file: str,
    function: str,
    hypothesis: str,
    body: str,
    *,
    callers: list[dict] | None = None,
    callees: list[dict] | None = None,
    evidence_tool: str = "",
    bug_class: str = "unknown",
) -> _Outcome:
    rr: dict[str, Any] = {"bug_class": bug_class}
    if callers:
        rr["callers"] = callers
    if callees:
        rr["callees"] = callees
    return _Outcome(
        file=file,
        function=function,
        status="weakness",
        body=body,
        hypothesis=hypothesis,
        evidence_tool=evidence_tool,
        review_result=rr,
    )


# ── Stub LLM client ────────────────────────────────────────────────

class _StubLLMClient:
    """Returns is_chain: true for every call."""

    model_name = "stub"

    def generate_structured(self, prompt, schema, **kwargs):
        return {
            "is_chain": True,
            "chain_description": "Stub: weaknesses compose.",
            "primitive": "write",
            "confidence": "high",
        }


class _StubLLMClientReject:
    """Returns is_chain: false for every call."""

    model_name = "stub"

    def generate_structured(self, prompt, schema, **kwargs):
        return {
            "is_chain": False,
            "chain_description": "",
        }


# ── 1. Buffer overflow: parse + process ────────────────────────────
#
#   parse_content_length returns a user-controlled length with no upper
#   bound.  process_body memcpy's into a 256-byte stack buffer using
#   that length.  Neither is exploitable alone; together → overflow.

class TestBufferOverflowChain:
    @staticmethod
    def _outcomes():
        parse = _make_weakness(
            file="parse.c",
            function="parse_content_length",
            hypothesis="Returns user-controlled length without upper-bound validation",
            body="atol(Content-Length header) returned directly; no cap.",
            callees=[{"file": "process.c", "name": "process_body"}],
            bug_class="missing_bounds_check",
        )
        process = _make_weakness(
            file="process.c",
            function="process_body",
            hypothesis="Copies into fixed-size stack buffer using caller-provided length",
            body="memcpy(buf, data, len) with char buf[256]; len from caller.",
            callers=[{"file": "parse.c", "name": "parse_content_length"}],
            bug_class="buffer_overflow",
        )
        return [parse, process]

    def test_candidates_found(self, tmp_path):
        outcomes = self._outcomes()
        candidates = find_weakness_chain_candidates(outcomes, tmp_path)
        assert len(candidates) == 1
        keys = {
            f"{c.file}:{c.function}" for pair in candidates for c in pair
        }
        assert keys == {"parse.c:parse_content_length", "process.c:process_body"}

    def test_chain_confirmed(self, tmp_path):
        outcomes = self._outcomes()
        candidates = find_weakness_chain_candidates(outcomes, tmp_path)
        chains = evaluate_weakness_chains(candidates, _StubLLMClient())
        assert len(chains) == 1
        chain = chains[0]
        assert chain["weakness_a"] in (
            "parse.c:parse_content_length",
            "process.c:process_body",
        )
        assert chain["weakness_b"] in (
            "parse.c:parse_content_length",
            "process.c:process_body",
        )
        assert chain["weakness_a"] != chain["weakness_b"]

    def test_fixture_files_exist(self):
        assert (FIXTURE_DIR / "parse.c").is_file()
        assert (FIXTURE_DIR / "process.c").is_file()


# ── 2. Auth bypass: dispatch + authenticate ────────────────────────
#
#   handle_request passes user-controlled flags to authenticate().
#   authenticate() has a legacy compat path (flags & 0x80) that skips
#   credential verification.  Neither is exploitable alone; together →
#   auth bypass.

class TestAuthBypassChain:
    @staticmethod
    def _outcomes():
        dispatch = _make_weakness(
            file="dispatch.c",
            function="handle_request",
            hypothesis="Passes user-controlled flags value to authenticate()",
            body="atoi(raw_flags) forwarded to authenticate(); no sanitisation.",
            callees=[{"file": "auth.c", "name": "authenticate"}],
            bug_class="missing_input_validation",
        )
        auth = _make_weakness(
            file="auth.c",
            function="authenticate",
            hypothesis="Legacy compat path sets auth flag without verifying credentials",
            body="flags & 0x80 → _authenticated = true; no credential check.",
            callers=[{"file": "dispatch.c", "name": "handle_request"}],
            bug_class="auth_bypass",
        )
        return [dispatch, auth]

    def test_candidates_found(self, tmp_path):
        outcomes = self._outcomes()
        candidates = find_weakness_chain_candidates(outcomes, tmp_path)
        assert len(candidates) == 1
        keys = {
            f"{c.file}:{c.function}" for pair in candidates for c in pair
        }
        assert keys == {"dispatch.c:handle_request", "auth.c:authenticate"}

    def test_chain_confirmed(self, tmp_path):
        outcomes = self._outcomes()
        candidates = find_weakness_chain_candidates(outcomes, tmp_path)
        chains = evaluate_weakness_chains(candidates, _StubLLMClient())
        assert len(chains) == 1
        chain = chains[0]
        assert "auth" in chain["weakness_a"] or "auth" in chain["weakness_b"]
        assert "dispatch" in chain["weakness_a"] or "dispatch" in chain["weakness_b"]

    def test_fixture_files_exist(self):
        assert (FIXTURE_DIR / "dispatch.c").is_file()
        assert (FIXTURE_DIR / "auth.c").is_file()


# ── 3. Cross-pair isolation ────────────────────────────────────────
#
#   parse ↔ process are connected; dispatch ↔ auth are connected.
#   parse ↔ auth, dispatch ↔ process should NOT form candidates.

class TestCrossPairIsolation:
    @staticmethod
    def _all_outcomes():
        parse = _make_weakness(
            file="parse.c",
            function="parse_content_length",
            hypothesis="Unbounded length",
            body="atol returns user-controlled length.",
            callees=[{"file": "process.c", "name": "process_body"}],
        )
        process = _make_weakness(
            file="process.c",
            function="process_body",
            hypothesis="Fixed-size buffer copy",
            body="memcpy(buf, data, len) with buf[256].",
            callers=[{"file": "parse.c", "name": "parse_content_length"}],
        )
        dispatch = _make_weakness(
            file="dispatch.c",
            function="handle_request",
            hypothesis="User-controlled flags",
            body="atoi(raw_flags) passed to authenticate().",
            callees=[{"file": "auth.c", "name": "authenticate"}],
        )
        auth = _make_weakness(
            file="auth.c",
            function="authenticate",
            hypothesis="Legacy compat skips auth",
            body="flags & 0x80 → _authenticated = true.",
            callers=[{"file": "dispatch.c", "name": "handle_request"}],
        )
        return [parse, process, dispatch, auth]

    def test_exactly_two_candidate_pairs(self, tmp_path):
        outcomes = self._all_outcomes()
        candidates = find_weakness_chain_candidates(outcomes, tmp_path)
        assert len(candidates) == 2

        pair_keys = set()
        for a, b in candidates:
            k = tuple(sorted([
                f"{a.file}:{a.function}",
                f"{b.file}:{b.function}",
            ]))
            pair_keys.add(k)

        assert ("parse.c:parse_content_length", "process.c:process_body") in pair_keys
        assert ("auth.c:authenticate", "dispatch.c:handle_request") in pair_keys

    def test_no_cross_pairs(self, tmp_path):
        outcomes = self._all_outcomes()
        candidates = find_weakness_chain_candidates(outcomes, tmp_path)
        for a, b in candidates:
            pair = {f"{a.file}:{a.function}", f"{b.file}:{b.function}"}
            assert pair != {"parse.c:parse_content_length", "auth.c:authenticate"}
            assert pair != {"dispatch.c:handle_request", "process.c:process_body"}


# ── 4. Non-weakness statuses excluded ──────────────────────────────

class TestNonWeaknessExcluded:
    def test_findings_not_chained(self, tmp_path):
        outcomes = [
            _make_weakness(
                file="a.c", function="fa",
                hypothesis="h", body="b",
                callees=[{"file": "b.c", "name": "fb"}],
            ),
            _Outcome(
                file="b.c", function="fb",
                status="finding",
                body="already exploitable",
                review_result={
                    "callers": [{"file": "a.c", "name": "fa"}],
                },
            ),
        ]
        candidates = find_weakness_chain_candidates(outcomes, tmp_path)
        assert candidates == []

    def test_safe_not_chained(self, tmp_path):
        outcomes = [
            _make_weakness(
                file="a.c", function="fa",
                hypothesis="h", body="b",
                callees=[{"file": "b.c", "name": "fb"}],
            ),
            _Outcome(
                file="b.c", function="fb",
                status="safe",
                body="no issue",
                review_result={
                    "callers": [{"file": "a.c", "name": "fa"}],
                },
            ),
        ]
        candidates = find_weakness_chain_candidates(outcomes, tmp_path)
        assert candidates == []


# ── 5. Evaluation stop gate ────────────────────────────────────────

class TestEvaluationStopGate:
    def test_should_stop_halts_evaluation(self, tmp_path):
        outcomes = TestCrossPairIsolation._all_outcomes()
        candidates = find_weakness_chain_candidates(outcomes, tmp_path)
        assert len(candidates) == 2

        chains = evaluate_weakness_chains(
            candidates, _StubLLMClient(),
            should_stop=lambda: True,
        )
        assert chains == []

    def test_reject_llm_returns_no_chains(self, tmp_path):
        outcomes = TestBufferOverflowChain._outcomes()
        candidates = find_weakness_chain_candidates(outcomes, tmp_path)
        chains = evaluate_weakness_chains(candidates, _StubLLMClientReject())
        assert chains == []


# ── 6. Single weakness (below threshold) ───────────────────────────

class TestSingleWeakness:
    def test_single_weakness_no_candidates(self, tmp_path):
        outcomes = [
            _make_weakness(
                file="a.c", function="fa",
                hypothesis="h", body="b",
            ),
        ]
        candidates = find_weakness_chain_candidates(outcomes, tmp_path)
        assert candidates == []


# ── 7. Disconnected weaknesses (no edge) ──────────────────────────

class TestDisconnectedWeaknesses:
    def test_no_edge_no_candidates(self, tmp_path):
        outcomes = [
            _make_weakness(
                file="a.c", function="fa",
                hypothesis="h", body="b",
            ),
            _make_weakness(
                file="z.c", function="fz",
                hypothesis="h", body="b",
            ),
        ]
        candidates = find_weakness_chain_candidates(outcomes, tmp_path)
        assert candidates == []
