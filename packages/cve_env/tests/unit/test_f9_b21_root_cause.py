"""Stage 5b — root-cause TDD for F-9 anomaly + B-21 ineffectiveness.

Migration-arc audit (Stage 4 bench50-20260508-003044) reproduced the B-21
premature-halt symptom (CVE-2022-31945 hit max_turns_reached at num_turns=34)
and surfaced an F-9 anomaly from earlier bench data: state.turn=250 reached
in CVE-2022-31945's audit JSONL despite ``effective_max_turns=96``.

These tests drive on_message far beyond the configured max_turns to verify
F-9 actually raises TurnCapReached at the expected message count. If they
fail, F-9 is wiring-broken (NOT just B-21 ineffective) and the migration
arc has a deeper bug.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import patch

from cve_env.agent.loop import build

# Reuse the existing test_loop helpers verbatim — we're in the same dir.
from .test_loop import (  # type: ignore[import-untyped]
    _assistant,
    _cve,
    _fake_run_agent_factory,
    _host,
    _text_block,
)


def _many_messages(n: int) -> list[Any]:
    """Generate n simple AssistantMessage(text) — each fires on_message once."""
    return [_assistant(_text_block(f"turn {i}")) for i in range(n)]


def test_f9_fires_when_messages_exceed_max_turns(tmp_path: Path) -> None:
    """RED guard for F-9: with max_turns=10 and 200 messages, F-9 must
    raise TurnCapReached. _fake_run_agent_factory mirrors _run_query_once
    semantics: catches TurnCapReached and sets early_stop_reason=
    "max_turns_reached". Outcome.status must map to "turn_cap".

    If this fails, F-9 is wiring-broken and the migration arc has a
    deeper bug than just B-21 ineffectiveness.
    """
    messages = _many_messages(200)
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(
                _cve(),
                _host(),
                run_id="run-f9",
                audit_root=tmp_path,
                max_turns=10,
                # Disable B-20 extension so F-9 fires cleanly without
                # bumping effective_max_turns.
                max_turn_extensions=0,
            )
        )
    assert outcome.status == "turn_cap", (
        f"F-9 did not raise — got status={outcome.status!r}. "
        f"Expected turn_cap from TurnCapReached caught in run_agent. "
        f"This means state.turn > effective_max_turns isn't actually "
        f"halting the SDK iteration."
    )


def test_f9_audit_truncates_at_cap_plus_1(tmp_path: Path) -> None:
    """When F-9 fires, the audit JSONL should NOT contain entries past
    state.turn = max_turns + 1 (the iteration that triggered the raise).
    This is the empirical signal we'd expect if F-9 is wiring-correct.

    Pre-Stage-5b reproduction: CVE-2022-31945 audit showed turn=250 with
    max_turns=96 — clearly beyond cap. Either (a) state.turn is bumped
    beyond F-9's check (counter mismatch) or (b) on_message handles
    the exception itself.
    """
    messages = _many_messages(200)
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        _outcome = asyncio.run(
            build(
                _cve(),
                _host(),
                run_id="run-f9-audit",
                audit_root=tmp_path,
                max_turns=10,
                max_turn_extensions=0,
            )
        )
    # Locate audit JSONL (cve-env writes to <audit_root>/<run_id>/<cve>.jsonl)
    audit_files = list(tmp_path.rglob("CVE-*.jsonl"))
    assert audit_files, "no audit JSONL written"
    import json

    with audit_files[0].open() as fh:
        lines = [json.loads(line) for line in fh if line.strip()]
    turns = [e.get("turn", 0) for e in lines]
    max_turn_in_audit = max(turns) if turns else 0
    # F-9 fires at state.turn=11 (max_turns=10, > check). Audit may go
    # up to state.turn=11 if the entry was written before the raise. Hard
    # cap at 12 to allow for one off-by-one.
    assert max_turn_in_audit <= 12, (
        f"audit JSONL reached turn={max_turn_in_audit} despite max_turns=10. "
        f"F-9 is wiring-broken: state.turn isn't halting on_message."
    )
