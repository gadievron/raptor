"""Shared isolation for the openant test directory.

The scanner's credential-posture decision
(``_operator_has_direct_credential`` + the ``RAPTOR_LLM_SOCKET``
dispatcher-route probe) reads the ambient environment and the
operator's real ``~/.config/openant/config.json``. Without this scrub,
a pytest run from a shell inside a RAPTOR-launched session would steer
every ``_run_subprocess`` test into the gateway mint path — against
the LIVE session dispatcher — and an exported operator key (or a
key-bearing real config file) flips keyless-posture assertions. Same
pattern as ``core/llm/tests/conftest.py``'s dispatcher-route scrub.

Tests that exercise a posture on purpose set the vars inside the test
body (``monkeypatch.setenv`` / ``patch.dict``), which runs after this
autouse scrub and wins.
"""

import pytest


@pytest.fixture(autouse=True)
def _scrub_credential_posture(monkeypatch, tmp_path):
    monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    # Route-family signals (a Bedrock-fronted host's ambient
    # CLAUDE_CODE_USE_BEDROCK + model pin would flip every gateway
    # route assertion to the Mantle shape).
    monkeypatch.delenv("CLAUDE_CODE_USE_BEDROCK", raising=False)
    monkeypatch.delenv("ANTHROPIC_MODEL", raising=False)
    # Point the operator-config lookup at an empty per-test directory
    # so the host's real config never leaks into a posture decision.
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg-scrub"))
