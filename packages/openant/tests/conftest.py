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
    # Session-registry isolation for SUBPROCESSES. The root conftest's
    # _sessions_registry_in_tmp fixture redirects SESSIONS_DIR and the
    # claude-ancestor walk IN-PROCESS only; the raptor.py subprocesses
    # these tests spawn resolve the session themselves — on a host with
    # a live claude session in the ancestry, they resolved the LIVE
    # session, ledger-recorded the test run into its real
    # ~/.local/share/raptor/sessions.d ledger, and the live session's
    # lifecycle Stop hook could then discover the test's in-flight run
    # and heuristically finalize it out from under the test (observed
    # as the exit-path lifecycle flake under peak parallel load: the
    # hook's unmarked ``completed`` beat the test run's real
    # ``fail_run``). A fresh HOME means the subprocess finds no
    # registered session entry: the ancestor walk yields nothing
    # identity-verified it can ledger against, ledger writes are
    # refused, and the live session's hooks can never see test runs.
    home = tmp_path / "home-scrub"
    home.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    # The env credential pair outranks the walk — scrub it too, or a
    # RAPTOR-launched pytest still hands subprocesses the live session.
    monkeypatch.delenv("RAPTOR_SESSION_PID", raising=False)
    monkeypatch.delenv("RAPTOR_SESSION_TOKEN", raising=False)
