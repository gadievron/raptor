"""The attack-path load-failure debug log must excerpt the ref.

``feasibility.attack_path_ref`` is read from finding JSON that may
originate from an LLM response or third-party SARIF — untrusted — and
an ``OSError`` message can embed the ref-derived filename. Both values
must be escaped and bounded at the log site (the excerpt doctrine);
honest short printable refs pass through byte-identical.
"""

import logging
from pathlib import Path

import pytest

from packages.llm_analysis import agent as agent_mod
from packages.llm_analysis.agent import AutonomousSecurityAgentV2


@pytest.fixture(autouse=True)
def _raptor_logger_propagates():
    """Let caplog see records from the 'raptor' logger.

    RaptorLogger sets propagate=False on logging.getLogger('raptor'),
    so records never reach root where pytest's caplog handler lives.
    """
    raptor = logging.getLogger("raptor")
    orig = raptor.propagate
    raptor.propagate = True
    yield
    raptor.propagate = orig


HOSTILE = "\x1b]0;pwn\x07\x9b2J‮evil"
RAW_BYTES = ("\x1b", "\x07", "\x9b", "‮")


def _agent(tmp_path: Path) -> AutonomousSecurityAgentV2:
    obj = AutonomousSecurityAgentV2.__new__(AutonomousSecurityAgentV2)
    obj.out_dir = tmp_path / "out"
    return obj


def _messages(caplog) -> str:
    return "\n".join(r.getMessage() for r in caplog.records)


def test_hostile_ref_escaped_and_bounded(
        tmp_path, caplog, monkeypatch) -> None:
    def _boom(*_a: object, **_k: object) -> None:
        raise OSError("cannot read " + HOSTILE + "B" * 300)

    monkeypatch.setattr(agent_mod, "load_json", _boom)
    # Hostile bytes in the FILENAME segment pass the bare-filename
    # containment check (it rejects only separators / NUL / dot-dot),
    # so this ref reaches the load attempt and the failure log.
    ref = "attack-paths" + HOSTILE + ".json#PATH-001"
    with caplog.at_level(logging.DEBUG, logger="raptor"):
        result = _agent(tmp_path)._load_attack_path(ref)
    assert result is None
    msg = _messages(caplog)
    assert "Failed to load attack path" in msg
    for raw in RAW_BYTES:
        assert raw not in msg
    # Escaped form present — the value is excerpted, not dropped.
    assert "\\x1b" in msg
    # Bounded with an explicit elision marker, never the verbatim flood.
    assert "B" * 250 not in msg
    assert "...[+" in msg


def test_honest_ref_identity(tmp_path, caplog, monkeypatch) -> None:
    def _boom(*_a: object, **_k: object) -> None:
        raise OSError("boom")

    monkeypatch.setattr(agent_mod, "load_json", _boom)
    with caplog.at_level(logging.DEBUG, logger="raptor"):
        result = _agent(tmp_path)._load_attack_path(
            "attack-paths.json#PATH-001")
    assert result is None
    msg = _messages(caplog)
    assert (
        "Failed to load attack path from 'attack-paths.json#PATH-001'"
        in msg
    )
    assert "boom" in msg
    assert "...[+" not in msg
