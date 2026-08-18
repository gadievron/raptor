"""Narrowed best-effort handlers: miswiring-class exceptions propagate.

Representative fails-before coverage for the suppress(Exception)
narrowing sweep in packages/llm_analysis: the guard-dominance server
teardown used to eat *any* exception, so a wired-in call gone wrong
(TypeError, AttributeError) vanished. After narrowing, only the
legitimate teardown failures (OSError, subprocess.SubprocessError)
are suppressed.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from packages.llm_analysis.agent import AutonomousSecurityAgentV2


def _agent(tmp_path):
    return AutonomousSecurityAgentV2(
        tmp_path, tmp_path / "out", prep_only=True,
    )


class TestStopGuardDominanceServerNarrowing:
    def test_miswiring_class_exception_propagates(self, tmp_path):
        agent = _agent(tmp_path)

        class MiswiredServer:
            def stop(self):
                raise TypeError("stop() got an unexpected keyword argument")

        agent._gd_server = MiswiredServer()
        agent._gd_server_probed = True
        with pytest.raises(TypeError):
            agent._stop_guard_dominance_server()

    @pytest.mark.parametrize(
        "exc",
        [
            OSError("socket already closed"),
            subprocess.TimeoutExpired(cmd="joern", timeout=5),
        ],
    )
    def test_legitimate_teardown_failures_still_suppressed(
        self, tmp_path, exc,
    ):
        agent = _agent(tmp_path)

        class FlakyServer:
            def stop(self):
                raise exc

        agent._gd_server = FlakyServer()
        agent._gd_server_probed = True
        agent._stop_guard_dominance_server()
        assert agent._gd_server is None
        assert agent._gd_server_probed is False
