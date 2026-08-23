"""Review-loop wiring for the Joern liveness probe.

The per-dispatch joern tick (``_joern_tick``, wired as the executor's
``on_tick``) must probe server liveness so a died server process gets
its bounded relaunch (``JoernServer.ensure_alive``) instead of keeping
the taint tier down for the rest of the run. Source-level wiring check
— the heavy loop scaffolding is exercised in integration tests,
mirroring ``TestReviewOneFunctionTimeoutPath``.
"""

from __future__ import annotations

from pathlib import Path


class TestJoernTickProbesLiveness:
    def test_tick_calls_ensure_alive(self):
        src = (Path(__file__).resolve().parents[1]
               / "orchestrator.py").read_text()
        idx = src.find("def _joern_tick")
        assert idx != -1
        end = src.find("\n    # --- Main executor pass ---", idx)
        window = src[idx:end if end != -1 else idx + 4000]
        assert "joern_server.ensure_alive()" in window

    def test_tick_is_wired_as_on_tick(self):
        src = (Path(__file__).resolve().parents[1]
               / "orchestrator.py").read_text()
        assert "on_tick=_joern_tick" in src
