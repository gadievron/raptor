"""The audit backend's DIRECT-START Joern server gets the short TTL.

``start_joern_server`` prefers a lifecycle acquire (state-file
recorded, warm-handoff re-acquirable, long orphan horizon). Its
fallback boots a RUN-PRIVATE server no later run can ever reconnect
to — that construction site must pass ``_RUN_PRIVATE_ORPHAN_TTL_S``
so an orphaned forwarder+JVM pair is reaped in minutes, not the
warm-handoff hours.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

import core.audit.joern_backend as jb
import packages.joern.lifecycle as lifecycle_mod
from packages.joern import netns_forwarder as nf
from packages.joern.server import JoernServer


class TestDirectStartTtl:
    def test_fallback_start_passes_run_private_ttl(self, monkeypatch):
        monkeypatch.setattr(jb, "joern_available", lambda overrides=None: True)
        monkeypatch.setattr(jb, "target_has_c_sources", lambda p: True)
        # Lifecycle path declines so the run-private fallback fires.
        monkeypatch.setattr(lifecycle_mod, "joern_acquire", lambda t=None: None)

        captured: dict[str, Any] = {}

        def _fake_from_tunables(
            tunables: Any = None, *,
            orphan_idle_ttl_s: float | None = None,
        ) -> Any:
            captured["ttl"] = orphan_idle_ttl_s

            def _no_boot() -> None:
                # Abort start_joern_server right after construction —
                # the test only cares what the site constructed with.
                raise RuntimeError("stub: no real server boot")

            return SimpleNamespace(start=_no_boot)

        monkeypatch.setattr(JoernServer, "from_tunables", _fake_from_tunables)
        assert jb.start_joern_server("/nonexistent-ttl-probe") is None
        assert captured["ttl"] == jb._RUN_PRIVATE_ORPHAN_TTL_S


class TestRunPrivateTtlPins:
    def test_ttl_lower_bound(self):
        # Below ~5 min the watchdog reaps a server a still-running
        # analysis may be about to query again: parent death is
        # observable mid-run (segment drain re-exec, debugger attach
        # while the original parent exits).
        assert jb._RUN_PRIVATE_ORPHAN_TTL_S >= 300.0

    def test_ttl_decisively_shorter_than_warm_handoff_horizon(self):
        # Longer buys nothing — no later run can re-acquire a server
        # with no lifecycle state file — and drifts back toward the
        # multi-hour multi-GB squat this value exists to end.
        assert jb._RUN_PRIVATE_ORPHAN_TTL_S <= nf._ORPHAN_IDLE_TTL_S / 8


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
