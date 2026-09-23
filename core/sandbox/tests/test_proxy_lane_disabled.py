"""Disabled-sandbox proxied runs subscribe telemetry to the lane the
child actually uses.

An operator-disabled sandbox never reaches enforcement: its children
run in the HOST netns against a TCP proxy listener. The construction
nevertheless bound a per-context netns UNIX lane (the capability check
ignored the disabled state) and registered the run's event buffer on
it — a lane no traffic could ever arrive on, so a forensic reader of a
``--sandbox none`` bisect run saw zero proxy events where egress
happened. The run must take the TCP-lane (or run-global) telemetry
view instead.
"""

from __future__ import annotations

import re
import sys

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform == "darwin", reason="netns lane decision is non-darwin",
)


def test_disabled_run_does_not_subscribe_to_a_unix_lane(
        tmp_path, monkeypatch):
    from core.sandbox import context, state
    from core.sandbox import proxy as proxy_mod

    monkeypatch.setattr(state, "_cli_sandbox_profile", "none")
    monkeypatch.setattr(state, "_cli_sandbox_disabled", True)

    captured: dict = {}
    orig = proxy_mod.EgressProxy.register_sandbox

    def spy(self, *args, **kwargs):
        captured["lane_key"] = kwargs.get("lane_key")
        return orig(self, *args, **kwargs)

    monkeypatch.setattr(proxy_mod.EgressProxy, "register_sandbox", spy)
    res = context.run(
        ["/bin/sh", "-c", "echo proxy=$HTTPS_PROXY"],
        target=str(tmp_path), output=str(tmp_path),
        use_egress_proxy=True, proxy_hosts=["localhost"],
        capture_output=True, text=True, timeout=30,
    )
    assert res.returncode == 0
    lane_key = captured.get("lane_key")
    # The child's proxy env points at a TCP listener in the host
    # netns; the event buffer must not be parked on a unix lane no
    # traffic can reach.
    assert not (isinstance(lane_key, str)
                and lane_key.endswith(".sock")), (
        f"disabled run subscribed to a netns unix lane "
        f"{lane_key!r} its child can never use"
    )
    m = re.search(r"proxy=http://127\.0\.0\.1:(\d+)", res.stdout)
    assert m, res.stdout
    if isinstance(lane_key, int):
        # TCP-lane view: attribution matches the child's endpoint.
        assert lane_key == int(m.group(1))
