"""Truth-in-stamping for per-call spawn demotions on proxied runs.

``proxy_enforcement`` must describe the DELIVERED lane, not the
construction-time tier decision: a proxied run demoted from the spawn
backend at call time (runtime unshare refusal after the probe passed)
executes on the plain host-netns lane — no forwarder, no netns
topology — while ``_use_proxy_netns`` stays True. Stamping "netns"
there told forensic readers the child had topological containment it
never had (an empty proxy-events list reads as "nothing tried to
egress" instead of "the enforcing tier never ran"). The engaged
demoted deny must also stamp ``degraded_net_deny`` — pre-fix only the
construction-time degrade arm did.
"""

from __future__ import annotations

import sys

import pytest

from core.sandbox.tests.capability import requires_landlock

pytestmark = [
    pytest.mark.skipif(
        sys.platform != "linux", reason="spawn demotion is Linux-only"),
    requires_landlock,
]


def test_demoted_proxy_run_is_not_stamped_netns(tmp_path, monkeypatch):
    from core.sandbox import _spawn as sp
    from core.sandbox import context as ctx
    from core.sandbox.errors import SandboxSetupError
    from core.sandbox.landlock import _get_landlock_abi

    if _get_landlock_abi() < 4:
        pytest.skip("Landlock ABI < 4 — demoted lane takes the "
                    "waiver/refusal path instead")

    def refuse_spawn(*args, **kwargs):
        raise SandboxSetupError(
            "sandbox spawn child died during setup: "
            "unshare(CLONE_NEWUSER) refused at runtime (simulated "
            "environmental demotion)",
            "test: the runtime-unshare-refusal shape after the probe "
            "passed",
            setup_category="U",
        )

    monkeypatch.setattr(sp, "run_sandboxed", refuse_spawn)
    res = ctx.run(
        ["/bin/sh", "-c", "echo ran-on-lane"],
        target=str(tmp_path), output=str(tmp_path),
        use_egress_proxy=True, proxy_hosts=["localhost"],
        capture_output=True, text=True, timeout=30,
    )
    si = res.sandbox_info
    assert res.returncode == 0
    assert si.get("mount_ns_active") is False
    # The delivered lane is the plain one — the netns label would
    # claim topological containment the child never had.
    assert si.get("proxy_enforcement") != "netns", si
    assert si.get("proxy_enforcement") in ("landlock_tcp", "advisory")
    # The demoted Landlock deny-all DID engage for this call; the
    # machine-readable stamp must say so.
    assert si.get("degraded_net_deny") is True, si
