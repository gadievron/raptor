"""Skip-budget guard for audit-mode tests.

Most audit tests gate themselves on `_audit_prereqs_ok()` (mount-ns
present + ptrace permitted + uidmap installed). On hosts that lack
those, the gating tests skip silently — which is the right behaviour
for ad-hoc dev runs but a real coverage hole in CI: if every audit
test skips on every CI run, the tracer code never executes in CI and
regressions slip through invisible.

This file provides one opt-in test that converts the silent-skip
into a loud failure when the operator (CI config, dev workflow)
explicitly asserts "I expect audit tests to run on this host". Set
``RAPTOR_REQUIRE_AUDIT_TESTS=1`` in the environment and any missing
prereq fails this test with a precise reason — operators see the
gap before merging.

When the env var is unset (default), this test no-ops. The audit
tests themselves continue to skip silently as before. This is
deliberate: zero behaviour change for casual contributors, an
explicit gate for CI infra.

Usage in CI:

    # In a CI job that has installed uidmap and flipped the sysctl:
    env RAPTOR_REQUIRE_AUDIT_TESTS=1 pytest core/sandbox/

If the prereqs aren't satisfied, this test fails with the reason —
forcing the CI maintainer to either install the prereqs or remove
the env var (with eyes-open acceptance of the coverage gap).
"""

from __future__ import annotations

import os
import platform

import pytest


def test_audit_prereqs_present_when_required():
    """Loud-fail when CI opts into audit-test enforcement.

    Reads exactly the same probes the audit tests use to gate
    themselves — keeps the two paths in sync, so this test fails
    iff at least one audit test would skip.
    """
    if os.environ.get("RAPTOR_REQUIRE_AUDIT_TESTS") != "1":
        pytest.skip(
            "RAPTOR_REQUIRE_AUDIT_TESTS not set; audit-test skip "
            "budget not enforced on this host. Set the env var in "
            "CI to fail loudly when prereqs are missing."
        )

    from core.sandbox import probes, ptrace_probe, tracer as tracer_mod

    missing = []
    if not tracer_mod._is_supported_arch():
        missing.append(
            f"tracer doesn't support arch={platform.machine()!r} "
            f"(supported: x86_64, aarch64). Add to "
            f"core/sandbox/tracer._ARCH_INFO."
        )
    if not probes.check_net_available():
        missing.append(
            "user namespaces unavailable. Most likely cause: "
            "running inside a container without "
            "`--security-opt seccomp=unconfined` or equivalent. "
            "Verify with: `unshare --user --pid sh -c 'echo ok'`."
        )
    if not ptrace_probe.check_ptrace_available():
        missing.append(
            "ptrace blocked. Causes: kernel.yama.ptrace_scope=3, "
            "container --cap-drop SYS_PTRACE, or restrictive "
            "container seccomp. Fix on host: "
            "`sysctl -w kernel.yama.ptrace_scope=1`."
        )
    if not probes.check_mount_available():
        missing.append(
            "mount-ns blocked. Cause: Ubuntu 24.04+ AppArmor "
            "sysctl. Fix: `sysctl -w "
            "kernel.apparmor_restrict_unprivileged_userns=0` and "
            "`apt install uidmap`."
        )

    if missing:
        pytest.fail(
            "RAPTOR_REQUIRE_AUDIT_TESTS=1 was set but the audit "
            "test prerequisites are NOT satisfied on this host. "
            "Audit tests will silently skip — tracer code is "
            "unexercised. Either install the prereqs, or unset "
            "the env var to accept the coverage gap.\n\n"
            "Missing prereqs:\n  - "
            + "\n  - ".join(missing)
        )
