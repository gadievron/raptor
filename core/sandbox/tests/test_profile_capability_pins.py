"""Semantic capability pins for the named sandbox profiles.

PROFILES is the ONLY legitimate downgrade surface: each profile's
capability flags decide what enforcement a sandbox() context actually
requests from the backend. These tests pin that chain — profile name
in, resolved enforcement out — rather than re-stating the table:
sandbox(profile=X) runs against patched availability probes and a
stubbed spawn backend, and the assertions read the enforcement
parameters the context hands the backend (block_network, the seccomp
profile string, restrict_reads, whether the target bind survived).

The final test is a mutation smoke-check: it flips every boolean
capability of every profile in a patched copy of the table and
asserts the probe helper resolves a DIFFERENT enforcement shape —
i.e. this suite cannot silently go blind to a table edit.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from core.sandbox import context, landlock as landlock_mod, probes as probes_mod, seccomp as seccomp_mod  # noqa: E402
from core.sandbox.profiles import DEFAULT_PROFILE, PROFILES  # noqa: E402

pytestmark = pytest.mark.skipif(
    sys.platform == "darwin",
    reason="exercises the Linux backend dispatch (probes are patched, "
           "no real kernel features used)",
)


def _resolved_enforcement(
    profile: str,
    tmp_path: Path,
    profiles_table: Any = None,
) -> dict[str, Any]:
    """Resolve one profile to its enforcement decisions.

    Drives ``sandbox(profile=..., target=...)`` + one ``run()`` with
    every availability probe patched True and the spawn backend
    stubbed, then returns the decisions that reached the backend.
    When the backend was never invoked (profiles that request no
    isolation lane at all), the plain-subprocess lane is recorded
    instead.
    """
    from core.sandbox import _spawn as linux_mod

    captured: dict[str, Any] = {}

    fake = mock.MagicMock()
    fake.returncode = 0
    fake.stdout = ""
    fake.stderr = ""
    fake._setup_status = None

    def spawn_stub(cmd: Any, **kw: Any) -> Any:
        captured.update(kw)
        captured["_lane"] = "spawn"
        return fake

    def preexec_stub(*args: Any, **kw: Any) -> Any:
        # Parent-side preexec construction (the ns-blocked/demotion
        # closures) — never let it dlopen libseccomp under the patched
        # availability probe; the spawn stub's kwargs stay the oracle.
        captured.setdefault("_preexec_kwargs", []).append(kw)
        return None

    target = tmp_path / "tgt"
    target.mkdir(exist_ok=True)

    patchers = [
        mock.patch.object(sys, "platform", "linux"),
        mock.patch.object(context, "check_seatbelt_available",
                          return_value=False),
        mock.patch.object(context, "check_mount_available",
                          return_value=True),
        mock.patch.object(context, "check_net_available",
                          return_value=True),
        mock.patch.object(seccomp_mod, "check_seccomp_available",
                          return_value=True),
        mock.patch.object(landlock_mod, "check_landlock_available",
                          return_value=True),
        mock.patch.object(landlock_mod, "_get_landlock_abi",
                          return_value=8),
        mock.patch.object(linux_mod, "run_sandboxed",
                          side_effect=spawn_stub),
        mock.patch.object(linux_mod, "mount_ns_available",
                          return_value=True),
        mock.patch.object(context, "_make_preexec_fn",
                          side_effect=preexec_stub),
        # The engage gate runs a REAL `unshare` CLI probe (context
        # imports it per call, so it dodges the context-namespace
        # patches above): on userns-denied hosts (stock container
        # seccomp, restricted-userns distros) it refuses and the
        # namespace-tier profiles raise before the stubbed backend
        # ever records their enforcement. Pin it True like every
        # other availability probe — these tests pin the profile →
        # enforcement TABLE, not host capability.
        mock.patch.object(probes_mod, "check_unshare_engages",
                          return_value=(True, "")),
    ]
    if profiles_table is not None:
        patchers.append(mock.patch.object(context, "PROFILES",
                                          profiles_table))
    try:
        for p in patchers:
            p.start()
        with context.sandbox(profile=profile, target=str(target)) as run:
            try:
                run(["/bin/true"], capture_output=True, timeout=30)
            except Exception as exc:  # noqa: BLE001 — shape recorded below
                captured["_exception"] = type(exc).__name__
    finally:
        for p in reversed(patchers):
            p.stop()

    return {
        "lane": captured.get("_lane", "plain"),
        "block_network": captured.get("block_network"),
        "seccomp_profile": captured.get("seccomp_profile"),
        "restrict_reads": captured.get("restrict_reads"),
        "target_bound": captured.get("target") == str(target),
        "exception": captured.get("_exception"),
    }


def test_default_profile_is_full() -> None:
    assert DEFAULT_PROFILE == "full"


def test_full_profile_enforcement(tmp_path: Path) -> None:
    got = _resolved_enforcement("full", tmp_path)
    assert got["lane"] == "spawn"
    assert got["block_network"] is True
    assert got["seccomp_profile"] == "full"
    assert not got["restrict_reads"]
    assert got["target_bound"] is True


def test_strict_profile_enforcement(tmp_path: Path) -> None:
    # Same policy intent as full, plus restrict_reads by default (the
    # fail-closed operator accepted compatibility risk; read-everywhere
    # leaves $HOME credentials exposed in Landlock-only mode).
    got = _resolved_enforcement("strict", tmp_path)
    assert got["lane"] == "spawn"
    assert got["block_network"] is True
    assert got["seccomp_profile"] == "full"
    assert got["restrict_reads"] is True
    assert got["target_bound"] is True


def test_target_run_profile_enforcement(tmp_path: Path) -> None:
    # target_run exists to expose a local listener: network open,
    # everything else full-strength.
    got = _resolved_enforcement("target_run", tmp_path)
    assert got["lane"] == "spawn"
    assert got["block_network"] is False
    assert got["seccomp_profile"] == "full"
    assert got["target_bound"] is True


def test_debug_profile_enforcement(tmp_path: Path) -> None:
    # debug = full with a ptrace-permitting seccomp profile so gdb/rr
    # can trace; network stays blocked.
    got = _resolved_enforcement("debug", tmp_path)
    assert got["lane"] == "spawn"
    assert got["block_network"] is True
    assert got["seccomp_profile"] == "debug"
    assert got["target_bound"] is True


def test_frida_profile_enforcement(tmp_path: Path) -> None:
    # frida attach modes speak TCP to a frida-server, so the profile
    # default leaves the network open (the sandboxed runner overrides
    # per call for spawned targets); seccomp uses the frida profile.
    got = _resolved_enforcement("frida", tmp_path)
    assert got["lane"] == "spawn"
    assert got["block_network"] is False
    assert got["seccomp_profile"] == "frida"
    assert got["target_bound"] is True


def test_network_only_profile_enforcement(tmp_path: Path) -> None:
    # network-only: network blocked, NO Landlock and NO seccomp — the
    # target bind is a Landlock/mount request and must be shed (warned)
    # rather than silently re-engage filesystem policy.
    got = _resolved_enforcement("network-only", tmp_path)
    assert got["block_network"] is True
    assert not got["seccomp_profile"]
    assert got["target_bound"] is False


def test_none_profile_enforcement(tmp_path: Path) -> None:
    # none: rlimits only. No network block, no seccomp, no binds.
    got = _resolved_enforcement("none", tmp_path)
    assert not got["block_network"]
    assert not got["seccomp_profile"]
    assert got["target_bound"] is False


def test_profile_capability_pins_are_mutation_sensitive(
        tmp_path: Path) -> None:
    """Mutation smoke-check for the capability table.

    For every boolean capability of every profile, resolve enforcement
    against a copy of PROFILES with that one flag flipped and require
    a DIFFERENT resolved shape (an exception counts — a refused
    combination is also 'noticed'). This pins the PROBE, so the pins
    above cannot silently lose sensitivity to a future table change.
    """
    baseline = {name: _resolved_enforcement(name, tmp_path)
                for name in PROFILES}
    blind: list[str] = []
    for name, caps in PROFILES.items():
        for key, val in caps.items():
            if not isinstance(val, bool):
                continue
            flipped = {n: dict(c) for n, c in PROFILES.items()}
            flipped[name][key] = not val
            table = types.MappingProxyType({
                n: types.MappingProxyType(c) for n, c in flipped.items()
            })
            try:
                mutated = _resolved_enforcement(name, tmp_path,
                                                profiles_table=table)
            except Exception:  # noqa: BLE001 — refusal = noticed
                continue
            if mutated == baseline[name]:
                blind.append(f"{name}.{key}")
    assert not blind, (
        "enforcement probe cannot distinguish these capability flips: "
        f"{blind}"
    )
