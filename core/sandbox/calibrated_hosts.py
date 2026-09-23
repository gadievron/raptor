"""Shared calibrated-profile layer for egress proxy-hosts ladders.

Every binary-scoped egress allowlist resolves through the same
three-layer ladder — operator override → calibrated profile →
static default — and the middle layer used to be re-implemented per
site (cc_dispatch, CodeQL pack download, the SCA resolvers, the
semgrep scanner). The copies drifted structurally: one memo was
keyed by binary path only, one by (binary, env-keys), one had no
cache key parametrisation at all, and only one had calibration-
stampede protection. This module owns that layer once.

Semantics (pinned by test_proxy_hosts_ladder_closure):

* Memoised per-process, keyed ``(bin_path, env_keys, probe_args)``
  — two tools sharing one binary with different env-key sets (or
  probe variants) never serve each other's profile.
* Stampede-safe: concurrent first-callers for one key wait on the
  single in-flight calibration instead of racing N probes.
* Fail-soft: calibration is advisory. Import failure, probe
  failure, or timeout memoise None; the caller's static layers
  carry the policy.
* Empty-value fallthrough: a profile whose ``proxy_hosts`` is empty
  (the default ``--version`` probe doesn't network) reads as "no
  calibrated hosts" — the caller falls through to its next layer.

Threat model: same as the site modules — calibration is a
portability/drift-detection tool, NOT a security feature; the
egress proxy enforces deny-by-default regardless.
"""

from __future__ import annotations

import logging
import subprocess
import threading
from collections.abc import Iterable, Sequence

from core.sandbox.errors import SandboxSetupError

logger = logging.getLogger(__name__)


_CACHE: dict[tuple[str, tuple[str, ...], tuple[str, ...]], object] = {}
_CACHE_LOCK = threading.Lock()
_MISSING = object()  # sentinel distinct from None (a valid cached result)


def calibrated_profile(
    bin_path: str | None,
    env_keys: Iterable[str],
    *,
    probe_args: Sequence[str] = ("--version",),
    timeout: int = 20,
    tag: str = "proxy_hosts",
):
    """Load (or trigger calibration of) the SandboxProfile for
    ``bin_path``. Returns None on any failure — calibration is
    advisory; the caller's static layers carry the policy.

    Args:
        bin_path: resolved binary path; None/empty short-circuits to
            None (binary not installed — calibration impossible).
        env_keys: env vars that change the binary's reach; part of
            both the on-disk fingerprint and the in-process memo key.
        probe_args: argv for the calibration probe.
        timeout: probe timeout in seconds.
        tag: caller name for log attribution.
    """
    if not bin_path:
        return None
    key = (bin_path, tuple(env_keys), tuple(probe_args))

    # Check the memo under the lock. On a miss, plant an Event so
    # concurrent threads wait for the single in-flight calibration
    # instead of stampeding N probes. The plant happens INSIDE the
    # try whose finally sets the Event: an owner dying between the
    # plant and the probe (an async BaseException in that window)
    # previously left the sentinel forever unset and parked every
    # later caller for this key in waiter.wait() for the process
    # lifetime.
    result = None
    sentinel: threading.Event | None = None
    try:
        with _CACHE_LOCK:
            cached = _CACHE.get(key, _MISSING)
            if isinstance(cached, threading.Event):
                waiter = cached
            elif cached is not _MISSING:
                return cached
            else:
                waiter = None
                sentinel = threading.Event()
                _CACHE[key] = sentinel

        if waiter is not None:
            waiter.wait()
            with _CACHE_LOCK:
                return _CACHE.get(key)

        # We own the calibration slot.
        try:
            from core.sandbox.calibrate import load_or_calibrate
        except ImportError:
            return None

        try:
            result = load_or_calibrate(
                bin_path,
                probe_args=key[2],
                env_keys=key[1],
                timeout=timeout,
            )
        except (FileNotFoundError, RuntimeError, OSError,
                subprocess.TimeoutExpired) as exc:
            # ptrace blocked, libseccomp absent, binary deleted
            # between which() and probe, or the probe exceeded its
            # timeout under sandbox. Debug-level: calibration is
            # advisory and the static fallback stays in place.
            logger.debug(
                "%s: calibration of %s failed (%s); falling back "
                "to static policy", tag, bin_path, exc,
            )
            result = None
        except SandboxSetupError as exc:
            # DELIBERATE BaseException absorption: SandboxSetupError
            # subclasses BaseException precisely so ENFORCEMENT
            # callers cannot swallow it — but this layer is
            # documented fail-soft ADVISORY measurement (every
            # consumer treats None as "use the static fallback").
            # On a degraded host the calibration probe's sandboxed
            # run refuses with SandboxSetupError; letting it escape
            # converted an advisory measurement into an exception no
            # consumer `except Exception` could absorb — failing
            # exactly the runs the static-hosts fallback exists to
            # carry.
            logger.debug(
                "%s: calibration of %s refused by the sandbox (%s); "
                "falling back to static policy", tag, bin_path, exc,
            )
            result = None
    finally:
        if sentinel is not None:
            with _CACHE_LOCK:
                _CACHE[key] = result
            sentinel.set()
    return result


def hosts_from_profile(profile) -> list[str] | None:
    """Empty-value fallthrough filter for a loaded profile: None when
    there is no profile OR its ``proxy_hosts`` is empty (the default
    ``--version`` probe doesn't network) — the caller falls through
    to its next ladder layer."""
    if profile is None or not getattr(profile, "proxy_hosts", None):
        return None
    return list(profile.proxy_hosts)


def reset_cache_for_tests() -> None:
    """Clear the per-process memo (all sites). Test-only —
    production never invalidates manually; the on-disk cache is
    sha-keyed and re-loads on binary self-update."""
    _CACHE.clear()
