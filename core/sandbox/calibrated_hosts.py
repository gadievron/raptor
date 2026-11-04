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

* Memoised per-process by ``(bin_path, env_keys, probe_args)``, with
  binary metadata and declared environment values checked on every
  lookup. Updates replace the slot instead of accumulating generations.
* Stampede-safe: concurrent first-callers for one key wait on the
  single in-flight calibration instead of racing N probes. Waiters
  use their own timeout and fall back without cancelling the owner.
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

import hashlib
import logging
import os
import subprocess
import threading
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from core.json import dumps_canonical
from core.sandbox.errors import SandboxSetupError

logger = logging.getLogger(__name__)


_CACHE: dict[tuple[str, tuple[str, ...], tuple[str, ...]], object] = {}
_CACHE_LOCK = threading.Lock()


@dataclass
class _CacheEntry:
    identity: tuple
    ready: threading.Event = field(default_factory=threading.Event)
    result: object = None


def _memo_identity(bin_path: str, env_keys: tuple[str, ...]) -> tuple:
    """Cheap freshness guard; the disk loader still verifies content hashes."""
    try:
        st = os.stat(bin_path)
        binary = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
    except OSError:
        binary = None
    # Keep credentials out of memo keys: retain only a digest of the
    # declared values, not the environment values themselves.
    values = [(key, os.environ.get(key, "")) for key in sorted(set(env_keys))]
    signature = hashlib.sha256(dumps_canonical(values).encode("ascii")).hexdigest()
    return binary, signature


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
    identity = _memo_identity(bin_path, key[1])

    # Check the memo under the lock. On a miss, plant an Event so
    # concurrent threads wait for the single in-flight calibration
    # instead of stampeding N probes. The plant happens INSIDE the
    # try whose finally sets the Event: an owner dying between the
    # plant and the probe (an async BaseException in that window)
    # previously left the sentinel forever unset and parked every
    # later caller for this key in waiter.wait() for the process
    # lifetime.
    result = None
    sentinel: _CacheEntry | None = None
    try:
        with _CACHE_LOCK:
            cached = _CACHE.get(key)
            if isinstance(cached, _CacheEntry) and cached.identity == identity:
                if cached.ready.is_set():
                    return cached.result
                waiter = cached
            else:
                waiter = None
                sentinel = _CacheEntry(identity)
                _CACHE[key] = sentinel

        if waiter is not None:
            if not waiter.ready.wait(timeout=max(timeout, 0)):
                logger.debug(
                    "%s: calibration of %s still pending; using static policy",
                    tag, bin_path,
                )
                return None
            return waiter.result

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
        if result is not None and _memo_identity(bin_path, key[1]) != identity:
            # The measured inputs changed while calibration was running.
            # Do not bind that result to the earlier snapshot or overwrite
            # a newer caller's slot; let a later stable call retry.
            result = None
            with _CACHE_LOCK:
                if _CACHE.get(key) is sentinel:
                    del _CACHE[key]
    finally:
        if sentinel is not None:
            with _CACHE_LOCK:
                sentinel.result = result
            sentinel.ready.set()
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
    production refreshes automatically when binary metadata or declared
    environment values change; the disk cache verifies content hashes."""
    _CACHE.clear()
