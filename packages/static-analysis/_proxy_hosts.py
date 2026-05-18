"""Egress-proxy hostname allowlist for the semgrep scanner.

Three-layer resolution: operator override → calibrated profile →
static default. Same shape as ``core.llm.cc_proxy_hosts`` /
``packages.codeql.codeql_proxy_hosts`` / ``packages.sca.resolvers._proxy_hosts``;
semgrep fits the binary-scoped pattern because (a) it has a small
fixed set of public registry endpoints, (b) those endpoints have
evolved across versions (``api.semgrep.dev`` was added more
recently than ``semgrep.dev``), and (c) operators on Semgrep
Enterprise / self-hosted Semgrep AppSec Platform need a way to
override without editing source.

Resolution layers:

  1. **Operator override** — ``~/.config/raptor/semgrep-proxy-hosts.json``
     with a flat ``{"hosts": [...]}`` list. Required for shops on
     Semgrep self-hosted / a corporate registry mirror.
  2. **Calibrated profile** — ``raptor-sandbox-calibrate --bin
     semgrep`` populates the profile cache. ``semgrep --version``
     doesn't network, so calibrated ``proxy_hosts`` will be empty
     and falls through to default; an operator running a
     network-engaging probe (e.g. ``semgrep ci --dry-run`` against
     a public registry pack) gets full host capture.
  3. **Static default** — the four public Semgrep endpoints
     (``semgrep.dev``, ``registry.semgrep.dev``, ``semgrep.app``,
     ``api.semgrep.dev``).

Empty calibrated values fall through to the next layer.

The egress proxy enforces deny-by-default at runtime regardless of
what this module returns.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


_OVERRIDE_CONFIG_PATH = (
    Path.home() / ".config" / "raptor" / "semgrep-proxy-hosts.json"
)


# Static default — the public Semgrep endpoints scanner.py historically
# hardcoded. Kept as a tuple so this module is a layered wrapper, not a
# policy change at the bottom of the chain.
_DEFAULT_SEMGREP_HOSTS: Tuple[str, ...] = (
    "semgrep.dev",
    "registry.semgrep.dev",
    "semgrep.app",
    "api.semgrep.dev",
)


# Env keys that discriminate the calibrate cache. ``SEMGREP_APP_TOKEN``
# is the auth token for Semgrep Cloud Platform; an operator with one
# token configured for org A and another for org B (rare but possible)
# gets distinct cache entries. ``SEMGREP_RULES`` and
# ``SEMGREP_RULES_CACHE`` shift the rule-fetch surface and
# legitimately discriminate the binary's reach.
_SEMGREP_ENV_KEYS: Tuple[str, ...] = (
    "SEMGREP_APP_TOKEN",
    "SEMGREP_RULES",
    "SEMGREP_RULES_CACHE",
)


# Per-process memoisation. Calibration is sha-keyed on disk; without
# this in-memory layer, every scanner-spawn in a /scan would stat the
# cache file independently.
_CALIBRATED_CACHE: "dict[str, Optional[object]]" = {}


def _load_override() -> Optional[list[str]]:
    """Return the operator override list, or None when no override
    is configured. Tolerant: malformed JSON, non-UTF-8 bytes, or an
    unexpected schema all degrade to None — production failure mode
    is loud at the proxy (scanner subprocess fails with "host not
    in allowlist"), not silent at startup."""
    if not _OVERRIDE_CONFIG_PATH.exists():
        return None
    try:
        data = json.loads(
            _OVERRIDE_CONFIG_PATH.read_text(encoding="utf-8"),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    hosts = data.get("hosts")
    if not isinstance(hosts, list):
        return None
    seen: set = set()
    result: list = []
    for h in hosts:
        if isinstance(h, str) and h and h not in seen:
            seen.add(h)
            result.append(h)
    return result or None


def _resolve_semgrep_bin() -> Optional[str]:
    """Resolve ``semgrep`` to its absolute path via PATH. None when
    not installed — calibration is impossible in that case so we
    fall through to defaults."""
    return shutil.which("semgrep")


def _calibrated_profile():
    """Load (or trigger calibration of) the SandboxProfile for the
    semgrep binary. Returns None on any failure — calibration is
    advisory; static layers carry the policy when it's unavailable.

    Memoised per-process by resolved binary path.
    """
    bin_path = _resolve_semgrep_bin()
    if bin_path is None:
        return None
    if bin_path in _CALIBRATED_CACHE:
        return _CALIBRATED_CACHE[bin_path]

    try:
        from core.sandbox.calibrate import load_or_calibrate
    except ImportError:
        _CALIBRATED_CACHE[bin_path] = None
        return None

    try:
        profile = load_or_calibrate(
            bin_path,
            probe_args=("--version",),
            env_keys=_SEMGREP_ENV_KEYS,
            timeout=20,
        )
    except (FileNotFoundError, RuntimeError, OSError,
            subprocess.TimeoutExpired) as exc:
        # ptrace blocked, libseccomp absent, binary deleted between
        # which() and probe, or `semgrep --version` exceeded 20s
        # under sandbox. Log at debug — calibration is advisory,
        # static fallback stays in place.
        logger.debug(
            "semgrep proxy_hosts: calibration of %s failed (%s); "
            "falling back to static policy",
            bin_path, exc,
        )
        _CALIBRATED_CACHE[bin_path] = None
        return None

    _CALIBRATED_CACHE[bin_path] = profile
    return profile


def _calibrated_proxy_hosts() -> Optional[list[str]]:
    """Calibrated layer — None when no profile exists OR the profile
    carries an empty ``proxy_hosts`` list (the common case for
    ``--version`` probes — they don't network)."""
    profile = _calibrated_profile()
    if profile is None or not getattr(profile, "proxy_hosts", None):
        return None
    return list(profile.proxy_hosts)


def proxy_hosts_for_semgrep() -> list[str]:
    """Egress-proxy hostname allowlist for the semgrep scanner
    subprocess.

    Three-layer resolution: operator override
    (``~/.config/raptor/semgrep-proxy-hosts.json`` ``{"hosts": [...]}``)
    → calibrated profile → static default. Returns a fresh list
    each call.
    """
    override = _load_override()
    if override is not None:
        return override

    calibrated = _calibrated_proxy_hosts()
    if calibrated is not None:
        return calibrated

    return list(_DEFAULT_SEMGREP_HOSTS)


def _reset_calibrate_cache_for_tests() -> None:
    """Clear the per-process calibrate memo. Test-only — production
    code never invalidates manually; the cache is sha-keyed and
    re-loads on binary self-update via the sha mismatch check."""
    _CALIBRATED_CACHE.clear()
