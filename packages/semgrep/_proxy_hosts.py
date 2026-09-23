"""Egress-proxy hostname allowlist for semgrep invocations.

Shared by both semgrep lanes: the ``packages.semgrep.runner``
registry-config path and the ``packages/static-analysis`` scanner
(which loads this module by path — its hyphenated directory is not
import-statement-addressable).

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

import logging
import shutil
from pathlib import Path

from core.config.hosts_override import load_hosts_override
from core.sandbox import calibrated_hosts

logger = logging.getLogger(__name__)


_OVERRIDE_CONFIG_PATH = (
    Path.home() / ".config" / "raptor" / "semgrep-proxy-hosts.json"
)


# Static default — the public Semgrep endpoints scanner.py historically
# hardcoded. Kept as a tuple so this module is a layered wrapper, not a
# policy change at the bottom of the chain.
_DEFAULT_SEMGREP_HOSTS: tuple[str, ...] = (
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
_SEMGREP_ENV_KEYS: tuple[str, ...] = (
    "SEMGREP_APP_TOKEN",
    "SEMGREP_RULES",
    "SEMGREP_RULES_CACHE",
)


def _load_override() -> list[str] | None:
    """Return the operator override list, or None when no override
    is configured. Tolerant: malformed JSON, non-UTF-8 bytes, or an
    unexpected schema all degrade to None — production failure mode
    is loud at the proxy (scanner subprocess fails with "host not
    in allowlist"), not silent at startup."""
    return load_hosts_override(_OVERRIDE_CONFIG_PATH)


def _resolve_semgrep_bin() -> str | None:
    """Resolve ``semgrep`` to its absolute path via PATH. None when
    not installed — calibration is impossible in that case so we
    fall through to defaults."""
    return shutil.which("semgrep")


def _calibrated_profile():
    """Load (or trigger calibration of) the SandboxProfile for the
    semgrep binary. Returns None on any failure — calibration is
    advisory; static layers carry the policy when it's unavailable.

    Memoised (with stampede protection) by the shared layer,
    ``core.sandbox.calibrated_hosts`` — keyed on (binary path,
    env-key set, probe args), so this site no longer diverges from
    its siblings' cache-key discipline.
    """
    return calibrated_hosts.calibrated_profile(
        _resolve_semgrep_bin(),
        _SEMGREP_ENV_KEYS,
        tag="semgrep_proxy_hosts",
    )


def _calibrated_proxy_hosts() -> list[str] | None:
    """Calibrated layer — None when no profile exists OR the profile
    carries an empty ``proxy_hosts`` list (the common case for
    ``--version`` probes — they don't network)."""
    return calibrated_hosts.hosts_from_profile(_calibrated_profile())


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
    """Clear the shared per-process calibrate memo. Test-only —
    production never invalidates manually; the cache is sha-keyed
    and re-loads on binary self-update via the sha mismatch check."""
    calibrated_hosts.reset_cache_for_tests()
