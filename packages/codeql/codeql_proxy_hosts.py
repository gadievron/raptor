"""Sandbox policy for CodeQL pack-download sites — proxy-hosts
allowlist and readable-paths set.

Mirrors ``core/llm/cc_proxy_hosts`` for cc_dispatch. Resolution
layers (priority high → low):

  1. ``~/.config/raptor/codeql-proxy-hosts.json`` — operator
     override for enterprise registries / corporate GitHub
     installs (``ghe.<corp>.com``-style hosts that the hardcoded
     fallback doesn't know about).
  2. Calibrated SandboxProfile — when ``raptor-sandbox-calibrate``
     has fingerprinted the resolved CodeQL binary + the env vars
     that change its behaviour (``CODEQL_DIST``, ``CODEQL_HOME``,
     ``XDG_CACHE_HOME``, ``GITHUB_TOKEN``), prefer the auto-
     discovered values. The default ``codeql --version`` probe
     captures filesystem reach reliably; proxy hostnames populate
     only when a future probe variant exercises an actual ``pack
     download`` against the operator's configured registry.
     Empty values from the cache fall through to the next layer.
  3. Default — the documented vanilla-CodeQL pack-download host
     set: ``ghcr.io`` + the GitHub Container Registry redirect
     chain. Same hardcoded list ``query_runner.py`` shipped with
     for the past N releases, lifted into a function so it has
     one definition and one place to extend.

Threat model: same as ``cc_proxy_hosts``. Calibration is a
portability/drift-detection tool, NOT a security feature. The
egress proxy enforces deny-by-default regardless of what this
module returns; if a future CodeQL version adds an essential
endpoint, the proxy denies, ``codeql pack download`` errors out,
and the operator updates the override config or upgrades RAPTOR.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Optional


logger = logging.getLogger(__name__)


_OVERRIDE_CONFIG_PATH = (
    Path.home() / ".config" / "raptor" / "codeql-proxy-hosts.json"
)


# Env vars that affect CodeQL's filesystem and registry resolution.
# Used for the calibrate cache-key (``env_signature``) so the same
# binary used with vs without ``CODEQL_DIST`` produces distinct
# profiles. Operators on enterprise GHE installs typically set
# at least ``GITHUB_TOKEN``; ``CODEQL_DIST`` / ``CODEQL_HOME``
# redirect the cache + pack root.
_CODEQL_ENV_KEYS: tuple[str, ...] = (
    "CODEQL_DIST",
    "CODEQL_HOME",
    "XDG_CACHE_HOME",
    "GITHUB_TOKEN",
)


# Default pack-download hostname allowlist. Same set
# ``query_runner.py`` has shipped with — lifted here for
# single-source-of-truth + extension via override / calibrate.
_DEFAULT_PACK_DOWNLOAD_HOSTS: tuple[str, ...] = (
    # CodeQL packs are published as OCI artefacts under ghcr.io.
    "ghcr.io",
    # GitHub-side download redirect (used when fetching tarballs).
    "codeload.github.com",
    # Object-storage backend that ghcr.io redirects fetches to.
    "objects.githubusercontent.com",
    # Container-image blob backend (used by `codeql pack download`).
    "pkg-containers.githubusercontent.com",
)


# Per-process memoisation. Pack-download is bursty (multiple
# missing packs in a single ``codeql analyze`` run trigger several
# back-to-back ``pack download`` invocations); re-loading the
# calibrated profile from disk on each is wasted effort.
_CALIBRATED_CACHE: dict[str, "object"] = {}


def _resolve_codeql_bin() -> Optional[str]:
    """Locate the CodeQL CLI on PATH. Returns None when not found
    (calibration disabled for that run; static fallback layers
    still apply)."""
    return shutil.which("codeql")


def _calibrated_profile(codeql_bin: Optional[str] = None):
    """Load (or trigger calibration of) a SandboxProfile for the
    target CodeQL binary + env. Returns None when calibration is
    unavailable (binary missing, observe-mode prerequisites
    missing, exception during probe).

    Args:
        codeql_bin: explicit binary path. When None, falls back to
            ``shutil.which("codeql")``. ``query_runner`` /
            ``database_manager`` should pass the same binary path
            they spawn so calibration fingerprints exactly that
            install rather than "whatever happens to be on PATH"
            (which can differ on multi-version setups, e.g. the
            CodeQL bundle vs `gh ext install`-ed CLI).

    Memoised per-process by binary path — same shape as
    ``cc_proxy_hosts._calibrated_profile``.
    """
    if codeql_bin is None:
        codeql_bin = _resolve_codeql_bin()
    if codeql_bin is None:
        return None
    if codeql_bin in _CALIBRATED_CACHE:
        return _CALIBRATED_CACHE[codeql_bin]

    try:
        from core.sandbox.calibrate import load_or_calibrate
    except ImportError:
        _CALIBRATED_CACHE[codeql_bin] = None
        return None

    try:
        profile = load_or_calibrate(
            codeql_bin,
            probe_args=("--version",),
            env_keys=_CODEQL_ENV_KEYS,
            timeout=20,
        )
    except (FileNotFoundError, RuntimeError, OSError,
            subprocess.TimeoutExpired) as exc:
        # TimeoutExpired: a sandboxed `codeql --version` exceeding
        # 20s (rare but observable on cold systems / large CodeQL
        # bundles) shouldn't break the resolver — fall through to
        # the static default like every other failure mode.
        logger.debug(
            "codeql_proxy_hosts: calibration of %s failed (%s); "
            "falling back to static policy",
            codeql_bin, exc,
        )
        _CALIBRATED_CACHE[codeql_bin] = None
        return None

    _CALIBRATED_CACHE[codeql_bin] = profile
    return profile


def _load_override_config() -> Optional[list[str]]:
    """Load the operator's override list, or None if not configured.

    Schema mirrors cc_proxy_hosts:
        {"proxy_hosts": ["ghe.corp.example", "..."]}

    Future fields can be added (commit history records schema
    evolution). Unknown fields are tolerated.
    """
    if not _OVERRIDE_CONFIG_PATH.exists():
        return None
    try:
        data = json.loads(
            _OVERRIDE_CONFIG_PATH.read_text(encoding="utf-8"),
        )
    except (OSError, json.JSONDecodeError):
        return None
    hosts = data.get("proxy_hosts") if isinstance(data, dict) else None
    if not isinstance(hosts, list):
        return None
    seen: set[str] = set()
    result: list[str] = []
    for h in hosts:
        if isinstance(h, str) and h and h not in seen:
            seen.add(h)
            result.append(h)
    return result or None


def _calibrated_proxy_hosts(
    codeql_bin: Optional[str] = None,
) -> Optional[list[str]]:
    """Calibrated layer of proxy_hosts_for_codeql's resolution
    chain. Returns None when no profile exists OR proxy_hosts is
    empty. Default ``codeql --version`` probe doesn't network, so
    empty is the common case until a network-engaging probe variant
    lands."""
    profile = _calibrated_profile(codeql_bin)
    if profile is None or not profile.proxy_hosts:
        return None
    return list(profile.proxy_hosts)


def _calibrated_readable_paths(
    codeql_bin: Optional[str] = None,
) -> Optional[list[str]]:
    """Calibrated layer of readable_paths_for_codeql's resolution
    chain. Returns the union of paths_read + paths_stat — both
    require Landlock read access (the kernel doesn't distinguish
    open() from stat() at the path-permission layer)."""
    profile = _calibrated_profile(codeql_bin)
    if profile is None:
        return None
    union = list(dict.fromkeys(
        list(profile.paths_read) + list(profile.paths_stat),
    ))
    if not union:
        return None
    return union


def _default_readable_paths() -> list[str]:
    """Documented CodeQL install layout fallback.

    The CodeQL CLI's pack cache + config dirs. Operators with
    non-default install locations (CODEQL_DIST set, custom
    XDG_CACHE_HOME) should rely on calibration to pick up the
    real layout — these defaults assume the vanilla GitHub
    Action / `gh ext install codeql` shape.
    """
    home = Path.home()
    return [
        # Pack cache (created on first ``codeql pack download``).
        str(home / ".codeql"),
        # Some installs use the XDG layout.
        str(home / ".cache" / "codeql"),
        # Configuration.
        str(home / ".config" / "codeql"),
    ]


def proxy_hosts_for_codeql(
    codeql_bin: Optional[str] = None,
) -> list[str]:
    """Return the egress proxy hostname allowlist for a
    ``codeql pack download`` invocation.

    Args:
        codeql_bin: explicit CodeQL CLI path. When provided,
            calibration fingerprints exactly that binary; when
            None, falls back to PATH lookup. Call sites should
            pass the same value they'll spawn so the policy
            matches.

    Priority: override config > calibrated profile > default
    GitHub Container Registry hosts.
    """
    override = _load_override_config()
    if override is not None:
        return override

    calibrated = _calibrated_proxy_hosts(codeql_bin)
    if calibrated is not None:
        return calibrated

    return list(_DEFAULT_PACK_DOWNLOAD_HOSTS)


def readable_paths_for_codeql(
    codeql_bin: Optional[str] = None,
) -> list[str]:
    """Return the Landlock readable-paths set for CodeQL.

    Args:
        codeql_bin: same semantics as ``proxy_hosts_for_codeql``.

    Priority: calibrated profile > default install layout.
    """
    calibrated = _calibrated_readable_paths(codeql_bin)
    if calibrated is not None:
        return calibrated
    return _default_readable_paths()


def _reset_calibrate_cache_for_tests() -> None:
    """Clear the per-process memo. Public so tests can isolate
    runs without monkeypatching the dict directly."""
    _CALIBRATED_CACHE.clear()
