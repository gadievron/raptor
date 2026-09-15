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

import logging
import shutil
from pathlib import Path


from core.config.hosts_override import load_hosts_override
from core.sandbox import calibrated_hosts


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


# Deny-all encoding shared with the cc / SCA siblings: non-empty
# allowlist for the sandbox, loopback targets refused by the proxy.
_LOOPBACK_ONLY_HOSTS: tuple[str, ...] = ("127.0.0.1", "localhost")


def _resolve_codeql_bin() -> str | None:
    """Locate the CodeQL CLI on PATH. Returns None when not found
    (calibration disabled for that run; static fallback layers
    still apply)."""
    return shutil.which("codeql")


def _calibrated_profile(codeql_bin: str | None = None):
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

    Memoised (with stampede protection) by the shared layer,
    ``core.sandbox.calibrated_hosts``.
    """
    if codeql_bin is None:
        codeql_bin = _resolve_codeql_bin()
    if codeql_bin is None:
        return None
    return calibrated_hosts.calibrated_profile(
        codeql_bin,
        _CODEQL_ENV_KEYS,
        tag="codeql_proxy_hosts",
    )


def _load_override_config() -> list[str] | None:
    """Load the operator's override list, or None if not configured.

    Schema mirrors cc_proxy_hosts:
        {"proxy_hosts": ["ghe.corp.example", "..."]}

    Delegates to the shared ``core.config.hosts_override`` loader:
    ``None`` means UNCONFIGURED (file absent, malformed, unreadable
    bytes, or the key missing / not a list) — the caller falls
    through to the next resolution layer. A configured list is
    honoured INCLUDING when it sanitises to empty (explicit operator
    deny-all; the public function encodes it loopback-only).
    """
    return load_hosts_override(_OVERRIDE_CONFIG_PATH, key="proxy_hosts")


def _calibrated_proxy_hosts(
    codeql_bin: str | None = None,
) -> list[str] | None:
    """Calibrated layer of proxy_hosts_for_codeql's resolution
    chain. Returns None when no profile exists OR proxy_hosts is
    empty. Default ``codeql --version`` probe doesn't network, so
    empty is the common case until a network-engaging probe variant
    lands."""
    return calibrated_hosts.hosts_from_profile(
        _calibrated_profile(codeql_bin),
    )


def _calibrated_readable_paths(
    codeql_bin: str | None = None,
) -> list[str] | None:
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
    codeql_bin: str | None = None,
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
        if not override:
            # Explicit operator deny-all ({"proxy_hosts": []}). The
            # sandbox rejects an empty allowlist outright, so
            # deny-all is encoded loopback-only — the CONNECT proxy
            # refuses loopback targets by design, leaving every
            # remote host denied at the chokepoint (same encoding
            # as the cc and SCA siblings). Pre-fix the raw empty
            # list was returned and the sandbox refused to start —
            # denial preserved, but as an opaque setup error rather
            # than a clean per-host proxy denial.
            return list(_LOOPBACK_ONLY_HOSTS)
        return override

    calibrated = _calibrated_proxy_hosts(codeql_bin)
    if calibrated is not None:
        return calibrated

    return list(_DEFAULT_PACK_DOWNLOAD_HOSTS)


def readable_paths_for_codeql(
    codeql_bin: str | None = None,
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
    """Clear the shared per-process memo. Public so tests can
    isolate runs without monkeypatching internals."""
    calibrated_hosts.reset_cache_for_tests()
