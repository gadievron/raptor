"""Egress-proxy hostname allowlists for SCA resolver subprocesses.

Each tool (pip / npm / cargo / go mod) has a small static default
(the public registry endpoints the tool talks to during
metadata-only resolves) plus two override layers:

  1. **Operator override** — ``~/.config/raptor/sca-proxy-hosts.json``
     with per-tool keys (``{"pip": [...], "npm": [...], ...}``).
     Required for shops on private mirrors / corporate gateways
     where the public defaults aren't reachable.
  2. **Calibrated profile** — when ``raptor-sandbox-calibrate`` has
     been run against the tool's binary, the cached profile's
     ``proxy_hosts`` are preferred. Cache is keyed on
     ``(sha256(realpath(bin)), env_signature)`` where the env
     signature includes per-tool registry-config vars
     (``PIP_INDEX_URL`` etc.) so a binary used with two configs
     gets two distinct cache entries.
  3. **Static default** — the public registry endpoints. Same as
     the historical class-tuple values; preserves behaviour when
     no override or calibration is in play.

Empty calibrated values fall through to the next layer — calibrating
``pip --version`` populates ``paths_read`` but not ``proxy_hosts``
(the version handler doesn't network), so the fallthrough is the
common case until a network-engaging probe runs.

The egress proxy enforces deny-by-default regardless of what this
module returns. If a tool reaches a host outside the resolved
allowlist, the proxy denies and the resolver subprocess fails with a
clear error — operators discover the gap and update the override
config (or re-calibrate).
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Iterable, Optional, Tuple

logger = logging.getLogger(__name__)


# Operator override config — single file with per-tool keys. Operators
# on a corporate gateway typically need to update all four tools at
# once (same proxy fronting every registry), so a combined file
# matches the common-case ergonomics. Per-tool sections are
# independently optional; missing keys fall through to calibrate /
# default.
_OVERRIDE_CONFIG_PATH = (
    Path.home() / ".config" / "raptor" / "sca-proxy-hosts.json"
)


# Static defaults — the public registry endpoints each tool reaches
# during metadata-only resolution. Unchanged from the historical
# class-tuple values; this module is a layered wrapper, not a policy
# change.
_DEFAULT_PIP_HOSTS: Tuple[str, ...] = (
    "pypi.org",
    "files.pythonhosted.org",
)
_DEFAULT_NPM_HOSTS: Tuple[str, ...] = (
    "registry.npmjs.org",
)
_DEFAULT_CARGO_HOSTS: Tuple[str, ...] = (
    "crates.io",
    "index.crates.io",
    "static.crates.io",
)
_DEFAULT_GOMOD_HOSTS: Tuple[str, ...] = (
    "proxy.golang.org",
    "sum.golang.org",
)

# Secondary resolvers — same shape, different registries.
_DEFAULT_BUNDLER_HOSTS: Tuple[str, ...] = (
    "rubygems.org",
    "index.rubygems.org",
)
_DEFAULT_COMPOSER_HOSTS: Tuple[str, ...] = (
    "repo.packagist.org",
    "packagist.org",
)
_DEFAULT_GRADLE_HOSTS: Tuple[str, ...] = (
    "repo.maven.apache.org",
    "repo1.maven.org",
    "plugins.gradle.org",
    "services.gradle.org",
)
_DEFAULT_MAVEN_HOSTS: Tuple[str, ...] = (
    "repo.maven.apache.org",
    "repo1.maven.org",
)
_DEFAULT_NUGET_HOSTS: Tuple[str, ...] = (
    "api.nuget.org",
    "nuget.org",
)
_DEFAULT_PNPM_HOSTS: Tuple[str, ...] = (
    "registry.npmjs.org",
)
_DEFAULT_POETRY_HOSTS: Tuple[str, ...] = (
    "pypi.org",
    "files.pythonhosted.org",
)
_DEFAULT_YARN_HOSTS: Tuple[str, ...] = (
    "registry.yarnpkg.com",
    "registry.npmjs.org",
)


# Per-tool env-key sets for calibrate cache disambiguation. A binary
# used with two registry configs gets two distinct cache entries; the
# resolved env signature is part of the cache fingerprint.
_PIP_ENV_KEYS: Tuple[str, ...] = (
    "PIP_INDEX_URL",
    "PIP_EXTRA_INDEX_URL",
)
_NPM_ENV_KEYS: Tuple[str, ...] = (
    "NPM_CONFIG_REGISTRY",
    "npm_config_registry",  # lowercase variant accepted by npm
)
_CARGO_ENV_KEYS: Tuple[str, ...] = (
    "CARGO_HTTP_REGISTRY",  # legacy override
    "CARGO_REGISTRIES_CRATES_IO_PROTOCOL",
)
_GOMOD_ENV_KEYS: Tuple[str, ...] = (
    "GOPROXY",
    "GOSUMDB",
    "GOPRIVATE",
)

# Secondary-resolver env keys. Most JVM / Ruby / PHP / .NET tools
# carry their registry config in repo files (Gemfile, composer.json,
# settings.xml, NuGet.config) rather than env vars; the env keys
# below are the *user-overridable* knobs that can shift the
# registry without editing the repo. A binary used with two
# different env values gets two cache entries.
_BUNDLER_ENV_KEYS: Tuple[str, ...] = (
    "BUNDLE_MIRROR_OF",   # e.g. ``bundle config mirror.https://...``
    "BUNDLE_GEMFILE",     # selects which Gemfile (and thus source URL)
)
_COMPOSER_ENV_KEYS: Tuple[str, ...] = (
    "COMPOSER",           # selects composer.json path
    "COMPOSER_HOME",      # config dir (auth.json with custom repos)
)
_GRADLE_ENV_KEYS: Tuple[str, ...] = (
    "GRADLE_USER_HOME",   # init.gradle / repos config lives here
)
_MAVEN_ENV_KEYS: Tuple[str, ...] = (
    "MAVEN_OPTS",         # may inject -Dmaven.repo.remote=...
    "M2_HOME",
)
_NUGET_ENV_KEYS: Tuple[str, ...] = (
    "NUGET_PACKAGES",
    "DOTNET_NUGET_SIGNATURE_VERIFICATION",
)
_PNPM_ENV_KEYS: Tuple[str, ...] = (
    # pnpm reads npm_config_* like npm; same discriminators.
    "NPM_CONFIG_REGISTRY",
    "npm_config_registry",
)
_POETRY_ENV_KEYS: Tuple[str, ...] = (
    "POETRY_REPOSITORIES_PRIMARY_URL",
    "PIP_INDEX_URL",  # poetry honours pip's index when configured
)
_YARN_ENV_KEYS: Tuple[str, ...] = (
    "YARN_REGISTRY",       # yarn 1
    "YARN_NPM_REGISTRY_SERVER",  # yarn 2+
)


# Per-process memoisation. Calibration is sha-keyed on disk; without
# this in-memory layer, every resolver subprocess in a scan would
# stat the cache file independently. Keyed on the resolved binary
# path.
_CALIBRATED_CACHE: "dict[str, Optional[object]]" = {}


def _load_override(tool: str) -> Optional[list]:
    """Return the operator override list for ``tool`` or None when
    no override is configured for it. Tolerant: malformed JSON or
    unexpected types degrade silently to None (calibrate / default
    layers carry the policy)."""
    if not _OVERRIDE_CONFIG_PATH.exists():
        return None
    try:
        data = json.loads(
            _OVERRIDE_CONFIG_PATH.read_text(encoding="utf-8"),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        # OSError: permission, vanished file, etc.
        # UnicodeDecodeError: garbage bytes at the override path
        #   (e.g. operator pointed at a binary file by mistake).
        # JSONDecodeError: malformed JSON.
        # All three degrade to "no override" rather than failing
        # the scan — production failure mode is loud at the proxy,
        # not silent at startup.
        return None
    if not isinstance(data, dict):
        return None
    hosts = data.get(tool)
    if not isinstance(hosts, list):
        return None
    seen: set = set()
    result: list = []
    for h in hosts:
        if isinstance(h, str) and h and h not in seen:
            seen.add(h)
            result.append(h)
    return result or None


def _resolve_bin(name: str) -> Optional[str]:
    """Resolve a tool name to its absolute binary path via PATH.
    Returns None when the binary isn't installed; calibration is
    impossible in that case so we fall through to defaults."""
    return shutil.which(name)


def _calibrated_profile(bin_path: Optional[str],
                        env_keys: Iterable[str]):
    """Load (or trigger calibration of) the SandboxProfile for
    ``bin_path``. Returns None on any failure — calibration is
    advisory; static layers carry the policy when it's unavailable.

    Memoised per-process by resolved binary path; the cache key for
    the on-disk profile already accounts for env_keys, so the memo
    just avoids repeated file stats during a single scan.
    """
    if not bin_path:
        return None
    if bin_path in _CALIBRATED_CACHE:
        return _CALIBRATED_CACHE[bin_path]

    try:
        from core.sandbox.calibrate import load_or_calibrate
    except ImportError:
        _CALIBRATED_CACHE[bin_path] = None
        return None

    try:
        # ``--version`` is the canonical low-cost probe: every tool
        # in scope supports it and the version handler exercises
        # startup-time filesystem reads. ``proxy_hosts`` will be
        # empty (no network) — the calibrated value contributes
        # only when an operator runs a network-engaging probe via
        # the libexec CLI. Empty values fall through here to the
        # default layer.
        profile = load_or_calibrate(
            bin_path,
            probe_args=("--version",),
            env_keys=tuple(env_keys),
            timeout=20,
        )
    except (FileNotFoundError, RuntimeError, OSError,
            subprocess.TimeoutExpired) as exc:
        # TimeoutExpired in particular: tools that take longer than
        # 20s under sandbox to print their version (rare but
        # observable for npm on cold systems) shouldn't break the
        # resolver — fall through to defaults.
        logger.debug(
            "sca.proxy_hosts: calibration of %s failed (%s); "
            "falling back to static policy",
            bin_path, exc,
        )
        _CALIBRATED_CACHE[bin_path] = None
        return None

    _CALIBRATED_CACHE[bin_path] = profile
    return profile


def _calibrated_proxy_hosts(
    bin_path: Optional[str],
    env_keys: Iterable[str],
) -> Optional[list]:
    """Calibrated layer of proxy_hosts resolution. Returns None when
    no profile exists OR the profile carries an empty ``proxy_hosts``
    list (the common case for ``--version`` probes — they don't
    network)."""
    profile = _calibrated_profile(bin_path, env_keys)
    if profile is None or not getattr(profile, "proxy_hosts", None):
        return None
    return list(profile.proxy_hosts)


def _resolve(
    tool: str,
    bin_name: str,
    env_keys: Iterable[str],
    default: Tuple[str, ...],
) -> list:
    """Generic three-layer resolution: override → calibrate → default.

    Args:
        tool: key under the override JSON (``"pip"`` etc.).
        bin_name: PATH-resolvable executable name for calibration.
        env_keys: per-tool env vars that disambiguate the calibrate
            cache entry.
        default: static fallback tuple — used as the policy when no
            override is configured and no calibrated profile exists.
    """
    override = _load_override(tool)
    if override is not None:
        return override

    bin_path = _resolve_bin(bin_name)
    calibrated = _calibrated_proxy_hosts(bin_path, env_keys)
    if calibrated is not None:
        return calibrated

    return list(default)


def proxy_hosts_for_pip() -> list:
    """Egress-proxy hostname allowlist for the pip resolver."""
    return _resolve("pip", "pip", _PIP_ENV_KEYS, _DEFAULT_PIP_HOSTS)


def proxy_hosts_for_npm() -> list:
    """Egress-proxy hostname allowlist for the npm resolver."""
    return _resolve("npm", "npm", _NPM_ENV_KEYS, _DEFAULT_NPM_HOSTS)


def proxy_hosts_for_cargo() -> list:
    """Egress-proxy hostname allowlist for the cargo resolver."""
    return _resolve(
        "cargo", "cargo", _CARGO_ENV_KEYS, _DEFAULT_CARGO_HOSTS,
    )


def proxy_hosts_for_gomod() -> list:
    """Egress-proxy hostname allowlist for the go mod resolver.

    The "go" binary is shared between ``go mod`` and other
    subcommands; calibration fingerprints the binary itself, so the
    cached profile is correct for both.
    """
    return _resolve(
        "gomod", "go", _GOMOD_ENV_KEYS, _DEFAULT_GOMOD_HOSTS,
    )


def proxy_hosts_for_bundler() -> list:
    """Egress-proxy hostname allowlist for the Ruby bundler resolver."""
    return _resolve(
        "bundler", "bundle", _BUNDLER_ENV_KEYS, _DEFAULT_BUNDLER_HOSTS,
    )


def proxy_hosts_for_composer() -> list:
    """Egress-proxy hostname allowlist for the PHP composer resolver."""
    return _resolve(
        "composer", "composer",
        _COMPOSER_ENV_KEYS, _DEFAULT_COMPOSER_HOSTS,
    )


def proxy_hosts_for_gradle() -> list:
    """Egress-proxy hostname allowlist for the Gradle resolver.

    Gradle reaches both Maven Central and the Gradle Plugin Portal —
    the static default carries both. Operators on a corporate Maven
    mirror should populate the override; calibration fingerprints
    the system ``gradle`` binary (project wrappers spawn it via
    ``gradlew`` which RAPTOR resolves separately at the call site).
    """
    return _resolve(
        "gradle", "gradle", _GRADLE_ENV_KEYS, _DEFAULT_GRADLE_HOSTS,
    )


def proxy_hosts_for_maven() -> list:
    """Egress-proxy hostname allowlist for the Maven resolver."""
    return _resolve(
        "maven", "mvn", _MAVEN_ENV_KEYS, _DEFAULT_MAVEN_HOSTS,
    )


def proxy_hosts_for_nuget() -> list:
    """Egress-proxy hostname allowlist for the NuGet (.NET) resolver.

    Calibration fingerprints the ``dotnet`` binary (the resolver's
    availability check uses ``dotnet --version``); ``NuGet.config``
    custom sources are operator-overridable but live in the repo so
    they don't disambiguate the cache.
    """
    return _resolve(
        "nuget", "dotnet", _NUGET_ENV_KEYS, _DEFAULT_NUGET_HOSTS,
    )


def proxy_hosts_for_pnpm() -> list:
    """Egress-proxy hostname allowlist for the pnpm resolver."""
    return _resolve(
        "pnpm", "pnpm", _PNPM_ENV_KEYS, _DEFAULT_PNPM_HOSTS,
    )


def proxy_hosts_for_poetry() -> list:
    """Egress-proxy hostname allowlist for the Poetry resolver."""
    return _resolve(
        "poetry", "poetry", _POETRY_ENV_KEYS, _DEFAULT_POETRY_HOSTS,
    )


def proxy_hosts_for_yarn() -> list:
    """Egress-proxy hostname allowlist for the Yarn resolver.

    Yarn 1 and Yarn 2+ have different env-key conventions
    (``YARN_REGISTRY`` vs ``YARN_NPM_REGISTRY_SERVER``); both are in
    the cache key so a binary used in both modes still discriminates
    correctly. The static default also includes ``registry.npmjs.org``
    because Yarn falls back to the npm registry for many packages.
    """
    return _resolve(
        "yarn", "yarn", _YARN_ENV_KEYS, _DEFAULT_YARN_HOSTS,
    )


def _reset_calibrate_cache_for_tests() -> None:
    """Clear the per-process calibrate memo. Test-only — production
    code never invalidates manually; the cache is sha-keyed and
    re-loads on binary self-update via the sha mismatch check."""
    _CALIBRATED_CACHE.clear()
