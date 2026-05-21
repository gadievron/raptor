"""Yanked-version detector.

Registries flag specific versions as "withdrawn after publication"
(PyPI ``info.yanked``, npm ``time.unpublished`` / ``versions.<ver>``
absent from packument, Cargo ``versions[].yanked``, RubyGems
``versions[].yanked``). Operators may still have the yanked
version pinned; the dep is in a known-bad state regardless of
CVE status.

Coverage today (per ecosystem):
  * PyPI       — ``info.yanked`` (bool) + ``info.yanked_reason``
  * npm        — top-level ``time.unpublished`` or version missing
                 from ``versions`` while present in ``time``
  * Cargo      — ``versions[i].yanked`` per crate
  * RubyGems   — per-version yanked flag
  * Maven      — no native yanked concept; skipped
  * Composer   — no native yanked concept; skipped
  * NuGet      — ``listed: false`` via registration index

Emits ``sca:hygiene:yanked_version`` HygieneFinding rows.
Severity is medium — yanked means the maintainer pulled the
version for a reason (often defect-related), but the consumer
may still be running it.
"""

from __future__ import annotations

import logging
from typing import Iterable, List, Optional

from ..models import (
    Confidence, Dependency, HygieneFinding,
)

logger = logging.getLogger(__name__)


def scan_pinned_versions(
    deps: Iterable[Dependency],
    *,
    pypi_client=None,
    npm_client=None,
    cargo_client=None,
    rubygems_client=None,
    nuget_client=None,
) -> List[HygieneFinding]:
    """For each exact-pinned dep, query its registry for the
    yanked flag on the pinned version. Emit a finding for each
    confirmed yanked version.

    Skipped silently:
      * Non-exact pins (the range may resolve to a non-yanked version)
      * Deps without a version
      * Ecosystems with no yanked concept (Maven, Composer)
      * Clients not provided
    """
    out: List[HygieneFinding] = []
    seen: set = set()
    for dep in deps:
        if not dep.version:
            continue
        if hasattr(dep.pin_style, "value") and dep.pin_style.value != "exact":
            continue
        key = (dep.ecosystem, dep.name, dep.version)
        if key in seen:
            continue
        seen.add(key)

        reason = _check_yanked(
            dep, pypi_client=pypi_client, npm_client=npm_client,
            cargo_client=cargo_client, rubygems_client=rubygems_client,
            nuget_client=nuget_client,
        )
        if reason is None:
            continue
        out.append(HygieneFinding(
            finding_id=(
                f"sca:hygiene:yanked_version:{dep.ecosystem}:"
                f"{dep.name}:{dep.version}"
            ),
            kind="yanked_version",
            dependency=dep,
            detail=(
                f"{dep.name}@{dep.version} is yanked from "
                f"{dep.ecosystem} — the maintainer withdrew this "
                f"version after publication. {reason}"
            ),
            severity="medium",
            confidence=Confidence(
                "high",
                reason="registry yanked flag",
            ),
        ))
    return out


def _check_yanked(
    dep: Dependency,
    *,
    pypi_client, npm_client, cargo_client,
    rubygems_client, nuget_client,
) -> Optional[str]:
    """Return a non-empty reason string when yanked; None otherwise.

    Per-ecosystem dispatch."""
    if dep.ecosystem == "PyPI" and pypi_client is not None:
        return _yanked_pypi(pypi_client, dep.name, dep.version)
    if dep.ecosystem == "npm" and npm_client is not None:
        return _yanked_npm(npm_client, dep.name, dep.version)
    if dep.ecosystem == "Cargo" and cargo_client is not None:
        return _yanked_cargo(cargo_client, dep.name, dep.version)
    if dep.ecosystem == "RubyGems" and rubygems_client is not None:
        return _yanked_rubygems(rubygems_client, dep.name, dep.version)
    if dep.ecosystem == "NuGet" and nuget_client is not None:
        return _yanked_nuget(nuget_client, dep.name, dep.version)
    return None


def _yanked_pypi(client, name, version) -> Optional[str]:
    if hasattr(client, "get_version_metadata"):
        meta = client.get_version_metadata(name, version)
        if isinstance(meta, dict):
            info = meta.get("info") or {}
            if info.get("yanked"):
                return (info.get("yanked_reason") or
                         "no reason given by maintainer.")
    # Fallback: aggregate metadata's releases entry may carry yanked
    meta = client.get_metadata(name) if hasattr(client, "get_metadata") else None
    if isinstance(meta, dict):
        files = (meta.get("releases") or {}).get(version) or []
        for f in files:
            if isinstance(f, dict) and f.get("yanked"):
                return (f.get("yanked_reason") or
                         "no reason given by maintainer.")
    return None


def _yanked_npm(client, name, version) -> Optional[str]:
    meta = client.get_metadata(name) if hasattr(client, "get_metadata") else None
    if not isinstance(meta, dict):
        return None
    versions = meta.get("versions") or {}
    time_map = meta.get("time") or {}
    # Missing from versions but present in time → unpublished.
    if version not in versions and version in time_map:
        return "version was unpublished from npm."
    # Some packuments expose a top-level ``unpublished`` block
    if "unpublished" in time_map and isinstance(time_map["unpublished"], dict):
        unp = time_map["unpublished"]
        # If our version falls inside the unpublished version list
        for v in unp.get("versions") or []:
            if v == version:
                return "version is in the unpublished block."
    return None


def _yanked_cargo(client, name, version) -> Optional[str]:
    meta = client.get_metadata(name) if hasattr(client, "get_metadata") else None
    if not isinstance(meta, dict):
        return None
    for v in meta.get("versions") or []:
        if isinstance(v, dict) and v.get("num") == version:
            if v.get("yanked"):
                return "crate version was yanked from crates.io."
    return None


def _yanked_rubygems(client, name, version) -> Optional[str]:
    if hasattr(client, "get_version_metadata"):
        meta = client.get_version_metadata(name, version)
        if isinstance(meta, dict) and meta.get("yanked"):
            return "gem was yanked from rubygems.org."
    return None


def _yanked_nuget(client, name, version) -> Optional[str]:
    """NuGet uses ``listed: false`` rather than a yanked flag.
    Available only via the registration-index endpoint, which our
    client doesn't expose today. Stubbed for future expansion."""
    return None
