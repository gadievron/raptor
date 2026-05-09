"""License-policy engine — emits :class:`LicenseFinding` rows when a
dependency's declared license matches operator-defined rules.

Two-stage flow:

  * :func:`enrich_licenses` — populate ``Dependency.declared_license``
    for ecosystems where it isn't supplied by the manifest itself.
    PyPI / npm parsers don't have license info (manifests pin
    versions, not licenses); registry metadata does. We only fetch
    when the dep's license is currently None and the operator
    cares (policy is non-empty).
  * :func:`evaluate` — walk the deps, classify each license against
    the policy, emit :class:`LicenseFinding` rows.

## Policy file format

YAML at ``<target>/.raptor-sca-license-policy.yml``::

    # Licenses operators explicitly allow — no finding.
    allow:
      - MIT
      - Apache-2.0
      - BSD-2-Clause
      - BSD-3-Clause
      - ISC

    # Licenses operators explicitly disallow — high severity.
    deny:
      - AGPL-3.0
      - AGPL-3.0-only
      - AGPL-3.0-or-later
      - SSPL-1.0
      - Commons-Clause

    # Licenses to flag as warning — medium severity.
    warn:
      - GPL-3.0
      - GPL-3.0-only
      - GPL-3.0-or-later

    # When a dep's license isn't in any list, this kind:
    #   "warn"  -> emit a warning finding
    #   "allow" -> permissive default (no finding)
    #   "deny"  -> strict default (every unmatched license is denied)
    default: allow

    # When a dep has no license at all (registry didn't provide):
    #   "warn"  -> info-severity finding ("license unknown")
    #   "deny"  -> high-severity finding (refused; explicit declaration required)
    #   "allow" -> no finding
    on_unknown: warn

The default policy (when no file exists) is permissive: allow is
empty, deny is AGPL-family + SSPL + Commons-Clause, warn is the
GPL-3 family, default=allow, on_unknown=warn. Operators committed
to compliance ship a tighter policy.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .models import (
    Confidence,
    Dependency,
    LicenseFinding,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LicensePolicy:
    """Operator-defined license rules. Use :func:`load_policy` to read
    from disk; :data:`DEFAULT_POLICY` is the no-config baseline."""

    allow: Set[str] = field(default_factory=set)
    deny: Set[str] = field(default_factory=set)
    warn: Set[str] = field(default_factory=set)
    default: str = "allow"          # "allow" | "warn" | "deny"
    on_unknown: str = "warn"        # "allow" | "warn" | "deny"


# Sensible default — out-of-the-box behaviour without a policy file.
# Reflects "most operators are fine with permissive licences but want
# AGPL / SSPL / Commons-Clause flagged as a compliance risk".
DEFAULT_POLICY = LicensePolicy(
    allow=set(),
    deny={
        "AGPL-3.0",
        "AGPL-3.0-only",
        "AGPL-3.0-or-later",
        "SSPL-1.0",
        "Commons-Clause",
        "BUSL-1.1",                 # Business Source License — non-OSS
    },
    warn={
        "GPL-2.0",
        "GPL-2.0-only",
        "GPL-2.0-or-later",
        "GPL-3.0",
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "LGPL-3.0",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
    },
    default="allow",
    on_unknown="warn",
)


def load_policy(target: Path) -> LicensePolicy:
    """Load policy from ``<target>/.raptor-sca-license-policy.yml`` or
    return :data:`DEFAULT_POLICY`.

    Tolerates: missing file, missing optional keys, malformed YAML
    (logs + falls back). A genuinely-broken policy file shouldn't
    abort the SCA run — operators get the default + a warning so
    they notice and fix the file.
    """
    path = target / ".raptor-sca-license-policy.yml"
    if not path.is_file():
        return DEFAULT_POLICY
    try:
        import yaml
        from packages.sca._yaml_fast import safe_load
    except ImportError:
        logger.warning(
            "sca.license: PyYAML not installed — skipping operator "
            "policy file at %s, using default", path,
        )
        return DEFAULT_POLICY
    try:
        text = path.read_text(encoding="utf-8")
        data = safe_load(text) or {}
    except (OSError, yaml.YAMLError) as e:
        logger.warning(
            "sca.license: failed to read %s (%s) — using default",
            path, e,
        )
        return DEFAULT_POLICY
    if not isinstance(data, dict):
        logger.warning(
            "sca.license: %s is not a YAML mapping — using default",
            path,
        )
        return DEFAULT_POLICY
    return LicensePolicy(
        allow=_as_set(data.get("allow")),
        deny=_as_set(data.get("deny")),
        warn=_as_set(data.get("warn")),
        default=_as_action(data.get("default"), default="allow"),
        on_unknown=_as_action(data.get("on_unknown"), default="warn"),
    )


def _as_set(v: Any) -> Set[str]:
    if v is None:
        return set()
    if isinstance(v, list):
        return {str(x).strip() for x in v if str(x).strip()}
    if isinstance(v, str):
        return {v.strip()} if v.strip() else set()
    return set()


def _as_action(v: Any, *, default: str) -> str:
    if v in ("allow", "warn", "deny"):
        return v
    return default


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def evaluate(
    deps: List[Dependency],
    policy: LicensePolicy,
) -> List[LicenseFinding]:
    """Classify each dep's declared_license against the policy.

    Dedups by (ecosystem, name, version) — no point reporting the
    same dep twice when it appears in multiple manifests; the dep
    keys are stable across appearances.
    """
    seen: Set[str] = set()
    out: List[LicenseFinding] = []
    for d in deps:
        key = d.key()
        if key in seen:
            continue
        seen.add(key)
        finding = _evaluate_one(d, policy)
        if finding is not None:
            out.append(finding)
    return out


def _evaluate_one(
    dep: Dependency,
    policy: LicensePolicy,
) -> Optional[LicenseFinding]:
    spdx = dep.declared_license
    if spdx is None or not spdx.strip():
        return _unknown_finding(dep, policy)

    spdx = spdx.strip()
    # Multi-license SPDX expressions (``MIT OR Apache-2.0``,
    # ``GPL-3.0 AND BSD-3-Clause``) — best-effort split. For OR
    # the operator only needs ONE acceptable license; for AND
    # ALL must be acceptable.
    if " OR " in spdx:
        choices = [s.strip() for s in spdx.split(" OR ")]
        if any(c in policy.allow for c in choices):
            return None
        if all(c in policy.deny for c in choices):
            return _deny_finding(dep, spdx)
        # Mixed / no acceptable choice — emit incompatible.
        return LicenseFinding(
            finding_id=_finding_id(dep, "license_incompatible"),
            kind="license_incompatible",
            dependency=dep,
            spdx=spdx,
            detail=(
                f"Multi-license OR expression {spdx!r} has no choice "
                f"in policy.allow; operator must pick one or add to allow"
            ),
            severity="medium",
            confidence=Confidence(
                "medium",
                reason="OR expression with no allowlisted choice",
            ),
        )
    if " AND " in spdx:
        choices = [s.strip() for s in spdx.split(" AND ")]
        for c in choices:
            f = _classify(dep, c, policy)
            if f is not None:
                # First denied / warned terminates — operator sees the
                # most-significant violation.
                return f
        return None

    return _classify(dep, spdx, policy)


def _classify(
    dep: Dependency,
    spdx: str,
    policy: LicensePolicy,
) -> Optional[LicenseFinding]:
    if spdx in policy.deny:
        return _deny_finding(dep, spdx)
    if spdx in policy.warn:
        return _warn_finding(dep, spdx)
    if spdx in policy.allow:
        return None
    # Unmatched — apply default.
    if policy.default == "deny":
        return _deny_finding(dep, spdx, why="not in policy.allow")
    if policy.default == "warn":
        return _warn_finding(dep, spdx, why="not in policy.allow")
    return None


def _deny_finding(
    dep: Dependency,
    spdx: str,
    *,
    why: str = "in policy.deny",
) -> LicenseFinding:
    return LicenseFinding(
        finding_id=_finding_id(dep, "license_denied"),
        kind="license_denied",
        dependency=dep,
        spdx=spdx,
        detail=f"License {spdx!r} {why}",
        severity="high",
        confidence=Confidence("high", reason=why),
    )


def _warn_finding(
    dep: Dependency,
    spdx: str,
    *,
    why: str = "in policy.warn",
) -> LicenseFinding:
    return LicenseFinding(
        finding_id=_finding_id(dep, "license_warned"),
        kind="license_warned",
        dependency=dep,
        spdx=spdx,
        detail=f"License {spdx!r} {why}",
        severity="medium",
        confidence=Confidence("high", reason=why),
    )


def _unknown_finding(
    dep: Dependency,
    policy: LicensePolicy,
) -> Optional[LicenseFinding]:
    if policy.on_unknown == "allow":
        return None
    severity = "high" if policy.on_unknown == "deny" else "info"
    return LicenseFinding(
        finding_id=_finding_id(dep, "license_unknown"),
        kind="license_unknown",
        dependency=dep,
        spdx=None,
        detail=(
            f"No license metadata for {dep.ecosystem}:{dep.name}"
            f"@{dep.version or '*'} — registry returned no SPDX field"
        ),
        severity=severity,
        confidence=Confidence(
            "medium",
            reason="declared_license is None after enrichment",
        ),
    )


def _finding_id(dep: Dependency, kind: str) -> str:
    return (
        f"sca:{kind}:{dep.ecosystem}:{dep.name}@{dep.version or '*'}"
        f":{dep.declared_in}"
    )


# ---------------------------------------------------------------------------
# Enrichment — fetch license metadata from registries when manifests
# don't carry it.
# ---------------------------------------------------------------------------


def enrich_licenses(
    deps: List[Dependency],
    *,
    http: Optional[Any] = None,
    cache: Optional[Any] = None,
    enabled: bool = True,
) -> int:
    """Populate ``Dependency.declared_license`` for deps where it's
    None by querying registry metadata. Returns the number of deps
    enriched.

    Currently covers PyPI and npm (the two largest ecosystems with
    registry-side license metadata). Other ecosystems will fall
    through to ``on_unknown`` policy handling.

    When ``http`` is None, returns 0 — license enrichment is
    network-dependent and tests that don't supply an http stub
    skip the network.
    """
    if not enabled or http is None:
        return 0
    try:
        from .registries.pypi import PyPIClient
        from .registries.npm import NpmClient
    except ImportError as e:
        logger.debug("sca.license: registry clients unavailable: %s", e)
        return 0

    # Pre-construct the per-ecosystem registry clients so all worker
    # threads share one set (no double-construction races; the
    # clients are stateless wrappers around http+cache).
    pypi = PyPIClient(http=http, cache=cache)
    npm = NpmClient(http=http, cache=cache)

    work = [d for d in deps if not d.declared_license]
    if not work:
        return 0

    def _enrich_one(d: Dependency) -> bool:
        try:
            if d.ecosystem == "PyPI":
                meta = pypi.get_metadata(d.name)
                spdx = _spdx_from_pypi(meta)
            elif d.ecosystem == "npm":
                meta = npm.get_metadata(d.name)
                spdx = _spdx_from_npm(meta, d.version)
            elif d.ecosystem == "Cargo":
                spdx = _fetch_crates_license(d.name, http=http, cache=cache)
            elif d.ecosystem == "Maven" and d.version:
                spdx = _fetch_maven_license(
                    d.name, d.version, http=http, cache=cache,
                )
            elif d.ecosystem == "RubyGems":
                spdx = _fetch_rubygems_license(
                    d.name, http=http, cache=cache,
                )
            elif d.ecosystem == "NuGet" and d.version:
                spdx = _fetch_nuget_license(
                    d.name, d.version, http=http, cache=cache,
                )
            elif d.ecosystem == "Packagist":
                spdx = _fetch_packagist_license(
                    d.name, d.version, http=http, cache=cache,
                )
            else:
                return False
        except Exception as e:                          # noqa: BLE001
            logger.debug(
                "sca.license: enrichment failed for %s:%s (%s)",
                d.ecosystem, d.name, e,
            )
            return False
        if spdx:
            d.declared_license = spdx
            return True
        return False

    # Parallelise — every fetch is HTTP-bound and independent. Same
    # 8-worker shape as registry_metadata.scan_deps. Skip the pool
    # for tiny inputs so the executor's spin-up doesn't cost more
    # than the sequential walk.
    if len(work) <= 4:
        return sum(1 for d in work if _enrich_one(d))
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(
        max_workers=8, thread_name_prefix="sca-license-enrich",
    ) as pool:
        results = list(pool.map(_enrich_one, work))
    return sum(1 for r in results if r)


# ---------------------------------------------------------------------------
# Cargo (crates.io)
# ---------------------------------------------------------------------------


def _fetch_crates_license(
    name: str, *, http: Any, cache: Any,
) -> Optional[str]:
    """Cargo's crates.io API exposes the license SPDX directly:

        https://crates.io/api/v1/crates/<name>

    Response shape:
        {"crate": {"name": "...", "license": "...", ...}, ...}

    The crate-level license carries the latest version's value;
    per-version differences are rare for Rust and not worth the
    extra round-trip.
    """
    cache_key = f"crates-license:{name.lower()}"
    if cache is not None:
        cached = cache.get(cache_key, ttl_seconds=24 * 3600)
        if cached is not None:
            return cached or None
    try:
        url = f"https://crates.io/api/v1/crates/{name}"
        data = http.get_json(url)
    except Exception:                                   # noqa: BLE001
        return None
    crate = (data or {}).get("crate") or {}
    spdx = crate.get("license") if isinstance(crate, dict) else None
    if isinstance(spdx, str) and spdx.strip():
        result = spdx.strip()
    else:
        result = None
    if cache is not None:
        cache.put(cache_key, result or "", ttl_seconds=24 * 3600)
    return result


# ---------------------------------------------------------------------------
# Maven (POM at repo.maven.apache.org)
# ---------------------------------------------------------------------------


def _fetch_maven_license(
    coord: str, version: str, *, http: Any, cache: Any,
) -> Optional[str]:
    """Fetch + parse a Maven artefact's POM and extract the
    license element. Maven coords are ``groupId:artifactId``; the
    POM URL composes them into a path.

    Maven's ``<licenses>`` section gives free-text license names
    (and sometimes URLs). We map common name strings to SPDX IDs
    via :data:`_MAVEN_NAME_TO_SPDX`. Unknown names fall through to
    ``None`` so the policy treats them as ``license_unknown``.
    """
    if ":" not in coord:
        return None
    cache_key = f"maven-license:{coord}@{version}"
    if cache is not None:
        cached = cache.get(cache_key, ttl_seconds=24 * 3600)
        if cached is not None:
            return cached or None

    group_id, artifact_id = coord.split(":", 1)
    group_path = group_id.replace(".", "/")
    pom_url = (
        f"https://repo.maven.apache.org/maven2/"
        f"{group_path}/{artifact_id}/{version}/"
        f"{artifact_id}-{version}.pom"
    )
    try:
        body = http.get_bytes(pom_url, max_bytes=2 * 1024 * 1024)
    except Exception:                                   # noqa: BLE001
        if cache is not None:
            cache.put(cache_key, "", ttl_seconds=24 * 3600)
        return None

    spdx = _spdx_from_pom(body)
    if cache is not None:
        cache.put(cache_key, spdx or "", ttl_seconds=24 * 3600)
    return spdx


def _spdx_from_pom(pom_bytes: bytes) -> Optional[str]:
    """Parse a POM and extract the first license name, mapped to
    SPDX. Uses ``defusedxml`` when available (XXE / billion-laughs
    hardening), falls back to stdlib ``xml.etree.ElementTree``.
    """
    try:
        try:
            import defusedxml.ElementTree as ET    # type: ignore[import-not-found]
        except ImportError:
            import xml.etree.ElementTree as ET     # type: ignore[no-redef]
        root = ET.fromstring(pom_bytes)
    except Exception:                                   # noqa: BLE001
        return None

    # POMs use namespaced or non-namespaced element names; iterate
    # and match on the local-name suffix.
    def _local(tag: str) -> str:
        return tag.split("}", 1)[-1]

    for elem in root.iter():
        if _local(elem.tag) != "license":
            continue
        for child in elem:
            if _local(child.tag) == "name" and child.text:
                spdx = _MAVEN_NAME_TO_SPDX.get(child.text.strip())
                if spdx:
                    return spdx
                # Fallback: if the free-text already looks SPDX-like
                # (single token, no spaces), accept it.
                text = child.text.strip()
                if " " not in text and len(text) < 40:
                    return text
                return None
        break
    return None


# ---------------------------------------------------------------------------
# RubyGems (rubygems.org)
# ---------------------------------------------------------------------------


def _fetch_rubygems_license(
    name: str, *, http: Any, cache: Any,
) -> Optional[str]:
    """RubyGems API exposes ``licenses`` as an array of SPDX strings:

        https://rubygems.org/api/v1/gems/<name>.json

    Response shape includes ``licenses: ["MIT"]`` (sometimes
    multi-license). We pick the first; multi-license expressions
    are uncommon for Ruby gems and the policy can resolve via OR
    semantics if the operator constructs one.
    """
    cache_key = f"rubygems-license:{name.lower()}"
    if cache is not None:
        cached = cache.get(cache_key, ttl_seconds=24 * 3600)
        if cached is not None:
            return cached or None
    try:
        url = f"https://rubygems.org/api/v1/gems/{name}.json"
        data = http.get_json(url)
    except Exception:                                   # noqa: BLE001
        return None
    licenses = (data or {}).get("licenses") if isinstance(data, dict) else None
    result: Optional[str] = None
    if isinstance(licenses, list) and licenses:
        first = licenses[0]
        if isinstance(first, str) and first.strip():
            result = first.strip()
    if cache is not None:
        cache.put(cache_key, result or "", ttl_seconds=24 * 3600)
    return result


# ---------------------------------------------------------------------------
# NuGet (api.nuget.org — flat container per-version nuspec)
# ---------------------------------------------------------------------------


def _fetch_nuget_license(
    name: str, version: str, *, http: Any, cache: Any,
) -> Optional[str]:
    """NuGet exposes per-package metadata via the registration
    endpoint:

        https://api.nuget.org/v3/registration5-semver1/<name-lower>/<version>.json

    Response includes ``licenseExpression`` (SPDX) AND/OR
    ``licenseUrl`` (legacy free-text URL). Modern packages carry
    SPDX; older ones only have the URL. We use SPDX when present
    and skip the URL (no SPDX mapping for arbitrary URLs).
    """
    cache_key = f"nuget-license:{name.lower()}@{version}"
    if cache is not None:
        cached = cache.get(cache_key, ttl_seconds=24 * 3600)
        if cached is not None:
            return cached or None
    try:
        url = (
            f"https://api.nuget.org/v3/registration5-semver1/"
            f"{name.lower()}/{version}.json"
        )
        data = http.get_json(url)
    except Exception:                                   # noqa: BLE001
        if cache is not None:
            cache.put(cache_key, "", ttl_seconds=24 * 3600)
        return None
    # registration5 entries embed the catalog entry inline.
    entry = (data or {}).get("catalogEntry") if isinstance(data, dict) else None
    if not isinstance(entry, dict):
        # Some endpoint shapes return the catalog entry as the
        # whole document.
        entry = data if isinstance(data, dict) else {}
    spdx = entry.get("licenseExpression")
    result: Optional[str] = None
    if isinstance(spdx, str) and spdx.strip():
        result = spdx.strip()
    if cache is not None:
        cache.put(cache_key, result or "", ttl_seconds=24 * 3600)
    return result


# ---------------------------------------------------------------------------
# Packagist (repo.packagist.org)
# ---------------------------------------------------------------------------


def _fetch_packagist_license(
    name: str, version: Optional[str], *, http: Any, cache: Any,
) -> Optional[str]:
    """Packagist exposes per-package metadata at:

        https://repo.packagist.org/p2/<vendor>/<package>.json

    Response: ``packages.<name>[]`` is a list of per-version
    blocks; each carries a ``license`` array. We pick the entry
    matching ``version`` when given, else the first entry.
    """
    if "/" not in name:
        return None
    cache_key = f"packagist-license:{name}@{version or '*'}"
    if cache is not None:
        cached = cache.get(cache_key, ttl_seconds=24 * 3600)
        if cached is not None:
            return cached or None
    try:
        url = f"https://repo.packagist.org/p2/{name}.json"
        data = http.get_json(url)
    except Exception:                                   # noqa: BLE001
        if cache is not None:
            cache.put(cache_key, "", ttl_seconds=24 * 3600)
        return None
    packages = (data or {}).get("packages") if isinstance(data, dict) else None
    if not isinstance(packages, dict):
        return None
    versions = packages.get(name)
    if not isinstance(versions, list) or not versions:
        return None
    chosen = None
    if version:
        for entry in versions:
            if isinstance(entry, dict) and entry.get("version") == version:
                chosen = entry
                break
    if chosen is None:
        chosen = versions[0] if isinstance(versions[0], dict) else None
    if not isinstance(chosen, dict):
        return None
    licenses = chosen.get("license")
    result: Optional[str] = None
    if isinstance(licenses, list) and licenses:
        first = licenses[0]
        if isinstance(first, str) and first.strip():
            result = first.strip()
    if cache is not None:
        cache.put(cache_key, result or "", ttl_seconds=24 * 3600)
    return result


# Mapping of common Maven license-element names to SPDX IDs. POMs
# carry free-text names; this table covers the licenses that
# appear most often in published OSS POMs.
_MAVEN_NAME_TO_SPDX: Dict[str, str] = {
    "The Apache Software License, Version 2.0": "Apache-2.0",
    "Apache License, Version 2.0": "Apache-2.0",
    "Apache 2.0": "Apache-2.0",
    "Apache License 2.0": "Apache-2.0",
    "MIT License": "MIT",
    "MIT": "MIT",
    "The MIT License": "MIT",
    "BSD License": "BSD-3-Clause",
    "BSD 3-Clause License": "BSD-3-Clause",
    "BSD-3-Clause": "BSD-3-Clause",
    "BSD 2-Clause License": "BSD-2-Clause",
    "Eclipse Public License - v 1.0": "EPL-1.0",
    "Eclipse Public License 1.0": "EPL-1.0",
    "Eclipse Public License - v 2.0": "EPL-2.0",
    "Eclipse Public License 2.0": "EPL-2.0",
    "GNU Lesser General Public License, Version 2.1": "LGPL-2.1",
    "GNU Lesser General Public License v2.1": "LGPL-2.1",
    "GNU Lesser General Public License, Version 3.0": "LGPL-3.0",
    "GNU General Public License, Version 2": "GPL-2.0",
    "GNU General Public License, version 2 with the Classpath Exception":
        "GPL-2.0-with-classpath-exception",
    "GNU General Public License, Version 3": "GPL-3.0",
    "Mozilla Public License Version 2.0": "MPL-2.0",
    "Mozilla Public License, Version 2.0": "MPL-2.0",
    "MPL 2.0": "MPL-2.0",
    "ISC License": "ISC",
    "Common Development and Distribution License (CDDL) v1.0": "CDDL-1.0",
    "Common Development and Distribution License (CDDL) v1.1": "CDDL-1.1",
    "The Unlicense": "Unlicense",
    "Public Domain": "Unlicense",
}


def _spdx_from_pypi(meta: Optional[dict]) -> Optional[str]:
    if not isinstance(meta, dict):
        return None
    info = meta.get("info") or {}
    # PEP 639 (Python 3.12+): info.license_expression is SPDX. Older
    # packages: info.license is a free-text license name.
    expr = info.get("license_expression")
    if isinstance(expr, str) and expr.strip():
        return expr.strip()
    license_text = info.get("license")
    if isinstance(license_text, str) and license_text.strip():
        # Only use when it looks like a single SPDX id (no spaces,
        # short). Free-text descriptions like "see LICENSE file" are
        # not useful to the policy engine.
        text = license_text.strip()
        if " " not in text and len(text) < 60:
            return text
    # Trove classifier fallback: "License :: OSI Approved :: MIT License"
    classifiers = info.get("classifiers") or []
    if isinstance(classifiers, list):
        for c in classifiers:
            if not isinstance(c, str):
                continue
            spdx = _spdx_from_trove(c)
            if spdx is not None:
                return spdx
    return None


def _spdx_from_trove(classifier: str) -> Optional[str]:
    """Map a single PyPI ``License ::`` Trove classifier to an SPDX id.

    Covers the common cases. Unknown classifiers return None — the
    policy engine treats those as "license unknown" via ``on_unknown``.
    """
    return _TROVE_TO_SPDX.get(classifier.strip())


_TROVE_TO_SPDX: Dict[str, str] = {
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: BSD License": "BSD-3-Clause",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: GNU General Public License v2 (GPLv2)": "GPL-2.0",
    "License :: OSI Approved :: GNU General Public License v3 (GPLv3)": "GPL-3.0",
    "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)":
        "GPL-3.0-or-later",
    "License :: OSI Approved :: GNU Affero General Public License v3":
        "AGPL-3.0",
    "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)":
        "AGPL-3.0-or-later",
    "License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)":
        "LGPL-2.0",
    "License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)":
        "LGPL-2.0-or-later",
    "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)":
        "LGPL-3.0",
    "License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)":
        "LGPL-3.0-or-later",
    "License :: Public Domain": "Unlicense",
    "License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication": "CC0-1.0",
}


def _spdx_from_npm(
    meta: Optional[dict], version: Optional[str],
) -> Optional[str]:
    """Extract the SPDX license string from npm registry metadata.

    Schema: top-level ``license`` is the package-level default; per-
    version overrides live in ``versions[<v>].license``. Per-version
    wins. Format is sometimes a string (modern), sometimes an
    object ``{"type": "MIT", "url": "..."}`` (legacy), sometimes
    a list of objects (very legacy). Handle all three.
    """
    if not isinstance(meta, dict):
        return None
    if version and isinstance(meta.get("versions"), dict):
        v_meta = meta["versions"].get(version)
        if isinstance(v_meta, dict):
            spdx = _spdx_from_npm_block(v_meta.get("license"))
            if spdx:
                return spdx
            spdx = _spdx_from_npm_block(v_meta.get("licenses"))
            if spdx:
                return spdx
    spdx = _spdx_from_npm_block(meta.get("license"))
    if spdx:
        return spdx
    return _spdx_from_npm_block(meta.get("licenses"))


def _spdx_from_npm_block(block: Any) -> Optional[str]:
    if isinstance(block, str):
        return block.strip() or None
    if isinstance(block, dict):
        t = block.get("type")
        if isinstance(t, str) and t.strip():
            return t.strip()
    if isinstance(block, list):
        # Take the first ``type``-bearing entry.
        for item in block:
            if isinstance(item, dict):
                t = item.get("type")
                if isinstance(t, str) and t.strip():
                    return t.strip()
            elif isinstance(item, str) and item.strip():
                return item.strip()
    return None


__all__ = [
    "DEFAULT_POLICY",
    "LicensePolicy",
    "enrich_licenses",
    "evaluate",
    "load_policy",
]
