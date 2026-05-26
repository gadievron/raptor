"""Mechanical hygiene findings — security-relevant integrity checks.

Five kinds, all derived from manifests + lockfiles already parsed:

| Kind                            | Trigger                                                |
|---------------------------------|--------------------------------------------------------|
| ``lockfile_missing``            | An ecosystem with manifests has no lockfile alongside  |
| ``lockfile_drift``              | Manifest pins ``==1.2.3`` but lockfile resolves 1.2.4  |
| ``unpinned_dependency``         | Manifest entry has no version or wildcard              |
| ``loose_pin``                   | Manifest entry uses caret/tilde/range pinning          |
| ``cross_manifest_inconsistency``| Same dep declared at two different versions across     |
|                                 | manifests in *different* workspaces                    |

Why these are *security* findings, not just dev nags:
- Without a lockfile, a vulnerable upgrade (or a malicious one — the
  recent ``ua-parser-js`` / ``coa`` style attacks) silently flows to
  every install. The user thinks their pinned manifest is safe; pip /
  npm / yarn re-resolve every time.
- Lockfile drift means the lockfile no longer reflects what the manifest
  says — CI builds will work, but new dev machines pull a different
  closure. CVE matching against either side is unreliable.
- Loose pinning hides the same problem behind a different door.

Pure-quality issues (duplicate_versions, dead_dependency, path/git deps
without security implications) live in SBOM metadata, not findings —
operators can review the full set in the report appendix without
triaging false-positive findings.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .models import (
    Confidence,
    Dependency,
    HygieneFinding,
    Manifest,
    PinStyle,
)
from .versions import VersionError, compare as version_compare

logger = logging.getLogger(__name__)

# Per-ecosystem expectation: at least one of these lockfiles should sit
# alongside a manifest. Empty tuple = no expectation (Maven / Cargo /
# Go projects without dependency-locking are normal).
_EXPECTED_LOCKFILES: Dict[str, Tuple[str, ...]] = {
    "npm": ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "shrinkwrap.json"),
    "PyPI": ("Pipfile.lock", "poetry.lock"),
    "Cargo": ("Cargo.lock",),
    "Go": ("go.sum",),
    "RubyGems": ("Gemfile.lock",),
    "NuGet": ("packages.lock.json",),
    "Packagist": ("composer.lock",),
    # Maven (via gradle.lockfile or no lockfile at all): no expectation.
}

# Pin styles considered "loose" — the dep can update silently.
_LOOSE_PINS: Set[PinStyle] = {PinStyle.CARET, PinStyle.TILDE, PinStyle.RANGE}

# Pin styles that count as "unpinned" — version isn't constrained at all.
_UNPINNED: Set[PinStyle] = {PinStyle.WILDCARD, PinStyle.UNKNOWN}


def evaluate(
    manifests: Iterable[Manifest],
    deps: Iterable[Dependency],
) -> List[HygieneFinding]:
    """Run every hygiene check; return one finding list."""
    manifests_list = list(manifests)
    deps_list = list(deps)
    out: List[HygieneFinding] = []
    out.extend(check_lockfile_missing(manifests_list, deps_list))
    out.extend(check_lockfile_drift(deps_list))
    out.extend(check_unpinned(deps_list))
    out.extend(check_loose_pin(deps_list))
    out.extend(check_cross_manifest_inconsistency(deps_list))
    return out


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def check_lockfile_missing(
    manifests: List[Manifest],
    deps: List[Dependency],
) -> List[HygieneFinding]:
    """Surface any manifest whose ecosystem expects a sibling lockfile."""
    out: List[HygieneFinding] = []
    # Index lockfile presence per (ecosystem, parent dir).
    lockfile_dirs: Set[Tuple[str, Path]] = set()
    for m in manifests:
        if m.is_lockfile:
            lockfile_dirs.add((m.ecosystem, m.path.parent))

    for m in manifests:
        if m.is_lockfile:
            continue
        expected = _EXPECTED_LOCKFILES.get(m.ecosystem, ())
        if not expected:
            continue
        if (m.ecosystem, m.path.parent) in lockfile_dirs:
            continue
        # Use the first manifest dep for the finding's dep slot, to keep
        # the finding shape uniform. If no deps were parsed, synthesise
        # a placeholder bound to the manifest itself.
        host = _first_dep_for(deps, m) or _placeholder_dep(m)
        out.append(_finding(
            kind="lockfile_missing",
            dep=host,
            detail=(
                f"{m.ecosystem} manifest at {m.path} has no sibling lockfile; "
                f"expected one of: {', '.join(expected)}"
            ),
            severity="medium",
            confidence=Confidence(
                "high",
                reason="manifest exists but lockfile siblings absent",
            ),
        ))
    return out


def check_lockfile_drift(
    deps: List[Dependency],
) -> List[HygieneFinding]:
    """Manifest pins ``==X`` but lockfile resolves ``Y`` where Y != X."""
    out: List[HygieneFinding] = []
    by_key: Dict[Tuple[str, Path, str], Dict[str, Dependency]] = defaultdict(dict)
    for d in deps:
        # Group by (ecosystem, parent dir of declared file, name) so we
        # only compare manifests + lockfiles in the same workspace.
        ws_key = (d.ecosystem, d.declared_in.parent, d.name)
        bucket = "lockfile" if d.is_lockfile else "manifest"
        by_key[ws_key].setdefault(bucket, d)

    for (eco, _ws, _name), bucket in by_key.items():
        manifest = bucket.get("manifest")
        lockfile = bucket.get("lockfile")
        if manifest is None or lockfile is None:
            continue
        if manifest.pin_style is not PinStyle.EXACT:
            continue
        if not manifest.version or not lockfile.version:
            continue
        if _versions_equal(eco, manifest.version, lockfile.version):
            continue
        out.append(_finding(
            kind="lockfile_drift",
            dep=manifest,
            detail=(
                f"manifest pins {manifest.version} but lockfile resolves "
                f"{lockfile.version}"
            ),
            severity="high",
            confidence=Confidence(
                "high",
                reason="manifest exact version differs from lockfile resolution",
            ),
        ))
    return out


def check_unpinned(deps: List[Dependency]) -> List[HygieneFinding]:
    """Manifest entries with no version constraint.

    Maven ``version is None`` is exempt: the standard Maven idiom
    is to let a parent POM's ``<dependencyManagement>`` block do
    the pinning, so child poms intentionally omit ``<version>``.
    Spring Boot / Quarkus / micronaut-parent / etc. all rely on
    this. Pre-fix this detector flagged 1468 such entries at
    medium severity on a Spring Boot 1.5 project — a 100%-false-
    positive cascade that drowned the actual findings.

    A genuinely-unpinned Maven entry (no version, no parent
    dependencyManagement) is also exempt here because Maven would
    fail the build before SCA ever ran — we're not the right
    layer to catch a malformed pom.xml.
    """
    out: List[HygieneFinding] = []
    for d in deps:
        if d.is_lockfile:
            continue
        # Maven exception: see docstring.
        if d.ecosystem == "Maven" and d.version is None:
            continue
        if d.pin_style in _UNPINNED or d.version is None:
            out.append(_finding(
                kind="unpinned_dependency",
                dep=d,
                detail=(
                    f"{d.name} declared without a version pin "
                    f"(pin_style={d.pin_style.value})"
                ),
                severity="medium",
                confidence=Confidence(
                    "high",
                    reason="parser observed wildcard / no version",
                ),
            ))
    return out


def check_loose_pin(deps: List[Dependency]) -> List[HygieneFinding]:
    """Manifest entries with caret / tilde / range pinning."""
    out: List[HygieneFinding] = []
    for d in deps:
        if d.is_lockfile:
            continue
        if d.pin_style in _LOOSE_PINS:
            out.append(_finding(
                kind="loose_pin",
                dep=d,
                detail=(
                    f"{d.name} uses loose pinning ({d.pin_style.value} "
                    f"{d.version or '*'}); range may admit new vulns silently"
                ),
                severity="low",
                confidence=Confidence(
                    "high",
                    reason="parser observed caret/tilde/range pinning",
                ),
            ))
    return out


def check_cross_manifest_inconsistency(
    deps: List[Dependency],
) -> List[HygieneFinding]:
    """Same dep declared at different versions in different workspaces.

    A workspace, for this check, is the parent directory of the manifest.
    Same-workspace duplicates are not flagged — that's the join layer's
    territory.
    """
    out: List[HygieneFinding] = []
    # Bucket by (ecosystem, name, manifest_role, scope). Two deps in
    # different roles or different scopes are EXPECTED to disagree:
    # an `optional` extras manifest can pin a different version than
    # the `main` one; `dev` deps need not match runtime deps. Without
    # this partitioning, comparing requirements.txt against
    # requirements-all-optional.txt floods the report with false
    # positives that aren't actually inconsistencies — those manifests
    # serve different purposes.
    by_key: Dict[Tuple[str, str, str, str], List[Dependency]] = defaultdict(list)
    for d in deps:
        if d.is_lockfile:
            continue
        if d.version is None:
            continue
        role = _manifest_role(d.declared_in)
        scope = d.scope or "main"
        by_key[(d.ecosystem, d.name, role, scope)].append(d)

    for (eco, name, role, scope), rows in by_key.items():
        unique_versions = {r.version for r in rows if r.version}
        if len(unique_versions) <= 1:
            continue
        # Cluster by workspace; only flag when *different workspaces*
        # disagree (same workspace declaring two different versions is
        # unusual but not a workspace-crossing problem).
        workspaces = {r.declared_in.parent for r in rows}
        if len(workspaces) <= 1:
            continue
        host = rows[0]
        # Mention role in detail when not "main" so operators can see
        # at a glance why this group is being compared.
        role_suffix = f" [{role} role]" if role != "main" else ""
        out.append(_finding(
            kind="cross_manifest_inconsistency",
            dep=host,
            detail=(
                f"{eco}:{name} declared at versions {sorted(unique_versions)} "
                f"across {len(workspaces)} workspaces{role_suffix}"
            ),
            severity="medium",
            confidence=Confidence(
                "medium",
                reason="multi-workspace divergence",
            ),
        ))
    return out


def _manifest_role(path: Path) -> str:
    """Classify a manifest by filename so cross-manifest comparison
    only fires within the same role.

    Returns one of: ``main``, ``dev``, ``test``, ``optional``.

    Heuristics — filename-based, deliberate over-inclusion of "main":
      * filename containing ``dev`` → ``dev`` (e.g. ``requirements-dev.txt``,
        ``dev-requirements.txt``)
      * filename containing ``test`` → ``test``
      * ``requirements-*.txt`` (any other suffix) and filenames
        containing ``optional`` / ``extras`` / ``all`` →
        ``optional``
      * everything else → ``main``

    Pyproject.toml-sourced deps don't dispatch through this — their
    ``scope`` field is already populated by the parser (``main`` for
    ``[project.dependencies]``, ``optional`` for
    ``[project.optional-dependencies.*]``, ``dev`` for
    ``[tool.poetry.group.dev.dependencies]``). Both are partitioned
    so cross-role + cross-scope divergence is allowed."""
    name = path.name.lower()
    if "dev" in name:
        return "dev"
    if "test" in name:
        return "test"
    if any(tok in name for tok in ("optional", "extras", "all-")):
        return "optional"
    if name.startswith("requirements-") and name.endswith(".txt"):
        return "optional"
    return "main"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _versions_equal(ecosystem: str, a: str, b: str) -> bool:
    if a == b:
        return True
    try:
        return version_compare(ecosystem, a, b) == 0
    except VersionError:
        # Unknown ecosystem comparator; fall back to literal compare.
        return a == b


def _first_dep_for(
    deps: List[Dependency], manifest: Manifest,
) -> Optional[Dependency]:
    for d in deps:
        if d.declared_in == manifest.path:
            return d
    return None


def _placeholder_dep(manifest: Manifest) -> Dependency:
    """Synthesise a Dependency to host a hygiene finding when a manifest
    has no parsed deps (empty package.json, etc.). The placeholder is
    *internal* — it's only used to attach a finding's ``dependency``
    slot and never makes it into SBOM or OSV calls.
    """
    return Dependency(
        ecosystem=manifest.ecosystem,
        name="<manifest>",
        version=None,
        declared_in=manifest.path,
        scope="main",
        is_lockfile=manifest.is_lockfile,
        pin_style=PinStyle.UNKNOWN,
        direct=True,
        purl="",
        parser_confidence=Confidence(
            "low", reason="placeholder for hygiene finding host",
        ),
    )


def _finding(
    *,
    kind,
    dep: Dependency,
    detail: str,
    severity,
    confidence: Confidence,
) -> HygieneFinding:
    return HygieneFinding(
        finding_id=f"sca:hygiene:{kind}:{dep.ecosystem}:{dep.name}:"
                    f"{dep.declared_in}",
        kind=kind,
        dependency=dep,
        detail=detail,
        severity=severity,
        confidence=confidence,
    )


__all__ = ["evaluate"]
