"""Helm Chart parsers — ``Chart.yaml`` and ``Chart.lock``.

Helm declares chart dependencies in ``Chart.yaml``:

    apiVersion: v2
    name: myapp
    version: 1.2.3
    dependencies:
      - name: postgresql
        version: 13.4.2
        repository: https://charts.bitnami.com/bitnami
      - name: redis
        version: ~18.0
        repository: oci://registry-1.docker.io/bitnamicharts

``Chart.lock`` (Helm v3+ when ``helm dependency update`` ran)
records resolved versions in the same shape with a SHA256 digest.

OSV doesn't have a ``Helm`` ecosystem today, so CVE matching
against these deps doesn't fire. The value here is SBOM
visibility: operators reviewing their deployment posture see what
charts they ship, with versions and repository origins. A future
iteration can plug into Helm's own security-scanning sources or a
chart-tracker like Artifact Hub.

What we don't cover:

  * ``values.yaml`` ``image.tag`` references — operator-
    configurable knobs, not pinned deps. The chart's own
    Chart.yaml is what matters.
  * Subchart trees beyond top-level ``dependencies`` —
    transitive resolution requires fetching each chart, which
    needs a real Helm-aware fetcher.
  * Inline charts (``library`` or ``application`` types) — the
    parser ignores the chart-self ``apiVersion`` / ``type`` /
    ``version`` fields and only records the ``dependencies:``
    array.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, List, Optional

from ..models import Confidence, Dependency, PinStyle
from . import register

logger = logging.getLogger(__name__)


ECOSYSTEM = "Helm"
_PURL_TYPE = "helm"


@register(filenames=["Chart.yaml", "Chart.lock"])
def parse(path: Path) -> List[Dependency]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning(
            "sca.parsers.helm_chart: read failed for %s: %s", path, e,
        )
        return []
    try:
        import yaml                 # type: ignore[import-untyped]
        from .._yaml_fast import safe_load
    except ImportError:
        logger.debug(
            "sca.parsers.helm_chart: PyYAML not installed; skipping %s",
            path,
        )
        return []
    try:
        data = safe_load(text)
    except yaml.YAMLError as e:
        logger.warning(
            "sca.parsers.helm_chart: YAML parse failed for %s: %s",
            path, e,
        )
        return []
    if not isinstance(data, dict):
        return []

    deps_raw = data.get("dependencies") or []
    if not isinstance(deps_raw, list):
        return []

    is_lockfile = path.name == "Chart.lock"

    out: List[Dependency] = []
    for entry in deps_raw:
        dep = _build_dep(entry, declared_in=path, is_lockfile=is_lockfile)
        if dep is not None:
            out.append(dep)
    return out


def _build_dep(
    entry: Any, *, declared_in: Path, is_lockfile: bool,
) -> Optional[Dependency]:
    if not isinstance(entry, dict):
        return None
    name = entry.get("name")
    version = entry.get("version")
    repository = entry.get("repository") or ""
    if not isinstance(name, str) or not name.strip():
        return None
    if not isinstance(version, str) or not version.strip():
        return None
    name = name.strip()
    version = version.strip()
    pin_style = _classify_version(version)
    purl = f"pkg:{_PURL_TYPE}/{name}@{version}"
    return Dependency(
        ecosystem=ECOSYSTEM,
        name=name,
        version=version,
        declared_in=declared_in,
        scope="main",
        is_lockfile=is_lockfile,
        pin_style=pin_style,
        direct=not is_lockfile,
        purl=purl,
        parser_confidence=Confidence(
            "high" if is_lockfile else "medium",
            reason=(
                "Chart.lock pinned dependency" if is_lockfile
                else f"Chart.yaml dependency entry "
                     f"(repository: {repository or 'unspecified'})"
            ),
        ),
        source_kind="helm_chart",
        source_extra={"repository": repository} if repository else None,
    )


def _classify_version(version: str) -> PinStyle:
    """Helm uses semver constraints similar to npm:
    ``13.4.2`` (exact), ``^13.4`` (caret), ``~13.4`` (tilde),
    ``>=13.0 <14.0`` (range), ``*`` (wildcard)."""
    if version in ("*", "x", "X", "latest"):
        return PinStyle.WILDCARD
    if version.startswith("^"):
        return PinStyle.CARET
    if version.startswith("~"):
        return PinStyle.TILDE
    if any(ch in version for ch in "<>=") or " - " in version:
        return PinStyle.RANGE
    if version[:1].isdigit():
        return PinStyle.EXACT
    return PinStyle.UNKNOWN


def chart_repository_hosts(target: Path) -> List[str]:
    """Return the union of Helm-repo hostnames referenced by every
    ``Chart.yaml`` under ``target``.

    Companion to :func:`packages.sca.dockerfile_from.
    image_source_registry_hosts` for the sandbox proxy allowlist —
    without this, ``raptor-sca bump`` walks ``Chart.yaml``
    dependencies but the underlying Helm-index fetch
    (``<repository>/index.yaml``) fails at the egress proxy with
    "host not on allowlist" for any repo that isn't in the static
    :data:`packages.sca.SCA_ALLOWED_HOSTS` set. The static set
    intentionally covers only OSV / KEV / EPSS / package-registry
    metadata hosts; Helm repos are project-specific and have to be
    derived from the target tree.

    Parsing is best-effort: a malformed ``Chart.yaml`` logs a
    debug line and is skipped, never aborts the walk. Empty list
    is a valid result (no charts in the target, no
    ``repository:`` fields, all repositories are ``oci://`` style
    — those route through the OCI client's existing allowlist).

    Output is deduplicated and sorted for deterministic
    allowlist composition.
    """
    from urllib.parse import urlparse

    found: set = set()
    for path in target.rglob("Chart.yaml"):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            logger.debug(
                "sca.parsers.helm_chart: read failed for %s during "
                "host extraction: %s", path, e,
            )
            continue
        try:
            import yaml             # type: ignore[import-untyped]
            from .._yaml_fast import safe_load
        except ImportError:
            return []
        try:
            data = safe_load(text)
        except yaml.YAMLError as e:
            logger.debug(
                "sca.parsers.helm_chart: YAML parse failed for %s "
                "during host extraction: %s", path, e,
            )
            continue
        if not isinstance(data, dict):
            continue
        deps_raw = data.get("dependencies") or []
        if not isinstance(deps_raw, list):
            continue
        for entry in deps_raw:
            if not isinstance(entry, dict):
                continue
            repo = entry.get("repository")
            if not isinstance(repo, str) or not repo.strip():
                continue
            repo = repo.strip()
            # ``oci://`` repositories route through the OCI
            # client's host allowlist (already covered by
            # ``image_source_registry_hosts``-style logic in
            # ``compose_proxy_hosts``); HTTP/HTTPS need their
            # hostname added here for the index.yaml fetch.
            if repo.startswith("oci://"):
                continue
            try:
                host = urlparse(repo).hostname
            except ValueError:
                continue
            if host:
                found.add(host)
    return sorted(found)
