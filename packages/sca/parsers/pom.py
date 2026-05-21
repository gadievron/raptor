"""Maven pom.xml parser.

Walks ``<dependencies>``, ``<dependencyManagement>/<dependencies>``,
``<build>/<plugins>``, ``<build>/<pluginManagement>/<plugins>``, and
``<parent>``. Handles namespaced and namespace-less POMs (some toy/test
POMs omit the namespace).

We do **not** invoke Maven. We do simple top-level ``<properties>``
substitution because the vast majority of real POMs use it. Anything we
can't resolve drops to ``parser_confidence: medium`` and ``pin_style:
unknown`` — the user sees the ambiguity rather than a guessed version.

Inheritance from a parent POM is *not* resolved here. A managed
dependency whose version comes only from its parent will surface as
``version=None``; that's fine for SCA's matcher (no version → no match,
explicitly logged), and a follow-up task can resolve parents when we
have a Maven local cache to consult.

XML safety: defusedxml's ``ElementTree.fromstring`` rejects DTDs and
entity declarations by default, blocking billion-laughs and external-
entity attacks from a hostile target repo.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..models import Confidence, Dependency, PinStyle
from . import register

logger = logging.getLogger(__name__)

try:
    from defusedxml import ElementTree as DET  # type: ignore[import-untyped]
    from defusedxml.common import (  # type: ignore[import-untyped]
        DefusedXmlException,
    )
    _AVAILABLE = True
except ImportError:                       # pragma: no cover — env-dependent
    DET = None                            # type: ignore[assignment]
    DefusedXmlException = Exception       # type: ignore[assignment,misc]
    _AVAILABLE = False
    logger.warning(
        "sca.parsers.pom: 'defusedxml' not installed — pom.xml files will "
        "be skipped. `pip install defusedxml` to enable Maven SCA coverage."
    )

ECOSYSTEM = "Maven"

# Maven POM 4.0.0 namespace. Some POMs omit it; we strip namespaces from
# tag names so a single XPath works for both.
_POM_NS = "http://maven.apache.org/POM/4.0.0"

_PROPERTY_RE = re.compile(r"\$\{([^}]+)\}")

# Scope values defined by Maven. ``main`` is the runtime
# ship-with-the-product set; ``provided`` / ``system`` are
# "supplied by the runtime container" — CVEs there apply only
# if the runtime version matches the declared version, so
# they're surfaced under a distinct scope for severity
# triage. ``test`` deps don't ship and should be tier-downgraded
# downstream.
_SCOPE_MAP = {
    "compile": "main",
    "runtime": "main",
    "provided": "provided",
    "system": "system",
    "test": "test",
    "import": "build",
}


def parse(path: Path) -> List[Dependency]:
    """Return all dependencies declared in ``path``."""
    if not _AVAILABLE:
        logger.warning(
            "sca.parsers.pom: skipping %s — 'defusedxml' not installed", path,
        )
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning("sca.parsers.pom: read failed for %s: %s", path, e)
        return []

    try:
        root = DET.fromstring(text)
    except DET.ParseError as e:
        logger.warning("sca.parsers.pom: XML parse failed for %s: %s", path, e)
        return []
    except DefusedXmlException as e:
        # XXE / DTD / entity-expansion blocked by defusedxml. Treat as a
        # hostile manifest: emit nothing and surface a warning so the
        # operator sees the file was rejected.
        logger.warning(
            "sca.parsers.pom: defused XML protection rejected %s: %s",
            path, e,
        )
        return []

    _strip_namespaces(root)

    properties = _collect_properties(root)
    project_license = _extract_license(root)
    deps: List[Dependency] = []

    # 1) Top-level <dependencies>/<dependency>
    for dep_el in root.findall("./dependencies/dependency"):
        d = _build_dep(dep_el, path, properties, scope_default="compile",
                       is_managed=False, is_plugin=False)
        if d is not None:
            if project_license:
                d.declared_license = project_license
            deps.append(d)

    # 2) <dependencyManagement>/<dependencies>/<dependency>
    for dep_el in root.findall("./dependencyManagement/dependencies/dependency"):
        d = _build_dep(dep_el, path, properties, scope_default="import",
                       is_managed=True, is_plugin=False)
        if d is not None:
            if project_license:
                d.declared_license = project_license
            deps.append(d)

    # 3) Plugin coordinates from <build>/<plugins> and pluginManagement.
    plugin_paths = (
        "./build/plugins/plugin",
        "./build/pluginManagement/plugins/plugin",
        "./reporting/plugins/plugin",
    )
    for xpath in plugin_paths:
        for plug_el in root.findall(xpath):
            d = _build_dep(plug_el, path, properties, scope_default="build",
                           is_managed=False, is_plugin=True)
            if d is not None:
                deps.append(d)

    # 4) <parent> — parent POM coordinate; record as build-scope so it's
    #    visible to OSV but doesn't pollute application dependency lists.
    parent = root.find("./parent")
    if parent is not None:
        d = _build_dep(parent, path, properties, scope_default="build",
                       is_managed=False, is_plugin=False)
        if d is not None:
            d.scope = "build"
            deps.append(d)

    # 5) Resolve local <dependencyManagement> inheritance — top-level
    # <dependency> entries that omit <version> inherit it from the
    # matching <dependencyManagement> entry in the SAME POM.
    _resolve_local_dep_management(deps)

    # 6) Resolve INHERITED dependency-management when a resolver is
    # installed (set_inheritance_resolver). Walks the local +
    # network parent chain plus BOM imports, then fills in versions
    # for child deps still at ``version=None`` from the merged
    # managed view. Closes the Spring Boot starter-parent case and
    # the in-house multi-module-monorepo case. No-op when no
    # resolver has been installed (default, tests, --offline).
    from . import pom_inheritance as _inh
    resolver = _inh.get_inheritance_resolver()
    if resolver is not None:
        try:
            view = resolver.resolve(path, root)
        except Exception as e:                              # noqa: BLE001
            # The resolver is best-effort: any unexpected failure
            # falls through to local-only behaviour. Operators
            # see the deps they would have seen pre-resolver, not
            # a crash.
            logger.warning(
                "sca.parsers.pom: inheritance resolver failed on "
                "%s: %s", path, e,
            )
            view = None
        if view is not None:
            _apply_inherited_view(deps, properties, view)

    return deps


def _apply_inherited_view(
    deps: List[Dependency],
    properties: Dict[str, str],
    view: Any,
) -> None:
    """Fill in ``version=None`` deps from the inheritance view's
    merged managed-map. Also extends ``properties`` with inherited
    keys so later property resolution can pick them up (callers
    that re-resolve properties on already-built deps would still
    use this).

    Properties are merged into the child's dict, but child values
    win (we only ``setdefault``), so a child's own property
    override stays authoritative."""
    for k, v in view.properties.items():
        properties.setdefault(k, v)

    for dep in deps:
        if dep.version is not None:
            continue
        # Maven coord — split package back into (group, artifact).
        # Dependency.name shape is "groupId:artifactId" for the
        # Maven ecosystem.
        if ":" not in dep.name:
            continue
        group, artifact = dep.name.split(":", 1)
        inherited = view.managed.get((group, artifact))
        if not inherited:
            continue
        # Resolve any ${...} in the inherited value against the
        # combined property set. (Most inherited versions are
        # already concrete; this handles cases like
        # ``spring-boot-dependencies`` declaring
        # ``${jackson.version}``.)
        from . import pom_inheritance as _inh
        resolved = _inh._resolve_property(inherited, view)
        if not resolved:
            continue
        dep.version = resolved
        # Reflect the new version in the purl.
        dep.purl = _build_purl(group, artifact, resolved)


def _resolve_local_dep_management(deps: List[Dependency]) -> None:
    """For any compile/runtime/test-scoped dep with version=None,
    look up its (groupId:artifactId) in the import-scoped managed
    deps and copy the version across. Mutates in place.

    The managed entries themselves keep ``scope="build"`` — they
    aren't installed; they only provide version pinning."""
    managed_version: dict = {}
    for d in deps:
        if d.scope == "build" and d.version:
            # Managed entries come in as scope="build" via the
            # "import" scope_default in _SCOPE_MAP.
            managed_version[d.name] = d.version
    for d in deps:
        if d.scope in ("build",):
            continue
        if d.version:
            continue
        inherited = managed_version.get(d.name)
        if inherited:
            d.version = inherited


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _extract_license(root) -> Optional[str]:
    """Collect names from ``<licenses>/<license>/<name>``; returns SPDX-OR
    when multiple are listed."""
    names: List[str] = []
    for el in root.findall("./licenses/license"):
        n = _text(el, "name")
        if n and n.strip():
            names.append(n.strip())
    if not names:
        return None
    return " OR ".join(names) if len(names) > 1 else names[0]


def _strip_namespaces(root) -> None:
    """Drop the POM 4.0.0 namespace prefix from every element tag in-place.

    Handling both namespaced and namespace-less POMs at every XPath site
    is noisy; flattening once at the top is cheaper and easier to read.
    """
    prefix = "{" + _POM_NS + "}"
    for el in root.iter():
        if isinstance(el.tag, str) and el.tag.startswith(prefix):
            el.tag = el.tag[len(prefix):]


def _collect_properties(root) -> Dict[str, str]:
    """Read top-level ``<properties>`` for ${...} substitution.

    Maven also exposes built-ins like ``${project.version}`` —
    we resolve a small allowlist of those (project.version,
    project.groupId, project.artifactId) since they're extremely common.
    """
    props: Dict[str, str] = {}
    props_el = root.find("./properties")
    if props_el is not None:
        for child in props_el:
            if isinstance(child.tag, str) and child.text is not None:
                props[child.tag] = child.text.strip()

    # Built-in project.* coordinates.
    for key, xpath in (
        ("project.version", "./version"),
        ("project.groupId", "./groupId"),
        ("project.artifactId", "./artifactId"),
    ):
        el = root.find(xpath)
        if el is not None and el.text:
            props.setdefault(key, el.text.strip())
        # Also resolve the parent coordinate if no top-level override.
        if key not in props:
            par = root.find("./parent" + xpath[1:])
            if par is not None and par.text:
                props[key] = par.text.strip()
    return props


def _resolve(value: Optional[str], properties: Dict[str, str]) -> Tuple[Optional[str], bool]:
    """Substitute ${...} placeholders. Return (resolved, fully_resolved)."""
    if value is None:
        return None, True
    text = value.strip()
    if not text:
        return None, True
    fully = True

    def _sub(match: "re.Match[str]") -> str:
        nonlocal fully
        key = match.group(1)
        if key in properties:
            return properties[key]
        fully = False
        return match.group(0)

    out = _PROPERTY_RE.sub(_sub, text)
    return out, fully


def _build_dep(
    el,
    path: Path,
    properties: Dict[str, str],
    *,
    scope_default: str,
    is_managed: bool,
    is_plugin: bool,
) -> Optional[Dependency]:
    """Materialise one Dependency from a <dependency>/<plugin>/<parent> element."""
    group_text = _text(el, "groupId")
    artifact_text = _text(el, "artifactId")
    version_text = _text(el, "version")
    scope_text = _text(el, "scope")

    group, group_ok = _resolve(group_text, properties)
    artifact, artifact_ok = _resolve(artifact_text, properties)
    version, version_ok = _resolve(version_text, properties)

    if not artifact:
        # Without an artifactId there's nothing to record.
        return None
    # Plugins may omit groupId (defaults to org.apache.maven.plugins).
    if not group:
        if is_plugin:
            group = "org.apache.maven.plugins"
            group_ok = True
        else:
            return None

    name = f"{group}:{artifact}"
    pin_style, version_for_record = _classify_version(version)
    fully_resolved = group_ok and artifact_ok and version_ok

    raw_scope = (scope_text or scope_default).strip().lower()
    scope = _SCOPE_MAP.get(raw_scope, "main")
    if is_plugin:
        scope = "build"
    if is_managed and not is_plugin and raw_scope != "import":
        # Managed deps that aren't BOM imports are still version
        # constraints, not actual deps — record as "build" to avoid
        # double-counting alongside their consuming <dependency> entry.
        scope = "build"

    confidence = _confidence(fully_resolved, version_for_record, is_managed)
    purl = _build_purl(group, artifact, version_for_record)

    return Dependency(
        ecosystem=ECOSYSTEM,
        name=name,
        version=version_for_record,
        declared_in=path,
        scope=scope,
        is_lockfile=False,
        pin_style=pin_style,
        direct=not is_managed,
        purl=purl,
        parser_confidence=confidence,
    )


def _text(el, tag: str) -> Optional[str]:
    child = el.find(tag)
    if child is None:
        return None
    return child.text


def _classify_version(version: Optional[str]) -> Tuple[PinStyle, Optional[str]]:
    """Map a Maven version expression to a PinStyle plus a usable string."""
    if version is None or version == "":
        return PinStyle.UNKNOWN, None
    v = version.strip()
    if "${" in v:
        # Unresolved placeholder.
        return PinStyle.UNKNOWN, v
    if v in ("LATEST", "RELEASE", "*"):
        return PinStyle.WILDCARD, v
    if v.startswith("[") and v.endswith("]") and "," not in v:
        # Hard requirement: "[1.2.3]"
        return PinStyle.EXACT, v[1:-1]
    if any(ch in v for ch in "[](),"):
        return PinStyle.RANGE, v
    return PinStyle.EXACT, v


def _confidence(
    fully_resolved: bool,
    version: Optional[str],
    is_managed: bool,
) -> Confidence:
    if not fully_resolved:
        return Confidence("medium",
                          reason="POM property substitution incomplete")
    if version is None:
        # Either a managed entry whose version comes from a parent we
        # don't read, or an inherited version. Either way the matcher
        # can't act without one — flag it.
        return Confidence(
            "medium",
            reason="POM dependency has no resolvable version",
        )
    if is_managed:
        return Confidence("high", reason="POM dependencyManagement entry")
    return Confidence("high", reason="POM dependency block")


def _build_purl(group: str, artifact: str, version: Optional[str]) -> str:
    """Build a Maven purl. Encoding follows the purl spec for Maven."""
    base = f"pkg:maven/{group}/{artifact}"
    if version:
        return f"{base}@{version}"
    return base


register(filenames=["pom.xml"])(parse)
