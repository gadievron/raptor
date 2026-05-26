"""Maven POM inheritance resolver.

Closes the Spring Boot / parent-POM gap in :mod:`packages.sca.parsers.pom`.

The base ``pom.parse`` reads a single POM and resolves local
``<dependencyManagement>`` inheritance — versions filled in from
managed entries in the SAME POM. That covers a small slice of real
Java projects. The dominant pattern in enterprise Java is:

  * **Spring Boot** — every project inherits from
    ``spring-boot-starter-parent``, which inherits from
    ``spring-boot-dependencies``, which BOM-imports a dozen more
    parents. Child deps like ``spring-boot-starter-web`` have NO
    explicit version; the version lives in a great-grandparent's
    ``dependencyManagement``.
  * **In-house multi-module monorepos** — child modules
    (``service-a/pom.xml``, ``service-b/pom.xml``) inherit from a
    sibling parent (``../pom.xml``) that declares property bundles
    and managed versions for the whole repo.

Without resolving these inheritance chains, every transitive whose
version comes from the parent surfaces as ``version=None`` and OSV
matching silently misses every CVE that hits it. For Spring Boot
specifically, that's the dominant Java security gap raptor-sca
could close.

## Three phases the resolver handles

  1. **Local parent** — ``<parent><relativePath>../pom.xml</relativePath>``
     (relativePath defaults to ``../pom.xml`` when absent). Read the
     file from disk, merge its properties + depMgmt into the child's
     view. Walks up recursively for grandparents.

  2. **Network parent** — when the parent isn't local OR the local
     parent's coordinate doesn't match the declared ``<parent>``,
     fetch the POM from Maven Central via the existing
     :class:`packages.sca.registries.maven.MavenRegistry.get_pom`.
     Recursive on grandparents. Cycle + depth guarded.

  3. **BOM imports** — entries in ``<dependencyManagement>`` with
     ``<scope>import</scope>`` are imported BOMs (typically
     ``spring-boot-dependencies``). Fetch the BOM (same machinery
     as Phase 2), merge its depMgmt into our consolidated view.
     Spring Boot's transitive CVE coverage depends on this.

## Why a separate module

Keeping :mod:`pom` pure-local (no network, no cache) means the
default ``parse(path)`` stays a fast, deterministic operation. The
inheritance resolver is opt-in: the pipeline injects a configured
instance via :func:`set_inheritance_resolver`; if no resolver is
set (``--offline``, tests, libraries that just want manifest
shape), behaviour is unchanged from the pre-resolver baseline.

## Safety

  * **Depth cap** (``_MAX_DEPTH=10``) — Maven's own resolver
    accepts deeper chains, but 10 covers Spring Boot
    (App → starter-parent → spring-boot-dependencies → ~4-5
    BOM hops) with room to spare. Beyond that is almost
    certainly a cycle or attack.
  * **Cycle detection** — visited-set on ``(groupId, artifactId,
    version)`` tuples; pathological POMs that declare themselves
    as their own grandparent terminate cleanly.
  * **defusedxml** — same XML parser the local POM walk uses;
    billion-laughs and external-entity attacks are blocked.
  * **404 / parse failure tolerance** — a missing or malformed
    upstream POM logs and falls through to "couldn't resolve",
    leaving the child's deps at version=None. No exception
    escapes.
  * **Offline mode** — if the resolver was constructed with
    ``offline=True`` OR the maven_client is None, network calls
    are skipped. Only local-parent resolution runs.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, Optional, Set, Tuple

logger = logging.getLogger(__name__)

try:
    import defusedxml.ElementTree as DET
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False


# Bounded recursion. Real Maven hierarchies rarely exceed 6;
# Spring Boot's deepest parent + BOM chain is ~5. 10 leaves
# headroom while terminating pathological chains.
_MAX_DEPTH = 10


# Maven coordinate field character set. Per the Maven specification,
# groupId / artifactId / version are restricted to alphanumeric,
# dot, dash, underscore. Real coords also use ``+`` (build metadata
# in semver-style versions). We reject anything outside this set
# before forwarding to ``MavenRegistry.get_pom`` — a hostile POM
# that declares ``<groupId>../../../evil</groupId>`` would otherwise
# inject path-traversal segments into the registry URL.
_MAVEN_COORD_RE = re.compile(r"^[A-Za-z0-9._+\-]+$")


def _valid_coord(group: Optional[str], artifact: Optional[str],
                 version: Optional[str]) -> bool:
    """True iff all three coord components are well-formed Maven
    identifiers. Anything outside ``[A-Za-z0-9._+-]`` is rejected
    so we never construct a URL from attacker-controlled
    path-traversal characters."""
    for part in (group, artifact, version):
        if not part or not _MAVEN_COORD_RE.match(part):
            return False
    return True


# The merged inheritance view assembled for a single POM.
# ``properties`` — fully resolved ``${...}`` substitutions ready
# for the caller's _resolve() pass.
# ``managed`` — ``(groupId, artifactId) → version`` from the
# combined parent chain + BOM imports. The child's own
# depMgmt is NOT in this map (the caller already has it); only
# inherited values.
class InheritanceView:
    __slots__ = ("properties", "managed")

    def __init__(self) -> None:
        self.properties: Dict[str, str] = {}
        self.managed: Dict[Tuple[str, str], str] = {}


# Module-level resolver — injected by the scan pipeline. ``None`` =
# inheritance resolution disabled (default, no behaviour change).
_RESOLVER: Optional["PomInheritanceResolver"] = None


def set_inheritance_resolver(
    resolver: Optional["PomInheritanceResolver"],
) -> None:
    """Install the resolver used by :func:`packages.sca.parsers.pom.parse`.

    Called by the scan pipeline (typically once per scan) with a
    configured resolver wrapping the scan's MavenRegistry instance.
    Passing ``None`` clears the resolver, restoring local-only
    behaviour — useful for tests and ``--offline`` mode.
    """
    global _RESOLVER
    _RESOLVER = resolver


def get_inheritance_resolver() -> Optional["PomInheritanceResolver"]:
    """Public accessor — used by :mod:`pom` to consult the resolver."""
    return _RESOLVER


class PomInheritanceResolver:
    """Walks a POM's parent chain + BOM imports, returning the
    merged ``(properties, managed)`` view that a child POM would see.

    Cache is per-resolver-instance, keyed on ``(group, artifact,
    version)``. Lifetime ties to one scan — long-running services
    that keep the resolver around accumulate cache hits across scans
    of the same project.

    Thread-safety: not safe to share across threads. SCA scans are
    single-threaded by design; if that ever changes, the cache + the
    in-flight ``visiting`` set need locking.
    """

    def __init__(
        self,
        maven_client: Any = None,
        *,
        offline: bool = False,
        max_depth: int = _MAX_DEPTH,
        scan_root: Optional[Path] = None,
    ) -> None:
        """``maven_client`` is a :class:`MavenRegistry`-shaped object
        with a ``get_pom(coord, version) -> Optional[dict]`` method.
        ``None`` (or ``offline=True``) disables network fetches —
        only local-parent resolution runs.

        ``scan_root``: when set, local-parent file reads are confined
        to this directory (after symlink resolution). A
        ``<relativePath>`` that escapes ``scan_root`` is refused —
        same defence Maven's own resolver employs against
        ``<relativePath>/etc/passwd``-style hostile references.
        When ``None``, no containment check runs — appropriate for
        tests but production pipelines must pass the scan target.
        """
        self._client = maven_client
        self._offline = offline or maven_client is None
        self._max_depth = max_depth
        # Resolve symlinks now so subsequent containment checks
        # compare like-for-like. ``None`` means "no containment
        # check" — the pipeline always passes a real root.
        self._scan_root = (
            scan_root.resolve() if scan_root is not None else None
        )
        # ``(group, artifact, version) → InheritanceView``. Caches the
        # MERGED view for a coordinate, so reuse across many child
        # POMs that share a parent is O(1).
        self._cache: Dict[Tuple[str, str, str], InheritanceView] = {}

    def resolve(
        self,
        pom_path: Path,
        root_element: Any,
    ) -> InheritanceView:
        """Return the merged ``(properties, managed)`` view for the
        POM at ``pom_path`` whose parsed XML root is ``root_element``.

        The view includes:
          * Properties from every ancestor (overridden by descendants)
          * Managed-dependency entries from every ancestor's
            ``dependencyManagement`` (overridden by descendants)
          * BOM-imported managed entries from any ancestor that
            ``<scope>import</scope>``s a BOM

        The CHILD's own properties and managed entries are NOT
        included — the caller already has them and applies its own
        precedence (child wins over inherited).
        """
        if not _AVAILABLE:
            return InheritanceView()
        view = InheritanceView()
        visited: Set[Tuple[str, str, str]] = set()
        self._walk_parents(
            pom_path, root_element, view, visited, depth=0,
        )
        return view

    # ------------------------------------------------------------------
    # Phase 1 + 2: parent chain walking
    # ------------------------------------------------------------------

    def _walk_parents(
        self,
        pom_path: Optional[Path],
        root: Any,
        view: InheritanceView,
        visited: Set[Tuple[str, str, str]],
        *,
        depth: int,
    ) -> None:
        """Walk up the ``<parent>`` chain, merging properties +
        depMgmt at each level. Mutates ``view`` in place.

        ``pom_path`` may be ``None`` when walking through a parent
        that was fetched from the network (the network path doesn't
        have a local file location). Only matters for resolving
        ``relativePath`` — without a path, we go straight to network.
        """
        if depth >= self._max_depth:
            logger.debug(
                "sca.pom_inheritance: max depth %d hit for parent "
                "chain — aborting walk", self._max_depth,
            )
            return

        parent_el = root.find("./parent")
        if parent_el is None:
            return

        group = _text(parent_el, "groupId")
        artifact = _text(parent_el, "artifactId")
        version = _text(parent_el, "version")
        if not (group and artifact and version):
            return
        # SECURITY: reject malformed coord characters before they
        # land in cache/visited keys. A crafted coord with
        # path-traversal chars wouldn't cause direct harm here
        # (it's just a dict key) but it MAY hit the network paths
        # later via cache miss; reject upfront for consistency.
        if not _valid_coord(group, artifact, version):
            logger.debug(
                "sca.pom_inheritance: refusing malformed parent "
                "coord on walk: (%r, %r, %r)", group, artifact, version,
            )
            return

        coord_key = (group, artifact, version)
        if coord_key in visited:
            logger.debug(
                "sca.pom_inheritance: cycle detected on %s:%s:%s — "
                "stopping walk", group, artifact, version,
            )
            return
        visited.add(coord_key)

        # Cache hit: merge the cached view + carry on.
        if coord_key in self._cache:
            cached = self._cache[coord_key]
            _merge_into(view, cached)
            # Process BOM imports declared in the child's own depMgmt
            # too (handled by the caller via _absorb_boms).
            return

        # Resolve the parent POM. Try local relativePath first
        # (Phase 1), fall back to network (Phase 2).
        parent_root = self._load_parent_xml(parent_el, pom_path)
        if parent_root is None:
            return

        # Build the parent's own view: its inherited stuff (recurse
        # into grandparent) PLUS its own properties + depMgmt.
        parent_view = InheritanceView()
        self._walk_parents(
            self._parent_path(parent_el, pom_path),
            parent_root, parent_view, visited, depth=depth + 1,
        )
        _absorb_self(parent_root, parent_view)
        self._absorb_boms(parent_root, parent_view, visited, depth + 1)

        # Stash for reuse; merge into the caller's view.
        self._cache[coord_key] = parent_view
        _merge_into(view, parent_view)

    def _load_parent_xml(
        self, parent_el: Any, child_path: Optional[Path],
    ) -> Optional[Any]:
        """Try Phase 1 (local), fall back to Phase 2 (network).
        Returns the parsed XML root, or ``None`` if neither works."""
        local = self._read_local_parent(parent_el, child_path)
        if local is not None:
            return local
        return self._read_network_parent(parent_el)

    def _read_local_parent(
        self, parent_el: Any, child_path: Optional[Path],
    ) -> Optional[Any]:
        """Phase 1: resolve ``<parent><relativePath>`` against the
        child's filesystem location. Default is ``../pom.xml``; an
        explicit ``<relativePath>`` overrides. Returns ``None`` when
        the file doesn't exist or the coord doesn't match."""
        if child_path is None:
            return None
        rel = _text(parent_el, "relativePath")
        if rel is None:
            rel = "../pom.xml"
        # relativePath of an empty string is the Maven convention for
        # "no local parent, only network" — respect it.
        if rel == "":
            return None
        # SECURITY: reject absolute paths in relativePath. Maven
        # convention is strictly relative; an absolute path here is
        # either a misconfigured POM or a hostile reference trying
        # to read an arbitrary file via the inheritance walk.
        if Path(rel).is_absolute():
            logger.debug(
                "sca.pom_inheritance: refusing absolute relativePath "
                "%r on %s", rel, child_path,
            )
            return None
        candidate = (child_path.parent / rel).resolve()
        # SECURITY: confine to scan_root. ``Path.resolve()`` follows
        # symlinks, so this also catches the "symlink in default
        # ../pom.xml points outside the project" case — the
        # resolved real path won't be under scan_root.
        if self._scan_root is not None:
            try:
                candidate.relative_to(self._scan_root)
            except ValueError:
                logger.debug(
                    "sca.pom_inheritance: refusing relativePath %r "
                    "→ %s; escapes scan_root %s",
                    rel, candidate, self._scan_root,
                )
                return None
        # If the path is a directory, append pom.xml (Maven also
        # accepts that shape).
        if candidate.is_dir():
            candidate = candidate / "pom.xml"
        if not candidate.is_file():
            return None
        try:
            text = candidate.read_text(encoding="utf-8", errors="replace")
            root = DET.fromstring(text)
        except (OSError, DET.ParseError) as e:
            logger.debug(
                "sca.pom_inheritance: local parent %s parse failed: %s",
                candidate, e,
            )
            return None
        except Exception as e:                                  # noqa: BLE001
            # defusedxml raises subclasses of Exception for
            # billion-laughs / XXE. Swallow + log.
            logger.debug(
                "sca.pom_inheritance: local parent %s rejected: %s",
                candidate, e,
            )
            return None
        _strip_namespaces(root)
        # Verify the coordinates match — a relative-path parent that
        # doesn't actually have the declared (group, artifact,
        # version) is a misconfigured POM. We could fall through to
        # network, but Maven itself errors here; we follow suit and
        # treat the local read as authoritative.
        if not _coord_matches(parent_el, root):
            logger.debug(
                "sca.pom_inheritance: local parent at %s coord mismatch; "
                "falling through to network",
                candidate,
            )
            return None
        return root

    def _read_network_parent(self, parent_el: Any) -> Optional[Any]:
        """Phase 2: fetch the parent POM from Maven Central via the
        configured client. Returns the parsed XML root or ``None``
        when network is disabled / fetch failed."""
        if self._offline or self._client is None:
            return None
        group = _text(parent_el, "groupId")
        artifact = _text(parent_el, "artifactId")
        version = _text(parent_el, "version")
        # SECURITY: validate the coordinate fields before forwarding
        # to the registry. A hostile POM declaring
        # ``<groupId>../../../evil</groupId>`` would otherwise inject
        # path-traversal segments into the Maven Central URL.
        if not _valid_coord(group, artifact, version):
            logger.debug(
                "sca.pom_inheritance: refusing malformed parent "
                "coord (%r, %r, %r)", group, artifact, version,
            )
            return None
        coord = f"{group}:{artifact}"
        try:
            pom_dict = self._client.get_pom(coord, version)
        except Exception as e:                                  # noqa: BLE001
            logger.debug(
                "sca.pom_inheritance: network parent fetch failed "
                "for %s@%s: %s", coord, version, e,
            )
            return None
        if pom_dict is None:
            return None
        # The MavenRegistry currently returns a parsed-dict shape
        # (``{dependencies: [...]}``) rather than the raw XML. For
        # full inheritance we need the XML to read <parent>,
        # <properties>, <dependencyManagement>, <scope>. Pull the
        # raw_xml field if the client populates it; otherwise treat
        # as unresolved.
        raw_xml = pom_dict.get("raw_xml")
        if not raw_xml:
            logger.debug(
                "sca.pom_inheritance: network parent for %s@%s "
                "lacks raw_xml; treating as unresolved",
                coord, version,
            )
            return None
        try:
            root = DET.fromstring(raw_xml)
        except (DET.ParseError, Exception) as e:                # noqa: BLE001
            logger.debug(
                "sca.pom_inheritance: network parent XML parse "
                "failed for %s@%s: %s", coord, version, e,
            )
            return None
        _strip_namespaces(root)
        return root

    def _parent_path(
        self, parent_el: Any, child_path: Optional[Path],
    ) -> Optional[Path]:
        """Compute the on-disk path of a local parent for recursive
        walks. Returns ``None`` for network parents (no local
        location)."""
        if child_path is None:
            return None
        rel = _text(parent_el, "relativePath") or "../pom.xml"
        if rel == "":
            return None
        # Mirror the security checks in ``_read_local_parent``: any
        # path we'd refuse to READ from must also not be returned as
        # the next-level child path (else a hostile chain at depth N
        # could escape via a relativePath that depth N+1 walks).
        if Path(rel).is_absolute():
            return None
        candidate = (child_path.parent / rel).resolve()
        if self._scan_root is not None:
            try:
                candidate.relative_to(self._scan_root)
            except ValueError:
                return None
        if candidate.is_dir():
            candidate = candidate / "pom.xml"
        if candidate.is_file():
            return candidate
        return None

    # ------------------------------------------------------------------
    # Phase 3: BOM imports
    # ------------------------------------------------------------------

    def _absorb_boms(
        self,
        root: Any,
        view: InheritanceView,
        visited: Set[Tuple[str, str, str]],
        depth: int,
    ) -> None:
        """Walk ``<dependencyManagement>`` for entries with
        ``<scope>import</scope>`` and fetch each as a BOM. Merge
        their managed-deps into ``view``."""
        if depth >= self._max_depth:
            return
        if self._offline or self._client is None:
            return
        bom_entries = root.findall(
            "./dependencyManagement/dependencies/dependency"
        )
        for entry in bom_entries:
            scope = _text(entry, "scope")
            if scope != "import":
                continue
            group = _text(entry, "groupId")
            artifact = _text(entry, "artifactId")
            version = _resolve_property(_text(entry, "version"), view)
            if not (group and artifact and version):
                continue
            coord_key = (group, artifact, version)
            if coord_key in visited:
                continue
            visited.add(coord_key)

            if coord_key in self._cache:
                _merge_into(view, self._cache[coord_key])
                continue

            # Fetch the BOM POM the same way we'd fetch a parent.
            bom_root = self._read_network_parent_by_coord(
                group, artifact, version,
            )
            if bom_root is None:
                continue
            bom_view = InheritanceView()
            # BOMs themselves can have <parent> chains + nested BOM
            # imports (spring-boot-dependencies inherits from
            # spring-boot-parent + imports several other BOMs).
            self._walk_parents(
                None, bom_root, bom_view, visited, depth=depth + 1,
            )
            _absorb_self(bom_root, bom_view)
            self._absorb_boms(bom_root, bom_view, visited, depth + 1)
            self._cache[coord_key] = bom_view
            _merge_into(view, bom_view)

    def _read_network_parent_by_coord(
        self, group: str, artifact: str, version: str,
    ) -> Optional[Any]:
        """Same as :meth:`_read_network_parent` but takes the
        coordinate directly. Used by the BOM walker which doesn't
        have a <parent> element to read from."""
        if self._offline or self._client is None:
            return None
        # Same coord validation as the parent-element path. BOM
        # imports declare their coord in dependencyManagement
        # entries — same threat shape, same defence.
        if not _valid_coord(group, artifact, version):
            logger.debug(
                "sca.pom_inheritance: refusing malformed BOM coord "
                "(%r, %r, %r)", group, artifact, version,
            )
            return None
        coord = f"{group}:{artifact}"
        try:
            pom_dict = self._client.get_pom(coord, version)
        except Exception as e:                                  # noqa: BLE001
            logger.debug(
                "sca.pom_inheritance: BOM fetch failed for %s@%s: %s",
                coord, version, e,
            )
            return None
        if pom_dict is None:
            return None
        raw_xml = pom_dict.get("raw_xml")
        if not raw_xml:
            return None
        try:
            root = DET.fromstring(raw_xml)
        except Exception as e:                                  # noqa: BLE001
            logger.debug(
                "sca.pom_inheritance: BOM XML parse failed for "
                "%s@%s: %s", coord, version, e,
            )
            return None
        _strip_namespaces(root)
        return root


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _absorb_self(root: Any, view: InheritanceView) -> None:
    """Add the POM's OWN top-level ``<properties>`` and
    ``<dependencyManagement>`` (excluding BOM imports) to ``view``.
    Called once per ancestor after its parent chain has been merged
    so the ancestor's own values override its grandparents'."""
    # Properties
    props_el = root.find("./properties")
    if props_el is not None:
        for child in props_el:
            if not child.tag:
                continue
            text = (child.text or "").strip()
            if text:
                view.properties[child.tag] = text

    # depMgmt — skip BOM imports (those are handled separately)
    for entry in root.findall(
            "./dependencyManagement/dependencies/dependency",
    ):
        if _text(entry, "scope") == "import":
            continue
        group = _text(entry, "groupId")
        artifact = _text(entry, "artifactId")
        version = _text(entry, "version")
        if not (group and artifact and version):
            continue
        # Property resolution against the in-progress view, so a
        # version like ``${spring.version}`` picks up the parent
        # chain's properties.
        version = _resolve_property(version, view)
        if not version:
            continue
        view.managed[(group, artifact)] = version


def _merge_into(dst: InheritanceView, src: InheritanceView) -> None:
    """Merge ``src`` into ``dst``. Existing keys in ``dst`` win —
    we're walking parents bottom-up and the child's view is
    accumulated before its ancestors'."""
    for k, v in src.properties.items():
        dst.properties.setdefault(k, v)
    for k, v in src.managed.items():
        dst.managed.setdefault(k, v)


def _resolve_property(
    value: Optional[str], view: InheritanceView,
) -> Optional[str]:
    """Resolve a single ``${prop}`` reference using ``view.properties``.
    Returns ``value`` unchanged when it's not a property reference,
    or when the property is undefined. Does not recurse on chained
    property references — Maven supports it but the cases are
    vanishingly rare in real POMs."""
    if value is None:
        return None
    if not (value.startswith("${") and value.endswith("}")):
        return value
    key = value[2:-1]
    return view.properties.get(key, value)


def _coord_matches(parent_el: Any, candidate_root: Any) -> bool:
    """Verify that the local file we just read declares the
    coordinate the ``<parent>`` element references. Catches the
    misconfigured-relativePath case where ``../pom.xml`` is some
    OTHER POM, not the declared parent."""
    p_group = _text(parent_el, "groupId")
    p_artifact = _text(parent_el, "artifactId")
    if p_group is None or p_artifact is None:
        return True
    c_group = _text(candidate_root, "groupId")
    c_artifact = _text(candidate_root, "artifactId")
    # The candidate root may inherit groupId from its own parent;
    # in that case it'll be missing here and we can't verify.
    if c_group is None and c_artifact is None:
        return True
    if c_artifact is not None and c_artifact != p_artifact:
        return False
    if c_group is not None and p_group is not None and c_group != p_group:
        return False
    return True


def _text(el: Any, tag: str) -> Optional[str]:
    if el is None:
        return None
    child = el.find(f"./{tag}")
    if child is None or child.text is None:
        return None
    text = child.text.strip()
    return text or None


def _strip_namespaces(root: Any) -> None:
    """Strip the XML namespace prefix from every tag so XPath
    queries work without a namespace map. Mirrors the helper in
    :mod:`pom`."""
    for elem in root.iter():
        if isinstance(elem.tag, str) and "}" in elem.tag:
            elem.tag = elem.tag.split("}", 1)[1]


__all__ = [
    "InheritanceView",
    "PomInheritanceResolver",
    "get_inheritance_resolver",
    "set_inheritance_resolver",
]
