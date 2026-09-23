"""Tests for the Maven POM inheritance resolver.

Covers the three phases:

  1. **Local multi-module** — child POM's ``<parent>`` resolves via
     ``relativePath`` (default ``../pom.xml``); properties +
     depMgmt merged from disk.

  2. **Network parent chain** — when the local parent isn't there
     OR its coordinate doesn't match, fetch from a stub Maven
     client. Recursive on grandparents (the Spring Boot pattern:
     spring-boot-starter-parent → spring-boot-dependencies).

  3. **BOM imports** — depMgmt entries with ``<scope>import</scope>``
     are fetched as BOMs; their depMgmt merges into the consolidated
     view. Covers the Spring Boot transitive case where deps like
     Jackson get pinned via spring-boot-dependencies' BOM imports.

Plus cycle + depth + offline + property-substitution edge cases.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from packages.sca.parsers import pom as pom_parser
from packages.sca.parsers import pom_inheritance
from packages.sca.parsers.pom_inheritance import (
    InheritanceView,
    PomInheritanceResolver,
    _strip_namespaces,
)

# The resolver under test no-ops without defusedxml (its own guarded
# import), so every assertion here would fail rather than skip on a
# host without it. Skip the module whole, matching the sibling
# parser suites' module-level importorskip convention.
DET = pytest.importorskip("defusedxml.ElementTree")


# ---------------------------------------------------------------------------
# Stub Maven client — returns canned POM XML by coordinate
# ---------------------------------------------------------------------------


class _StubMavenClient:
    """Minimal MavenRegistry-shaped stub.

    ``poms`` maps ``"group:artifact:version"`` to raw POM XML
    string. ``get_pom(coord, version)`` returns the
    ``{raw_xml, dependencies}`` shape the resolver expects.
    """

    def __init__(self, poms: dict[str, str]):
        self._poms = poms
        self.fetch_calls: list[str] = []

    def get_pom(self, coord: str, version: str) -> dict | None:
        key = f"{coord}:{version}"
        self.fetch_calls.append(key)
        xml = self._poms.get(key)
        if xml is None:
            return None
        return {"raw_xml": xml, "dependencies": []}


def _write(tmp_path: Path, rel: str, content: str) -> Path:
    """Write a POM at the relative path; create parents as needed."""
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Helper: parse a POM with the resolver installed
# ---------------------------------------------------------------------------


def _parse_with_resolver(
    pom_path: Path, client: _StubMavenClient | None, *,
    offline: bool = False,
):
    """Install the resolver, parse, ensure cleanup."""
    resolver = pom_inheritance.PomInheritanceResolver(
        client, offline=offline,
    )
    pom_inheritance.set_inheritance_resolver(resolver)
    try:
        return pom_parser.parse(pom_path)
    finally:
        pom_inheritance.set_inheritance_resolver(None)


# ---------------------------------------------------------------------------
# Phase 1: local multi-module
# ---------------------------------------------------------------------------


def test_phase1_local_parent_depmgmt_fills_child_version(tmp_path: Path):
    """Child omits version; sibling parent ``../pom.xml`` declares
    the managed version. Resolver fills it in offline."""
    _write(tmp_path, "pom.xml", '''\
<project>
  <groupId>com.example</groupId>
  <artifactId>parent-app</artifactId>
  <version>1.0</version>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-databind</artifactId>
        <version>2.15.0</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
''')
    child = _write(tmp_path, "service/pom.xml", '''\
<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent-app</artifactId>
    <version>1.0</version>
  </parent>
  <artifactId>service</artifactId>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
    </dependency>
  </dependencies>
</project>
''')
    deps = _parse_with_resolver(child, client=None)
    db = next((d for d in deps if d.name == "com.fasterxml.jackson.core:jackson-databind"), None)
    assert db is not None
    assert db.version == "2.15.0", (
        f"expected jackson-databind 2.15.0 from local parent, got {db.version}"
    )


def test_phase1_local_parent_properties_inherited(tmp_path: Path):
    """Parent declares ``<jackson.version>``; child references
    ``${jackson.version}`` in a managed entry. Resolver substitutes."""
    _write(tmp_path, "pom.xml", '''\
<project>
  <groupId>com.example</groupId>
  <artifactId>parent-app</artifactId>
  <version>1.0</version>
  <properties>
    <jackson.version>2.16.1</jackson.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-databind</artifactId>
        <version>${jackson.version}</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
''')
    child = _write(tmp_path, "service/pom.xml", '''\
<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent-app</artifactId>
    <version>1.0</version>
  </parent>
  <artifactId>service</artifactId>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
    </dependency>
  </dependencies>
</project>
''')
    deps = _parse_with_resolver(child, client=None)
    db = next((d for d in deps if d.name == "com.fasterxml.jackson.core:jackson-databind"), None)
    assert db is not None
    assert db.version == "2.16.1"


_CORPORATE_PARENT_XML = '''\
<project>
  <groupId>com.example</groupId>
  <artifactId>corp-parent</artifactId>
  <version>1.0</version>
  <properties>
    <jackson.version>2.9.0</jackson.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-databind</artifactId>
        <version>${jackson.version}</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
'''

_CHILD_WITH_OVERRIDE_XML = '''\
<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>corp-parent</artifactId>
    <version>1.0</version>
  </parent>
  <artifactId>service</artifactId>
  <properties>
    <jackson.version>2.17.1</jackson.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
    </dependency>
  </dependencies>
</project>
'''

_CHILD_NO_OVERRIDE_XML = '''\
<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>corp-parent</artifactId>
    <version>1.0</version>
  </parent>
  <artifactId>plain</artifactId>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
    </dependency>
  </dependencies>
</project>
'''


def _jackson(deps):
    return next(
        (d for d in deps
         if d.name == "com.fasterxml.jackson.core:jackson-databind"),
        None,
    )


def test_child_property_override_wins_over_parent_scope(tmp_path: Path):
    """The canonical corporate pattern: parent pins
    ``<jackson.version>2.9.0</jackson.version>`` and manages
    ``jackson-databind ${jackson.version}``; the child OVERRIDES the
    property. Maven's effective POM resolves managed ``${...}``
    versions with child-wins property precedence — reporting the
    parent's stale 2.9.0 mints false CVE findings against a version
    the build never uses (and hides real ones when a child
    DOWNGRADES)."""
    _write(tmp_path, "pom.xml", _CORPORATE_PARENT_XML)
    child = _write(tmp_path, "service/pom.xml", _CHILD_WITH_OVERRIDE_XML)
    deps = _parse_with_resolver(child, client=None)
    db = _jackson(deps)
    assert db is not None
    assert db.version == "2.17.1"
    assert db.purl is not None and db.purl.endswith("@2.17.1")


def test_parent_scope_resolution_without_override_unchanged(
    tmp_path: Path,
) -> None:
    """Counter-direction pin: a child with NO override still gets the
    parent-resolved value (deferring resolution must not lose the
    ancestor-only case)."""
    _write(tmp_path, "pom.xml", _CORPORATE_PARENT_XML)
    child = _write(tmp_path, "plain/pom.xml", _CHILD_NO_OVERRIDE_XML)
    deps = _parse_with_resolver(child, client=None)
    db = _jackson(deps)
    assert db is not None
    assert db.version == "2.9.0"


def test_shared_parent_cache_serves_each_child_its_own_view(
    tmp_path: Path,
) -> None:
    """The per-coordinate view cache used to bake the FIRST child's
    resolution into the shared entry — sibling modules of one
    corporate parent then all inherited whichever property scope was
    walked first. Each child must resolve against its own merged
    property set."""
    _write(tmp_path, "pom.xml", _CORPORATE_PARENT_XML)
    plain = _write(tmp_path, "plain/pom.xml", _CHILD_NO_OVERRIDE_XML)
    service = _write(tmp_path, "service/pom.xml", _CHILD_WITH_OVERRIDE_XML)
    resolver = pom_inheritance.PomInheritanceResolver(None)
    pom_inheritance.set_inheritance_resolver(resolver)
    try:
        deps_plain = pom_parser.parse(plain)      # caches the parent
        deps_service = pom_parser.parse(service)  # cache hit
    finally:
        pom_inheritance.set_inheritance_resolver(None)
    assert _jackson(deps_plain).version == "2.9.0"
    assert _jackson(deps_service).version == "2.17.1"


def test_child_override_does_not_rewrite_imported_bom(tmp_path: Path):
    """The other direction of the resolution-scope split: an imported
    BOM resolves ``${...}`` at its OWN scope (Maven semantics — the
    importing POM's properties never rewrite an imported BOM's
    managed versions). The child's override must NOT leak into the
    BOM-pinned version."""
    bom_xml = '''\
<project>
  <groupId>com.fasterxml.jackson</groupId>
  <artifactId>jackson-bom</artifactId>
  <version>2.16.0</version>
  <properties>
    <jackson.version>2.16.0</jackson.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-databind</artifactId>
        <version>${jackson.version}</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
'''
    child = _write(tmp_path, "pom.xml", '''\
<project>
  <groupId>com.example</groupId>
  <artifactId>bom-consumer</artifactId>
  <version>1.0</version>
  <properties>
    <jackson.version>9.9.9</jackson.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.fasterxml.jackson</groupId>
        <artifactId>jackson-bom</artifactId>
        <version>2.16.0</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
    </dependency>
  </dependencies>
</project>
''')
    client = _StubMavenClient({
        "com.fasterxml.jackson:jackson-bom:2.16.0": bom_xml,
    })
    deps = _parse_with_resolver(child, client=client)
    db = _jackson(deps)
    assert db is not None
    assert db.version == "2.16.0"


def test_unresolvable_inherited_property_refused(tmp_path: Path):
    """An inherited managed version whose ``${prop}`` no scope
    defines must NOT flow verbatim into ``dep.version`` / purl —
    ``${jackson.version}`` is not a version and poisons CVE
    matching downstream. The dep stays unpinned."""
    _write(tmp_path, "pom.xml", '''\
<project>
  <groupId>com.example</groupId>
  <artifactId>corp-parent</artifactId>
  <version>1.0</version>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-databind</artifactId>
        <version>${undefined.version}</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
''')
    child = _write(tmp_path, "plain/pom.xml", _CHILD_NO_OVERRIDE_XML)
    deps = _parse_with_resolver(child, client=None)
    db = _jackson(deps)
    assert db is not None
    assert db.version is None


def test_phase1_explicit_relativepath(tmp_path: Path):
    """``<parent><relativePath>../../shared/pom.xml</relativePath>``
    is honoured."""
    _write(tmp_path, "shared/pom.xml", '''\
<project>
  <groupId>com.example</groupId>
  <artifactId>shared</artifactId>
  <version>1.0</version>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.apache.commons</groupId>
        <artifactId>commons-text</artifactId>
        <version>1.9</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
''')
    child = _write(tmp_path, "modules/web/pom.xml", '''\
<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>shared</artifactId>
    <version>1.0</version>
    <relativePath>../../shared/pom.xml</relativePath>
  </parent>
  <artifactId>web</artifactId>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-text</artifactId>
    </dependency>
  </dependencies>
</project>
''')
    deps = _parse_with_resolver(child, client=None)
    ct = next(
        (d for d in deps if d.name == "org.apache.commons:commons-text"),
        None,
    )
    assert ct is not None
    assert ct.version == "1.9"


def test_phase1_grandparent_walk(tmp_path: Path):
    """Three-deep local chain: app → parent → grandparent. Resolver
    walks all the way up."""
    _write(tmp_path, "pom.xml", '''\
<project>
  <groupId>com.example</groupId>
  <artifactId>grandparent</artifactId>
  <version>1.0</version>
  <properties>
    <spring.version>6.0.0</spring.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-core</artifactId>
        <version>${spring.version}</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
''')
    _write(tmp_path, "mid/pom.xml", '''\
<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>grandparent</artifactId>
    <version>1.0</version>
  </parent>
  <artifactId>mid</artifactId>
</project>
''')
    child = _write(tmp_path, "mid/app/pom.xml", '''\
<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>mid</artifactId>
    <version>1.0</version>
  </parent>
  <artifactId>app</artifactId>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
    </dependency>
  </dependencies>
</project>
''')
    deps = _parse_with_resolver(child, client=None)
    sc = next(
        (d for d in deps if d.name == "org.springframework:spring-core"),
        None,
    )
    assert sc is not None
    assert sc.version == "6.0.0"


# ---------------------------------------------------------------------------
# Phase 2: network parent chain (Spring Boot starter-parent)
# ---------------------------------------------------------------------------


def test_phase2_network_parent_fills_version(tmp_path: Path):
    """Canonical Spring Boot case: app inherits from
    spring-boot-starter-parent which depMgmt-pins
    spring-boot-starter-web."""
    boot_parent_xml = '''\
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-parent</artifactId>
  <version>3.2.0</version>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
        <version>3.2.0</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
'''
    client = _StubMavenClient({
        "org.springframework.boot:spring-boot-starter-parent:3.2.0":
            boot_parent_xml,
    })
    app = _write(tmp_path, "pom.xml", '''\
<project>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.2.0</version>
  </parent>
  <artifactId>myapp</artifactId>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
  </dependencies>
</project>
''')
    deps = _parse_with_resolver(app, client=client)
    web = next(
        (d for d in deps if d.name == "org.springframework.boot:spring-boot-starter-web"),
        None,
    )
    assert web is not None
    assert web.version == "3.2.0"


def test_phase2_grandparent_via_network(tmp_path: Path):
    """Spring Boot's two-level pattern:
    app → starter-parent → spring-boot-dependencies (which has
    the actual depMgmt). Resolver follows the chain."""
    boot_parent_xml = '''\
<project>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-dependencies</artifactId>
    <version>3.2.0</version>
  </parent>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-parent</artifactId>
  <version>3.2.0</version>
</project>
'''
    boot_deps_xml = '''\
<project>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-dependencies</artifactId>
  <version>3.2.0</version>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-actuator</artifactId>
        <version>3.2.0</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
'''
    client = _StubMavenClient({
        "org.springframework.boot:spring-boot-starter-parent:3.2.0":
            boot_parent_xml,
        "org.springframework.boot:spring-boot-dependencies:3.2.0":
            boot_deps_xml,
    })
    app = _write(tmp_path, "pom.xml", '''\
<project>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.2.0</version>
  </parent>
  <artifactId>myapp</artifactId>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-actuator</artifactId>
    </dependency>
  </dependencies>
</project>
''')
    deps = _parse_with_resolver(app, client=client)
    act = next(
        (d for d in deps if d.name == "org.springframework.boot:spring-boot-starter-actuator"),
        None,
    )
    assert act is not None
    assert act.version == "3.2.0"


# ---------------------------------------------------------------------------
# Phase 3: BOM imports
# ---------------------------------------------------------------------------


def test_phase3_bom_import_fills_transitive_version(tmp_path: Path):
    """spring-boot-dependencies BOM-imports a Jackson BOM; the
    Jackson BOM is what pins ``jackson-databind``. Resolver
    follows the import chain."""
    boot_deps_xml = '''\
<project>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-dependencies</artifactId>
  <version>3.2.0</version>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.fasterxml.jackson</groupId>
        <artifactId>jackson-bom</artifactId>
        <version>2.16.0</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
'''
    jackson_bom_xml = '''\
<project>
  <groupId>com.fasterxml.jackson</groupId>
  <artifactId>jackson-bom</artifactId>
  <version>2.16.0</version>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-databind</artifactId>
        <version>2.16.0</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
'''
    client = _StubMavenClient({
        "org.springframework.boot:spring-boot-dependencies:3.2.0":
            boot_deps_xml,
        "com.fasterxml.jackson:jackson-bom:2.16.0":
            jackson_bom_xml,
    })
    app = _write(tmp_path, "pom.xml", '''\
<project>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-dependencies</artifactId>
    <version>3.2.0</version>
  </parent>
  <artifactId>myapp</artifactId>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
    </dependency>
  </dependencies>
</project>
''')
    deps = _parse_with_resolver(app, client=client)
    jdb = next(
        (d for d in deps if d.name == "com.fasterxml.jackson.core:jackson-databind"),
        None,
    )
    assert jdb is not None
    assert jdb.version == "2.16.0"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_no_resolver_installed_means_no_inheritance(tmp_path: Path):
    """Default: no resolver installed → parser stays pure-local.
    Inherited deps remain at version=None."""
    _write(tmp_path, "pom.xml", '''\
<project>
  <groupId>com.example</groupId>
  <artifactId>parent</artifactId>
  <version>1.0</version>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>junit</groupId>
        <artifactId>junit</artifactId>
        <version>4.13</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
''')
    child = _write(tmp_path, "service/pom.xml", '''\
<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent</artifactId>
    <version>1.0</version>
  </parent>
  <artifactId>service</artifactId>
  <dependencies>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
    </dependency>
  </dependencies>
</project>
''')
    # Explicitly DO NOT install a resolver
    pom_inheritance.set_inheritance_resolver(None)
    deps = pom_parser.parse(child)
    j = next((d for d in deps if d.name == "junit:junit"), None)
    # The managed version sits in the parent's own POM, not in the
    # child's. Without a resolver, version stays None.
    assert j is not None
    assert j.version is None


def test_offline_mode_does_not_call_network(tmp_path: Path):
    """When the resolver is offline=True, the maven client is
    never called even if installed. Local-only resolution still
    runs."""
    boot_parent_xml = '''\
<project>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-parent</artifactId>
  <version>3.2.0</version>
</project>
'''
    client = _StubMavenClient({
        "org.springframework.boot:spring-boot-starter-parent:3.2.0":
            boot_parent_xml,
    })
    app = _write(tmp_path, "pom.xml", '''\
<project>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.2.0</version>
  </parent>
  <artifactId>myapp</artifactId>
</project>
''')
    _parse_with_resolver(app, client=client, offline=True)
    assert client.fetch_calls == [], (
        f"network calls in offline mode: {client.fetch_calls}"
    )


def test_cycle_terminates_cleanly(tmp_path: Path):
    """Pathological local hierarchy: A is its own parent.
    Resolver detects + bails."""
    _write(tmp_path, "pom.xml", '''\
<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>self-parent</artifactId>
    <version>1.0</version>
    <relativePath>./pom.xml</relativePath>
  </parent>
  <groupId>com.example</groupId>
  <artifactId>self-parent</artifactId>
  <version>1.0</version>
  <dependencies>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13</version>
    </dependency>
  </dependencies>
</project>
''')
    # No crash, no hang. Standard local deps still extracted.
    deps = _parse_with_resolver(tmp_path / "pom.xml", client=None)
    j = next((d for d in deps if d.name == "junit:junit"), None)
    assert j is not None
    assert j.version == "4.13"


def test_missing_local_parent_falls_through_to_network(tmp_path: Path):
    """When the local sibling parent doesn't exist on disk (or
    has a coord mismatch), the resolver falls through to the
    network client."""
    boot_parent_xml = '''\
<project>
  <groupId>com.example</groupId>
  <artifactId>shared-deps</artifactId>
  <version>1.0</version>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.slf4j</groupId>
        <artifactId>slf4j-api</artifactId>
        <version>2.0.9</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
'''
    client = _StubMavenClient({
        "com.example:shared-deps:1.0": boot_parent_xml,
    })
    # NO local pom.xml at tmp_path — the relative-path resolution
    # will miss; resolver falls through to network.
    child = _write(tmp_path, "service/pom.xml", '''\
<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>shared-deps</artifactId>
    <version>1.0</version>
  </parent>
  <artifactId>service</artifactId>
  <dependencies>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
    </dependency>
  </dependencies>
</project>
''')
    deps = _parse_with_resolver(child, client=client)
    s = next((d for d in deps if d.name == "org.slf4j:slf4j-api"), None)
    assert s is not None
    assert s.version == "2.0.9"


def test_explicit_version_wins_over_inherited(tmp_path: Path):
    """When child declares ``<version>``, the inherited one is
    NOT used. Resolver only fills version=None."""
    _write(tmp_path, "pom.xml", '''\
<project>
  <groupId>com.example</groupId>
  <artifactId>parent</artifactId>
  <version>1.0</version>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>junit</groupId>
        <artifactId>junit</artifactId>
        <version>4.13</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
''')
    child = _write(tmp_path, "service/pom.xml", '''\
<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent</artifactId>
    <version>1.0</version>
  </parent>
  <artifactId>service</artifactId>
  <dependencies>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.12</version>
    </dependency>
  </dependencies>
</project>
''')
    deps = _parse_with_resolver(child, client=None)
    j = next((d for d in deps if d.name == "junit:junit"), None)
    assert j is not None
    # Child's explicit version wins.
    assert j.version == "4.12"


def test_absolute_relativepath_refused(tmp_path: Path):
    """A POM declaring ``<relativePath>/etc/passwd</relativePath>``
    must be refused — Maven convention is strictly relative, and an
    absolute path here is either misconfiguration or hostile."""
    # Plant a "shared" parent at /tmp somewhere that the probe could
    # in principle escape to.
    outside = tmp_path / "actual_outside" / "pom.xml"
    outside.parent.mkdir(parents=True, exist_ok=True)
    outside.write_text('''<project>
  <groupId>com.example</groupId>
  <artifactId>shared</artifactId>
  <version>1.0</version>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>ESCAPED</groupId>
        <artifactId>via-abs-path</artifactId>
        <version>9.9.9</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>''', encoding="utf-8")
    child = _write(tmp_path / "project", "pom.xml", f'''\
<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>shared</artifactId>
    <version>1.0</version>
    <relativePath>{outside}</relativePath>
  </parent>
  <artifactId>app</artifactId>
  <dependencies>
    <dependency>
      <groupId>ESCAPED</groupId>
      <artifactId>via-abs-path</artifactId>
    </dependency>
  </dependencies>
</project>''')
    deps = _parse_with_resolver(child, client=None)
    esc = next((d for d in deps if d.name == "ESCAPED:via-abs-path"), None)
    assert esc is not None
    assert esc.version is None, (
        f"absolute relativePath escaped — got {esc.version}"
    )


def test_scan_root_confines_resolution(tmp_path: Path):
    """Even a SYMLINK at the conventional ``../pom.xml`` location
    pointing outside ``scan_root`` is refused — the resolved real
    path lands outside the confinement zone."""
    import os
    outside_pom = tmp_path / "outside" / "pom.xml"
    outside_pom.parent.mkdir(parents=True, exist_ok=True)
    outside_pom.write_text('''<project>
  <groupId>com.example</groupId>
  <artifactId>shared</artifactId>
  <version>1.0</version>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>FROM_OUTSIDE</groupId>
        <artifactId>sneaky</artifactId>
        <version>9.9.9</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>''', encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir(parents=True)
    # Symlink at ../pom.xml (the default relativePath) → outside.
    symlink = project.parent / "pom.xml"
    os.symlink(outside_pom, symlink)
    child = project / "pom.xml"
    child.write_text('''<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>shared</artifactId>
    <version>1.0</version>
  </parent>
  <artifactId>app</artifactId>
  <dependencies>
    <dependency>
      <groupId>FROM_OUTSIDE</groupId>
      <artifactId>sneaky</artifactId>
    </dependency>
  </dependencies>
</project>''', encoding="utf-8")
    # scan_root = the project dir; symlink target escapes it
    resolver = pom_inheritance.PomInheritanceResolver(
        None, offline=True, scan_root=project,
    )
    pom_inheritance.set_inheritance_resolver(resolver)
    try:
        deps = pom_parser.parse(child)
    finally:
        pom_inheritance.set_inheritance_resolver(None)
    s = next((d for d in deps if d.name == "FROM_OUTSIDE:sneaky"), None)
    assert s is not None
    assert s.version is None, (
        f"symlink escape via scan_root miss — got {s.version}"
    )


def test_malformed_coord_does_not_reach_network(tmp_path: Path):
    """Coord fields with path-traversal chars must NOT be forwarded
    to the registry — they'd inject into the URL."""
    class _ProbeClient:
        def __init__(self):
            self.fetched = []

        def get_pom(self, coord, version):
            self.fetched.append((coord, version))

    client = _ProbeClient()
    child = _write(tmp_path, "pom.xml", '''\
<project>
  <parent>
    <groupId>../../../evil</groupId>
    <artifactId>../../also-evil</artifactId>
    <version>1.0</version>
    <relativePath></relativePath>
  </parent>
  <artifactId>app</artifactId>
</project>''')
    resolver = pom_inheritance.PomInheritanceResolver(
        client, offline=False, scan_root=tmp_path,
    )
    pom_inheritance.set_inheritance_resolver(resolver)
    try:
        pom_parser.parse(child)
    finally:
        pom_inheritance.set_inheritance_resolver(None)
    assert client.fetched == [], (
        f"malformed coord reached client: {client.fetched}"
    )


def test_xxe_in_parent_pom_blocked(tmp_path: Path):
    """A parent POM with a DOCTYPE / entity payload must be
    rejected by defusedxml (billion-laughs defence)."""
    _write(tmp_path, "pom.xml", '''<?xml version="1.0"?>
<!DOCTYPE project [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">
]>
<project>
  <groupId>com.example</groupId>
  <artifactId>shared</artifactId>
  <version>1.0</version>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>SHOULD_NOT_LAND</groupId>
        <artifactId>via-xxe</artifactId>
        <version>9.9.9</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>''')
    child = _write(tmp_path, "service/pom.xml", '''\
<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>shared</artifactId>
    <version>1.0</version>
  </parent>
  <artifactId>app</artifactId>
  <dependencies>
    <dependency>
      <groupId>SHOULD_NOT_LAND</groupId>
      <artifactId>via-xxe</artifactId>
    </dependency>
  </dependencies>
</project>''')
    # Don't crash, don't merge depMgmt from the rejected parent
    deps = _parse_with_resolver(child, client=None)
    s = next((d for d in deps if d.name == "SHOULD_NOT_LAND:via-xxe"), None)
    assert s is not None
    assert s.version is None, (
        f"depMgmt merged from XXE-rejected parent — got {s.version}"
    )


def test_relativepath_empty_skips_local_and_uses_network(tmp_path: Path):
    """``<relativePath></relativePath>`` is Maven's convention for
    'no local parent, only network'. Resolver respects it."""
    parent_xml = '''\
<project>
  <groupId>com.example</groupId>
  <artifactId>only-on-net</artifactId>
  <version>1.0</version>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.slf4j</groupId>
        <artifactId>slf4j-api</artifactId>
        <version>1.7.36</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
'''
    client = _StubMavenClient({
        "com.example:only-on-net:1.0": parent_xml,
    })
    # Plant a DIFFERENT pom.xml at the default-relativePath location;
    # the empty-relativePath should bypass it.
    _write(tmp_path, "pom.xml", '''\
<project>
  <groupId>com.example</groupId>
  <artifactId>some-other-pom</artifactId>
  <version>1.0</version>
</project>
''')
    child = _write(tmp_path, "service/pom.xml", '''\
<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>only-on-net</artifactId>
    <version>1.0</version>
    <relativePath></relativePath>
  </parent>
  <artifactId>service</artifactId>
  <dependencies>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
    </dependency>
  </dependencies>
</project>
''')
    deps = _parse_with_resolver(child, client=client)
    s = next((d for d in deps if d.name == "org.slf4j:slf4j-api"), None)
    assert s is not None
    assert s.version == "1.7.36"
    assert "com.example:only-on-net:1.0" in client.fetch_calls


# ---------------------------------------------------------------------------
# Cache vs cycle-guard ordering in _walk_parents
# ---------------------------------------------------------------------------


def _root(xml: str):
    root = DET.fromstring(xml)
    _strip_namespaces(root)
    return root


_CHILD_XML = (
    "<project><artifactId>child</artifactId>"
    "<parent><groupId>g</groupId><artifactId>parent</artifactId>"
    "<version>1.0</version><relativePath></relativePath></parent>"
    "</project>"
)


def test_cache_hit_merges_even_when_coord_already_visited() -> None:
    """Cache entries exist only for fully-resolved coords, so a hit
    must merge regardless of the visited set (previously the visited
    check short-circuited first and dropped the merge)."""
    resolver = PomInheritanceResolver(None, offline=True)
    cached = InheritanceView()
    cached.managed[("g", "dep")] = "9.9"
    cached.properties["k"] = "v"
    resolver._cache[("parent", "g", "parent", "1.0")] = cached

    view = InheritanceView()
    visited = {("g", "parent", "1.0")}   # already seen in this walk
    resolver._walk_parents(None, _root(_CHILD_XML), view, visited, depth=0)

    assert view.managed[("g", "dep")] == "9.9"
    assert view.properties["k"] == "v"


def test_cache_hit_merges_on_fresh_walk() -> None:
    resolver = PomInheritanceResolver(None, offline=True)
    cached = InheritanceView()
    cached.managed[("g", "dep")] = "1.2"
    resolver._cache[("parent", "g", "parent", "1.0")] = cached

    view = InheritanceView()
    resolver._walk_parents(None, _root(_CHILD_XML), view, set(), depth=0)
    assert view.managed[("g", "dep")] == "1.2"


def test_uncached_visited_coord_still_treated_as_cycle() -> None:
    """No cache entry + already-visited = genuine in-flight cycle;
    the walk must stop without recursing or fetching."""
    resolver = PomInheritanceResolver(None, offline=True)
    view = InheritanceView()
    visited = {("g", "parent", "1.0")}
    resolver._walk_parents(None, _root(_CHILD_XML), view, visited, depth=0)
    assert not view.managed
    assert not view.properties


def test_self_parent_cycle_terminates(tmp_path: Path) -> None:
    """A POM that names itself as its parent must terminate cleanly
    (visited-set cycle detection through the local-parent path)."""
    pom = _write(tmp_path, "pom.xml", (
        "<project><groupId>g</groupId><artifactId>self</artifactId>"
        "<version>1.0</version>"
        "<parent><groupId>g</groupId><artifactId>self</artifactId>"
        "<version>1.0</version><relativePath>pom.xml</relativePath></parent>"
        "</project>"
    ))
    resolver = PomInheritanceResolver(None, offline=True, scan_root=tmp_path)
    view = resolver.resolve(pom, _root(pom.read_text(encoding="utf-8")))
    assert isinstance(view, InheritanceView)


# ---------------------------------------------------------------------------
# Empty <relativePath/> — Maven's "network only" convention
# ---------------------------------------------------------------------------


def test_relative_path_helper_distinguishes_empty_and_missing() -> None:
    """``_relative_path`` preserves the empty-vs-missing distinction
    that ``_text`` collapses: absent element → ``../pom.xml`` default;
    present-but-empty element → ``""`` (network only)."""
    from packages.sca.parsers.pom_inheritance import _relative_path

    empty = _root("<parent><relativePath></relativePath></parent>")
    self_closing = _root("<parent><relativePath/></parent>")
    absent = _root("<parent></parent>")
    explicit = _root(
        "<parent><relativePath>../x/pom.xml</relativePath></parent>"
    )

    assert _relative_path(empty) == ""
    assert _relative_path(self_closing) == ""
    assert _relative_path(absent) == "../pom.xml"
    assert _relative_path(explicit) == "../x/pom.xml"


def test_relativepath_empty_skips_matching_local_parent(tmp_path: Path):
    """The "network only" convention holds even when ``../pom.xml``
    carries the MATCHING coordinate. Collapsing the empty element to
    the default read the local file (whose managed versions may be
    stale) instead of Maven Central."""
    network_xml = '''\
<project>
  <groupId>com.example</groupId>
  <artifactId>shared</artifactId>
  <version>1.0</version>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.slf4j</groupId>
        <artifactId>slf4j-api</artifactId>
        <version>1.7.36</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
'''
    client = _StubMavenClient({"com.example:shared:1.0": network_xml})
    # Local file at the default relativePath location with the SAME
    # coordinate but a DIFFERENT managed version — must be bypassed.
    _write(tmp_path, "pom.xml", '''\
<project>
  <groupId>com.example</groupId>
  <artifactId>shared</artifactId>
  <version>1.0</version>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.slf4j</groupId>
        <artifactId>slf4j-api</artifactId>
        <version>0.0.1</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
''')
    child = _write(tmp_path, "service/pom.xml", '''\
<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>shared</artifactId>
    <version>1.0</version>
    <relativePath></relativePath>
  </parent>
  <artifactId>service</artifactId>
  <dependencies>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
    </dependency>
  </dependencies>
</project>
''')
    deps = _parse_with_resolver(child, client=client)
    s = next((d for d in deps if d.name == "org.slf4j:slf4j-api"), None)
    assert s is not None
    assert s.version == "1.7.36", (
        f"local parent consulted despite empty relativePath — got {s.version}"
    )
    assert "com.example:shared:1.0" in client.fetch_calls


def test_bom_missing_raw_xml_logs_debug(caplog) -> None:
    """Logging parity with ``_read_network_parent``: a BOM fetch whose
    payload lacks ``raw_xml`` must leave a debug trace, not return
    silently."""
    import logging

    class _NoRawXmlClient:
        def get_pom(self, coord: str, version: str) -> dict | None:
            return {"dependencies": []}

    resolver = PomInheritanceResolver(_NoRawXmlClient())
    with caplog.at_level(
        logging.DEBUG, logger="packages.sca.parsers.pom_inheritance",
    ):
        out = resolver._read_network_parent_by_coord("g", "a", "1.0")

    assert out is None
    assert any(
        "raw_xml" in rec.getMessage() and "g:a" in rec.getMessage()
        for rec in caplog.records
    ), f"no raw_xml debug record: {[r.getMessage() for r in caplog.records]}"


def test_phase3_child_direct_bom_import_without_parent(tmp_path: Path):
    """Spring's documented alternative to inheriting starter-parent:
    a pom with NO <parent> that BOM-imports spring-boot-dependencies
    directly (mandatory whenever the project needs its own corporate
    parent). The child's own dependencyManagement imports must be
    absorbed — the caller only holds the import DECLARATION, not the
    BOM's contents."""
    boot_deps_xml = '''\
<project>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-dependencies</artifactId>
  <version>3.2.0</version>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-databind</artifactId>
        <version>2.16.0</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
'''
    client = _StubMavenClient({
        "org.springframework.boot:spring-boot-dependencies:3.2.0":
            boot_deps_xml,
    })
    app = _write(tmp_path, "pom.xml", '''\
<project>
  <artifactId>myapp</artifactId>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-dependencies</artifactId>
        <version>3.2.0</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
    </dependency>
  </dependencies>
</project>
''')
    deps = _parse_with_resolver(app, client=client)
    jdb = next(
        (d for d in deps
         if d.name == "com.fasterxml.jackson.core:jackson-databind"),
        None,
    )
    assert jdb is not None
    assert jdb.version == "2.16.0"


def test_phase3_child_own_bom_version_from_same_pom_property(
    tmp_path: Path,
):
    """The routine corporate/Spring spelling of the parent-less BOM
    import: the version centralised in the SAME pom's <properties>
    (``<version>${boot.version}</version>``). The ancestor view is
    empty on a parent-less child, so resolution must overlay the
    child's own properties — pre-fix the coord failed _valid_coord
    with the unresolved ``${...}`` and the whole managed set was lost
    silently (managed == {} with zero fetches)."""
    boot_deps_xml = '''\
<project>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-dependencies</artifactId>
  <version>3.2.0</version>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-databind</artifactId>
        <version>2.16.0</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
'''
    client = _StubMavenClient({
        "org.springframework.boot:spring-boot-dependencies:3.2.0":
            boot_deps_xml,
    })
    app = _write(tmp_path, "pom.xml", '''\
<project>
  <artifactId>myapp</artifactId>
  <properties>
    <boot.version>3.2.0</boot.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-dependencies</artifactId>
        <version>${boot.version}</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
    </dependency>
  </dependencies>
</project>
''')
    deps = _parse_with_resolver(app, client=client)
    jdb = next(
        (d for d in deps
         if d.name == "com.fasterxml.jackson.core:jackson-databind"),
        None,
    )
    assert jdb is not None
    assert jdb.version == "2.16.0"
    assert client.fetch_calls == [
        "org.springframework.boot:spring-boot-dependencies:3.2.0",
    ]


def test_phase3_child_own_property_beats_inherited(tmp_path: Path):
    """Precedence on the overlay: when the child and its parent both
    define the property, the child's value wins (Maven precedence) —
    the BOM fetched is the child-pinned version."""
    boot_new = '''\
<project>
  <groupId>org.example</groupId>
  <artifactId>corp-bom</artifactId>
  <version>2.0</version>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-databind</artifactId>
        <version>2.17.0</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
'''
    client = _StubMavenClient({"org.example:corp-bom:2.0": boot_new})
    _write(tmp_path, "parent/pom.xml", '''\
<project>
  <groupId>org.example</groupId>
  <artifactId>parent</artifactId>
  <version>1</version>
  <properties>
    <bom.version>1.0</bom.version>
  </properties>
</project>
''')
    app = _write(tmp_path, "app/pom.xml", '''\
<project>
  <artifactId>myapp</artifactId>
  <parent>
    <groupId>org.example</groupId>
    <artifactId>parent</artifactId>
    <version>1</version>
    <relativePath>../parent/pom.xml</relativePath>
  </parent>
  <properties>
    <bom.version>2.0</bom.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.example</groupId>
        <artifactId>corp-bom</artifactId>
        <version>${bom.version}</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
    </dependency>
  </dependencies>
</project>
''')
    deps = _parse_with_resolver(app, client=client)
    jdb = next(
        (d for d in deps
         if d.name == "com.fasterxml.jackson.core:jackson-databind"),
        None,
    )
    assert jdb is not None
    assert jdb.version == "2.17.0"


def _find(deps, suffix: str):
    return next(d for d in deps if d.name.endswith(suffix))


def test_bom_undefined_property_never_resolves_at_importer_scope(
    tmp_path: Path,
):
    """A BOM's own managed entry referencing a property the BOM does
    NOT define is scope-final at absorption: Maven leaves the
    reference literal, and a literal ``${...}`` is not a version.
    Left raw in the view, the apply pass resolved it against the
    IMPORTING pom's properties — a name collision reported a version
    the build never uses."""
    bom_xml = '''\
<project>
  <groupId>corp</groupId><artifactId>bom2</artifactId><version>1.0</version>
  <dependencyManagement><dependencies>
    <dependency><groupId>io.vendor</groupId><artifactId>vendor-core</artifactId>
      <version>${vendor.core.version}</version></dependency>
  </dependencies></dependencyManagement>
</project>
'''
    child = _write(tmp_path, "pom.xml", '''\
<project>
  <groupId>corp</groupId><artifactId>app</artifactId><version>1</version>
  <properties><vendor.core.version>99.99</vendor.core.version></properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>corp</groupId><artifactId>bom2</artifactId>
      <version>1.0</version><type>pom</type><scope>import</scope></dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <dependency><groupId>io.vendor</groupId><artifactId>vendor-core</artifactId></dependency>
  </dependencies>
</project>
''')
    client = _StubMavenClient({"corp:bom2:1.0": bom_xml})
    deps = _parse_with_resolver(child, client)
    # The importer defines the property, but the BOM's scope doesn't:
    # the entry is dropped at BOM finalisation and the dep stays
    # unpinned — never 99.99.
    assert _find(deps, ":vendor-core").version is None


def test_bom_undefined_property_refused_without_importer_collision(
    tmp_path: Path,
):
    """Control for the scope-final rule: with NO importer property of
    the same name, the entry is equally refused (the two shapes must
    agree — refusal fired only in this one before)."""
    bom_xml = '''\
<project>
  <groupId>corp</groupId><artifactId>bom2</artifactId><version>1.0</version>
  <dependencyManagement><dependencies>
    <dependency><groupId>io.vendor</groupId><artifactId>vendor-core</artifactId>
      <version>${vendor.core.version}</version></dependency>
  </dependencies></dependencyManagement>
</project>
'''
    child = _write(tmp_path, "pom.xml", '''\
<project>
  <groupId>corp</groupId><artifactId>app</artifactId><version>1</version>
  <dependencyManagement><dependencies>
    <dependency><groupId>corp</groupId><artifactId>bom2</artifactId>
      <version>1.0</version><type>pom</type><scope>import</scope></dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <dependency><groupId>io.vendor</groupId><artifactId>vendor-core</artifactId></dependency>
  </dependencies>
</project>
''')
    client = _StubMavenClient({"corp:bom2:1.0": bom_xml})
    deps = _parse_with_resolver(child, client)
    assert _find(deps, ":vendor-core").version is None


def test_bom_parent_chain_property_resolves_at_bom_scope(tmp_path: Path):
    """Arrival path two for the same mechanism: the BOM's PARENT
    chain contributes raw-by-design managed values; they must settle
    at the BOM's merged scope (2.9.0 here), not at the importer's
    (9.9.9-IMPORTER)."""
    bom_xml = '''\
<project>
  <parent><groupId>corp</groupId><artifactId>bom-parent</artifactId>
    <version>1.0</version></parent>
  <groupId>corp</groupId><artifactId>bom</artifactId><version>1.0</version>
</project>
'''
    bom_parent_xml = '''\
<project>
  <groupId>corp</groupId><artifactId>bom-parent</artifactId><version>1.0</version>
  <properties><jackson.version>2.9.0</jackson.version></properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>${jackson.version}</version></dependency>
  </dependencies></dependencyManagement>
</project>
'''
    child = _write(tmp_path, "pom.xml", '''\
<project>
  <groupId>corp</groupId><artifactId>app</artifactId><version>1</version>
  <properties><jackson.version>9.9.9-IMPORTER</jackson.version></properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>corp</groupId><artifactId>bom</artifactId>
      <version>1.0</version><type>pom</type><scope>import</scope></dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <dependency><groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId></dependency>
  </dependencies>
</project>
''')
    client = _StubMavenClient({
        "corp:bom:1.0": bom_xml,
        "corp:bom-parent:1.0": bom_parent_xml,
    })
    deps = _parse_with_resolver(child, client)
    assert _find(deps, ":jackson-databind").version == "2.9.0"
