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
from typing import Dict, Optional

from packages.sca.parsers import pom as pom_parser
from packages.sca.parsers import pom_inheritance


# ---------------------------------------------------------------------------
# Stub Maven client — returns canned POM XML by coordinate
# ---------------------------------------------------------------------------


class _StubMavenClient:
    """Minimal MavenRegistry-shaped stub.

    ``poms`` maps ``"group:artifact:version"`` to raw POM XML
    string. ``get_pom(coord, version)`` returns the
    ``{raw_xml, dependencies}`` shape the resolver expects.
    """

    def __init__(self, poms: Dict[str, str]):
        self._poms = poms
        self.fetch_calls: list[str] = []

    def get_pom(self, coord: str, version: str) -> Optional[dict]:
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
    pom_path: Path, client: Optional[_StubMavenClient], *,
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
    # Parent's depMgmt sits in feat/sca's own POM, not in the
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
            return None

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
