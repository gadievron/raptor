"""Tests for the Maven pom.xml parser."""

from __future__ import annotations

from pathlib import Path


from packages.sca.models import PinStyle
from packages.sca.parsers.pom import parse


def _write(tmp_path: Path, body: str, name: str = "pom.xml") -> Path:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


def test_namespaced_pom_basic_dep(tmp_path: Path) -> None:
    body = """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
  </dependencies>
</project>
"""
    deps = parse(_write(tmp_path, body))
    assert len(deps) == 1
    d = deps[0]
    assert d.ecosystem == "Maven"
    assert d.name == "org.apache.logging.log4j:log4j-core"
    assert d.version == "2.14.1"
    assert d.pin_style is PinStyle.EXACT
    assert d.scope == "main"
    assert d.direct is True
    assert d.parser_confidence.level == "high"
    assert d.purl == "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"


def test_namespaceless_pom_parses(tmp_path: Path) -> None:
    body = """<project>
  <dependencies>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>
"""
    deps = parse(_write(tmp_path, body))
    assert len(deps) == 1
    assert deps[0].scope == "test"


def test_property_substitution(tmp_path: Path) -> None:
    body = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <properties>
    <log4j.version>2.17.1</log4j.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>${log4j.version}</version>
    </dependency>
  </dependencies>
</project>
"""
    deps = parse(_write(tmp_path, body))
    assert len(deps) == 1
    assert deps[0].version == "2.17.1"
    assert deps[0].parser_confidence.level == "high"


def test_unresolved_property_drops_to_medium(tmp_path: Path) -> None:
    body = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>thing</artifactId>
      <version>${unknown.version}</version>
    </dependency>
  </dependencies>
</project>
"""
    deps = parse(_write(tmp_path, body))
    assert len(deps) == 1
    assert deps[0].pin_style is PinStyle.UNKNOWN
    assert deps[0].parser_confidence.level == "medium"


def test_dependency_management_recorded_as_build(tmp_path: Path) -> None:
    body = """<project xmlns="http://maven.apache.org/POM/4.0.0">
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
</project>
"""
    deps = parse(_write(tmp_path, body))
    assert len(deps) == 1
    d = deps[0]
    assert d.scope == "build"
    assert d.direct is False  # managed → not declared at top-level


def test_plugin_block_records_build_scope(tmp_path: Path) -> None:
    body = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <build>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-compiler-plugin</artifactId>
        <version>3.11.0</version>
      </plugin>
    </plugins>
  </build>
</project>
"""
    deps = parse(_write(tmp_path, body))
    assert len(deps) == 1
    assert deps[0].scope == "build"
    assert deps[0].name == "org.apache.maven.plugins:maven-compiler-plugin"


def test_plugin_default_groupid_when_missing(tmp_path: Path) -> None:
    body = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <build>
    <plugins>
      <plugin>
        <artifactId>maven-jar-plugin</artifactId>
        <version>3.3.0</version>
      </plugin>
    </plugins>
  </build>
</project>
"""
    deps = parse(_write(tmp_path, body))
    assert len(deps) == 1
    assert deps[0].name == "org.apache.maven.plugins:maven-jar-plugin"


def test_parent_pom_recorded(tmp_path: Path) -> None:
    body = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.2.0</version>
  </parent>
</project>
"""
    deps = parse(_write(tmp_path, body))
    assert len(deps) == 1
    assert deps[0].scope == "build"
    assert deps[0].version == "3.2.0"


def test_hard_version_range_classified_as_exact(tmp_path: Path) -> None:
    body = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <dependencies>
    <dependency>
      <groupId>g</groupId><artifactId>a</artifactId><version>[1.2.3]</version>
    </dependency>
  </dependencies>
</project>
"""
    deps = parse(_write(tmp_path, body))
    assert deps[0].pin_style is PinStyle.EXACT
    assert deps[0].version == "1.2.3"


def test_open_range_classified_as_range(tmp_path: Path) -> None:
    body = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <dependencies>
    <dependency>
      <groupId>g</groupId><artifactId>a</artifactId><version>[1.0,2.0)</version>
    </dependency>
  </dependencies>
</project>
"""
    deps = parse(_write(tmp_path, body))
    assert deps[0].pin_style is PinStyle.RANGE


def test_missing_version_yields_unknown(tmp_path: Path) -> None:
    body = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <dependencies>
    <dependency>
      <groupId>g</groupId><artifactId>a</artifactId>
    </dependency>
  </dependencies>
</project>
"""
    deps = parse(_write(tmp_path, body))
    assert len(deps) == 1
    assert deps[0].version is None
    assert deps[0].pin_style is PinStyle.UNKNOWN
    assert deps[0].parser_confidence.level == "medium"


def test_malformed_xml_returns_empty(tmp_path: Path) -> None:
    deps = parse(_write(tmp_path, "<project><dependencies>"))
    assert deps == []


def test_doctype_with_external_entity_is_blocked(tmp_path: Path) -> None:
    body = """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <dependencies>
    <dependency>
      <groupId>&xxe;</groupId><artifactId>a</artifactId><version>1</version>
    </dependency>
  </dependencies>
</project>
"""
    # defusedxml refuses DTDs by default; parser returns []. The exact
    # exception type isn't part of the contract — what matters is no
    # /etc/passwd contents end up in the dependency.
    deps = parse(_write(tmp_path, body))
    assert deps == []
