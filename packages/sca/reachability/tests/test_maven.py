"""Tests for ``packages.sca.reachability.maven`` — the module-level
heuristic scanner for Maven Java deps."""

from __future__ import annotations

from pathlib import Path

from packages.sca.reachability.maven import (
    _PACKAGE_OVERRIDES,
    resolve_dep,
    scan_imports,
)


def _java(tmp_path: Path, rel: str, source: str) -> Path:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(source)
    return p


# ---------------------------------------------------------------------------
# scan_imports
# ---------------------------------------------------------------------------


def test_scan_picks_up_regular_import(tmp_path: Path) -> None:
    _java(tmp_path, "src/main/java/X.java",
          "package x;\nimport org.springframework.core.Foo;\nclass X {}\n")
    scan = scan_imports(tmp_path)
    assert "org.springframework.core.Foo" in scan


def test_scan_picks_up_static_import(tmp_path: Path) -> None:
    _java(tmp_path, "src/main/java/X.java",
          "package x;\nimport static java.util.Collections.emptyList;\n"
          "class X {}\n")
    scan = scan_imports(tmp_path)
    assert "java.util.Collections.emptyList" in scan


def test_scan_picks_up_wildcard_import(tmp_path: Path) -> None:
    _java(tmp_path, "src/main/java/X.java",
          "package x;\nimport com.example.foo.*;\nclass X {}\n")
    scan = scan_imports(tmp_path)
    assert "com.example.foo" in scan


def test_scan_skips_build_dirs(tmp_path: Path) -> None:
    _java(tmp_path, "build/X.java",
          "package x;\nimport ignored.Whatever;\nclass X {}\n")
    _java(tmp_path, "target/Y.java",
          "package y;\nimport ignored.Whatever2;\nclass Y {}\n")
    _java(tmp_path, "src/main/java/Z.java",
          "package z;\nimport kept.Real;\nclass Z {}\n")
    scan = scan_imports(tmp_path)
    assert "kept.Real" in scan
    assert "ignored.Whatever" not in scan
    assert "ignored.Whatever2" not in scan


def test_scan_marks_test_files(tmp_path: Path) -> None:
    _java(tmp_path, "src/main/java/X.java",
          "package x;\nimport org.junit.Foo;\nclass X {}\n")
    _java(tmp_path, "src/test/java/XTest.java",
          "package x;\nimport org.junit.Bar;\nclass XTest {}\n")
    scan = scan_imports(tmp_path)
    main_hits = scan["org.junit.Foo"]
    test_hits = scan["org.junit.Bar"]
    assert main_hits[0][2] is False
    assert test_hits[0][2] is True


# ---------------------------------------------------------------------------
# resolve_dep — heuristic prefix matching
# ---------------------------------------------------------------------------


def test_resolve_groupid_prefix_match(tmp_path: Path) -> None:
    """``org.springframework:spring-core`` -> imports start with
    ``org.springframework.*`` (groupId IS the prefix)."""
    _java(tmp_path, "src/main/java/X.java",
          "package x;\n"
          "import org.springframework.core.Foo;\n"
          "class X {}\n")
    scan = scan_imports(tmp_path)
    r = resolve_dep("org.springframework:spring-core", scan, target=tmp_path)
    assert r.verdict == "imported"


def test_resolve_curated_override_jackson(tmp_path: Path) -> None:
    """Jackson's groupId doesn't match its package; curated map fixes it."""
    _java(tmp_path, "src/main/java/X.java",
          "package x;\n"
          "import com.fasterxml.jackson.databind.ObjectMapper;\n"
          "class X {}\n")
    scan = scan_imports(tmp_path)
    r = resolve_dep(
        "com.fasterxml.jackson.core:jackson-databind",
        scan, target=tmp_path,
    )
    assert r.verdict == "imported"


def test_resolve_curated_override_guava(tmp_path: Path) -> None:
    """Guava ships ``com.google.common.*`` from
    ``com.google.guava:guava`` — curated."""
    _java(tmp_path, "src/main/java/X.java",
          "package x;\n"
          "import com.google.common.collect.ImmutableList;\n"
          "class X {}\n")
    scan = scan_imports(tmp_path)
    r = resolve_dep("com.google.guava:guava", scan, target=tmp_path)
    assert r.verdict == "imported"


def test_resolve_curated_override_commons_io(tmp_path: Path) -> None:
    """``commons-io:commons-io`` ships ``org.apache.commons.io.*``."""
    _java(tmp_path, "src/main/java/X.java",
          "package x;\n"
          "import org.apache.commons.io.FileUtils;\n"
          "class X {}\n")
    scan = scan_imports(tmp_path)
    r = resolve_dep("commons-io:commons-io", scan, target=tmp_path)
    assert r.verdict == "imported"


def test_resolve_no_match_returns_not_evaluated(tmp_path: Path) -> None:
    """Heuristic missed -> ``not_evaluated`` (NOT
    ``not_reachable`` — we can't be confident the dep isn't used)."""
    _java(tmp_path, "src/main/java/X.java",
          "package x;\n"
          "import com.example.something.Else;\n"
          "class X {}\n")
    scan = scan_imports(tmp_path)
    r = resolve_dep(
        "io.completely.unrelated:thing", scan, target=tmp_path,
    )
    assert r.verdict == "not_evaluated"
    assert "heuristic" in r.confidence.reason.lower()


def test_resolve_only_test_file_imports_low_confidence(tmp_path: Path) -> None:
    """Imports only in test files -> ``imported`` but with low
    confidence (not the full production-path signal)."""
    _java(tmp_path, "src/test/java/XTest.java",
          "package x;\n"
          "import org.springframework.core.Foo;\n"
          "class XTest {}\n")
    scan = scan_imports(tmp_path)
    r = resolve_dep("org.springframework:spring-core", scan, target=tmp_path)
    assert r.verdict == "imported"
    assert r.confidence.level == "low"


def test_resolve_malformed_coord_returns_not_evaluated(tmp_path: Path) -> None:
    """A coord without a colon isn't a valid Maven coord."""
    scan = scan_imports(tmp_path)
    r = resolve_dep("not-a-real-coord", scan, target=tmp_path)
    assert r.verdict == "not_evaluated"


def test_resolve_subpackage_match(tmp_path: Path) -> None:
    """Import of a sub-package counts: ``org.springframework.core.io``
    matches ``org.springframework`` prefix."""
    _java(tmp_path, "src/main/java/X.java",
          "package x;\n"
          "import org.springframework.core.io.Resource;\n"
          "class X {}\n")
    scan = scan_imports(tmp_path)
    r = resolve_dep("org.springframework:spring-core", scan, target=tmp_path)
    assert r.verdict == "imported"


def test_resolve_evidence_lines_carry_filename_and_line(tmp_path: Path) -> None:
    _java(tmp_path, "src/main/java/X.java",
          "package x;\n"
          "import org.springframework.core.Foo;\n"
          "class X {}\n")
    scan = scan_imports(tmp_path)
    r = resolve_dep("org.springframework:spring-core", scan, target=tmp_path)
    assert any("X.java:" in line for line in r.evidence)


# ---------------------------------------------------------------------------
# Curated overrides — sanity
# ---------------------------------------------------------------------------


def test_overrides_table_well_formed() -> None:
    """Each override entry is ``groupId:artifactId -> dotted.path``."""
    for coord, prefix in _PACKAGE_OVERRIDES.items():
        assert ":" in coord, coord
        assert "." in prefix or prefix.isidentifier(), prefix


# ---------------------------------------------------------------------------
# Integration with the orchestrator (scan() entry point)
# ---------------------------------------------------------------------------


def test_orchestrator_routes_maven_to_this_handler(tmp_path: Path) -> None:
    """The reachability orchestrator picks up Maven deps via
    ``_HANDLERS["Maven"]`` and produces ``imported`` for matches."""
    from packages.sca.models import (
        Confidence, Dependency, PinStyle,
    )
    from packages.sca.reachability import scan

    _java(tmp_path, "src/main/java/X.java",
          "package x;\nimport org.springframework.core.Foo;\nclass X {}\n")
    dep = Dependency(
        ecosystem="Maven",
        name="org.springframework:spring-core",
        version="5.3.0",
        declared_in=tmp_path / "pom.xml",
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl="pkg:maven/org.springframework/spring-core@5.3.0",
        parser_confidence=Confidence("high", reason="t"),
    )
    out = scan(tmp_path, [dep])
    assert out[dep.key()].verdict == "imported"
