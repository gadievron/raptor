"""Tests for Go module reachability (``packages.sca.reachability.gomod``)."""

from __future__ import annotations

from pathlib import Path

from packages.sca.reachability.gomod import (
    resolve_dep,
    scan_imports,
    _grep_symbols,
)


def test_scan_finds_single_import(tmp_path: Path) -> None:
    go_file = tmp_path / "main.go"
    go_file.write_text(
        'package main\n\nimport "github.com/foo/bar"\n',
        encoding="utf-8",
    )
    result = scan_imports(tmp_path)
    assert "github.com/foo/bar" in result
    assert result["github.com/foo/bar"][0][1] >= 1


def test_scan_finds_block_imports(tmp_path: Path) -> None:
    go_file = tmp_path / "main.go"
    go_file.write_text(
        'package main\n\nimport (\n\t"fmt"\n\t"github.com/foo/bar"\n)\n',
        encoding="utf-8",
    )
    result = scan_imports(tmp_path)
    assert "github.com/foo/bar" in result
    assert "fmt" in result


def test_scan_marks_test_files(tmp_path: Path) -> None:
    test_file = tmp_path / "main_test.go"
    test_file.write_text(
        'package main\n\nimport "github.com/stretchr/testify"\n',
        encoding="utf-8",
    )
    result = scan_imports(tmp_path)
    assert "github.com/stretchr/testify" in result
    assert result["github.com/stretchr/testify"][0][2] is True


def test_resolve_dep_imported(tmp_path: Path) -> None:
    go_file = tmp_path / "main.go"
    go_file.write_text(
        'package main\n\nimport "github.com/foo/bar"\n',
        encoding="utf-8",
    )
    scan = scan_imports(tmp_path)
    r = resolve_dep("github.com/foo/bar", scan, target=tmp_path)
    assert r.verdict == "imported"


def test_resolve_dep_subpackage_match(tmp_path: Path) -> None:
    go_file = tmp_path / "main.go"
    go_file.write_text(
        'package main\n\nimport "github.com/foo/bar/sub"\n',
        encoding="utf-8",
    )
    scan = scan_imports(tmp_path)
    r = resolve_dep("github.com/foo/bar", scan, target=tmp_path)
    assert r.verdict == "imported"


def test_resolve_dep_not_reachable(tmp_path: Path) -> None:
    go_file = tmp_path / "main.go"
    go_file.write_text(
        'package main\n\nimport "github.com/other/thing"\n',
        encoding="utf-8",
    )
    scan = scan_imports(tmp_path)
    r = resolve_dep("github.com/foo/bar", scan, target=tmp_path)
    assert r.verdict == "not_reachable"


def test_resolve_dep_test_only_not_reachable(tmp_path: Path) -> None:
    test_file = tmp_path / "main_test.go"
    test_file.write_text(
        'package main\n\nimport "github.com/foo/bar"\n',
        encoding="utf-8",
    )
    scan = scan_imports(tmp_path)
    r = resolve_dep("github.com/foo/bar", scan, target=tmp_path)
    assert r.verdict == "not_reachable"
    assert "test" in r.confidence.reason.lower()


def test_resolve_dep_with_advisory_symbols_likely_called(tmp_path: Path) -> None:
    go_file = tmp_path / "main.go"
    go_file.write_text(
        'package main\n\n'
        'import "github.com/foo/bar"\n\n'
        'func main() {\n\tbar.VulnerableFunc()\n}\n',
        encoding="utf-8",
    )
    scan = scan_imports(tmp_path)
    r = resolve_dep(
        "github.com/foo/bar", scan, target=tmp_path,
        advisory_symbols=["VulnerableFunc"],
    )
    assert r.verdict == "likely_called"
    assert r.confidence.level == "high"
    assert any("VulnerableFunc" in e for e in r.evidence)


def test_resolve_dep_with_advisory_symbols_not_found(tmp_path: Path) -> None:
    go_file = tmp_path / "main.go"
    go_file.write_text(
        'package main\n\n'
        'import "github.com/foo/bar"\n\n'
        'func main() {\n\tbar.SafeFunc()\n}\n',
        encoding="utf-8",
    )
    scan = scan_imports(tmp_path)
    r = resolve_dep(
        "github.com/foo/bar", scan, target=tmp_path,
        advisory_symbols=["VulnerableFunc"],
    )
    assert r.verdict == "imported"


def test_grep_symbols_word_boundary(tmp_path: Path) -> None:
    go_file = tmp_path / "main.go"
    go_file.write_text(
        'package main\n\nfunc main() {\n\tFoo()\n\tFooBar()\n}\n',
        encoding="utf-8",
    )
    hits = [(go_file, 4, False)]
    found = _grep_symbols(hits, ["Foo", "Baz"])
    assert "Foo" in found
    assert "Baz" not in found


def test_grep_symbols_multiple_files(tmp_path: Path) -> None:
    f1 = tmp_path / "a.go"
    f2 = tmp_path / "b.go"
    f1.write_text("package a\nfunc x() { Alpha() }\n", encoding="utf-8")
    f2.write_text("package b\nfunc y() { Beta() }\n", encoding="utf-8")
    hits = [(f1, 2, False), (f2, 2, False)]
    found = _grep_symbols(hits, ["Alpha", "Beta", "Gamma"])
    assert set(found) == {"Alpha", "Beta"}


def test_resolve_dep_advisory_symbols_in_test_only(tmp_path: Path) -> None:
    """Advisory symbols in test-only files should not upgrade to likely_called."""
    test_file = tmp_path / "main_test.go"
    test_file.write_text(
        'package main\n\n'
        'import "github.com/foo/bar"\n\n'
        'func TestX() {\n\tbar.VulnerableFunc()\n}\n',
        encoding="utf-8",
    )
    scan = scan_imports(tmp_path)
    r = resolve_dep(
        "github.com/foo/bar", scan, target=tmp_path,
        advisory_symbols=["VulnerableFunc"],
    )
    assert r.verdict == "not_reachable"
