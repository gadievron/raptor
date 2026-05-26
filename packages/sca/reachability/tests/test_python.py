"""Tests for the Python reachability scanner."""

from __future__ import annotations

from pathlib import Path

from packages.sca.reachability.python import resolve_dep, scan_imports


def _write(p: Path, body: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


def test_scan_collects_top_level_modules(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "app.py", "import requests\nfrom packaging.version import Version\n")
    scan = scan_imports(repo)
    assert "requests" in scan
    assert "packaging" in scan


def test_scan_skips_node_modules_and_venv(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "src" / "ok.py", "import requests\n")
    _write(repo / ".venv" / "lib" / "shadow.py", "import poison\n")
    _write(repo / "node_modules" / "junk.py", "import poison\n")
    scan = scan_imports(repo)
    assert "requests" in scan
    assert "poison" not in scan


def test_scan_marks_test_files(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "src" / "app.py", "import requests\n")
    _write(repo / "tests" / "test_app.py", "import requests\n")
    scan = scan_imports(repo)
    flags = sorted(is_test for _path, _line, is_test in scan["requests"])
    assert flags == [False, True]


def test_scan_ignores_relative_imports(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "pkg" / "__init__.py", "")
    _write(repo / "pkg" / "a.py", "from . import b\nfrom .sub import c\n")
    scan = scan_imports(repo)
    # Only relative imports — no module names recorded.
    assert scan == {}


def test_resolve_dep_with_explicit_dist_to_module_map(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "app.py", "import yaml\n")
    scan = scan_imports(repo)
    r = resolve_dep("PyYAML", scan, target=repo)
    assert r.verdict == "imported"
    assert r.confidence.level == "high"
    assert any("app.py" in line for line in r.evidence)


def test_resolve_dep_heuristic_dash_to_underscore(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "x.py", "import my_lib\n")
    scan = scan_imports(repo)
    r = resolve_dep("my-lib", scan, target=repo)
    assert r.verdict == "imported"


def test_resolve_dep_with_no_imports_is_not_reachable(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "x.py", "import requests\n")
    scan = scan_imports(repo)
    r = resolve_dep("django", scan)
    assert r.verdict == "not_reachable"
    assert "no import found" in r.confidence.reason


def test_test_only_imports_classified_not_reachable(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "tests" / "test_x.py", "import pytest_mock\n")
    scan = scan_imports(repo)
    r = resolve_dep("pytest-mock", scan, target=repo)
    assert r.verdict == "not_reachable"
    assert "test code" in r.confidence.reason


def test_dotted_module_match_via_first_segment(tmp_path: Path) -> None:
    """``from google.protobuf import descriptor`` should reach the
    ``protobuf`` distribution via the dotted-module entry."""
    repo = tmp_path / "repo"
    _write(repo / "x.py", "from google.protobuf import descriptor\n")
    scan = scan_imports(repo)
    r = resolve_dep("protobuf", scan)
    assert r.verdict == "imported"


def test_syntax_error_in_one_file_does_not_break_scan(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "ok.py", "import requests\n")
    _write(repo / "bad.py", "def broken(:\n  pass")
    scan = scan_imports(repo)
    assert "requests" in scan


def test_evidence_truncation(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    for i in range(10):
        _write(repo / f"f{i}.py", "import requests\n")
    scan = scan_imports(repo)
    r = resolve_dep("requests", scan, target=repo)
    assert r.verdict == "imported"
    assert any("more" in line for line in r.evidence)
    assert len(r.evidence) <= 6   # 5 lines + the "... N more" footer
