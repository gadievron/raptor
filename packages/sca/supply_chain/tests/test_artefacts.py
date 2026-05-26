"""Tests for ``packages.sca.supply_chain.artefacts``."""

from __future__ import annotations

from pathlib import Path

from packages.sca.models import Manifest
from packages.sca.supply_chain.artefacts import scan_target


def test_pth_file_flagged(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "evil.pth").write_text(
        "import os; os.system('rm -rf /')\n", encoding="utf-8",
    )
    findings = scan_target(tmp_path, [])
    assert len(findings) == 1
    assert findings[0].kind == "python_pth_file"
    assert findings[0].severity == "high"


def test_pth_file_inside_excluded_dir_skipped(tmp_path: Path) -> None:
    (tmp_path / ".venv" / "lib").mkdir(parents=True)
    (tmp_path / ".venv" / "lib" / "junk.pth").write_text("import junk\n")
    assert scan_target(tmp_path, []) == []


def test_binary_in_tests_flagged(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    blob = b"\x7fELF\x02\x01\x01" + b"\x00" * (20 * 1024)
    (tmp_path / "tests" / "evil.bin").write_bytes(blob)
    findings = scan_target(tmp_path, [])
    assert any(f.kind == "binary_in_tests" for f in findings)


def test_small_test_binary_below_threshold_skipped(tmp_path: Path) -> None:
    """A small image fixture shouldn't trip the binary_in_tests heuristic.

    The full 8-byte PNG magic is needed so the new disguised_filename
    check (which validates extension/content) doesn't flag it instead.
    """
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "tiny.png").write_bytes(
        b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
    )
    assert scan_target(tmp_path, []) == []


def test_text_file_in_tests_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "fixture.txt").write_text("ascii " * 5000)
    assert scan_target(tmp_path, []) == []


def test_finding_anchored_to_nearest_manifest(tmp_path: Path) -> None:
    """The artefact finding's host is the manifest closest in the tree."""
    (tmp_path / "frontend").mkdir()
    pkg = tmp_path / "frontend" / "package.json"
    pkg.write_text("{}", encoding="utf-8")
    (tmp_path / "frontend" / "src").mkdir()
    (tmp_path / "frontend" / "src" / "evil.pth").write_text("x")
    manifests = [Manifest(path=pkg, ecosystem="npm", is_lockfile=False)]
    findings = scan_target(tmp_path, manifests)
    assert findings and findings[0].dependency.declared_in == pkg
    assert findings[0].dependency.ecosystem == "npm"


def test_node_modules_excluded(tmp_path: Path) -> None:
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "evil.pth").write_text("x")
    assert scan_target(tmp_path, []) == []
