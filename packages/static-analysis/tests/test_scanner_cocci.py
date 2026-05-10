"""Tests for ``scanner.run_cocci`` and helpers (PR-3).

Same hyphenated-package importlib pattern as ``test_scanner_semgrep``.
Covers:
  * ``_repo_has_c_cpp_source`` heuristic (positive, negative, bounded)
  * ``_shipped_cocci_rules_dir`` discovery
  * ``run_cocci`` skip paths (no spatch, no C source, no rules dir)
  * ``run_cocci`` happy path (mocked spatch, real SARIF write)
  * 1 real-spatch E2E that runs the shipped ``missing_null_check``
    rule against a tiny C fixture and verifies SARIF round-trips
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

_RAPTOR_DIR = os.environ["RAPTOR_DIR"]
if _RAPTOR_DIR not in sys.path:
    sys.path.insert(0, _RAPTOR_DIR)

# packages/static-analysis has a hyphen — load via importlib.
_SCANNER_PATH = Path(_RAPTOR_DIR) / "packages/static-analysis/scanner.py"
_spec = importlib.util.spec_from_file_location(
    "static_analysis_scanner_cocci", _SCANNER_PATH,
)
_scanner = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_scanner)


# ---------------------------------------------------------------------
# Repo-language heuristic
# ---------------------------------------------------------------------


def test_repo_has_c_cpp_source_finds_c(tmp_path):
    (tmp_path / "main.c").write_text("int main(void){return 0;}\n")
    assert _scanner._repo_has_c_cpp_source(tmp_path) is True


def test_repo_has_c_cpp_source_finds_header(tmp_path):
    (tmp_path / "include").mkdir()
    (tmp_path / "include" / "api.hpp").write_text("class A {};\n")
    assert _scanner._repo_has_c_cpp_source(tmp_path) is True


def test_repo_has_c_cpp_source_python_only_returns_false(tmp_path):
    (tmp_path / "main.py").write_text("\n")
    (tmp_path / "lib.py").write_text("\n")
    assert _scanner._repo_has_c_cpp_source(tmp_path) is False


def test_repo_has_c_cpp_source_missing_path_returns_false(tmp_path):
    assert _scanner._repo_has_c_cpp_source(tmp_path / "nonexistent") is False


def test_repo_has_c_cpp_source_bounded_scan(tmp_path):
    """50 .py files under a ``max_files_to_check=10`` cap → return
    False without walking the whole tree."""
    for i in range(50):
        (tmp_path / f"f{i}.py").write_text("\n")
    assert _scanner._repo_has_c_cpp_source(
        tmp_path, max_files_to_check=10,
    ) is False


# ---------------------------------------------------------------------
# Shipped rules discovery
# ---------------------------------------------------------------------


def test_shipped_cocci_rules_dir_resolves():
    """The in-tree shipped rules directory exists and is discovered
    by the scanner. Pin so a future repo-layout change that moves
    the rules surfaces here, not at /scan run time."""
    rules_dir = _scanner._shipped_cocci_rules_dir()
    assert rules_dir is not None
    assert rules_dir.is_dir()
    # At least the three documented production rules present.
    rule_files = sorted(p.name for p in rules_dir.glob("*.cocci"))
    for expected in (
        "missing_null_check.cocci",
        "lock_imbalance.cocci",
        "unchecked_return.cocci",
    ):
        assert expected in rule_files, (
            f"shipped rule {expected!r} missing — production rule "
            f"corpus drifted, /scan cocci leg lost coverage"
        )


# ---------------------------------------------------------------------
# run_cocci — skip paths
# ---------------------------------------------------------------------


def test_run_cocci_skips_when_spatch_missing(tmp_path):
    """spatch off PATH → returns [] without crash. Every consumer
    treats [] as "no SARIF added"."""
    (tmp_path / "x.c").write_text("\n")
    out = tmp_path / "out"; out.mkdir()
    with patch(
        "packages.coccinelle.runner.is_available", return_value=False,
    ):
        result = _scanner.run_cocci(tmp_path, out)
    assert result == []


def test_run_cocci_skips_when_no_c_source(tmp_path):
    """Python-only target → skipped silently (cocci is C-only)."""
    (tmp_path / "main.py").write_text("\n")
    out = tmp_path / "out"; out.mkdir()
    with patch(
        "packages.coccinelle.runner.is_available", return_value=True,
    ):
        result = _scanner.run_cocci(tmp_path, out)
    assert result == []


def test_run_cocci_skips_when_no_shipped_rules_dir(tmp_path):
    """No shipped rules → skipped silently (minimal install /
    packaging strip). Don't error; let other tools provide signal."""
    (tmp_path / "x.c").write_text("\n")
    out = tmp_path / "out"; out.mkdir()
    with patch(
        "packages.coccinelle.runner.is_available", return_value=True,
    ), patch.object(_scanner, "_shipped_cocci_rules_dir",
                    return_value=None):
        result = _scanner.run_cocci(tmp_path, out)
    assert result == []


# ---------------------------------------------------------------------
# run_cocci — happy path (mocked spatch)
# ---------------------------------------------------------------------


def test_run_cocci_writes_sarif_with_matches(tmp_path):
    """Mocked ``spatch_run_rules`` returns synthetic results;
    ``run_cocci`` must emit a valid SARIF at out_dir/cocci.sarif
    containing the rule + match."""
    (tmp_path / "x.c").write_text("\n")
    rules_dir = tmp_path / "rules"; rules_dir.mkdir()
    (rules_dir / "stub.cocci").write_text("@r@\n@@\n@@\n")
    out = tmp_path / "out"; out.mkdir()

    from packages.coccinelle.models import SpatchMatch, SpatchResult
    fake_results = [SpatchResult(
        rule="stub",
        matches=[SpatchMatch(file="x.c", line=1, message="found")],
    )]

    with patch(
        "packages.coccinelle.runner.is_available", return_value=True,
    ), patch(
        "packages.coccinelle.runner.run_rules", return_value=fake_results,
    ):
        sarifs = _scanner.run_cocci(tmp_path, out, rules_dir=rules_dir)

    assert len(sarifs) == 1
    sarif_path = Path(sarifs[0])
    assert sarif_path.name == "cocci.sarif"
    doc = json.loads(sarif_path.read_text())
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "coccinelle"
    assert len(run["results"]) == 1
    assert run["results"][0]["ruleId"] == "stub"


def test_run_cocci_emits_sarif_even_when_no_matches(tmp_path):
    """Clean target (no matches) → still emits a SARIF (with
    rule definitions in the driver, empty results list). Operators
    see what rules ran in the combined output."""
    (tmp_path / "x.c").write_text("\n")
    rules_dir = tmp_path / "rules"; rules_dir.mkdir()
    (rules_dir / "stub.cocci").write_text("@r@\n@@\n@@\n")
    out = tmp_path / "out"; out.mkdir()

    from packages.coccinelle.models import SpatchResult
    with patch(
        "packages.coccinelle.runner.is_available", return_value=True,
    ), patch(
        "packages.coccinelle.runner.run_rules",
        return_value=[SpatchResult(rule="stub", matches=[])],
    ):
        sarifs = _scanner.run_cocci(tmp_path, out, rules_dir=rules_dir)

    assert len(sarifs) == 1
    doc = json.loads(Path(sarifs[0]).read_text())
    run = doc["runs"][0]
    assert run["results"] == []
    # Rule still in driver:
    assert any(r["id"] == "stub" for r in run["tool"]["driver"]["rules"])


# ---------------------------------------------------------------------
# Real-spatch E2E
# ---------------------------------------------------------------------


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed — skip real-spatch E2E",
)
def test_e2e_real_spatch_finds_missing_null_check(tmp_path):
    """End-to-end: real spatch executes the shipped
    ``missing_null_check`` rule against a tiny C fixture, the
    scanner emits SARIF, and the SARIF carries the expected match.
    Pin against the shipped rule corpus so corpus drift surfaces here."""
    src_dir = tmp_path / "src"; src_dir.mkdir()
    # Classic missing-NULL-check pattern — malloc result dereferenced
    # without IS_ERR/NULL check.
    (src_dir / "vuln.c").write_text(
        "#include <stdlib.h>\n"
        "void deref_unchecked(void) {\n"
        "    int *p = malloc(sizeof(int));\n"
        "    *p = 42;\n"
        "}\n"
    )
    out = tmp_path / "out"; out.mkdir()

    sarifs = _scanner.run_cocci(tmp_path, out)
    assert sarifs, "expected SARIF emission against shipped rules"
    doc = json.loads(Path(sarifs[0]).read_text())
    run = doc["runs"][0]

    # missing_null_check should fire on the malloc + deref pattern.
    null_check_results = [
        r for r in run["results"] if r["ruleId"] == "missing_null_check"
    ]
    assert null_check_results, (
        f"missing_null_check rule didn't fire on the canonical "
        f"unchecked-deref pattern; got results: "
        f"{[r['ruleId'] for r in run['results']]!r}"
    )
    # Match points at vuln.c.
    files = {
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for r in null_check_results
    }
    assert any("vuln.c" in f for f in files), (
        f"match path doesn't include vuln.c; got files: {files!r}"
    )
