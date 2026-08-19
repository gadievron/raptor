"""Keep the CI controls docs tied to real repo controls."""

from __future__ import annotations

import tomllib
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]


def _read(relative: str) -> str:
    return (REPO / relative).read_text(encoding="utf-8")


def test_ruff_rules_live_in_root_pyproject() -> None:
    config = tomllib.loads(_read("pyproject.toml"))
    assert config["tool"]["ruff"]["target-version"] == "py310"
    assert config["tool"]["ruff"]["lint"]["select"] == [
        "F401",
        "F811",
        "F821",
        "F841",
    ]


def test_lint_workflow_uses_ruff_config_instead_of_inline_rule_flags() -> None:
    workflow = _read(".github/workflows/lint.yml")
    assert "ruff check --select" not in workflow
    assert workflow.count("ruff check --output-format=github") == 2


def test_readme_links_to_ci_controls_doc() -> None:
    readme = _read("README.md")
    assert "## How RAPTOR checks itself" in readme
    assert "docs/ci-controls.md" in readme


def test_documented_control_paths_exist() -> None:
    required = [
        "pyproject.toml",
        "pytest.ini",
        ".github/workflows/lint.yml",
        ".github/workflows/tests.yml",
        ".github/workflows/nightly.yml",
        ".github/workflows/nightly_shuffled.yml",
        ".github/workflows/codeql.yml",
        ".github/workflows/miswiring-scan.yml",
        ".github/workflows/corpus-labels.yml",
        ".github/workflows/sca-pr-gate.yml",
        ".github/workflows/sca-self-bump.yml",
        ".github/workflows/sca-compromise-check.yml",
        ".github/workflows/sca-stress-sweep.yml",
        ".github/workflows/refresh-sca-calibration.yml",
        ".github/workflows/refresh-sca-project-samples.yml",
        ".github/workflows/refit-sca-calibration.yml",
        ".github/workflows/refresh-sca-data.yml",
        ".github/workflows/typosquat-reaudit.yml",
        ".github/workflows/ci-deps-image.yml",
        ".github/workflows/_tier.yml",
        ".github/workflows/release.yml",
        ".github/scripts/check_command_metadata.py",
        ".github/scripts/check_miswiring.py",
        ".github/scripts/check_env_docs.py",
        ".github/scripts/check_vocab_lists.py",
        ".github/scripts/check_optional_dep_imports.py",
        ".github/scripts/test_scope.py",
        ".github/scripts/codeql_scope.py",
        ".github/scripts/sarif_known_fp_suppressions.py",
        ".github/scripts/miswiring_baseline.json",
        ".github/scripts/vocab_baseline.json",
        ".github/scripts/env_docs_baseline.json",
        ".github/scripts/optional_dep_imports_baseline.json",
        ".github/codeql/codeql-config.yml",
        "core/dataflow/corpus",
        "core/dataflow/corpus_metrics.py",
        "test/data/smt_codeql_testbench",
        "test/data/sca-e2e/compromise-corpus",
        "test/data/sca-e2e/modes-corpus",
        "packages/sca/data/calibration",
        "packages/sca/calibration/validate.py",
        "packages/sca/calibration/stress.py",
    ]

    missing = [path for path in required if not (REPO / path).exists()]
    assert not missing, f"CI controls docs point at missing paths: {missing}"
