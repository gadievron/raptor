"""Tests for .github/scripts/test_scope.py — import-graph-based
test tier dispatch."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from test_scope import (
    FAST_TIER_IGNORES,
    TIERS,
    batch_matrix,
    compute_tier_dispatch,
    file_in_dir,
    file_in_fast_tier,
    file_matches_tier,
    is_test_file,
)


class TestIsTestFile:
    def test_test_prefix(self):
        assert is_test_file(Path("core/llm/tests/test_client.py"))

    def test_test_suffix(self):
        assert is_test_file(Path("core/llm/client_test.py"))

    def test_in_tests_dir(self):
        assert is_test_file(Path("core/llm/tests/helpers.py"))

    def test_not_test(self):
        assert not is_test_file(Path("core/llm/client.py"))

    def test_not_python(self):
        assert not is_test_file(Path("core/llm/tests/data.json"))


class TestFileInDir:
    def test_direct_child(self):
        assert file_in_dir(Path("core/sandbox/tests/test_a.py"), "core/sandbox/tests")

    def test_exact_match(self):
        assert file_in_dir(Path("packages/sca"), "packages/sca")

    def test_no_match(self):
        assert not file_in_dir(Path("core/llm/tests/test_a.py"), "core/sandbox/tests")

    def test_no_prefix_collision(self):
        assert not file_in_dir(Path("core/sandbox_extra/test.py"), "core/sandbox")


class TestFileMatchesTier:
    def test_matches_test_dir(self):
        tier = {"test_dirs": ["core/sandbox/tests"]}
        assert file_matches_tier(Path("core/sandbox/tests/test_a.py"), tier)

    def test_matches_test_file(self):
        tier = {"test_files": ["core/security/tests/test_prompt_envelope_audit.py"]}
        assert file_matches_tier(
            Path("core/security/tests/test_prompt_envelope_audit.py"), tier
        )

    def test_no_match(self):
        tier = {"test_dirs": ["core/sandbox/tests"]}
        assert not file_matches_tier(Path("core/llm/tests/test_a.py"), tier)


class TestFileInFastTier:
    def test_fast_tier_test(self):
        assert file_in_fast_tier(Path("core/llm/tests/test_client.py"))

    def test_carved_out_test(self):
        assert not file_in_fast_tier(Path("core/sandbox/tests/test_a.py"))

    def test_sca_carved_out(self):
        assert not file_in_fast_tier(Path("packages/sca/tests/test_a.py"))

    def test_non_test_file(self):
        assert not file_in_fast_tier(Path("core/llm/client.py"))


class TestBatchMatrix:
    def test_empty_returns_empty(self):
        assert batch_matrix([]) == []

    def test_single_file(self):
        result = batch_matrix([Path("core/llm/tests/test_a.py")])
        assert len(result) == 1
        assert result[0]["batch"] == 1
        assert result[0]["files"] == "core/llm/tests/test_a.py"

    def test_under_threshold_single_batch(self):
        files = [Path(f"core/tests/test_{i}.py") for i in range(25)]
        result = batch_matrix(files)
        assert len(result) == 1
        assert len(result[0]["files"].split()) == 25

    def test_over_threshold_splits(self):
        files = [Path(f"core/tests/test_{i:03d}.py") for i in range(26)]
        result = batch_matrix(files)
        assert len(result) == 2
        sizes = [len(b["files"].split()) for b in result]
        assert sorted(sizes) == [13, 13]

    def test_large_count_caps_at_max(self):
        files = [Path(f"core/tests/test_{i:03d}.py") for i in range(200)]
        result = batch_matrix(files)
        assert len(result) == 8

    def test_batches_are_balanced(self):
        files = [Path(f"core/tests/test_{i:03d}.py") for i in range(50)]
        result = batch_matrix(files)
        sizes = [len(b["files"].split()) for b in result]
        assert max(sizes) - min(sizes) <= 1

    def test_files_are_sorted(self):
        files = [Path("z.py"), Path("a.py"), Path("m.py")]
        result = batch_matrix(files)
        assert result[0]["files"] == "a.py m.py z.py"

    def test_batch_numbers_sequential(self):
        files = [Path(f"t_{i}.py") for i in range(60)]
        result = batch_matrix(files)
        assert [b["batch"] for b in result] == [1, 2, 3]

    def test_custom_parameters(self):
        files = [Path(f"t_{i}.py") for i in range(10)]
        result = batch_matrix(files, max_batches=2, target_per_batch=3)
        assert len(result) == 2


class TestTierConsistency:
    """Verify TIERS and FAST_TIER_IGNORES are consistent."""

    def test_every_tier_with_test_dirs_is_in_fast_ignores(self):
        for name, config in TIERS.items():
            for d in config.get("test_dirs", []):
                if d.startswith("core/") or d.startswith("packages/"):
                    assert any(
                        d == fi or d.startswith(fi + "/")
                        for fi in FAST_TIER_IGNORES
                    ), f"Tier {name}'s test dir {d} not in FAST_TIER_IGNORES"

    def test_every_fast_ignore_has_a_tier(self):
        all_tier_dirs = set()
        for config in TIERS.values():
            for d in config.get("test_dirs", []):
                all_tier_dirs.add(d)
        for fi in FAST_TIER_IGNORES:
            if fi.endswith(".py"):
                continue
            has_tier = any(
                fi == td or fi.startswith(td + "/") or td.startswith(fi + "/")
                for td in all_tier_dirs
            )
            has_tests = any(Path(fi).rglob("test_*.py")) if Path(fi).is_dir() else False
            if has_tests:
                assert has_tier, (
                    f"FAST_TIER_IGNORES entry {fi} has test files "
                    f"but no tier handles it"
                )


@pytest.mark.slow
class TestOnRealRepo:
    """Integration tests against the actual RAPTOR codebase."""

    @pytest.fixture()
    def repo(self):
        repo = Path(__file__).resolve().parents[2]
        if not (repo / "core").is_dir():
            pytest.skip("not running from RAPTOR repo root")
        return repo

    def test_leaf_change_scopes_tightly(self, repo):
        result = compute_tier_dispatch(
            ["packages/web/scanner.py"], repo
        )
        active = [t for t, i in result.items()
                  if not t.startswith("_") and i["run"]]
        assert len(active) <= 3, f"leaf change activated too many tiers: {active}"

    def test_sca_only_change(self, repo):
        result = compute_tier_dispatch(
            ["packages/sca/optimise.py"], repo
        )
        assert result["sca"]["run"]
        assert len(result["sca"]["files"]) > 0
        non_sca = [t for t, i in result.items()
                   if t != "sca" and not t.startswith("_") and i["run"]]
        assert len(non_sca) == 0, f"SCA-only change triggered: {non_sca}"

    def test_ci_script_change_triggers_ci_lint(self, repo):
        result = compute_tier_dispatch(
            [".github/scripts/compute_filters.py"], repo
        )
        assert result["ci_lint"]["run"]

    def test_prompt_audit_trigger(self, repo):
        result = compute_tier_dispatch(
            ["packages/llm_analysis/agent.py"], repo
        )
        assert result["prompt_audit"]["run"]

    def test_prompt_audit_trigger_files_match_registry(self, repo):
        """The prompt_audit tier's trigger_files must mirror
        _PROMPT_CONSTRUCTION_FILES from the audit module."""
        sys.path.insert(0, str(repo))
        try:
            from core.security.prompt_envelope_audit import (
                _PROMPT_CONSTRUCTION_FILES,
            )
        finally:
            sys.path.pop(0)

        tier_triggers = set(TIERS["prompt_audit"]["trigger_files"])
        required = set(_PROMPT_CONSTRUCTION_FILES) | {
            "core/security/prompt_envelope_audit.py",
            "core/security/tests/test_prompt_envelope_audit.py",
        }
        missing = required - tier_triggers
        assert not missing, (
            f"prompt_audit trigger_files missing registered files: {missing}\n"
            "Update TIERS['prompt_audit']['trigger_files'] in test_scope.py"
        )

    def test_no_changes_returns_all_skipped_or_empty(self, repo):
        result = compute_tier_dispatch(
            ["README.md"], repo
        )
        active = [t for t, i in result.items()
                  if not t.startswith("_") and i["run"]]
        assert len(active) == 0

    def test_python_tier_has_matrix(self, repo):
        """The python tier always includes a matrix key."""
        result = compute_tier_dispatch(
            ["core/config/__init__.py"], repo
        )
        assert "matrix" in result["python"]
        if result["python"]["run"]:
            matrix = result["python"]["matrix"]
            assert len(matrix) >= 1
            assert all("batch" in entry and "files" in entry
                       for entry in matrix)
            assert json.dumps(matrix)

    def test_python_matrix_empty_when_no_files(self, repo):
        result = compute_tier_dispatch(
            ["README.md"], repo
        )
        assert result["python"]["matrix"] == []

    def test_category_tier_has_file_list(self, repo):
        """Category tiers produce file lists, not whole directories."""
        result = compute_tier_dispatch(
            ["packages/sca/optimise.py"], repo
        )
        sca_files = result["sca"]["files"]
        assert len(sca_files) > 0
        assert all(is_test_file(f) for f in sca_files)
