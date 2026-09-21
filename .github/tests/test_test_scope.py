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
    ROOT_HARNESS_FILES,
    TIERS,
    batch_matrix,
    compute_tier_dispatch,
    expand_conftest,
    file_in_dir,
    file_in_fast_tier,
    file_matches_tier,
    is_dependency_manifest,
    is_test_file,
)


class TestExpandConftest:
    _ALL = [
        Path("conftest.py"),
        Path("core/llm/client.py"),
        Path("core/sandbox/tests/conftest.py"),
        Path("core/sandbox/tests/test_a.py"),
        Path("core/sandbox/context.py"),
    ]

    def test_nested_conftest_expands_to_its_tree_only(self):
        extra = expand_conftest(
            {Path("core/sandbox/tests/conftest.py")}, self._ALL,
        )
        assert extra == {Path("core/sandbox/tests/test_a.py")}

    def test_root_conftest_expands_to_whole_repo(self):
        # The root's prefix would be "./", which matches no relative
        # path — pre-fix the expansion returned nothing and a PR
        # touching only the root conftest dispatched zero tiers.
        extra = expand_conftest({Path("conftest.py")}, self._ALL)
        assert extra == set(self._ALL) - {Path("conftest.py")}

    def test_non_conftest_changes_expand_nothing(self):
        assert expand_conftest({Path("core/llm/client.py")}, self._ALL) == set()


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

    def test_fixtures_excluded(self):
        assert not is_test_file(Path("packages/llm_analysis/tests/fixtures/iris_e2e/src/app.py"))

    def test_fixtures_deep_excluded(self):
        assert not is_test_file(Path("core/dataflow/tests/fixtures/cvefix_cmdi_py/after/app.py"))


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


class TestCiLintTriggerClosure:
    """Registry closure: every repo file whose CONTENT a ci_lint test
    pins must fire the ci_lint tier, or a breaking edit to it merges
    green and reddens the next unrelated .github PR, misattributed."""

    def test_read_targets_are_covered_by_extra_triggers(self):
        # Mechanically enumerate the `_read("<path>")` targets across
        # the .github test suites (the convention content-pinning
        # tests use) and assert each is claimed by an extra_triggers
        # entry. Tests that pin content through other idioms
        # (directory scans like test_libexec_marker_coverage) cannot
        # be enumerated this way — their roots are covered by
        # explicit extra_triggers entries (libexec, bin).
        import ast as ast_mod

        github_dir = Path(__file__).resolve().parents[1]
        pinned: set[str] = set()
        for tf in [
            *(github_dir / "tests").glob("*.py"),
            *(github_dir / "scripts" / "tests").glob("*.py"),
        ]:
            tree = ast_mod.parse(tf.read_text(encoding="utf-8"))
            for node in ast_mod.walk(tree):
                if (
                    isinstance(node, ast_mod.Call)
                    and isinstance(node.func, ast_mod.Name)
                    and node.func.id == "_read"
                    and node.args
                    and isinstance(node.args[0], ast_mod.Constant)
                    and isinstance(node.args[0].value, str)
                ):
                    pinned.add(node.args[0].value)

        assert pinned, "no _read() pins found — enumeration broke"
        triggers = TIERS["ci_lint"]["extra_triggers"]
        uncovered = sorted(
            p for p in pinned
            if not any(p == t or p.startswith(t + "/") for t in triggers)
        )
        assert not uncovered, (
            f"ci_lint tests pin the content of {uncovered} but those "
            "paths do not fire the tier — add them to "
            "TIERS['ci_lint']['extra_triggers'] in test_scope.py"
        )


def _manifest_cache_key_gaps(
    workflows_dir: Path,
) -> tuple[list[str], list[str], list[str]]:
    """(unclaimed root keys, directory-level manifest keys, root keys)
    from the hashFiles() cache-key expressions in *workflows_dir*.

    ``*.y*ml``: GHA accepts both workflow extensions. A key counts as
    manifest-named when any path segment starts with ``requirements``
    or is ``pyproject.toml`` — that is exactly the vocabulary
    is_dependency_manifest claims, so a claimed name moving into a
    directory cannot drop out of the checked set silently.
    """
    import re

    args: set[str] = set()
    for wf in sorted(workflows_dir.glob("*.y*ml")):
        for call in re.findall(
            r"hashFiles\(([^)]*)\)", wf.read_text(encoding="utf-8")
        ):
            args.update(re.findall(r"'([^']+)'", call))
    root_level = sorted(a for a in args if "/" not in a)
    unclaimed = [
        a for a in root_level
        if not is_dependency_manifest(a.replace("*", "x"))
    ]
    moved = sorted(
        a for a in args
        if "/" in a and any(
            seg.startswith("requirements") or seg == "pyproject.toml"
            for seg in Path(a).parts
        )
    )
    return unclaimed, moved, root_level


def _active(result: dict) -> list[str]:
    return sorted(t for t, i in result.items()
                  if not t.startswith("_") and i["run"])


def _is_full_dispatch(result: dict) -> bool:
    return all(i["run"] for t, i in result.items() if not t.startswith("_"))


@pytest.fixture(scope="module")
def mini_repo(tmp_path_factory) -> Path:
    """Synthetic scan tree exercising every PR shape the dispatcher
    must map: imported modules, package tests, tier-owned packages,
    runtime data files with and without an owning package, and a
    package with code but no test coverage."""
    repo = tmp_path_factory.mktemp("mini_repo")
    # Imported module + its test (fast tier).
    (repo / "core/pkga").mkdir(parents=True)
    (repo / "core/pkga/__init__.py").write_text("")
    (repo / "core/pkga/mod.py").write_text("VALUE = 1\n")
    (repo / "core/pkga/tests").mkdir()
    (repo / "core/pkga/tests/fixtures").mkdir()
    (repo / "core/pkga/tests/fixtures/sample.json").write_text("{}")
    (repo / "core/pkga/tests/test_mod.py").write_text(
        "from pathlib import Path\n\nimport core.pkga.mod\n\n"
        'FIXTURES = Path(__file__).parent / "fixtures"\n\n'
        "def test_value():\n"
        "    assert core.pkga.mod.VALUE == 1\n"
    )
    # Runtime data owned by pkga (no test references the file itself).
    (repo / "core/pkga/data").mkdir()
    (repo / "core/pkga/data/rules.json").write_text("{}")
    # Data directory with NO .py-bearing ancestor below the scan root.
    (repo / "core/orphan").mkdir()
    (repo / "core/orphan/blob.bin").write_text("x")
    # Package with code but no tests and no importers.
    (repo / "core/untested").mkdir()
    (repo / "core/untested/helper.py").write_text("X = 1\n")
    (repo / "core/untested/data").mkdir()
    (repo / "core/untested/data/cfg.yml").write_text("a: 1\n")
    # Tier-owned package (sca's test_dirs is the whole package).
    (repo / "packages/sca/tests").mkdir(parents=True)
    (repo / "packages/sca/__init__.py").write_text("")
    (repo / "packages/sca/optimise.py").write_text("Y = 2\n")
    (repo / "packages/sca/tests/test_shape.py").write_text(
        "def test_shape():\n    assert True\n"
    )
    (repo / "packages/sca/data/popular").mkdir(parents=True)
    (repo / "packages/sca/data/popular/pypi.json").write_text("[]")
    # Repo-root entry module whose only dependent is a test that
    # imports it by bare name (the raptor*.py shape). Deliberately
    # NOT raptor-named: graph coverage derives from the root-level
    # location, never from a name pattern or hand-list.
    (repo / "entrymod.py").write_text("def main() -> int:\n    return 0\n")
    (repo / "core/pkga/tests/test_entry.py").write_text(
        "import entrymod\n\n"
        "def test_main():\n"
        "    assert entrymod.main() == 0\n"
    )
    return repo


class TestDispatchFailsOpen:
    """Simulation harness for the PR shapes that must never dispatch
    zero tiers: deleted / renamed imported modules, data-only changes,
    and workflow-harness-only changes. The dispatch decision fails
    toward FULL dispatch on any file it cannot map — never toward
    zero — while mappable shapes stay scoped."""

    def test_plain_edit_stays_scoped(self, mini_repo):
        # Control: an in-place edit of the same module dispatches its
        # test without falling to full dispatch.
        result = compute_tier_dispatch(["core/pkga/mod.py"], mini_repo)
        assert result["python"]["run"]
        assert Path("core/pkga/tests/test_mod.py") in result["python"]["files"]
        assert not _is_full_dispatch(result)

    def test_deleted_module_forces_full_dispatch(self, mini_repo):
        # A deletion PR lists the removed path; the file is absent
        # from the checkout, so the reverse graph has no key for it —
        # its broken importers cannot be resolved.
        result = compute_tier_dispatch(["core/pkga/gone.py"], mini_repo)
        assert _is_full_dispatch(result), (
            f"deleted module under-dispatched: only {_active(result)}"
        )

    def test_renamed_module_forces_full_dispatch(self, mini_repo):
        # A rename arrives as [old_path, new_path]; the old path is
        # absent from the checkout while importers still name it.
        result = compute_tier_dispatch(
            ["core/pkga/old_name.py", "core/pkga/mod.py"], mini_repo,
        )
        assert _is_full_dispatch(result), (
            f"renamed module under-dispatched: only {_active(result)}"
        )

    def test_missing_py_outside_graph_stays_scoped(self, mini_repo):
        # Both directions: a deleted .py the graph never covered
        # (outside core//packages) proves nothing about lost import
        # edges and must NOT torch scoping with a full dispatch.
        result = compute_tier_dispatch(["docs/example.py"], mini_repo)
        assert not _is_full_dispatch(result)
        assert _active(result) == []

    def test_data_only_in_tier_tree_runs_that_tier(self, mini_repo):
        # sca's test_dirs is the whole package: a data-only PR (the
        # weekly refresh auto-PR shape) must run the tier's tests —
        # corrupted detector data merged with zero tests before.
        result = compute_tier_dispatch(
            ["packages/sca/data/popular/pypi.json"], mini_repo,
        )
        assert result["sca"]["run"]
        assert Path("packages/sca/tests/test_shape.py") in result["sca"]["files"]
        assert not _is_full_dispatch(result)

    def test_data_only_owning_package_seeds_its_tests(self, mini_repo):
        # A runtime resource with no tier claim routes through the
        # package that owns it: core/pkga/data → core/pkga's modules →
        # their tests via the import graph.
        result = compute_tier_dispatch(
            ["core/pkga/data/rules.json"], mini_repo,
        )
        assert result["python"]["run"]
        assert Path("core/pkga/tests/test_mod.py") in result["python"]["files"]
        assert not _is_full_dispatch(result)

    def test_top_level_test_data_forces_full_dispatch(self, mini_repo):
        # The top-level test/ tree is data with repo-relative
        # consumers (sca-e2e corpora, scanner fixtures): the graph
        # cannot claim it, so a corpus-only PR must fail toward FULL
        # dispatch — it dispatched zero tiers before DATA_ROOTS
        # joined the resource routing.
        result = compute_tier_dispatch(
            ["test/data/sca-e2e/labels.json"], mini_repo,
        )
        assert _is_full_dispatch(result), (
            f"test/-data change under-dispatched: only {_active(result)}"
        )

    def test_test_data_python_fixture_forces_full_dispatch(self, mini_repo):
        # .py files under test/ are fixture data too — no import-graph
        # key, so seeding them proves nothing; they must route through
        # the same fail-toward-full arm, not the silent .py lane.
        result = compute_tier_dispatch(
            ["test/data/python_sql_injection.py"], mini_repo,
        )
        assert _is_full_dispatch(result), (
            f"test/-py fixture change under-dispatched: "
            f"only {_active(result)}"
        )

    def test_fixture_data_routes_to_referencing_test(self, mini_repo):
        # Fixture data maps to the tests that reference its directory
        # (Path(__file__).parent / "fixtures" chain in the test file).
        result = compute_tier_dispatch(
            ["core/pkga/tests/fixtures/sample.json"], mini_repo,
        )
        assert result["python"]["run"]
        assert Path("core/pkga/tests/test_mod.py") in result["python"]["files"]
        assert not _is_full_dispatch(result)

    @pytest.mark.parametrize("changed", [
        # No .py-bearing ancestor below the scan root at all.
        "core/orphan/blob.bin",
        # Owning package exists but its closure reaches no test.
        "core/untested/data/cfg.yml",
    ])
    def test_unmappable_data_forces_full_dispatch(self, mini_repo, changed):
        result = compute_tier_dispatch([changed], mini_repo)
        assert _is_full_dispatch(result), (
            f"unmappable resource under-dispatched: only {_active(result)}"
        )

    def test_resource_outside_scan_roots_stays_inert(self, mini_repo):
        # Both directions: docs and other out-of-tree files are not
        # runtime inputs to any tier — they must not fall to full
        # dispatch just because no mapping claims them.
        result = compute_tier_dispatch(["docs/guide.md"], mini_repo)
        assert _active(result) == []

    def test_dangling_symlink_tree_still_dispatches(self, tmp_path):
        # A dangling .py symlink anywhere under a scan root used to
        # crash graph construction (FileNotFoundError), reddening the
        # dispatch job for EVERY PR against that tree. It must instead
        # be inert for unrelated changes, and a PR that touches the
        # symlink itself fails toward full dispatch (not a regular
        # file on disk — same as a deletion).
        (tmp_path / "core/pkgb").mkdir(parents=True)
        (tmp_path / "core/pkgb/mod.py").write_text("V = 1\n")
        (tmp_path / "core/pkgb/tests").mkdir()
        (tmp_path / "core/pkgb/tests/test_mod.py").write_text(
            "import core.pkgb.mod\n\ndef test_v():\n"
            "    assert core.pkgb.mod.V == 1\n"
        )
        try:
            (tmp_path / "core/pkgb/dangling.py").symlink_to(
                tmp_path / "core/pkgb/no_such_target.py"
            )
        except OSError:
            pytest.skip("platform cannot create symlinks")

        # Unrelated edit: no crash, scoped dispatch.
        result = compute_tier_dispatch(["core/pkgb/mod.py"], tmp_path)
        assert Path("core/pkgb/tests/test_mod.py") in result["python"]["files"]
        assert not _is_full_dispatch(result)

        # The symlink itself changed: cannot be mapped, full dispatch.
        result = compute_tier_dispatch(["core/pkgb/dangling.py"], tmp_path)
        assert _is_full_dispatch(result), (
            f"changed dangling symlink under-dispatched: only {_active(result)}"
        )

    def test_root_module_edit_dispatches_importing_tests(self, mini_repo):
        # A PR editing only a repo-root entry module must dispatch the
        # tests that import it. Pre-fix the scan-root import filter
        # erased those edges: the module sat in the graph as a node
        # with zero reverse-dependents, the PR dispatched zero tiers,
        # and tests-passed went green with the importing tests unrun.
        result = compute_tier_dispatch(["entrymod.py"], mini_repo)
        assert result["python"]["run"], "root-module edit dispatched zero tiers"
        assert Path("core/pkga/tests/test_entry.py") in result["python"]["files"]
        assert not _is_full_dispatch(result)

    def test_root_module_deletion_forces_full_dispatch(self, mini_repo):
        # Deleting a root entry module (absent from the checkout, so
        # no graph key) must fail toward full dispatch — pre-fix only
        # a hand-list of two names was covered and deleting any other
        # root module stayed "outside graph → inert".
        result = compute_tier_dispatch(["gone_root.py"], mini_repo)
        assert _is_full_dispatch(result), (
            f"deleted root module under-dispatched: only {_active(result)}"
        )

    def test_tier_workflow_only_change_forces_full_dispatch(self, mini_repo):
        # tests.yml/_tier.yml ARE every tier's execution harness
        # (pytest invocations, env guards, venv steps). GHA runs the
        # modified workflow on the PR, but only the jobs that gate ON
        # — pre-fix that was none, so a tier-command regression merged
        # green and surfaced on the next real PR, misattributed.
        result = compute_tier_dispatch(
            [".github/workflows/tests.yml"], mini_repo,
        )
        assert _is_full_dispatch(result), (
            f"workflow-only PR under-dispatched: only {_active(result)}"
        )

    @pytest.mark.parametrize("manifest", [
        "requirements.txt",
        "requirements-dev.txt",
        "pyproject.toml",
    ])
    def test_dependency_manifest_forces_full_dispatch(self, mini_repo, manifest):
        # Every heavy tier installs from the root manifests (venv jobs
        # key their caches on hashFiles('requirements*.txt')); pre-fix
        # a manifest-only PR ran only the fast tier, so a pin bump
        # that broke a carved-out tier merged green and reddened that
        # tier's next unrelated run, misattributed.
        result = compute_tier_dispatch([manifest], mini_repo)
        assert _is_full_dispatch(result), (
            f"{manifest}-only PR under-dispatched: only {_active(result)}"
        )

    def test_nested_manifest_stays_inert(self, mini_repo):
        # Both directions: a requirements file inside a fixture tree
        # is test data, not the CI install surface — it must not torch
        # scoping with a full dispatch.
        result = compute_tier_dispatch(
            ["core/pkga/tests/fixtures/requirements.txt"], mini_repo,
        )
        assert not _is_full_dispatch(result)

    def test_hashfiles_manifests_are_claimed(self):
        # Oracle tying is_dependency_manifest to the CI install
        # surface it mirrors: every ROOT-LEVEL file the workflows'
        # hashFiles() cache keys reference must be claimed as a
        # manifest, and no manifest-named key may sit in a directory
        # (the pattern is root-only, so a cache key moved to e.g.
        # requirements/base.txt — even while other keys stay at root —
        # would silently dispatch only the fast tier again). Either
        # direction of drift fails loud with the remedy named.
        workflows = Path(__file__).resolve().parents[1] / "workflows"
        unclaimed, moved, root_level = _manifest_cache_key_gaps(workflows)
        assert root_level, "hashFiles enumeration broke (no root-level keys)"
        assert not unclaimed, (
            f"workflow cache keys reference root manifest(s) "
            f"{unclaimed} that is_dependency_manifest does not claim — "
            "widen the pattern in test_scope.py"
        )
        assert not moved, (
            f"workflow cache keys reference manifest(s) inside a "
            f"directory {moved} — is_dependency_manifest is root-level "
            "only, so these would dispatch nothing; widen the pattern "
            "in test_scope.py together with the cache-key move"
        )

    def test_hashfiles_oracle_flags_drift_shapes(self, tmp_path):
        # Failing-first fixtures for both drift directions, plus the
        # .yaml workflow extension (GHA accepts both spellings).
        (tmp_path / "new-name.yml").write_text(
            "key: ${{ hashFiles('constraints.txt') }}\n"
        )
        unclaimed, moved, root_level = _manifest_cache_key_gaps(tmp_path)
        assert unclaimed == ["constraints.txt"]

        (tmp_path / "new-name.yml").unlink()
        (tmp_path / "partial-move.yaml").write_text(
            "key: ${{ hashFiles('requirements.txt', "
            "'requirements/base.txt') }}\n"
        )
        unclaimed, moved, root_level = _manifest_cache_key_gaps(tmp_path)
        assert unclaimed == []
        assert moved == ["requirements/base.txt"]
        assert root_level == ["requirements.txt"]

    def test_scope_script_change_forces_full_dispatch(self, mini_repo):
        # The dispatcher itself under-dispatching is the same failure
        # shape: a scope-script bug gates every job off, so nothing
        # validates the change beyond its unit tests.
        result = compute_tier_dispatch(
            [".github/scripts/test_scope.py"], mini_repo,
        )
        assert _is_full_dispatch(result)

    def test_non_harness_workflow_stays_scoped(self, mini_repo):
        # Both directions: other workflows (lint.yml etc.) are not the
        # Python-tier harness — they fire ci_lint via extra_triggers,
        # never a full dispatch.
        result = compute_tier_dispatch(
            [".github/workflows/lint.yml"], mini_repo,
        )
        assert not _is_full_dispatch(result)
        assert _active(result) == ["ci_lint"]

    def test_mixed_data_and_code_change(self, mini_repo):
        # Mixed PR shape: tier-owned data + an imported module — both
        # routes dispatch, still without a full fallback.
        result = compute_tier_dispatch(
            ["packages/sca/data/popular/pypi.json", "core/pkga/mod.py"],
            mini_repo,
        )
        assert result["sca"]["run"]
        assert result["python"]["run"]
        assert not _is_full_dispatch(result)


@pytest.mark.slow
class TestOnRealRepo:
    """Integration tests against the actual RAPTOR codebase."""

    @pytest.fixture(scope="class")
    @staticmethod
    def repo():
        repo = Path(__file__).resolve().parents[2]
        if not (repo / "core").is_dir():
            pytest.skip("not running from RAPTOR repo root")
        return repo

    @pytest.fixture(scope="class", autouse=True)
    @staticmethod
    def _shared_import_graph(repo):
        """Build the whole-repo import graph once for the class.

        ``compute_tier_dispatch`` rebuilds the reverse import graph —
        an AST parse of every Python file in the repo, tens of seconds
        per call on a CI runner — on every invocation. The graph is a
        pure function of the tree, and the tree does not change while
        this class runs, so every test after the first re-derived the
        same value. Serve one build to all of them; discovery, the
        closure walk, tier mapping, and batching still run for real
        in each test.
        """
        import test_scope as _ts
        cached = _ts.build_graph(_ts.discover_py_files(repo), repo)
        real_build_graph = _ts.build_graph

        def _build_graph_cached(all_py, repo_arg):
            if repo_arg == repo:
                return cached
            return real_build_graph(all_py, repo_arg)

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(_ts, "build_graph", _build_graph_cached)
            yield

    @pytest.mark.parametrize("harness_file", sorted(ROOT_HARNESS_FILES))
    def test_root_harness_change_dispatches_every_tier(
            self, repo, harness_file):
        """A PR touching only a harness file (root pytest config, the
        tier workflows, or the scope scripts that drive dispatch)
        reconfigures what every tier runs; pre-fix it dispatched ZERO
        tiers and tests-passed went green with no tests run."""
        result = compute_tier_dispatch([harness_file], repo)
        inactive = [t for t, i in result.items()
                    if not t.startswith("_") and not i["run"]]
        assert inactive == [], (
            f"{harness_file} left tiers undispatched: {inactive}")
        assert result["python"]["files"], "fast tier got no files"

    def test_every_root_entry_module_dispatches(self, repo):
        """Closure oracle, derived from the tree — never a hand-list.

        Every repo-root .py file must either be harness-grade (in
        ROOT_HARNESS_FILES, forcing full dispatch — pinned by
        test_root_harness_change_dispatches_every_tier) or acquire
        reverse-dependents in the import graph so a PR editing it
        dispatches the tiers that test it. A new root entry point
        with neither fails here instead of silently dispatching zero
        tiers until the cron reddens, misattributed."""
        root_modules = sorted(
            p.name for p in repo.glob("*.py") if p.is_file()
        )
        assert root_modules, "root-module enumeration broke"
        undispatchable = []
        for name in root_modules:
            if name in ROOT_HARNESS_FILES:
                continue
            result = compute_tier_dispatch([name], repo)
            if not any(i["run"] for t, i in result.items()
                       if not t.startswith("_")):
                undispatchable.append(name)
        assert not undispatchable, (
            f"root entry module(s) dispatch ZERO test tiers: "
            f"{undispatchable} — no test imports them; add an importing "
            "test or register them in ROOT_HARNESS_FILES"
        )

    def test_nested_conftest_still_scopes_to_its_tree(self, repo):
        result = compute_tier_dispatch(
            ["core/sandbox/tests/conftest.py"], repo,
        )
        assert result["sandbox"]["run"]
        inactive = [t for t, i in result.items()
                    if not t.startswith("_") and not i["run"]]
        assert inactive, "nested conftest must not force full dispatch"

    def test_leaf_change_scopes_tightly(self, repo):
        result = compute_tier_dispatch(
            ["packages/web/scanner.py"], repo
        )
        active = [t for t, i in result.items()
                  if not t.startswith("_") and i["run"]]
        assert len(active) <= 3, f"leaf change activated too many tiers: {active}"

    def test_no_dead_deps_gate_in_result(self, repo):
        # deps-job gating lives in tests.yml (it ORs the venv tier
        # outputs); a "_deps" entry computed here was never emitted
        # (_emit_outputs skips underscore keys) and misled readers
        # into thinking this script drove the deps job.
        result = compute_tier_dispatch(
            ["packages/web/scanner.py"], repo
        )
        assert "_deps" not in result

    def test_sca_only_change(self, repo):
        result = compute_tier_dispatch(
            ["packages/sca/optimise.py"], repo
        )
        assert result["sca"]["run"]
        assert len(result["sca"]["files"]) > 0
        # raptor.py imports packages.sca.cli, so the entry-surface
        # tests that import raptor are genuine dependents and their
        # tiers legitimately dispatch (asserting zero non-sca tiers
        # here used to pin the erased root-module edges). The dispatch
        # must still stay scoped: no full fallback, and tiers with no
        # graph path from sca stay off.
        assert not _is_full_dispatch(result)
        assert not result["sandbox"]["run"]
        assert not result["sage"]["run"]

    def test_ci_script_change_triggers_ci_lint(self, repo):
        result = compute_tier_dispatch(
            [".github/scripts/compute_filters.py"], repo
        )
        assert result["ci_lint"]["run"]

    @pytest.mark.parametrize("changed", [
        ".github/workflows/lint.yml",
        "CLAUDE.md",
        ".claude/commands/scan.md",
        # test_ci_controls_docs pins README's self-check section and
        # pyproject's exact ruff select list; a breaking edit to
        # either merged green while only these tests would redden.
        "README.md",
        "pyproject.toml",
        # test_libexec_marker_coverage / test_symlink_hop_bound pin
        # the launcher-preamble templates byte-for-byte.
        "libexec/raptor-agentic",
        "bin/raptor",
    ])
    def test_asserted_content_change_triggers_ci_lint(self, repo, changed):
        # .github/tests pins workflow content (test_ci_controls_docs)
        # and CLAUDE.md / command-doc prose (test_lifecycle_doc_syntax);
        # edits to those files must fire the tier that runs them.
        result = compute_tier_dispatch([changed], repo)
        assert result["ci_lint"]["run"], f"{changed} did not fire ci_lint"

    def test_unrelated_root_file_does_not_trigger_ci_lint(self, repo):
        # The extra_triggers are exact/prefix-scoped: a root-level file
        # NO ci_lint test pins must not drag the whole tier in. (This
        # used to pin README.md as non-firing — wrong direction: its
        # content IS asserted by test_ci_controls_docs, so a README
        # edit that broke the pin merged green. LICENSE is pinned by
        # nothing this tier runs.)
        result = compute_tier_dispatch(["LICENSE"], repo)
        assert not result["ci_lint"]["run"]

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
        # LICENSE, not README.md: README now fires ci_lint (its content
        # is pinned by test_ci_controls_docs).
        result = compute_tier_dispatch(
            ["LICENSE"], repo
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
            ["LICENSE"], repo
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
