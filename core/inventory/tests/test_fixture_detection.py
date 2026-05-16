"""Tests for ``core.inventory.fixture_detection``.

Two halves:

  * Path-pattern unit tests for ``is_fixture_path`` — exhaustive
    across the conventional fixture path shapes per language /
    framework.
  * Integration tests for ``detect_fixture`` — exercise the full
    path-match + reachability-gate flow with realistic inventory
    fixtures, mocked reachability outcomes, and adversarial
    inputs.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from core.inventory.fixture_detection import (
    FixtureVerdict,
    HarnessEvidence,
    detect_fixture,
    is_fixture_path,
)


# ---------------------------------------------------------------------------
# Path-pattern detection
# ---------------------------------------------------------------------------


class TestIsFixturePath:
    @pytest.mark.parametrize("path,expected_label", [
        ("tests/conftest.py", "tests directory"),
        ("tests/sub/test_foo.py", "tests directory"),
        ("test/foo.go", "tests directory"),
        ("src/__tests__/Foo.test.tsx", "JS __tests__ directory"),
        ("spec/lib/foo_spec.rb", "spec directory (Ruby/JS/etc.)"),
        ("internal/testdata/sample.txt", "Go testdata directory"),
        ("tests/fixtures/users.json", "tests directory"),
        ("fixtures/users.json", "fixtures directory"),
        ("test_runner.py", "Python test_*.py"),
        ("src/foo/test_bar.py", "Python test_*.py"),
        ("src/foo/bar_test.py", "Python *_test.py"),
        ("conftest.py", "pytest conftest.py"),
        ("src/conftest.py", "pytest conftest.py"),
        ("src/foo_test.go", "Go *_test.go"),
        ("Foo.test.js", "JS/TS *.test.{js,ts,jsx,tsx}"),
        ("Foo.test.ts", "JS/TS *.test.{js,ts,jsx,tsx}"),
        ("Foo.spec.tsx", "JS/TS *.spec.{js,ts,jsx,tsx}"),
        ("src/main/java/TestRunner.java", "Java Test*.java"),
        ("src/main/java/RunnerTest.java", "Java *Test.java"),
    ])
    def test_matches_conventional_fixture_paths(self, path, expected_label):
        matched, label = is_fixture_path(path)
        assert matched, f"expected match for {path!r}"
        assert label == expected_label

    @pytest.mark.parametrize("path", [
        "src/api/upload.py",
        "src/db/query.py",
        "src/auth/login.py",
        "lib/util.go",
        "internal/handler.go",  # internal/ is NOT testdata/
        "src/main.rs",
        "src/components/Button.tsx",
        "main.py",
        # Substring "test" inside a real word doesn't match — pattern
        # is component-anchored.
        "src/contestant.py",
        "src/protest.go",
    ])
    def test_does_not_match_production_paths(self, path):
        matched, label = is_fixture_path(path)
        assert not matched, f"unexpected match for {path!r}"
        assert label == ""

    def test_empty_path_returns_no_match(self):
        assert is_fixture_path("") == (False, "")

    def test_windows_separators_normalised(self):
        # Python OS-path separators get normalised to forward slash
        # before matching — Windows paths shouldn't break detection.
        matched, label = is_fixture_path("tests\\sub\\conftest.py")
        assert matched
        assert label == "tests directory"


# ---------------------------------------------------------------------------
# detect_fixture — full path + reachability gate
# ---------------------------------------------------------------------------


class TestDetectFixture:
    def test_non_fixture_path_short_circuits_to_false(self):
        v = detect_fixture(
            file_path="src/api/upload.py", function="save",
        )
        assert v.likely_test_harness == "false"
        assert v.evidence == ()

    def test_fixture_path_no_inventory_yields_candidate(self):
        v = detect_fixture(
            file_path="tests/conftest.py", function="setup_user",
        )
        assert v.likely_test_harness == "candidate"
        # Two evidence items: the path match and the
        # reachability-data-missing tag.
        assert len(v.evidence) == 2
        assert v.evidence[0].type == "fixture_path_match"
        assert v.evidence[1].type == "reachability_check"
        assert v.evidence[1].result == "data_missing"

    def test_fixture_path_with_called_verdict_yields_false(self):
        # Path matches BUT reachability says CALLED — production
        # caller exists, so D-5 must NOT fire.
        from core.inventory.reachability import (
            ReachabilityResult, Verdict,
        )
        with patch(
            "core.inventory.reachability.function_called",
            return_value=ReachabilityResult(
                verdict=Verdict.CALLED,
                evidence=(("src/api/main.py", 42),),
            ),
        ):
            v = detect_fixture(
                file_path="tests/conftest.py",
                function="setup_user",
                inventory={"files": [{"path": "src/x.py"}]},  # truthy; mocked anyway
                qualified_name="tests.conftest.setup_user",
            )
        assert v.likely_test_harness == "false"
        # Evidence preserved so operator can see WHY this wasn't
        # demoted — the production caller location.
        reach = next(
            e for e in v.evidence if e.type == "reachability_check"
        )
        assert reach.result == "reachable_from_prod"
        assert "src/api/main.py:42" in reach.checked_against

    def test_fixture_path_with_not_called_verdict_yields_true(self):
        from core.inventory.reachability import (
            ReachabilityResult, Verdict,
        )
        with patch(
            "core.inventory.reachability.function_called",
            return_value=ReachabilityResult(verdict=Verdict.NOT_CALLED),
        ):
            v = detect_fixture(
                file_path="tests/conftest.py",
                function="setup_user",
                inventory={"files": [{"path": "src/x.py"}]},
                qualified_name="tests.conftest.setup_user",
            )
        assert v.likely_test_harness == "true"
        reach = next(
            e for e in v.evidence if e.type == "reachability_check"
        )
        assert reach.result == "not_reachable_from_prod"

    def test_fixture_path_with_uncertain_yields_candidate(self):
        from core.inventory.reachability import (
            ReachabilityResult, Verdict,
        )
        with patch(
            "core.inventory.reachability.function_called",
            return_value=ReachabilityResult(
                verdict=Verdict.UNCERTAIN,
                uncertain_reasons=(("src/dynamic.py", "getattr"),),
            ),
        ):
            v = detect_fixture(
                file_path="tests/conftest.py",
                function="setup_user",
                inventory={"files": [{"path": "src/x.py"}]},
                qualified_name="tests.conftest.setup_user",
            )
        assert v.likely_test_harness == "candidate"
        reach = next(
            e for e in v.evidence if e.type == "reachability_check"
        )
        assert reach.result == "data_uncertain"
        assert any(
            "getattr" in s for s in reach.checked_against
        )

    def test_function_called_raises_falls_through_to_candidate(self):
        # Bad inventory / wrong shape → resolver raises. Helper
        # must NOT crash; verdict falls to candidate so LLM can
        # verify.
        with patch(
            "core.inventory.reachability.function_called",
            side_effect=ValueError("bad qname"),
        ):
            v = detect_fixture(
                file_path="tests/conftest.py",
                function="setup_user",
                inventory={"files": [{"path": "src/x.py"}]},
                qualified_name="tests.conftest.setup_user",
            )
        assert v.likely_test_harness == "candidate"
        reach = next(
            e for e in v.evidence if e.type == "reachability_check"
        )
        assert reach.result == "data_missing"

    def test_no_function_yields_candidate_after_path_match(self):
        # Path matches, function missing → can't construct
        # qualified name → can't run reachability gate → candidate.
        v = detect_fixture(
            file_path="tests/conftest.py", function="",
            inventory={"files": [{"path": "src/x.py"}]},
        )
        assert v.likely_test_harness == "candidate"

    def test_empty_inventory_files_yields_candidate(self):
        # ``inventory={"files": []}`` would let the resolver return
        # NOT_CALLED (no callers found because no files in the
        # inventory), which would falsely mark every fixture-path
        # finding as ``true``. Helper detects empty-inventory
        # upstream and falls to ``candidate``.
        v = detect_fixture(
            file_path="tests/conftest.py", function="f",
            inventory={"files": []},
            qualified_name="tests.conftest.f",
        )
        assert v.likely_test_harness == "candidate"

    def test_evidence_size_capped(self):
        # Reachability returns 100 evidence sites — fixture
        # detection caps the surface so on-disk evidence stays
        # bounded.
        from core.inventory.reachability import (
            ReachabilityResult, Verdict,
        )
        many_sites = tuple(("src/f.py", i) for i in range(100))
        with patch(
            "core.inventory.reachability.function_called",
            return_value=ReachabilityResult(
                verdict=Verdict.CALLED, evidence=many_sites,
            ),
        ):
            v = detect_fixture(
                file_path="tests/conftest.py",
                function="setup_user",
                inventory={"files": [{"path": "src/x.py"}]},
                qualified_name="tests.conftest.setup_user",
            )
        reach = next(
            e for e in v.evidence if e.type == "reachability_check"
        )
        # Bounded to 5 to keep the on-disk size sane.
        assert len(reach.checked_against) == 5


class TestSerialisation:
    def test_to_dict_round_trip_shape(self):
        v = FixtureVerdict(
            likely_test_harness="true",
            evidence=(
                HarnessEvidence(
                    type="fixture_path_match",
                    path="tests/conftest.py",
                    pattern="pytest conftest.py",
                ),
                HarnessEvidence(
                    type="reachability_check",
                    result="not_reachable_from_prod",
                ),
            ),
        )
        d = v.to_dict()
        assert d["likely_test_harness"] == "true"
        assert len(d["harness_evidence"]) == 2
        assert d["harness_evidence"][0]["type"] == "fixture_path_match"
        assert d["harness_evidence"][0]["pattern"] == "pytest conftest.py"


# ---------------------------------------------------------------------------
# Adversarial — hostile / malformed inputs must not crash
# ---------------------------------------------------------------------------


class TestAdversarial:
    def test_path_traversal_in_file_path(self):
        # Doesn't crash; the pattern detector treats traversal
        # paths the same as any other — check still works on the
        # normalised form.
        v = detect_fixture(
            file_path="../../etc/passwd", function="getpwent",
        )
        assert v.likely_test_harness == "false"

    def test_extremely_long_path_does_not_blow_up(self):
        long_path = "tests/" + ("x" * 50_000)
        v = detect_fixture(file_path=long_path, function="f")
        # Path matched; evidence carries the full path (caller
        # decides whether to truncate).
        assert v.likely_test_harness == "candidate"

    def test_unicode_path(self):
        v = detect_fixture(
            file_path="tests/應用_test.py", function="f",
        )
        # Matches because "tests/" is anchored. Function present;
        # no inventory; falls to candidate.
        assert v.likely_test_harness == "candidate"

    def test_null_byte_in_path(self):
        # Path-pattern regex doesn't operate on null bytes
        # specially; doesn't crash.
        v = detect_fixture(
            file_path="tests/conftest.py\x00evil", function="f",
        )
        assert v.likely_test_harness in ("candidate", "false")

    def test_inventory_missing_files_key(self):
        # Resolver expects ``inventory["files"]``. Malformed
        # inventory raises; helper catches and falls to candidate.
        v = detect_fixture(
            file_path="tests/conftest.py", function="f",
            inventory={},  # no "files" key
            qualified_name="tests.conftest.f",
        )
        assert v.likely_test_harness == "candidate"
