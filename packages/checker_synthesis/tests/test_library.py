"""Tests for the persistent rule library."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

RAPTOR_DIR = Path(__file__).resolve().parents[3]
os.environ.setdefault("RAPTOR_DIR", str(RAPTOR_DIR))
if str(RAPTOR_DIR) not in sys.path:
    sys.path.insert(0, str(RAPTOR_DIR))

from packages.checker_synthesis.cwe_families import (  # noqa: E402
    cwe_family,
    cwe_siblings,
)
from packages.checker_synthesis.library import (  # noqa: E402
    RuleLibrary,
    _body_hash,
    _compute_rates,
)
from packages.checker_synthesis.models import (  # noqa: E402
    CheckerSynthesisResult,
    Match,
    MatchTriage,
    SeedBug,
    SynthesisedRule,
)


def _seed(cwe: str = "CWE-89") -> SeedBug:
    return SeedBug(
        file="src/db.py",
        function="run_query",
        line_start=10,
        line_end=20,
        cwe=cwe,
        reasoning="SQL injection via string concat",
    )


def _rule(engine: str = "semgrep", rule_id: str = "r1") -> SynthesisedRule:
    return SynthesisedRule(
        engine=engine,
        rule_id=rule_id,
        body="rules:\n  - id: r1\n    pattern: $DB.execute($Q)\n",
        rationale="Matches unparameterised execute calls",
        test_positive="db.execute(user_input)",
        test_negative="db.execute('SELECT 1')",
    )


def _result(
    *,
    cwe: str = "CWE-89",
    engine: str = "semgrep",
    dual_control: bool = True,
    matches: int = 3,
    triage_status: str = "variant",
) -> CheckerSynthesisResult:
    seed = _seed(cwe)
    rule = _rule(engine)
    match_list = [
        Match(file=f"src/f{i}.py", line=i * 10) for i in range(matches)
    ]
    triage_list = [
        MatchTriage(match=m, status=triage_status, reasoning="test")
        for m in match_list
    ]
    result = CheckerSynthesisResult(seed=seed)
    result.rule = rule
    result.rule_path = Path("/tmp/fake/r1.yml")
    result.positive_control = True
    result.dual_control = dual_control
    result.matches = match_list
    result.triage = triage_list
    return result


class TestComputeRates:
    def test_all_variants(self):
        triage = [
            MatchTriage(match=Match(file="a.py", line=1), status="variant", reasoning=""),
            MatchTriage(match=Match(file="b.py", line=2), status="variant", reasoning=""),
        ]
        tp, fp, count = _compute_rates(triage)
        assert tp == 1.0
        assert fp == 0.0
        assert count == 2

    def test_mixed(self):
        triage = [
            MatchTriage(match=Match(file="a.py", line=1), status="variant", reasoning=""),
            MatchTriage(match=Match(file="b.py", line=2), status="false_positive", reasoning=""),
        ]
        tp, fp, count = _compute_rates(triage)
        assert tp == 0.5
        assert fp == 0.5
        assert count == 1

    def test_uncertain_excluded(self):
        triage = [
            MatchTriage(match=Match(file="a.py", line=1), status="variant", reasoning=""),
            MatchTriage(match=Match(file="b.py", line=2), status="uncertain", reasoning=""),
        ]
        tp, fp, count = _compute_rates(triage)
        assert tp == 1.0
        assert count == 1

    def test_empty(self):
        tp, fp, count = _compute_rates([])
        assert tp == 0.0
        assert count == 0


class TestRuleLibraryPromote:
    def test_promote_creates_manifest_and_rule_file(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        result = _result()
        # Write a real rule file so promote can copy it
        rule_file = tmp_path / "r1.yml"
        rule_file.write_text(result.rule.body)
        result.rule_path = rule_file

        entry = lib.promote(result, target_hash="abc123", timestamp="2026-07-23T12:00:00")

        assert entry is not None
        assert entry.rule_id == "r1"
        assert entry.engine == "semgrep"
        assert entry.cwe == "CWE-89"
        assert entry.dual_control is True
        assert entry.tp_rate == 1.0
        assert len(entry.targets) == 1
        assert entry.targets[0].target_hash == "abc123"

        manifest = tmp_path / "lib" / "manifest.json"
        assert manifest.exists()
        data = json.loads(manifest.read_text())
        assert len(data["rules"]) == 1

        rule_on_disk = tmp_path / "lib" / "semgrep" / "r1.yml"
        assert rule_on_disk.exists()
        assert "execute" in rule_on_disk.read_text()

    def test_promote_rejects_no_dual_control(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        result = _result(dual_control=False)
        assert lib.promote(result) is None

    def test_promote_rejects_no_rule(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        result = _result()
        result.rule = None
        assert lib.promote(result) is None

    def test_promote_rejects_no_triage(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        result = _result()
        result.triage = []
        assert lib.promote(result) is None

    def test_promote_deduplicates_by_body_hash(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        result1 = _result()
        rule_file = tmp_path / "r1.yml"
        rule_file.write_text(result1.rule.body)
        result1.rule_path = rule_file

        lib.promote(result1, target_hash="t1", timestamp="ts1")
        lib.promote(result1, target_hash="t2", timestamp="ts2")

        entries = lib.all_entries()
        assert len(entries) == 1
        assert len(entries[0].targets) == 2

    def test_promote_coccinelle(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        result = _result(engine="coccinelle")
        result.rule = _rule(engine="coccinelle")
        rule_file = tmp_path / "r1.cocci"
        rule_file.write_text(result.rule.body)
        result.rule_path = rule_file
        result.seed = _seed()

        entry = lib.promote(result, target_hash="t1")
        assert entry is not None
        assert (tmp_path / "lib" / "coccinelle" / "r1.cocci").exists()


class TestRuleLibraryFind:
    def test_find_by_cwe_and_engine(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        result = _result()
        rule_file = tmp_path / "r1.yml"
        rule_file.write_text(result.rule.body)
        result.rule_path = rule_file
        lib.promote(result, target_hash="t1")

        found = lib.find("CWE-89", "semgrep")
        assert len(found) == 1
        assert found[0].cwe == "CWE-89"

        assert lib.find("CWE-787", "semgrep") == []
        assert lib.find("CWE-89", "coccinelle") == []

    def test_find_excludes_archived(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        result = _result()
        rule_file = tmp_path / "r1.yml"
        rule_file.write_text(result.rule.body)
        result.rule_path = rule_file
        entry = lib.promote(result, target_hash="t1")
        entry.archived = True
        lib._save()

        assert lib.find("CWE-89", "semgrep") == []

    def test_find_replayable_requires_tp_threshold(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        result = _result(triage_status="false_positive")
        rule_file = tmp_path / "r1.yml"
        rule_file.write_text(result.rule.body)
        result.rule_path = rule_file
        lib.promote(result, target_hash="t1")

        assert lib.find_replayable("CWE-89", "semgrep") == []

    def test_find_replayable_with_high_tp(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        result = _result(triage_status="variant")
        rule_file = tmp_path / "r1.yml"
        rule_file.write_text(result.rule.body)
        result.rule_path = rule_file
        lib.promote(result, target_hash="t1")

        found = lib.find_replayable("CWE-89", "semgrep")
        assert len(found) == 1


class TestRuleLibraryUpdate:
    def test_update_adds_target(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        result = _result()
        rule_file = tmp_path / "r1.yml"
        rule_file.write_text(result.rule.body)
        result.rule_path = rule_file
        lib.promote(result, target_hash="t1")

        matches = [Match(file="new.py", line=5)]
        triage = [MatchTriage(match=matches[0], status="variant", reasoning="")]
        entry = lib.update("r1", "t2", matches, triage, timestamp="ts2")

        assert entry is not None
        assert len(entry.targets) == 2
        assert entry.targets[1].target_hash == "t2"

    def test_update_unknown_rule_returns_none(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        assert lib.update("nonexistent", "t1", [], []) is None

    def test_update_does_not_duplicate_target(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        result = _result()
        rule_file = tmp_path / "r1.yml"
        rule_file.write_text(result.rule.body)
        result.rule_path = rule_file
        lib.promote(result, target_hash="t1")

        matches = [Match(file="new.py", line=5)]
        triage = [MatchTriage(match=matches[0], status="variant", reasoning="")]
        lib.update("r1", "t1", matches, triage)

        entry = lib.get_by_body_hash(_body_hash(result.rule.body))
        assert len(entry.targets) == 1


class TestAutoArchive:
    def test_archives_after_n_targets_zero_variants(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        result = _result(matches=0)
        result.matches = []
        result.triage = [
            MatchTriage(
                match=Match(file="x.py", line=1),
                status="false_positive",
                reasoning="",
            ),
        ]
        rule_file = tmp_path / "r1.yml"
        rule_file.write_text(result.rule.body)
        result.rule_path = rule_file
        lib.promote(result, target_hash="t1")

        for i in range(2, 4):
            lib.update(
                "r1", f"t{i}",
                matches=[],
                triage=[],
                timestamp=f"ts{i}",
            )

        entry = lib.get_by_body_hash(_body_hash(result.rule.body))
        assert entry.archived is True

    def test_does_not_archive_with_variants(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        result = _result(triage_status="variant")
        rule_file = tmp_path / "r1.yml"
        rule_file.write_text(result.rule.body)
        result.rule_path = rule_file
        lib.promote(result, target_hash="t1")

        matches = [Match(file="new.py", line=5)]
        triage = [MatchTriage(match=matches[0], status="variant", reasoning="")]
        for i in range(2, 5):
            lib.update("r1", f"t{i}", matches, triage)

        entry = lib.get_by_body_hash(_body_hash(result.rule.body))
        assert entry.archived is False


class TestRuleLibraryPersistence:
    def test_reloads_from_disk(self, tmp_path):
        lib1 = RuleLibrary(tmp_path / "lib")
        result = _result()
        rule_file = tmp_path / "r1.yml"
        rule_file.write_text(result.rule.body)
        result.rule_path = rule_file
        lib1.promote(result, target_hash="t1")

        lib2 = RuleLibrary(tmp_path / "lib")
        entries = lib2.all_entries()
        assert len(entries) == 1
        assert entries[0].rule_id == "r1"

    def test_handles_corrupt_manifest(self, tmp_path):
        lib_dir = tmp_path / "lib"
        lib_dir.mkdir()
        (lib_dir / "manifest.json").write_text("not valid json")

        lib = RuleLibrary(lib_dir)
        assert lib.all_entries() == []

    def test_empty_library(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        assert lib.all_entries() == []
        assert lib.find("CWE-89", "semgrep") == []
        assert lib.find_replayable("CWE-89", "semgrep") == []


class TestRuleLibraryStats:
    def test_stats_empty(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        s = lib.stats()
        assert s["total_rules"] == 0
        assert s["active_rules"] == 0
        assert s["avg_tp_rate"] == 0.0

    def test_stats_with_entries(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        result = _result()
        rule_file = tmp_path / "r1.yml"
        rule_file.write_text(result.rule.body)
        result.rule_path = rule_file
        lib.promote(result, target_hash="t1")

        s = lib.stats()
        assert s["total_rules"] == 1
        assert s["active_rules"] == 1
        assert s["engines"]["semgrep"] == 1
        assert s["total_variants_found"] == 3
        assert s["avg_tp_rate"] == 1.0


class TestRulePath:
    def test_rule_path_resolves(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        result = _result()
        rule_file = tmp_path / "r1.yml"
        rule_file.write_text(result.rule.body)
        result.rule_path = rule_file
        entry = lib.promote(result, target_hash="t1")

        path = lib.rule_path(entry)
        assert path.exists()
        assert "execute" in path.read_text()


class TestCweFamilies:
    def test_known_family(self):
        assert cwe_family("CWE-89") == "sql_injection"
        assert cwe_family("CWE-564") == "sql_injection"

    def test_unknown_cwe_returns_itself(self):
        assert cwe_family("CWE-999") == "CWE-999"

    def test_siblings_returns_full_family(self):
        sibs = cwe_siblings("CWE-89")
        assert "CWE-89" in sibs
        assert "CWE-564" in sibs
        assert "CWE-943" in sibs

    def test_siblings_unknown_returns_singleton(self):
        assert cwe_siblings("CWE-999") == ["CWE-999"]

    def test_buffer_overflow_family(self):
        sibs = cwe_siblings("CWE-787")
        assert "CWE-120" in sibs
        assert "CWE-121" in sibs
        assert "CWE-122" in sibs

    def test_families_are_symmetric(self):
        for cwe in ["CWE-89", "CWE-564", "CWE-943"]:
            assert set(cwe_siblings(cwe)) == {"CWE-89", "CWE-564", "CWE-943"}


class TestCweFamilyLookup:
    def test_find_matches_sibling_cwe(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        result = _result(cwe="CWE-564")
        rule_file = tmp_path / "r1.yml"
        rule_file.write_text(result.rule.body)
        result.rule_path = rule_file
        lib.promote(result, target_hash="t1")

        found = lib.find("CWE-89", "semgrep")
        assert len(found) == 1
        assert found[0].cwe == "CWE-564"

    def test_find_replayable_matches_sibling_cwe(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        result = _result(cwe="CWE-564", triage_status="variant")
        rule_file = tmp_path / "r1.yml"
        rule_file.write_text(result.rule.body)
        result.rule_path = rule_file
        lib.promote(result, target_hash="t1")

        found = lib.find_replayable("CWE-89", "semgrep")
        assert len(found) == 1

    def test_unrelated_cwe_not_matched(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        result = _result(cwe="CWE-89")
        rule_file = tmp_path / "r1.yml"
        rule_file.write_text(result.rule.body)
        result.rule_path = rule_file
        lib.promote(result, target_hash="t1")

        assert lib.find("CWE-787", "semgrep") == []


class TestTargetProfile:
    def test_profile_roundtrips(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        result = _result()
        rule_file = tmp_path / "r1.yml"
        rule_file.write_text(result.rule.body)
        result.rule_path = rule_file
        lib.promote(result, target_hash="t1", timestamp="ts1")

        entry = lib.all_entries()[0]
        entry.targets[0].target_profile = "python;flask;postgresql"
        lib._save()

        lib2 = RuleLibrary(tmp_path / "lib")
        reloaded = lib2.all_entries()[0]
        assert reloaded.targets[0].target_profile == "python;flask;postgresql"

    def test_empty_profile_omitted_from_json(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        result = _result()
        rule_file = tmp_path / "r1.yml"
        rule_file.write_text(result.rule.body)
        result.rule_path = rule_file
        lib.promote(result, target_hash="t1")

        data = json.loads((tmp_path / "lib" / "manifest.json").read_text())
        target = data["rules"][0]["targets"][0]
        assert "target_profile" not in target
