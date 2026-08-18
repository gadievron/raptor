"""Tests for the persistent rule library."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

RAPTOR_DIR = Path(__file__).resolve().parents[3]
# Hard-SET (never setdefault): the code under test derives paths from
# RAPTOR_DIR; an ambient value for another checkout must not win.
os.environ["RAPTOR_DIR"] = str(RAPTOR_DIR)
if str(RAPTOR_DIR) not in sys.path:
    sys.path.insert(0, str(RAPTOR_DIR))

from packages.checker_synthesis.cwe_families import (  # noqa: E402  (import after sys.path setup)
    cwe_family,
    cwe_siblings,
)
from packages.checker_synthesis.library import (  # noqa: E402  (import after sys.path setup)
    LibraryEntry,
    RuleLibrary,
    _body_hash,
    _compute_rates,
)
from packages.checker_synthesis.models import (  # noqa: E402  (import after sys.path setup)
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
    rule_tier: str = "library",
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
    # Library promotion requires every mechanical control to have
    # passed; the helper models that happy path by default.
    result.rule_tier = rule_tier if dual_control else "sweep_once"
    result.fix_mutant_control = True if rule_tier == "library" else None
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
        tp, _fp, count = _compute_rates(triage)
        assert tp == 1.0
        assert count == 1

    def test_empty(self):
        tp, _fp, count = _compute_rates([])
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

    def test_promote_rejects_sweep_once_tier(self, tmp_path):
        """Fail-closed library gate: dual control alone is not enough —
        a rule whose fix-mutant control did not pass (or whose fixtures
        were missing) stays rule_tier=sweep_once and is refused."""
        lib = RuleLibrary(tmp_path / "lib")
        result = _result(rule_tier="sweep_once")
        result.fix_mutant_control = None
        assert lib.promote(result) is None

    def test_promote_rejects_missing_rule_tier_field(self, tmp_path):
        """Legacy/foreign result objects without rule_tier fail closed."""
        lib = RuleLibrary(tmp_path / "lib")
        result = _result()
        del result.rule_tier
        assert lib.promote(result) is None

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


def _entry_dict(**overrides) -> dict:
    d = {
        "rule_id": "r1",
        "engine": "semgrep",
        "cwe": "CWE-89",
        "body_hash": "abc123",
        "rule_path": "semgrep/r1.yml",
        "rationale": "",
        "seed_file": "",
        "seed_function": "",
        "dual_control": True,
        "promoted_at": "",
        "tp_rate": 1.0,
        "fp_rate": 0.0,
        "total_variants": 5,
        "total_matches": 0,
        "targets": [],
        "archived": False,
    }
    d.update(overrides)
    return d


class TestFromDictTotalMatches:
    """``from_dict`` preserves an explicitly persisted ``total_matches: 0``
    instead of substituting ``total_variants`` — the legacy fallback
    applies only when the key is absent."""

    def test_explicit_zero_preserved(self):
        entry = LibraryEntry.from_dict(_entry_dict(total_matches=0))
        assert entry.total_matches == 0

    def test_round_trip_preserves_zero(self):
        entry = LibraryEntry.from_dict(_entry_dict(total_matches=0))
        again = LibraryEntry.from_dict(entry.to_dict())
        assert again.total_matches == 0

    def test_legacy_manifest_falls_back_to_total_variants(self):
        d = _entry_dict()
        del d["total_matches"]
        entry = LibraryEntry.from_dict(d)
        assert entry.total_matches == 5

    def test_nonzero_value_kept(self):
        entry = LibraryEntry.from_dict(_entry_dict(total_matches=7))
        assert entry.total_matches == 7


class TestPipelineMaintainsTotalMatches:
    """The promote / update pipeline maintains ``total_matches`` alongside
    ``total_variants`` so ``record_match`` derives ``tp_rate`` from a
    truthful denominator after a save/reload round-trip."""

    def test_promote_sets_total_matches(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        entry = lib.promote(_result(matches=3), target_hash="t1")
        assert entry is not None
        assert entry.total_matches == 3

    def test_promote_survives_reload(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        lib.promote(_result(matches=3), target_hash="t1")
        reloaded = RuleLibrary(tmp_path / "lib").all_entries()
        assert len(reloaded) == 1
        assert reloaded[0].total_matches == 3

    def test_repromote_increments_total_matches(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        lib.promote(_result(matches=3), target_hash="t1")
        entry = lib.promote(_result(matches=2), target_hash="t2")
        assert entry is not None
        assert entry.total_matches == 5

    def test_update_increments_total_matches(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        lib.promote(_result(matches=3), target_hash="t1")
        replay = _result(matches=2)
        entry = lib.update("r1", "t2", replay.matches, replay.triage)
        assert entry is not None
        assert entry.total_matches == 5

    def test_record_match_uses_true_denominator(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        lib.promote(_result(matches=3), target_hash="t1")
        # Reload to prove the denominator survives serialisation.
        lib = RuleLibrary(tmp_path / "lib")
        lib.record_match("r1", is_tp=True)
        lib.record_match("r1", is_tp=False)
        entry = lib.all_entries()[0]
        assert entry.total_matches == 5
        assert entry.total_variants == 4
        assert entry.tp_rate == 4 / 5

    def test_record_match_on_fresh_add_rule_entry(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        lib.add_rule("r2", "semgrep", "rules:\n  - id: r2\n")
        # Reload: total_matches must come back as the persisted 0, not
        # be silently replaced by total_variants.
        lib = RuleLibrary(tmp_path / "lib")
        lib.record_match("r2", is_tp=False)
        entry = lib.all_entries()[0]
        assert entry.total_matches == 1
        assert entry.total_variants == 0
        assert entry.tp_rate == 0.0


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


class TestPromoteStoresSageMetadata:
    """Graduation indexes the proven rule in SAGE (P33 write side)."""

    def test_promote_stores_rule_metadata(self, tmp_path):
        from unittest.mock import patch

        lib = RuleLibrary(library_dir=tmp_path)
        result = _result(matches=3, triage_status="variant")

        with patch(
            "core.sage.hooks.store_proven_rule_metadata", return_value=True,
        ) as mock_store:
            entry = lib.promote(result, target_hash="t1", timestamp="ts")

        assert entry is not None
        assert mock_store.call_count == 1
        kw = mock_store.call_args.kwargs
        assert kw["engine"] == "semgrep"
        assert kw["cwe"] == "CWE-89"
        assert kw["rule_id"] == entry.rule_id
        assert kw["rule_body_hash"] == entry.body_hash
        assert kw["rule_path"] == str(lib.rule_path(entry))
        assert kw["tp_count"] == 3
        assert kw["fp_count"] == 0
        assert kw["dual_control_passed"] is True
        assert kw["targets_tested"] == 1

    def test_promote_survives_sage_failure(self, tmp_path):
        from unittest.mock import patch

        lib = RuleLibrary(library_dir=tmp_path)
        result = _result()

        with patch(
            "core.sage.hooks.store_proven_rule_metadata",
            side_effect=RuntimeError("sidecar down"),
        ):
            entry = lib.promote(result, target_hash="t1", timestamp="ts")

        assert entry is not None  # SAGE failure never blocks graduation

    def test_refused_promotion_stores_nothing(self, tmp_path):
        from unittest.mock import patch

        lib = RuleLibrary(library_dir=tmp_path)
        result = _result(dual_control=False)

        with patch(
            "core.sage.hooks.store_proven_rule_metadata", return_value=True,
        ) as mock_store:
            assert lib.promote(result) is None

        mock_store.assert_not_called()


class TestAtomicRuleWrites:
    """Module contract: manifest AND rule files are written atomically.

    Both file-copy paths (promote-from-rule_path and graduate) must go
    through ``core.atomic_fs`` — a concurrent /scan or /agentic reader
    must never observe a half-copied rule file."""

    @staticmethod
    def _spy_atomic_writes(monkeypatch):
        import packages.checker_synthesis.library as lib_mod

        calls: list[Path] = []
        real = lib_mod.write_bytes_atomically

        def spy(path, content, **kwargs):
            calls.append(Path(path))
            real(path, content, **kwargs)

        monkeypatch.setattr(lib_mod, "write_bytes_atomically", spy)
        return calls

    def test_promote_copies_rule_file_atomically(self, tmp_path, monkeypatch):
        calls = self._spy_atomic_writes(monkeypatch)
        lib = RuleLibrary(tmp_path / "lib")
        result = _result()
        rule_file = tmp_path / "r1.yml"
        rule_file.write_text(result.rule.body)
        result.rule_path = rule_file

        entry = lib.promote(result, target_hash="t1", timestamp="ts")

        assert entry is not None
        dest = tmp_path / "lib" / "semgrep" / "r1.yml"
        assert dest in calls
        assert dest.read_text() == result.rule.body
        # No orphaned tempfiles left next to the rule.
        leftovers = [p for p in dest.parent.iterdir() if p.name != dest.name]
        assert leftovers == []

    def test_graduate_copies_rule_file_atomically(self, tmp_path, monkeypatch):
        lib = RuleLibrary(tmp_path / "lib")
        result = _result(matches=3)  # tp_rate 1.0, 3 variants, 3 matches
        rule_file = tmp_path / "r1.yml"
        rule_file.write_text(result.rule.body)
        result.rule_path = rule_file
        assert lib.promote(result, target_hash="t1", timestamp="ts") is not None

        calls = self._spy_atomic_writes(monkeypatch)
        engine_dir = tmp_path / "engine"
        graduated = lib.graduate(engine_dir)

        assert graduated == ["r1"]
        dest = engine_dir / "semgrep" / "rules" / "r1.yaml"
        assert dest in calls
        assert dest.read_text() == result.rule.body
        leftovers = [p for p in dest.parent.iterdir() if p.name != dest.name]
        assert leftovers == []


class TestAddRuleTierGate:
    """add_rule persists /audit-side rules; the tier gate must ride
    along or graduate() would ship uncontrolled rules to /scan."""

    def test_default_add_rule_is_sweep_once(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        entry = lib.add_rule("r1", "semgrep", "rules:\n  - id: r1\n")
        assert entry.rule_tier == "sweep_once"
        assert entry.dual_control is False

    def test_library_tier_requires_dual_control(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        entry = lib.add_rule(
            "r1", "semgrep", "rules:\n  - id: r1\n",
            rule_tier="library",  # claims library without controls
        )
        assert entry.rule_tier == "sweep_once"

    def test_full_control_evidence_accepted(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        entry = lib.add_rule(
            "r1", "semgrep", "rules:\n  - id: r1\n",
            dual_control=True, rule_tier="library",
        )
        assert entry.rule_tier == "library"
        assert entry.dual_control is True

    def test_unknown_tier_normalised_fail_closed(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        entry = lib.add_rule(
            "r1", "semgrep", "rules:\n  - id: r1\n",
            dual_control=True, rule_tier="totally-made-up",
        )
        assert entry.rule_tier == "sweep_once"

    def test_tier_roundtrips_through_manifest(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        lib.add_rule(
            "r1", "semgrep", "rules:\n  - id: r1\n",
            dual_control=True, rule_tier="library",
        )
        fresh = RuleLibrary(tmp_path / "lib")
        entry = fresh.get_by_body_hash(
            lib.get_by_body_hash.__self__._load()[0].body_hash,
        )
        assert entry.rule_tier == "library"

    def test_legacy_manifest_infers_tier_from_dual_control(self):
        legacy = {
            "rule_id": "r", "engine": "semgrep", "cwe": "CWE-89",
            "body_hash": "x", "rule_path": "semgrep/r.yml",
            "dual_control": True,
        }
        assert LibraryEntry.from_dict(legacy).rule_tier == "library"
        legacy["dual_control"] = False
        assert LibraryEntry.from_dict(legacy).rule_tier == "sweep_once"


class TestGraduateRequiresControls:
    """graduate() must require dual_control + rule_tier='library' —
    record_match-inflated tp_rate alone cannot ship a rule to the
    engine rules dir as a first-class /scan rule."""

    def test_uncontrolled_rule_never_graduates(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        lib.add_rule("r1", "semgrep", "rules:\n  - id: r1\n")
        # Inflate precision through match feedback alone.
        for _ in range(5):
            lib.record_match("r1", is_tp=True)
        # Give it target records so total_matches passes the threshold.
        match_list = [Match(file=f"src/f{i}.py", line=i) for i in range(5)]
        triage_list = [
            MatchTriage(match=m, status="variant", reasoning="t")
            for m in match_list
        ]
        lib.update("r1", target_hash="t1",
                   matches=match_list, triage=triage_list)
        entry = next(e for e in lib._load() if e.rule_id == "r1")
        assert entry.tp_rate >= 0.80          # thresholds all pass...
        assert sum(t.matches for t in entry.targets) >= 3
        graduated = lib.graduate(tmp_path / "engine")
        assert graduated == []                # ...controls still gate

    def test_promoted_rule_still_graduates(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        result = _result(matches=3)
        rule_file = tmp_path / "r1.yml"
        rule_file.write_text(result.rule.body)
        result.rule_path = rule_file
        assert lib.promote(result, target_hash="t1", timestamp="ts") \
            is not None
        graduated = lib.graduate(tmp_path / "engine")
        assert graduated == ["r1"]
