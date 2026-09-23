"""Tests for the persistent rule library."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

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
    rule_join_key,
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
        tp, fp, count, classified = _compute_rates(triage)
        assert tp == 1.0
        assert fp == 0.0
        assert count == 2
        assert classified == 2

    def test_mixed(self):
        triage = [
            MatchTriage(match=Match(file="a.py", line=1), status="variant", reasoning=""),
            MatchTriage(match=Match(file="b.py", line=2), status="false_positive", reasoning=""),
        ]
        tp, fp, count, classified = _compute_rates(triage)
        assert tp == 0.5
        assert fp == 0.5
        assert count == 1
        assert classified == 2

    def test_uncertain_excluded(self):
        triage = [
            MatchTriage(match=Match(file="a.py", line=1), status="variant", reasoning=""),
            MatchTriage(match=Match(file="b.py", line=2), status="uncertain", reasoning=""),
        ]
        tp, _fp, count, classified = _compute_rates(triage)
        assert tp == 1.0
        assert count == 1
        assert classified == 1

    def test_empty(self):
        tp, _fp, count, classified = _compute_rates([])
        assert tp == 0.0
        assert count == 0
        assert classified == 0

    def test_all_uncertain_classifies_nothing(self):
        # LLM transport failure stamps every match uncertain: no rate
        # exists — classified 0 is the signal callers gate on.
        triage = [
            MatchTriage(match=Match(file="a.py", line=1),
                        status="uncertain", reasoning=""),
            MatchTriage(match=Match(file="b.py", line=2),
                        status="skipped", reasoning=""),
        ]
        tp, _fp, count, classified = _compute_rates(triage)
        assert tp == 0.0
        assert count == 0
        assert classified == 0


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

    def test_find_replayable_requires_library_tier(self, tmp_path):
        # dual passed but fix-mutant failed: an add_rule sweep_once
        # entry that later accrues a rated target must stay
        # replay-ineligible — replay treats the rule as proven, and it
        # never proved it distinguishes fixed from unfixed code (same
        # doctrine as graduate()).
        lib = RuleLibrary(tmp_path / "lib")
        lib.add_rule(
            "r1", "semgrep", "rules:\n  - id: r1\n", cwe="CWE-89",
            dual_control=True,
        )
        matches = [Match(file="a.py", line=1)]
        triage = [MatchTriage(match=matches[0], status="variant",
                              reasoning="")]
        entry = lib.update("r1", "t1", matches, triage)
        assert entry is not None
        assert entry.tp_rate == 1.0
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

    def test_all_uncertain_update_records_no_rate(self, tmp_path):
        # An outage-shaped triage (all uncertain, matches present)
        # must persist tp_rate=None on the target record — pre-fix the
        # truthy triage LIST minted tp_rate=0.0, matches-weighted hard
        # negative evidence feeding the replay gate and retirement.
        lib = RuleLibrary(tmp_path / "lib")
        result = _result()
        rule_file = tmp_path / "r1.yml"
        rule_file.write_text(result.rule.body)
        result.rule_path = rule_file
        lib.promote(result, target_hash="t1")
        entry0 = lib.find(cwe="CWE-89", engine="semgrep")[0]
        agg_before = entry0.tp_rate

        matches = [Match(file="new.py", line=5),
                   Match(file="new2.py", line=6)]
        triage = [
            MatchTriage(match=m, status="uncertain", reasoning="outage")
            for m in matches
        ]
        entry = lib.update("r1", "t2", matches, triage, timestamp="ts2")
        assert entry is not None
        rec = [t for t in entry.targets if t.target_hash == "t2"][0]
        assert rec.tp_rate is None
        # No-evidence must not drag the aggregate.
        assert entry.tp_rate == agg_before

    def test_update_unknown_rule_returns_none(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        assert lib.update("nonexistent", "t1", [], []) is None


def _promote(lib, tmp_path, result):
    rule_file = tmp_path / "r1.yml"
    rule_file.write_text(result.rule.body)
    result.rule_path = rule_file
    return lib.promote(result, target_hash="t1")


class TestOutageIsNotEvidence:
    """An outage-shaped triage (matches present, nothing classified)
    is NO evidence — it must not feed retirement or auto-archive."""

    def test_all_uncertain_promote_cannot_retire(self, tmp_path):
        # Promote during an LLM outage: 6 matches, every triage row
        # uncertain. Pre-fix the entry aggregate seeded 0.0 and the
        # unrated target's matches met min_evidence, so the very next
        # retire_low_precision() archived a rule whose mechanical
        # controls all passed.
        lib = RuleLibrary(tmp_path / "lib")
        entry = _promote(
            lib, tmp_path, _result(matches=6, triage_status="uncertain"),
        )
        assert entry is not None
        assert lib.retire_low_precision() == []
        assert lib.find(cwe="CWE-89", engine="semgrep")[0].archived is False

    def test_rated_low_precision_still_retires(self, tmp_path):
        # Two-direction: genuine verdict-backed 0% precision with
        # enough rated matches still retires.
        lib = RuleLibrary(tmp_path / "lib")
        entry = _promote(
            lib, tmp_path,
            _result(matches=6, triage_status="false_positive"),
        )
        assert entry is not None
        assert lib.retire_low_precision() == ["r1"]
        assert lib.all_entries()[0].archived is True

    def test_outage_targets_do_not_advance_auto_archive(self, tmp_path):
        # A rule promoted during an outage plus two more outage-time
        # replays: three targets, none carrying verdict evidence.
        # Pre-fix they counted toward the archive floor and the rule
        # was archived as "0 variants across 3 targets".
        lib = RuleLibrary(tmp_path / "lib")
        _promote(
            lib, tmp_path, _result(matches=6, triage_status="uncertain"),
        )
        for th in ("t2", "t3"):
            matches = [Match(file=f"{th}.py", line=1)]
            triage = [MatchTriage(match=matches[0], status="uncertain",
                                  reasoning="outage")]
            entry = lib.update("r1", th, matches, triage)
        assert entry is not None
        assert entry.archived is False

    def test_zero_match_targets_still_auto_archive(self, tmp_path):
        # Two-direction: zero-match targets are deliberate negative
        # evidence (the rule found nothing) and still advance the
        # archive floor for a rule with no variants anywhere.
        lib = RuleLibrary(tmp_path / "lib")
        _promote(
            lib, tmp_path,
            _result(matches=3, triage_status="false_positive"),
        )
        for th in ("t2", "t3"):
            entry = lib.update("r1", th, [], [])
        assert entry is not None
        assert entry.archived is True

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


def _mixed_result(*, matches: int, classified_statuses: list[str]):
    """A result whose first len(classified_statuses) matches carry
    those verdicts and the rest are uncertain."""
    result = _result(matches=matches)
    result.triage = [
        MatchTriage(
            match=m,
            status=(classified_statuses[i]
                    if i < len(classified_statuses) else "uncertain"),
            reasoning="test",
        )
        for i, m in enumerate(result.matches)
    ]
    return result


class TestPartialOutageIsOneVerdict:
    """A partially-classified triage carries exactly its verdict
    count as evidence — one false_positive + five uncertain over six
    matches is ONE sample, not six."""

    def test_single_verdict_over_six_matches_cannot_retire(self, tmp_path):
        # Pre-fix: tp_rate=0.0 (rated) let ALL 6 matches feed
        # min_evidence and the rule retired off a single verdict.
        lib = RuleLibrary(tmp_path / "lib")
        entry = _promote(
            lib, tmp_path,
            _mixed_result(matches=6, classified_statuses=["false_positive"]),
        )
        assert entry is not None
        assert lib.retire_low_precision() == []
        assert lib.all_entries()[0].archived is False

    def test_enough_real_verdicts_still_retire(self, tmp_path):
        # Two-direction: verdict-backed 0% precision across targets
        # whose CLASSIFIED counts reach the floor still retires,
        # even when each triage also carried uncertain rows.
        lib = RuleLibrary(tmp_path / "lib")
        _promote(
            lib, tmp_path,
            _mixed_result(matches=4, classified_statuses=["false_positive"] * 3),
        )
        matches = [Match(file=f"m{i}.py", line=i) for i in range(4)]
        triage = [
            MatchTriage(match=m, status="false_positive", reasoning="t")
            for m in matches[:3]
        ] + [MatchTriage(match=matches[3], status="uncertain", reasoning="t")]
        lib.update("r1", "t2", matches, triage)
        assert lib.retire_low_precision() == ["r1"]

    def test_aggregate_weighs_verdicts_not_matches(self, tmp_path):
        # Target A: 5 matches, all classified variant (tp 100%).
        # Target B: 20 matches, ONE false_positive verdict.
        # Verdict-weighted aggregate is 5/6 — pre-fix the match-
        # weighted blend read 5/25 and genuine precision drowned
        # under one partial triage's match volume.
        lib = RuleLibrary(tmp_path / "lib")
        _promote(
            lib, tmp_path,
            _mixed_result(matches=5, classified_statuses=["variant"] * 5),
        )
        matches = [Match(file=f"m{i}.py", line=i) for i in range(20)]
        triage = [
            MatchTriage(match=matches[0], status="false_positive",
                        reasoning="t"),
        ] + [
            MatchTriage(match=m, status="uncertain", reasoning="t")
            for m in matches[1:]
        ]
        entry = lib.update("r1", "t2", matches, triage)
        assert entry is not None
        assert entry.tp_rate == pytest.approx(5 / 6)
        assert lib.retire_low_precision() == []

    def test_target_record_classified_persisted(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        entry = _promote(
            lib, tmp_path,
            _mixed_result(matches=6, classified_statuses=["false_positive"]),
        )
        assert entry is not None
        assert entry.targets[0].matches == 6
        assert entry.targets[0].classified == 1
        # Round-trips through the manifest.
        reloaded = RuleLibrary(tmp_path / "lib").all_entries()[0]
        assert reloaded.targets[0].classified == 1

    def test_legacy_rated_record_defaults_classified_to_matches(self):
        from packages.checker_synthesis.library import TargetRecord
        t = TargetRecord.from_dict({
            "target_hash": "t1", "ts": "", "matches": 6,
            "variants": 2, "tp_rate": 0.33,
        })
        # Pre-field evidence weight preserved for legacy manifests.
        assert t.classified == 6

    def test_legacy_unrated_record_defaults_classified_to_zero(self):
        from packages.checker_synthesis.library import TargetRecord
        t = TargetRecord.from_dict({
            "target_hash": "t1", "ts": "", "matches": 6,
            "variants": 0, "tp_rate": None,
        })
        assert t.classified == 0


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


class TestPathConfinement:
    """rule_id / engine become file-name components; ids also arrive
    from persisted manifests and replayed metadata stores that are not
    re-validated upstream, so the library boundary itself must confine
    them — a traversal id must never write outside the library dir
    (or, at graduation, outside the engine rules dir)."""

    @staticmethod
    def _everything_under(base: Path) -> bool:
        base = base.resolve()
        return all(
            p.resolve().is_relative_to(base)
            for p in base.rglob("*")
        )

    def test_add_rule_traversal_ids_confined(self, tmp_path):
        root = tmp_path / "root"
        lib_dir = root / "lib"
        lib = RuleLibrary(lib_dir)
        for bad_id in ("../../evil", "/abs/path", "a/b", ".."):
            lib.add_rule(bad_id, "semgrep", f"rules: {bad_id}\n")
        lib.add_rule("ok-rule", "../../evil-engine", "rules: e\n")
        # Nothing escaped the library dir...
        assert not (tmp_path / "evil.yml").exists()
        assert not Path("/abs/path.yml").exists()
        assert self._everything_under(lib_dir)
        # ...and every entry's recorded path resolves inside it.
        for e in lib.all_entries():
            assert (lib_dir / e.rule_path).resolve().is_relative_to(
                lib_dir.resolve(),
            )

    def test_add_rule_safe_id_round_trips(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        entry = lib.add_rule("src_db.py.run_query.CWE-89.0", "semgrep",
                             "rules: ok\n")
        dest = tmp_path / "lib" / entry.rule_path
        assert dest.exists()
        assert dest.read_text() == "rules: ok\n"
        assert entry.rule_path == "semgrep/src_db.py.run_query.CWE-89.0.yml"

    def test_graduate_traversal_manifest_confined(self, tmp_path):
        # Threat shape: the persisted manifest is loaded without
        # re-validation, so a traversal rule_id stored there must not
        # steer the graduation write outside the engine rules dir.
        lib_dir = tmp_path / "lib"
        (lib_dir / "semgrep").mkdir(parents=True)
        (lib_dir / "semgrep" / "evil.yml").write_text("rules: evil\n")
        manifest = {
            "rules": [{
                "rule_id": "../../escape",
                "engine": "semgrep",
                "cwe": "CWE-89",
                "body_hash": _body_hash("rules: evil\n"),
                "rule_path": "semgrep/evil.yml",
                "rationale": "",
                "seed_file": "",
                "seed_function": "",
                "dual_control": True,
                "promoted_at": "ts",
                "tp_rate": 1.0,
                "fp_rate": 0.0,
                "total_variants": 3,
                "total_matches": 3,
                "targets": [{
                    "target_hash": "t1", "ts": "ts",
                    "matches": 3, "variants": 3, "tp_rate": 1.0,
                }],
                "archived": False,
                "rule_tier": "library",
            }],
        }
        (lib_dir / "manifest.json").write_text(json.dumps(manifest))
        lib = RuleLibrary(lib_dir)
        engine_dir = tmp_path / "engine"
        graduated = lib.graduate(engine_dir)
        # Confined: whatever name it graduated under is INSIDE the dir.
        assert not (tmp_path / "escape.yaml").exists()
        assert not (tmp_path / "semgrep").exists()
        if graduated:
            assert self._everything_under(engine_dir)

    def test_graduate_normal_id_round_trips(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        result = _result(matches=3)
        rule_file = tmp_path / "r1.yml"
        rule_file.write_text(result.rule.body)
        result.rule_path = rule_file
        assert lib.promote(result, target_hash="t1", timestamp="ts") \
            is not None
        graduated = lib.graduate(tmp_path / "engine")
        assert graduated == ["r1"]
        dest = tmp_path / "engine" / "semgrep" / "rules" / "r1.yaml"
        assert dest.read_text() == result.rule.body


class TestRulePathCollision:
    """Two rules may share a rule_id with different bodies (same seed
    across runs / CVEs). Each body must keep its own file — otherwise
    the earlier manifest entry points at the later entry's body and a
    replay of entry 1 silently runs entry 2's rule."""

    def test_same_id_different_bodies_get_distinct_files(self, tmp_path):
        import hashlib

        lib = RuleLibrary(tmp_path / "lib")
        e1 = lib.add_rule("same-id", "semgrep", "rules: BODY-A\n")
        e2 = lib.add_rule("same-id", "semgrep", "rules: BODY-B\n")
        assert e1.rule_path != e2.rule_path
        body1 = (tmp_path / "lib" / e1.rule_path).read_text()
        body2 = (tmp_path / "lib" / e2.rule_path).read_text()
        assert body1 == "rules: BODY-A\n"
        assert body2 == "rules: BODY-B\n"
        # On-disk content matches each entry's recorded body hash.
        for e, body in ((e1, body1), (e2, body2)):
            assert e.body_hash == hashlib.sha256(
                body.encode(),
            ).hexdigest()[:16]

    def test_identical_body_still_dedups(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        e1 = lib.add_rule("same-id", "semgrep", "rules: BODY-A\n")
        e2 = lib.add_rule("same-id", "semgrep", "rules: BODY-A\n")
        assert e1 is e2 or e1.rule_path == e2.rule_path
        assert len(lib.all_entries()) == 1


class TestRecordMatchFeedback:
    """Per-match feedback is one verdict sample: it must nudge
    precision, never divide the verdict count by the raw match count
    (which includes untriaged sweep hits) — that let a single
    true-positive report collapse a proven rule below the replay and
    retirement thresholds."""

    def test_positive_feedback_does_not_collapse_proven_rule(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        lib.promote(_result(matches=3), target_hash="t1")
        # Inflate raw match count with an untriaged sweep (coverage
        # only, no verdicts).
        sweep_matches = [Match(file=f"m{i}.c", line=i) for i in range(97)]
        lib.update("r1", "t2", sweep_matches, [])
        entry = lib.all_entries()[0]
        assert entry.total_matches == 100
        assert entry.tp_rate == 1.0

        lib.record_match("r1", is_tp=True)
        entry = RuleLibrary(tmp_path / "lib").all_entries()[0]
        # A TP verdict must keep a perfect rule at 1.0 — not 4/101.
        assert entry.tp_rate == 1.0

    def test_negative_feedback_still_lowers_precision(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        lib.promote(_result(matches=3), target_hash="t1")
        lib.record_match("r1", is_tp=False)
        entry = lib.all_entries()[0]
        assert entry.tp_rate == 3 / 4

    def test_update_preserves_recorded_feedback(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        lib.promote(_result(matches=3), target_hash="t1")
        lib.record_match("r1", is_tp=False)  # 3 TP / 4 verdicts
        # A later replay recompute must not discard the FP verdict.
        replay_matches = [Match(file="n.c", line=1)]
        replay_triage = [
            MatchTriage(match=replay_matches[0], status="variant",
                        reasoning="t"),
        ]
        lib.update("r1", "t3", replay_matches, replay_triage)
        entry = lib.all_entries()[0]
        assert entry.tp_rate == pytest.approx(4 / 5)


class TestNonUniqueRuleIdJoin:
    """Mutation APIs must never resolve a shared rule_id
    first-entry-wins: replay verdicts, sweep coverage and precision
    feedback recorded onto a DIFFERENT rule body drive that rule
    toward retirement/graduation off evidence about another rule.
    Entries are produced through the real producer (promote), which
    documents that two bodies can legitimately share a rule id.
    """

    @staticmethod
    def _colliding_library(tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        lib.promote(_result(matches=3), target_hash="t1")
        res_b = _result(matches=3)
        res_b.rule = SynthesisedRule(
            engine="semgrep",
            rule_id="r1",  # same id...
            body="rules:\n  - id: r1\n    pattern: $DB.exec_two($Q)\n",
            rationale="re-synthesised body for the same seed",
        )
        lib.promote(res_b, target_hash="t2")
        entries = lib.all_entries()
        assert [e.rule_id for e in entries] == ["r1", "r1"]
        assert entries[0].body_hash != entries[1].body_hash
        return lib

    def test_update_by_join_key_hits_only_that_entry(self, tmp_path):
        lib = self._colliding_library(tmp_path)
        first, second = lib.all_entries()
        first_targets = {t.target_hash for t in first.targets}

        updated = lib.update(
            rule_join_key(second), "t9",
            [Match(file="v.py", line=1)],
            [MatchTriage(match=Match(file="v.py", line=1),
                         status="false_positive", reasoning="t")],
        )
        assert updated is not None
        assert updated.body_hash == second.body_hash

        reloaded_first, reloaded_second = RuleLibrary(
            tmp_path / "lib").all_entries()
        # The first entry's precision and targets are untouched.
        assert {t.target_hash for t in reloaded_first.targets} == first_targets
        assert reloaded_first.tp_rate == first.tp_rate
        assert "t9" in {t.target_hash for t in reloaded_second.targets}

    def test_update_by_shared_rule_id_refused(self, tmp_path):
        lib = self._colliding_library(tmp_path)
        before = [(e.body_hash, e.tp_rate, len(e.targets))
                  for e in lib.all_entries()]
        assert lib.update("r1", "t9", [Match(file="v.py", line=1)], []) is None
        after = [(e.body_hash, e.tp_rate, len(e.targets))
                 for e in RuleLibrary(tmp_path / "lib").all_entries()]
        assert after == before

    def test_record_match_shared_rule_id_refused(self, tmp_path):
        lib = self._colliding_library(tmp_path)
        before = [(e.tp_rate, e.feedback_classified)
                  for e in lib.all_entries()]
        lib.record_match("r1", is_tp=False)
        after = [(e.tp_rate, e.feedback_classified)
                 for e in RuleLibrary(tmp_path / "lib").all_entries()]
        assert after == before

    def test_record_match_joins_graduated_stem(self, tmp_path):
        # Graduated findings carry the sanitised FILE STEM, not the
        # raw rule id — feedback must still land on the entry.
        from packages.checker_synthesis.library import graduated_stem

        lib = RuleLibrary(tmp_path / "lib")
        lib.add_rule("weird id/with sep", "semgrep", "rules: BODY-A\n")
        stem = graduated_stem("weird id/with sep")
        assert stem != "weird id/with sep"
        lib.record_match(stem, is_tp=True)
        entry = lib.all_entries()[0]
        assert entry.feedback_classified == 1


class TestTotalsFollowTargetDedup:
    """total_matches / total_variants must follow the TargetRecord
    dedup: a re-sweep of an already-recorded target must not inflate
    the totals the per-target records refuse to double-count."""

    def _lib_with_rule(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        lib.add_rule(
            "r1", "semgrep", "rules:\n  - id: r1\n", cwe="CWE-89",
            dual_control=True,
        )
        return lib

    def test_same_target_resweep_does_not_inflate_totals(self, tmp_path):
        lib = self._lib_with_rule(tmp_path)
        matches = [Match(file="a.py", line=1)]
        triage = [MatchTriage(match=matches[0], status="variant",
                              reasoning="")]
        lib.update("r1", "t1", matches, triage)
        entry = lib.update("r1", "t1", matches, triage)
        assert entry is not None
        assert len(entry.targets) == 1
        assert entry.total_matches == 1
        assert entry.total_variants == 1

    def test_new_target_still_counts(self, tmp_path):
        lib = self._lib_with_rule(tmp_path)
        matches = [Match(file="a.py", line=1)]
        triage = [MatchTriage(match=matches[0], status="variant",
                              reasoning="")]
        lib.update("r1", "t1", matches, triage)
        entry = lib.update("r1", "t2", matches, triage)
        assert entry.total_matches == 2
        assert len(entry.targets) == 2


class TestPrecisionDenominatorsAgree:
    def test_summary_and_stats_share_the_rated_denominator(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        # One rated rule at 100%, one unrated (never replayed).
        lib.add_rule("rated", "semgrep", "rules:\n  - id: rated\n",
                     cwe="CWE-89", dual_control=True)
        lib.add_rule("unrated", "semgrep", "rules:\n  - id: unrated\n",
                     cwe="CWE-79", dual_control=True)
        m = [Match(file="a.py", line=1)]
        lib.update("rated", "t1", m,
                   [MatchTriage(match=m[0], status="variant",
                                reasoning="")])
        s = lib.stats()
        assert s["rated_rules"] == 1
        assert s["avg_tp_rate"] == 1.0          # rated-only average
        assert "avg precision 100%" in lib.summary()


class TestDefaultLibraryDirAnchor:
    def test_default_dir_anchors_at_raptor_dir(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RAPTOR_DIR", str(tmp_path))
        lib = RuleLibrary()
        assert lib.library_dir == tmp_path / "out" / "rule-library"

    def test_default_dir_falls_back_to_cwd_without_raptor_dir(
        self, tmp_path, monkeypatch,
    ):
        monkeypatch.delenv("RAPTOR_DIR", raising=False)
        monkeypatch.chdir(tmp_path)
        lib = RuleLibrary()
        assert lib.library_dir == tmp_path / "out" / "rule-library"
