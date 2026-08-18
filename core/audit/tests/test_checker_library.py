"""Tests for audit's use of the unified RuleLibrary.

Verifies the audit-specific integration points: add_rule (direct add
without CheckerSynthesisResult), record_match, retire_low_precision,
graduate, and summary.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

_WORKTREE_ROOT = Path(__file__).resolve().parents[3]
_MAIN_REPO = Path(os.environ.get("RAPTOR_DIR", str(_WORKTREE_ROOT)))
# Hard-SET (never setdefault; same value — _MAIN_REPO already resolves
# the deliberate ambient-first choice above, falling back to this tree).
os.environ["RAPTOR_DIR"] = str(_MAIN_REPO)
for _p in (str(_MAIN_REPO), str(_WORKTREE_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from packages.checker_synthesis.library import (  # noqa: E402
    RuleLibrary,
    TargetRecord,
)


def _add_rule(lib, rule_id="r1", engine="semgrep", cwe="CWE-89", **kw):
    return lib.add_rule(
        rule_id=rule_id,
        engine=engine,
        body=f"rules:\n  - id: {rule_id}\n    pattern: $X\n",
        cwe=cwe,
        source="audit",
        **kw,
    )


class TestAddRule:
    def test_add_creates_entry_and_rule_file(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        entry = _add_rule(lib)
        assert entry.rule_id == "r1"
        assert entry.source == "audit"
        assert entry.dual_control is False
        assert (tmp_path / "lib" / "semgrep" / "r1.yml").exists()

    def test_add_deduplicates_by_body(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        e1 = _add_rule(lib, rule_id="r1")
        e2 = _add_rule(lib, rule_id="r1")
        assert e1 is e2
        assert len(lib.all_entries()) == 1

    def test_add_coccinelle(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        entry = lib.add_rule(
            rule_id="c1", engine="coccinelle",
            body="@@\n expression E;\n@@\n- E == E\n",
        )
        assert (tmp_path / "lib" / "coccinelle" / "c1.cocci").exists()
        assert entry.engine == "coccinelle"


class TestRecordMatch:
    def test_record_tp(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        _add_rule(lib)
        lib.record_match("r1", True)
        entry = lib.all_entries()[0]
        assert entry.total_variants == 1

    def test_record_fp(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        _add_rule(lib)
        lib.record_match("r1", False)
        entry = lib.all_entries()[0]
        assert entry.total_variants == 0

    def test_record_unknown_rule(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        lib.record_match("nonexistent", True)


class TestRetireLowPrecision:
    def test_retires_below_threshold(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        _add_rule(lib, rule_id="r1")
        entry = lib.all_entries()[0]
        entry.tp_rate = 0.1
        entry.targets = [
            TargetRecord(target_hash=f"t{i}", ts="", matches=2,
                         variants=0, tp_rate=0.1)
            for i in range(3)
        ]
        lib._save()

        lib2 = RuleLibrary(tmp_path / "lib")
        retired = lib2.retire_low_precision()
        assert "r1" in retired
        assert lib2.all_entries()[0].archived is True

    def test_keeps_high_precision(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        _add_rule(lib, rule_id="r1")


        entry = lib.all_entries()[0]
        entry.tp_rate = 0.9
        entry.targets = [
            TargetRecord(target_hash=f"t{i}", ts="", matches=2,
                         variants=1, tp_rate=0.9)
            for i in range(3)
        ]
        lib._save()

        lib2 = RuleLibrary(tmp_path / "lib")
        retired = lib2.retire_low_precision()
        assert retired == []

    def test_skips_insufficient_evidence(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        _add_rule(lib, rule_id="r1")
        entry = lib.all_entries()[0]
        entry.tp_rate = 0.0
        lib._save()

        lib2 = RuleLibrary(tmp_path / "lib")
        retired = lib2.retire_low_precision()
        assert retired == []


class TestGraduate:
    def test_graduates_high_quality_rule(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        # Graduation additionally requires the mechanical-control
        # tier (dual_control + rule_tier="library") — precision
        # stats alone cannot ship a rule to the engine rules dir.
        # This test pins the file-copy mechanics, so it supplies
        # the control evidence.
        _add_rule(lib, rule_id="grad1",
                  dual_control=True, rule_tier="library")


        entry = lib.all_entries()[0]
        entry.tp_rate = 0.9
        entry.total_variants = 3
        entry.targets = [
            TargetRecord(target_hash=f"t{i}", ts="", matches=2,
                         variants=1, tp_rate=0.9)
            for i in range(3)
        ]
        lib._save()

        lib2 = RuleLibrary(tmp_path / "lib")
        rules_dir = tmp_path / "engine-rules"
        graduated = lib2.graduate(rules_dir)
        assert "grad1" in graduated
        assert (rules_dir / "semgrep" / "rules" / "grad1.yaml").exists()

    def test_skips_low_precision(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        _add_rule(lib, rule_id="low1")


        entry = lib.all_entries()[0]
        entry.tp_rate = 0.3
        entry.total_variants = 1
        entry.targets = [
            TargetRecord(target_hash="t1", ts="", matches=5,
                         variants=1, tp_rate=0.3)
        ]
        lib._save()

        lib2 = RuleLibrary(tmp_path / "lib")
        graduated = lib2.graduate(tmp_path / "rules")
        assert graduated == []

    def test_skips_archived(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        _add_rule(lib, rule_id="arch1")


        entry = lib.all_entries()[0]
        entry.archived = True
        entry.tp_rate = 1.0
        entry.total_variants = 5
        entry.targets = [
            TargetRecord(target_hash="t1", ts="", matches=5,
                         variants=5, tp_rate=1.0)
        ]
        lib._save()

        lib2 = RuleLibrary(tmp_path / "lib")
        graduated = lib2.graduate(tmp_path / "rules")
        assert graduated == []

    def test_coccinelle_graduation_path(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        # Control evidence required by the graduation gate — this
        # test pins the coccinelle destination-path mechanics.
        lib.add_rule(
            rule_id="cocci1", engine="coccinelle",
            body="@@\n@@\n- foo()\n",
            dual_control=True, rule_tier="library",
        )


        entry = lib.all_entries()[0]
        entry.tp_rate = 1.0
        entry.total_variants = 3
        entry.targets = [
            TargetRecord(target_hash=f"t{i}", ts="", matches=2,
                         variants=1, tp_rate=1.0)
            for i in range(3)
        ]
        lib._save()

        lib2 = RuleLibrary(tmp_path / "lib")
        rules_dir = tmp_path / "engine-rules"
        graduated = lib2.graduate(rules_dir)
        assert "cocci1" in graduated
        assert (rules_dir / "coccinelle" / "cocci1.cocci").exists()


class TestSummary:
    def test_empty(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        assert "empty" in lib.summary()

    def test_with_entries(self, tmp_path):
        lib = RuleLibrary(tmp_path / "lib")
        _add_rule(lib, rule_id="r1")
        s = lib.summary()
        assert "1 active" in s
