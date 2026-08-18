"""Tests for prefilter/SARIF evidence↔hypothesis correlation.

An uncorrelated prefilter or cached-SARIF hit may be kept as review
context, but must not stamp evidence_tool, count as a tool-chain
confirmation, or drive suspicious→finding promotion.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

import pytest

from core.audit.prefilter import (
    PREFILTER_RULE_FAMILY,
    PrefilterHit,
    evidence_matches_hypothesis,
    family_for_rule,
)


class TestFamilyForRule:
    def test_prefilter_ids_resolve_via_map(self):
        assert family_for_rule("unbounded-strcpy") == "memory"
        assert family_for_rule("use-after-free") == "memory"
        assert family_for_rule("sql-string-format") == "injection"
        assert family_for_rule("path-join-no-containment") == "path"
        assert family_for_rule("toctou-filesystem") == "concurrency"
        assert family_for_rule("perl-chmod-unsafe") == "auth"
        assert family_for_rule("assign-in-conditional") == "other"

    def test_every_map_value_is_a_known_family(self):
        known = {
            "memory", "injection", "crypto", "auth",
            "concurrency", "path", "other",
        }
        assert set(PREFILTER_RULE_FAMILY.values()) <= known

    def test_sarif_rule_ids_inferred_from_text(self):
        assert family_for_rule(
            "python.lang.security.audit.sql-injection-db-cursor",
        ) == "injection"
        assert family_for_rule("cpp/unbounded-buffer-overflow") == "memory"
        assert family_for_rule("java/path-traversal-local") == "path"

    def test_unknown_rule_is_other(self):
        assert family_for_rule("totally-opaque-rule-9000") == "other"
        assert family_for_rule("") == "other"


class TestEvidenceMatchesHypothesis:
    def test_same_family_correlates(self):
        assert evidence_matches_hypothesis(
            "memory", "use after free of conn buffer",
        )
        assert evidence_matches_hypothesis(
            "injection", "SQL injection through user-controlled query",
        )
        assert evidence_matches_hypothesis(
            "path", "path traversal via unsanitised filename",
        )

    def test_cross_family_does_not_correlate(self):
        assert not evidence_matches_hypothesis(
            "memory", "SQL injection through user-controlled query",
        )
        assert not evidence_matches_hypothesis(
            "injection", "use after free of conn buffer",
        )

    def test_cwe_in_vuln_type_correlates(self):
        assert evidence_matches_hypothesis(
            "injection", "attacker controls the statement", "CWE-89",
        )
        assert evidence_matches_hypothesis(
            "memory", "stale pointer dereferenced", "CWE-416",
        )
        assert not evidence_matches_hypothesis(
            "memory", "attacker controls the statement", "CWE-89",
        )

    def test_other_family_never_correlates(self):
        assert not evidence_matches_hypothesis(
            "other", "assignment instead of comparison bug",
        )

    def test_empty_hypothesis_does_not_correlate(self):
        assert not evidence_matches_hypothesis("memory", "", "")


def _mk_outcome(hypothesis, cwe=""):
    from core.audit.orchestrator import ReviewOutcome

    outcome = ReviewOutcome(
        file="src/a.c",
        function="handler",
        status="finding",
        body="claim",
        hypothesis=hypothesis,
        line=10,
    )
    outcome.review_result = {"hypothesis": hypothesis}
    if cwe:
        outcome.review_result["cwe_class"] = cwe
    return outcome


def _mk_config(tmp_path):
    from core.audit.orchestrator import OrchestratorConfig

    (tmp_path / "out").mkdir(exist_ok=True)
    return OrchestratorConfig(
        target_path=tmp_path, out_dir=tmp_path / "out",
    )


def _unlink_chain_rules(chain):
    """Remove the on-disk audit_sweep_ rule files a chain carries.

    The real _run_tool_chain unlinks them in a finally; a stub that
    replaces it must do the same or every mocked sweep strands the
    rule file that _sweep_validate/_promote_suspicious just built.
    """
    import os
    for entry in chain:
        rule = entry.get("config", {}).get("rule") or ""
        if isinstance(rule, str) and \
                os.path.basename(rule).startswith("audit_sweep_"):
            Path(rule).unlink(missing_ok=True)


def _patch_common(monkeypatch, *, hits, chain_confirms):
    class _PF:
        def __init__(self, hits):
            self.hits = hits

    monkeypatch.setattr(
        "core.audit.orchestrator.run_prefilter",
        lambda **kw: _PF(list(hits)),
    )
    monkeypatch.setattr(
        "core.audit.orchestrator._read_raw_source",
        lambda *a, **kw: "void handler(void) { }",
    )
    calls = []

    def fake_chain(chain, *a, **kw):
        calls.append(kw)
        _unlink_chain_rules(chain)
        return list(chain_confirms)

    monkeypatch.setattr("core.audit.orchestrator._run_tool_chain", fake_chain)
    return calls


class TestSweepValidateCorrelation:
    UAF_HIT = PrefilterHit(
        rule_id="use-after-free",
        message="'p' freed at line 9, dereferenced at line 11",
        line=11,
    )

    def test_correlated_hit_stamps_evidence(self, tmp_path, monkeypatch):
        from core.audit.orchestrator import _sweep_validate

        _patch_common(monkeypatch, hits=[self.UAF_HIT], chain_confirms=[])
        outcome = _mk_outcome("use after free of request buffer")
        result = _sweep_validate(outcome, _mk_config(tmp_path))
        assert result.evidence_tool == "prefilter:use-after-free"

    def test_uncorrelated_hit_does_not_stamp(self, tmp_path, monkeypatch):
        from core.audit.orchestrator import _sweep_validate

        calls = _patch_common(
            monkeypatch, hits=[self.UAF_HIT], chain_confirms=[],
        )
        outcome = _mk_outcome(
            "SQL injection through user-controlled query parameter",
        )
        result = _sweep_validate(outcome, _mk_config(tmp_path))
        assert not (result.evidence_tool or "").startswith("prefilter:")
        # falls through to the hypothesis-specific tool chain
        assert len(calls) == 1

    def test_uncorrelated_hit_kept_as_context(self, tmp_path, monkeypatch):
        from core.audit.orchestrator import _sweep_validate

        _patch_common(monkeypatch, hits=[self.UAF_HIT], chain_confirms=[])
        outcome = _mk_outcome(
            "SQL injection through user-controlled query parameter",
        )
        result = _sweep_validate(outcome, _mk_config(tmp_path))
        ctx = (result.review_result or {}).get("uncorrelated_tool_hits")
        assert ctx and ctx[0]["rule_id"] == "use-after-free"

    def test_cwe_class_correlates_without_keywords(self, tmp_path, monkeypatch):
        from core.audit.orchestrator import _sweep_validate

        _patch_common(monkeypatch, hits=[self.UAF_HIT], chain_confirms=[])
        outcome = _mk_outcome(
            "stale object reachable after release", cwe="CWE-416",
        )
        result = _sweep_validate(outcome, _mk_config(tmp_path))
        assert result.evidence_tool == "prefilter:use-after-free"

    def test_first_correlated_hit_wins(self, tmp_path, monkeypatch):
        from core.audit.orchestrator import _sweep_validate

        sql_hit = PrefilterHit(
            rule_id="sql-string-format", message="fmt sql", line=12,
        )
        _patch_common(
            monkeypatch, hits=[self.UAF_HIT, sql_hit], chain_confirms=[],
        )
        outcome = _mk_outcome("SQL injection via string formatting")
        result = _sweep_validate(outcome, _mk_config(tmp_path))
        assert result.evidence_tool == "prefilter:sql-string-format"


class TestPromoteSuspiciousCorrelation:
    def _run(self, tmp_path, monkeypatch, *, hypothesis, hits, confirms=()):
        from core.audit.orchestrator import (
            OrchestratorResult,
            _promote_suspicious,
        )

        outcome = _mk_outcome(hypothesis)
        outcome.status = "suspicious"
        result = OrchestratorResult()
        result.outcomes = [outcome]
        result.suspicious = 1
        _patch_common(monkeypatch, hits=hits, chain_confirms=confirms)
        _promote_suspicious(result, _mk_config(tmp_path))
        return result

    def test_correlated_hit_promotes(self, tmp_path, monkeypatch):
        result = self._run(
            tmp_path, monkeypatch,
            hypothesis="use after free of request buffer",
            hits=[TestSweepValidateCorrelation.UAF_HIT],
        )
        assert result.outcomes[0].status == "finding"
        assert result.outcomes[0].evidence_tool == "prefilter:use-after-free"
        assert result.sweep_promoted == 1

    def test_uncorrelated_hit_does_not_promote(self, tmp_path, monkeypatch):
        result = self._run(
            tmp_path, monkeypatch,
            hypothesis="SQL injection through user-controlled query",
            hits=[TestSweepValidateCorrelation.UAF_HIT],
        )
        assert result.outcomes[0].status == "suspicious"
        assert result.sweep_promoted == 0
        ctx = (result.outcomes[0].review_result or {}).get(
            "uncorrelated_tool_hits",
        )
        assert ctx and ctx[0]["rule_id"] == "use-after-free"


class TestSarifCacheCorrelation:
    def _cache(self, rule_id, line=12):
        from core.audit.sweep import SarifCache

        cache = SarifCache()
        cache._by_file["src/a.c"] = [{
            "ruleId": rule_id,
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/a.c"},
                    "region": {"startLine": line},
                },
            }],
        }]
        return cache

    def _run_chain(self, tmp_path, *, hypothesis, rule_id, cwe=""):
        from core.audit.orchestrator import _run_tool_chain

        chain = [{"type": "semgrep", "config": {"rule": "unused.yaml"}}]
        return _run_tool_chain(
            chain,
            config=_mk_config(tmp_path),
            file_path="src/a.c",
            function_name="handler",
            source="void handler(void) {}",
            hypothesis=hypothesis,
            line_start=10,
            sarif_cache=self._cache(rule_id),
            cwe=cwe,
        )

    def test_correlated_sarif_hit_confirms(self, tmp_path):
        confirmed = self._run_chain(
            tmp_path,
            hypothesis="buffer overflow via unchecked strcpy",
            rule_id="c-unbounded-strcpy-buffer-overflow",
        )
        assert confirmed == ["sarif_cache:semgrep"]

    def test_uncorrelated_sarif_hit_does_not_confirm(self, tmp_path):
        confirmed = self._run_chain(
            tmp_path,
            hypothesis="SQL injection through user-controlled query",
            rule_id="c-unbounded-strcpy-buffer-overflow",
        )
        assert confirmed == []

    def test_cwe_correlates_sarif_hit(self, tmp_path):
        confirmed = self._run_chain(
            tmp_path,
            hypothesis="attacker-controlled length reaches copy",
            rule_id="c-unbounded-strcpy-buffer-overflow",
            cwe="CWE-120",
        )
        assert confirmed == ["sarif_cache:semgrep"]


class TestRecordUncorrelatedHits:
    def test_creates_review_result_when_missing(self):
        from core.audit.orchestrator import (
            ReviewOutcome,
            _record_uncorrelated_hits,
        )

        outcome = ReviewOutcome(
            file="a.c", function="f", status="suspicious",
            body="", hypothesis="h",
        )
        outcome.review_result = None
        hit = PrefilterHit(rule_id="eval-exec", message="m", line=3)
        _record_uncorrelated_hits(outcome, [hit])
        ctx = outcome.review_result["uncorrelated_tool_hits"]
        assert ctx == [{
            "tool": "prefilter", "rule_id": "eval-exec",
            "line": 3, "message": "m",
        }]

    def test_deduplicates_repeat_hits(self):
        from core.audit.orchestrator import (
            ReviewOutcome,
            _record_uncorrelated_hits,
        )

        outcome = ReviewOutcome(
            file="a.c", function="f", status="suspicious",
            body="", hypothesis="h",
        )
        hit = PrefilterHit(rule_id="eval-exec", message="m", line=3)
        _record_uncorrelated_hits(outcome, [hit])
        _record_uncorrelated_hits(outcome, [hit])
        assert len(outcome.review_result["uncorrelated_tool_hits"]) == 1


class TestMechDetectorPromotion:
    """Prep-phase mechanical detector hits join the promotion pass."""

    UAF_HYP = "use after free: object written after early free"

    def _mech(self, detector, func="handler"):
        return {
            f"src/a.c:{func}": [{
                "file": "src/a.c",
                "function": func,
                "detector": detector,
                "line": 11,
                "description": "freed then used",
            }],
        }

    def test_correlated_cocci_hit_returns_tool_id(self):
        from core.audit.orchestrator import _correlated_mech_detector_tool

        outcome = _mk_outcome(self.UAF_HYP)
        tool = _correlated_mech_detector_tool(
            outcome, self.UAF_HYP, "CWE-416",
            self._mech("cocci:use_after_free"),
        )
        assert tool == "coccinelle:use_after_free"

    def test_uncorrelated_cocci_hit_returns_none(self):
        from core.audit.orchestrator import _correlated_mech_detector_tool

        outcome = _mk_outcome("SQL injection via string concat")
        tool = _correlated_mech_detector_tool(
            outcome,
            "SQL injection via string concat", "CWE-89",
            self._mech("cocci:use_after_free"),
        )
        assert tool is None

    def test_detection_role_rule_never_promotes(self):
        from core.audit.orchestrator import _correlated_mech_detector_tool

        outcome = _mk_outcome("resource leak on error path")
        tool = _correlated_mech_detector_tool(
            outcome, "resource leak on error path", "",
            self._mech("cocci:resource_leak_err"),
        )
        assert tool is None

    def test_non_cocci_detector_stays_context(self):
        from core.audit.orchestrator import _correlated_mech_detector_tool

        outcome = _mk_outcome(self.UAF_HYP)
        tool = _correlated_mech_detector_tool(
            outcome, self.UAF_HYP, "CWE-416",
            self._mech("callback_lifetime_local"),
        )
        assert tool is None

    def test_promote_suspicious_uses_mech_hit(self, tmp_path, monkeypatch):
        from core.audit.orchestrator import (
            OrchestratorResult,
            _promote_suspicious,
        )

        outcome = _mk_outcome(self.UAF_HYP)
        outcome.status = "suspicious"
        result = OrchestratorResult()
        result.outcomes = [outcome]
        result.suspicious = 1
        # no prefilter hits, no chain confirms — only the mech hit
        _patch_common(monkeypatch, hits=[], chain_confirms=[])
        _promote_suspicious(
            result, _mk_config(tmp_path),
            mechanical_findings=self._mech("cocci:use_after_free"),
        )
        assert result.outcomes[0].status == "finding"
        assert result.outcomes[0].evidence_tool == "coccinelle:use_after_free"
        assert result.sweep_promoted == 1

    def test_corroboration_sees_mech_hits(self, tmp_path, monkeypatch):
        from core.audit.orchestrator import _has_mechanical_corroboration

        monkeypatch.setattr(
            "core.audit.orchestrator._read_raw_source",
            lambda *a, **kw: "void handler(void) { }",
        )
        class _PF:
            hits: ClassVar[list] = []
        monkeypatch.setattr(
            "core.audit.orchestrator.run_prefilter",
            lambda **kw: _PF(),
        )
        outcome = _mk_outcome(self.UAF_HYP)
        assert _has_mechanical_corroboration(
            outcome, _mk_config(tmp_path), None, None,
            mechanical_findings=self._mech("cocci:use_after_free"),
        )
        assert not _has_mechanical_corroboration(
            outcome, _mk_config(tmp_path), None, None,
            mechanical_findings={},
        )


@pytest.mark.parametrize("rule_id", sorted(PREFILTER_RULE_FAMILY))
def test_family_map_covers_emitted_rule_ids(rule_id):
    """Every mapped id resolves without falling back to inference."""
    assert family_for_rule(rule_id) == PREFILTER_RULE_FAMILY[rule_id]


def test_all_emitted_prefilter_rule_ids_are_mapped():
    """Every rule_id literal emitted by prefilter.py is in the FAMILY map."""
    import re

    import core.audit.prefilter as prefilter_mod

    src = Path(prefilter_mod.__file__).read_text()
    emitted = set(re.findall(r'rule_id="([^"]+)"', src))
    assert emitted <= set(PREFILTER_RULE_FAMILY), (
        f"unmapped prefilter rule ids: {emitted - set(PREFILTER_RULE_FAMILY)}"
    )
