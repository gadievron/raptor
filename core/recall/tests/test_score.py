"""Scorer math, report shape, segregation guard, compare mode."""

from __future__ import annotations

from pathlib import Path

from core.recall.manifest import (
    ExpectedFinding,
    Provenance,
    RecallManifest,
    Tolerance,
    compute_label_digest,
)
from core.recall.matcher import MatchResult
from core.recall.score import (
    LABEL_CLASS,
    compare_reports,
    render_markdown,
    score,
)

_PROV = Provenance(kind="benchmark", suite="s", case="c")


def _manifest(*, clean_regions=(), profile="scan-codeql",
              expected=()) -> RecallManifest:
    return RecallManifest(
        name="fixture", repo_url="https://example.org/r",
        pinned_sha="deadbeefcafe", local_path="out/f", language="java",
        profile=profile, expected=list(expected),
        clean_regions=list(clean_regions), tolerance=Tolerance(),
    )


def _clean_region(eid="clean-1") -> ExpectedFinding:
    return ExpectedFinding(id=eid, file="src/B.java", cwe="CWE-78",
                           provenance=_PROV, line_start=1)


def _mr(cwe: str, matched: bool, tools=(), eid="e") -> MatchResult:
    exp = ExpectedFinding(id=eid, file="src/A.java", cwe=cwe,
                          provenance=_PROV, line_start=1)
    return MatchResult(expected=exp, matched=matched, tools=list(tools),
                       hits=[{}] if matched else [])


class TestScore:
    def test_per_cwe_and_overall_math(self):
        matches = [
            _mr("CWE-78", True, ["semgrep"], "a"),
            _mr("CWE-78", False, eid="b"),
            _mr("CWE-89", True, ["codeql", "semgrep"], "c"),
        ]
        rep = score(_manifest(), matches, [])
        assert rep.expected_total == 3
        assert rep.found_total == 2
        assert rep.recall == 2 / 3
        rows = {r.cwe: r for r in rep.per_cwe}
        assert rows["CWE-78"].expected == 2
        assert rows["CWE-78"].found == 1
        assert rows["CWE-78"].recall == 0.5
        assert rows["CWE-89"].recall == 1.0

    def test_tool_attribution_counts_expected_not_hits(self):
        matches = [
            _mr("CWE-78", True, ["semgrep"], "a"),
            _mr("CWE-89", True, ["codeql", "semgrep"], "b"),
        ]
        rep = score(_manifest(), matches, [])
        assert rep.tool_attribution == {"semgrep": 2, "codeql": 1}

    def test_missed_list_carries_provenance(self):
        rep = score(_manifest(), [_mr("CWE-78", False, eid="m1")], [])
        assert rep.missed[0]["id"] == "m1"
        assert rep.missed[0]["provenance"]["kind"] == "benchmark"

    def test_clean_region_fps_secondary(self):
        clean_hit = _mr("CWE-78", True, ["semgrep"], "clean-1")
        rep = score(_manifest(), [_mr("CWE-78", True, ["semgrep"])],
                    [clean_hit])
        assert rep.recall == 1.0  # clean hits never enter recall
        assert rep.clean_region_fp_count == 1
        assert rep.clean_region_fps[0]["tools"] == ["semgrep"]

    def test_empty_expected_recall_none(self):
        rep = score(_manifest(), [], [])
        assert rep.recall is None


class TestReportShape:
    def test_label_class_and_segregation_present(self):
        d = score(_manifest(), [_mr("CWE-78", True)], []).to_dict()
        assert d["label_class"] == LABEL_CLASS
        assert "never feed" in d["segregation"].lower() or \
               "must never feed" in d["segregation"]
        assert d["pinned_sha"] == "deadbeefcafe"

    def test_markdown_renders(self):
        rep = score(_manifest(),
                    [_mr("CWE-78", True, ["semgrep"]),
                     _mr("CWE-89", False, eid="miss-1")], [])
        md = render_markdown(rep)
        assert "CWE-78" in md and "miss-1" in md
        assert LABEL_CLASS in md


class TestLabelSetPins:
    def test_report_stamps_clean_region_total_and_digest(self):
        m = _manifest(clean_regions=[_clean_region(),
                                     _clean_region("clean-2")])
        rep = score(m, [_mr("CWE-78", True)], [])
        assert rep.clean_region_total == 2
        assert rep.label_digest == compute_label_digest(m)
        d = rep.to_dict()
        assert d["clean_region_total"] == 2
        assert d["label_digest"] == rep.label_digest
        assert len(rep.label_digest) == 64

    def test_digest_ignores_profile_but_not_labels(self):
        # The flip pair differs in profile BY DESIGN — the digest must
        # compare equal across it, and change when label content does.
        clean = [_clean_region(), _clean_region("clean-2")]
        base = _manifest(clean_regions=clean, profile="agentic")
        cand = _manifest(clean_regions=clean, profile="agentic-taint")
        assert compute_label_digest(base) == compute_label_digest(cand)
        pruned = _manifest(clean_regions=clean[:1], profile="agentic")
        assert compute_label_digest(pruned) != compute_label_digest(base)

    def test_digest_sensitive_to_expected_and_order(self):
        e1 = ExpectedFinding(id="a", file="f.java", cwe="CWE-78",
                             provenance=_PROV, line_start=1)
        e2 = ExpectedFinding(id="b", file="g.java", cwe="CWE-89",
                             provenance=_PROV, line_start=2)
        d12 = compute_label_digest(_manifest(expected=[e1, e2]))
        d21 = compute_label_digest(_manifest(expected=[e2, e1]))
        assert d12 != compute_label_digest(_manifest(expected=[e1]))
        # Order-sensitive on purpose: a reordered label file is a
        # changed label file (re-freeze, never guess).
        assert d12 != d21

    def test_digest_deterministic(self):
        m = _manifest(clean_regions=[_clean_region()])
        assert compute_label_digest(m) == compute_label_digest(m)


class TestSegregationGuard:
    def test_recall_never_imports_learning_stores(self):
        """FN labels must not reach FP-suppression/scorecard stores.

        Source-level guard: no module in core/recall may reference the
        verdict/scorecard learning surfaces, so the harness cannot
        write recall labels where they would corrupt calibration.
        """
        pkg = Path(__file__).resolve().parents[1]
        banned = (
            "store_finding_verdict",
            "recall_prior_finding_verdict",
            "core.llm.scorecard",
            "fp_feedback",
            "verdict_reuse",
            "core.sage",
        )
        for path in pkg.glob("*.py"):
            text = path.read_text(encoding="utf-8")
            for token in banned:
                assert token not in text, (
                    f"{path.name} references {token!r} — recall "
                    "ground truth must stay segregated from learning "
                    "stores")


class TestCompare:
    def test_delta_and_newly_lists(self):
        base = {
            "manifest": "m", "recall": 0.5,
            "per_cwe": [{"cwe": "CWE-78", "expected": 2, "found": 1}],
            "missed": [{"id": "a"}, {"id": "b"}],
        }
        new = {
            "manifest": "m", "recall": 0.75,
            "per_cwe": [{"cwe": "CWE-78", "expected": 2, "found": 2},
                        {"cwe": "CWE-89", "expected": 2, "found": 1}],
            "missed": [{"id": "c"}],
        }
        delta = compare_reports(base, new)
        row78 = next(r for r in delta["per_cwe"] if r["cwe"] == "CWE-78")
        assert row78["delta_found"] == 1
        assert delta["newly_found"] == ["a", "b"]
        assert delta["newly_missed"] == ["c"]
        assert delta["label_class"] == LABEL_CLASS
