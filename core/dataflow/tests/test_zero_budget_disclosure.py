"""A valid zero file budget still discloses omitted evidence scope."""

from core.dataflow.evidence_collector import collect_sanitizer_evidence
from core.dataflow.evidence_renderer import render_evidence_for_prompt
from core.dataflow.finding import Finding, Step


def test_zero_budget_discloses_truncation_without_extracting(tmp_path):
    (tmp_path / "owned.py").write_text("source = input()\nsink(source)\n")
    finding = Finding(
        finding_id="owned", producer="fixture", rule_id="fixture/owned", message="owned",
        source=Step("owned.py", 1, 0, "source"), sink=Step("owned.py", 2, 0, "sink"),
    )

    calls = []

    def forbidden(bundle):
        calls.append(bundle)
        raise AssertionError("zero file budget must not authorise extraction")

    evidence = collect_sanitizer_evidence(
        finding, repo_root=tmp_path, extractor=forbidden, max_files=0,
    )
    assert evidence.candidate_pool == evidence.extraction_failures == ()
    assert not calls
    assert evidence.pool_completeness == "scoped_to_first_0_files_truncated"
    assert "Pool completeness: scoped_to_first_0_files_truncated" in render_evidence_for_prompt(evidence)
