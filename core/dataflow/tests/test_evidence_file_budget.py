"""Invalid file budgets cannot authorize extraction callbacks."""

import pytest

from core.dataflow.evidence_collector import collect_sanitizer_evidence
from core.dataflow.finding import Finding, Step


def _finding(tmp_path):
    for file in ("a.py", "b.py", "c.py"):
        (tmp_path / file).write_text("pass\n")
    return Finding(
        finding_id="budget-fixture", producer="fixture", rule_id="fixture/evidence",
        message="Inert file-budget control", source=Step("a.py", 1, 0, "value"),
        sink=Step("c.py", 1, 0, "value"), intermediate_steps=(Step("b.py", 1, 0, "value"),),
    )


def test_invalid_file_limits_do_not_authorize_extraction(tmp_path):
    finding = _finding(tmp_path)
    calls = []

    def scripted_response(bundle):
        calls.append(bundle)
        return '{"validators": []}'

    for limit in (-1, True, 1.5, "2"):
        calls.clear()
        try:
            collect_sanitizer_evidence(
                finding, repo_root=tmp_path, extractor=scripted_response, max_files=limit,
            )
        except ValueError as error:
            assert "max_files" in str(error)
            assert not calls
        else:
            pytest.fail(f"invalid max_files={limit!r} accepted with {len(calls)} callbacks")


def test_zero_and_positive_file_limits_keep_their_bounds(tmp_path):
    finding = _finding(tmp_path)
    calls = []

    def scripted_response(bundle):
        calls.append(bundle)
        return '{"validators": []}'

    for limit in (0, 1, 3):
        calls.clear()
        evidence = collect_sanitizer_evidence(
            finding, repo_root=tmp_path, extractor=scripted_response, max_files=limit,
        )
        assert len(calls) == limit
        assert not evidence.candidate_pool
        assert not evidence.extraction_failures
