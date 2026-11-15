"""A non-positive tool location cannot confirm source reachability."""

from packages.hypothesis_validation.adapters.base import ToolEvidence
from packages.llm_analysis import dataflow_validation as dv


def test_negative_match_line_cannot_confirm_nearby_finding():
    negative = ToolEvidence(
        tool="codeql", rule="owned", success=True,
        matches=[{"file": "a.c", "line": -1}],
    )
    for target_line in (1, 0):
        finding = {"file_path": "a.c", "start_line": target_line}
        assert not dv._any_match_at_finding_location(negative.matches, finding)
        assert dv._verdict_from_prebuilt(negative, finding) == "inconclusive"
        assert dv._verdict_from_template(negative, finding) == "inconclusive"
    positive = ToolEvidence(
        tool="codeql", rule="owned", success=True,
        matches=[{"file": "a.c", "line": 1}],
    )
    for target_line in (1, 0):
        finding = {"file_path": "a.c", "start_line": target_line}
        assert dv._verdict_from_prebuilt(positive, finding) == "confirmed"
        assert dv._verdict_from_template(positive, finding) == "confirmed"
