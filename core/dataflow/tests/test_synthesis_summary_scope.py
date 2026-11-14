import json

import pytest

from core.dataflow import barrier_synth


@pytest.mark.parametrize("first_uri,first_line", [("other.py", 4), ("target.py", 4)])
def test_summary_uses_the_location_matching_the_count_scope(tmp_path, first_uri, first_line):
    def location(uri, line):
        return {"physicalLocation": {
            "artifactLocation": {"uri": uri}, "region": {"startLine": line},
        }}

    path = tmp_path / "owned.sarif"
    path.write_text(json.dumps({"runs": [{"results": [{
        "locations": [location(first_uri, first_line), location("target.py", 9)],
        "message": {"text": "owned finding"},
    }]}]}))
    assert barrier_synth._count_results_for_target(path, "target.py", 9) == 1
    summary = barrier_synth._summarise_surviving_finding(path, "target.py", 9)
    assert "target.py:9" in summary
    assert "owned finding" in summary
