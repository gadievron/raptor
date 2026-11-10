"""Captured claims preserve source precedence without verdict inference."""
from copy import deepcopy
from pathlib import Path

import pytest

from core.run.tests.test_verdict_tri_state import _violations_in
from packages.llm_analysis import reporting


def test_reporting_source_preserves_tri_state_read_idioms():
    assert _violations_in(Path(reporting.__file__)) == []


@pytest.mark.parametrize("result,expected,limited", [
    ({"analysis": {"is_exploitable": False}, "is_exploitable": True}, False, False),
    ({"analysis": {"is_exploitable": None}, "is_exploitable": True}, None, False),
    ({"analysis": {}, "is_exploitable": False}, False, False),
    ({"analysis": [], "is_exploitable": True}, True, False),
    ({}, None, False),
    ({"analysis": {"is_exploitable": "unknown"}, "is_exploitable": True}, "unknown", False),
    ({"analysis": {"is_exploitable": 0}, "is_exploitable": True}, 0, False),
    ({"analysis": {"is_exploitable": {"captured": True}}, "is_exploitable": True}, None, True),
    ({"analysis": {"is_exploitable": [False]}, "is_exploitable": True}, None, True),
])
def test_retained_claim_precedence_and_unavailable_shapes(result, expected, limited):
    report = {"results": [result]}
    before = deepcopy(report)
    document = reporting.build_document(report)
    recorded = document.blocks[0].rows[0][4]
    assert recorded == expected and type(recorded) is type(expected)
    assert document.extensions["raptor.capture_limited"] is limited
    assert document.extensions["raptor.telemetry_values_or_subtrees_unavailable"] == int(limited)
    assert report == before
