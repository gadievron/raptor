"""Overflowing JSON coordinates retain best-effort hypothesis admission."""
import json

from packages.hypothesis_validation.hypothesis import FlowStep, Hypothesis, Location


def test_overflowing_json_lines_degrade_without_losing_hypothesis():
    for token, expected in (("1e400", 0), ("-1e400", 0), ("17", 17), ('"23"', 23)):
        record = json.loads('{"claim":"owned claim","source":{"line":' + token
                            + '},"sink":{"line":' + token
                            + '},"flow_steps":[{"line":' + token + '}]}')
        assert Location.from_dict(record["source"]).line == expected
        assert FlowStep.from_dict(record["flow_steps"][0]).line == expected
        hypothesis = Hypothesis.from_dict(record)
        assert hypothesis.claim == "owned claim"
        assert hypothesis.source.line == expected
        assert hypothesis.sink.line == expected
        assert [step.line for step in hypothesis.flow_steps] == [expected]
        assert hypothesis.to_dict()["source"]["line"] == expected
