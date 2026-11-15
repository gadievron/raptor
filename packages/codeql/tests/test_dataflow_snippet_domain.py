"""Optional snippet text cannot discard a usable primary dataflow path."""

import copy
import logging

from packages.codeql import dataflow_validator as module


def _location(label, line):
    return {"location": {"message": {"text": label}, "physicalLocation": {
        "artifactLocation": {"uri": "owned.c"}, "region": {"startLine": line},
    }}}


def test_optional_snippet_domain_preserves_primary_path(caplog):
    validator = module.DataflowValidator.__new__(module.DataflowValidator)
    validator.logger = logging.getLogger("owned-dataflow-snippets")
    cases = [(None, "", False), ({}, "", False),
             ({"text": ""}, "", False), ({"text": "source();\n"}, "source();\n", False)]
    cases += [(value, "", True) for value in (
        ["snippet"], "snippet", True, 7, {"text": ["snippet"]},
        {"text": None}, {"text": True}, {"text": 7}, {"text": {}},
    )]
    for snippet, expected, warned in cases:
        first = _location("primary", 1)
        first["location"]["physicalLocation"]["region"]["snippet"] = snippet
        result = {"ruleId": "cpp/owned", "codeFlows": [{"threadFlows": [
            {"locations": [first, _location("sink", 3)]},
            {"locations": [_location("sibling", 1), _location("other-sink", 3)]},
        ]}]}
        before = copy.deepcopy(result)
        caplog.clear()
        path = validator.extract_dataflow_from_sarif(result)
        assert path is not None
        assert path.source.label == "primary"
        assert path.source.snippet == expected
        assert (path.source.file_path, path.source.line, path.sink.line) == ("owned.c", 1, 3)
        assert [p.source.label for p in path.alternatives] == ["sibling"]
        assert any("SARIF flow snippet" in r.message for r in caplog.records) is warned
        assert result == before
