"""Finding identities distinguish delimiter-bearing location components."""

import pytest

from core.dataflow.adapters.codeql import make_finding_id as codeql_id
from core.dataflow.adapters.taint_native import make_finding_id as native_id
from core.dataflow.finding import Step


@pytest.mark.parametrize("make_id", [codeql_id, native_id])
def test_distinct_locations_with_identical_legacy_key(make_id):
    first = (Step("a:1|b", 2, 0, ""), Step("c", 3, 0, ""))
    second = (Step("a", 1, 0, ""), Step("b:2|c", 3, 0, ""))
    assert first != second
    assert make_id("test/rule", *first) != make_id("test/rule", *second)


@pytest.mark.parametrize(
    ("make_id", "expected"),
    [(codeql_id, "codeql_test-rule_e60611cf8f58"),
     (native_id, "taint-crossfile_test-rule_1a22a94378b2")],
)
def test_ordinary_location_identity_remains_stable(make_id, expected):
    assert make_id("test/rule", Step("a", 1, 0, ""), Step("b", 2, 0, "")) == expected


@pytest.mark.parametrize("make_id", [codeql_id, native_id])
@pytest.mark.parametrize("field", ["producer", "rule", "source", "sink"])
def test_every_delimiter_bearing_component_uses_structured_identity(make_id, field):
    producer = "test|producer" if field == "producer" else "test"
    rule = "test|rule" if field == "rule" else "rule"
    source = Step("a|b" if field == "source" else "a", 1, 0, "")
    sink = Step("c|d" if field == "sink" else "c", 2, 0, "")
    result = make_id(rule, source, sink, producer=producer)
    assert "_v2_" in result
    assert result == make_id(rule, source, sink, producer=producer)
    moved_sink = Step(sink.file_path, 3, 0, "")
    assert result != make_id(rule, source, moved_sink, producer=producer)
