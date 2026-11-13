"""Invalid boolean SARIF lines retain native-adapter skip semantics."""

from types import SimpleNamespace

from core.dataflow.adapters.taint_native import from_emission_report, from_sarif_result


def _location(line):
    return {"location": {"physicalLocation": {"artifactLocation": {"uri": "fixture.py"},
                                              "region": {"startLine": line}}}}


def _result(source=1, intermediate=None):
    locations = [_location(source)]
    if intermediate is not None:
        locations.append(_location(intermediate))
    locations.append(_location(3))
    return {"ruleId": "fixture", "message": {"text": "fixture"},
            "codeFlows": [{"threadFlows": [{"locations": locations}]}]}


def test_native_adapter_skips_boolean_lines():
    valid = from_sarif_result(_result())
    assert valid is not None and valid.source.line == 1
    for invalid in (True, False, 1.5):
        assert from_sarif_result(_result(source=invalid)) is None
    with_gap = from_sarif_result(_result(intermediate=True))
    assert with_gap is not None
    assert with_gap.intermediate_steps == ()
    assert with_gap.raw["adapter_steps_dropped_unlocated"] == 1
    report = SimpleNamespace(sarif={"runs": [{"results": [_result(source=True), _result()]}]})
    assert from_emission_report(report) == [valid]
