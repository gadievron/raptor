"""Per-step ``properties`` carry through the SARIF dataflow parser.

ThreadFlow locations may carry a ``properties`` bag (the cross-file
taint engine's per-hop tier/kind/tags surface). ``extract_dataflow_path``
carries a sanitized, bounded copy onto each step so tier-aware
consumers get mechanical per-hop input from a SARIF re-parse — and
steps from locations WITHOUT properties keep the exact pre-existing
shape.
"""

from __future__ import annotations

import pytest

from core.sarif.parser import (
    _STEP_PROPS_MAX_KEYS,
    _STEP_PROPS_MAX_LIST,
    _STEP_PROPS_MAX_STRING,
    _sanitize_step_properties,
    extract_dataflow_path,
)


def _loc(uri: str, line: int, properties: dict | None = None) -> dict:
    wrapper: dict = {
        "location": {
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": line},
            },
        },
    }
    if properties is not None:
        wrapper["properties"] = properties
    return wrapper


def _flows(*locations: dict) -> list[dict]:
    return [{"threadFlows": [{"locations": list(locations)}]}]


class TestPropertiesCarry:
    def test_tier_and_tags_ride_onto_steps(self):
        path = extract_dataflow_path(_flows(
            _loc("a.py", 1, {"tier": "resolved_static", "kind": "seed"}),
            _loc("b.py", 5, {"tier": "heuristic_dynamic",
                             "tags": ["assumed_propagation"]}),
            _loc("c.py", 9, {"tier": "resolved_static", "kind": "sink"}),
        ))
        assert path["source"]["properties"]["tier"] == "resolved_static"
        assert path["steps"][0]["properties"]["tier"] == "heuristic_dynamic"
        assert path["steps"][0]["properties"]["tags"] == [
            "assumed_propagation"]
        assert path["sink"]["properties"]["kind"] == "sink"

    def test_no_properties_keeps_pre_existing_step_shape(self):
        # The differential: locations without properties produce steps
        # with the exact pre-carry key set.
        path = extract_dataflow_path(_flows(
            _loc("a.py", 1), _loc("b.py", 2),
        ))
        for step in (path["source"], path["sink"]):
            assert sorted(step) == [
                "column", "file", "label", "line", "snippet",
            ]

    def test_empty_properties_bag_omitted(self):
        path = extract_dataflow_path(_flows(
            _loc("a.py", 1, {}), _loc("b.py", 2, {}),
        ))
        assert "properties" not in path["source"]

    def test_non_dict_properties_dropped(self):
        wrapper = _loc("a.py", 1)
        wrapper["properties"] = "junk"
        path = extract_dataflow_path(
            _flows(wrapper, _loc("b.py", 2)))
        assert "properties" not in path["source"]


class TestSanitisation:
    def test_hostile_bytes_escaped(self):
        # ANSI clear-screen + bidi override in a tier string must
        # arrive display-inert.
        props = _sanitize_step_properties({
            "tier": "evil\x1b[2J‮tier",
            "tags": ["ok", "bad\x9btag"],
        })
        assert "\x1b" not in props["tier"]
        assert "\\x1b" in props["tier"]
        assert "‮" not in props["tier"]
        assert all("\x9b" not in t for t in props["tags"])

    def test_hostile_key_escaped(self):
        props = _sanitize_step_properties({"ke\x1by": "v"})
        assert all("\x1b" not in k for k in props)

    def test_non_string_keys_dropped(self):
        assert _sanitize_step_properties({1: "a", None: "b"}) == {}

    def test_value_type_allowlist(self):
        props = _sanitize_step_properties({
            "s": "str", "b": True, "i": 7,
            "f": 1.5, "d": {"nested": 1}, "n": None,
            "mixed_list": ["keep", 3, None, "also"],
        })
        assert props["s"] == "str"
        assert props["b"] is True
        assert props["i"] == 7
        assert "f" not in props
        assert "d" not in props
        assert "n" not in props
        # Non-string list entries dropped, strings kept in order.
        assert props["mixed_list"] == ["keep", "also"]

    def test_bool_not_coerced_to_int(self):
        props = _sanitize_step_properties({"excerpt_truncated": False})
        assert props["excerpt_truncated"] is False


class TestBounds:
    def test_key_count_capped(self):
        big = {f"k{i:03d}": "v" for i in range(_STEP_PROPS_MAX_KEYS + 10)}
        assert len(_sanitize_step_properties(big)) == _STEP_PROPS_MAX_KEYS

    def test_string_length_capped(self):
        props = _sanitize_step_properties(
            {"tier": "x" * (_STEP_PROPS_MAX_STRING * 4)})
        assert len(props["tier"]) == _STEP_PROPS_MAX_STRING

    def test_list_length_capped(self):
        props = _sanitize_step_properties(
            {"tags": ["t"] * (_STEP_PROPS_MAX_LIST * 3)})
        assert len(props["tags"]) == _STEP_PROPS_MAX_LIST

    def test_list_entry_length_capped(self):
        props = _sanitize_step_properties(
            {"tags": ["y" * (_STEP_PROPS_MAX_STRING * 2)]})
        assert len(props["tags"][0]) == _STEP_PROPS_MAX_STRING


def test_malformed_thread_does_not_hide_valid_sibling_paths():
    first = {'locations': [_loc('source-a.c', 1), _loc('sink-a.c', 2)]}
    last = {'locations': [_loc('source-b.c', 3), _loc('sink-b.c', 4)]}
    malformed = {'locations': [None, None]}
    path = extract_dataflow_path([{'threadFlows': [first, malformed, last]}])
    assert path['source']['file'] == 'source-a.c'
    assert path['alternative_paths'][0]['source']['file'] == 'source-b.c'


def test_dataflow_hops_use_their_owning_run_artifacts_and_uri_bases(tmp_path):
    import json
    from core.sarif.parser import parse_sarif_findings

    runs = []
    for root in ['first/', 'second/']:
        source = _loc('unused', 1, {'kind': 'seed'})
        source['location']['physicalLocation']['artifactLocation'] = {'index': 0}
        middle = _loc('middle.c', 2)
        middle['location']['physicalLocation']['artifactLocation']['uriBaseId'] = 'ROOT'
        sink = _loc('unused', 3, {'kind': 'sink'})
        sink['location']['physicalLocation']['artifactLocation'] = {'index': 1}
        runs.append({
            'tool': {'driver': {'name': 'CodeQL'}},
            'originalUriBaseIds': {'ROOT': {'uri': root}},
            'artifacts': [{'location': {'uri': name, 'uriBaseId': 'ROOT'}} for name in ['source.c', 'sink.c']],
            'results': [{'ruleId': 'flow', 'message': {'text': root},
                         'locations': [{'physicalLocation': {'artifactLocation': {'index': 1}}}],
                         'codeFlows': _flows(source, middle, sink)}],
        })
    report = tmp_path / 'flows.sarif'
    report.write_text(json.dumps({'runs': runs}))
    findings = parse_sarif_findings(report)
    for finding, root in zip(findings, ['first/', 'second/'], strict=True):
        path = finding['dataflow_path']
        assert finding['file'] == root + 'sink.c'
        assert path['source']['file'] == root + 'source.c'
        assert path['steps'][0]['file'] == root + 'middle.c'
        assert path['sink']['file'] == finding['file']
        assert path['source']['properties'] == {'kind': 'seed'}
        assert path['sink']['properties'] == {'kind': 'sink'}


@pytest.mark.parametrize('external_artifact', [
    {'uri': '../outside.c'}, {'uri': '%2e%2e/outside.c'}, {'index': 0},
    {'uri': 'outside.c', 'uriBaseId': 'OUT'}, {'uri': 'https://example.invalid/outside.c'},
], ids=['relative', 'encoded', 'indexed', 'based', 'remote'])
def test_source_root_rejects_external_flow_without_hiding_an_in_root_alternative(tmp_path, external_artifact, caplog):
    import json
    from core.sarif.parser import parse_sarif_findings

    root = tmp_path / 'source'
    root.mkdir()
    bad = {'locations': [_loc('../outside.c', 1), _loc('sink.c', 2)]}
    bad['locations'][0]['location']['physicalLocation']['artifactLocation'] = external_artifact
    good = {'locations': [_loc('source.c', 1), _loc('sink.c', 2)]}
    report = tmp_path / 'contained.sarif'
    report.write_text(json.dumps({'runs': [{
        'tool': {'driver': {'name': 'CodeQL'}},
        'originalUriBaseIds': {'OUT': {'uri': '../'}},
        'artifacts': [{'location': {'uri': '../outside.c'}}],
        'results': [{'ruleId': 'flow', 'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'sink.c'}}}],
                     'codeFlows': [{'threadFlows': [bad, bad, good]}]}],
    }]}))
    finding = parse_sarif_findings(report, source_root=root)[0]
    assert finding['has_dataflow']
    assert finding['dataflow_path']['source']['file'] == 'source.c'
    assert finding['dataflow_path']['alternative_paths'] == []
    assert len([record for record in caplog.records if 'out-of-root URIs' in record.message]) == 1


def test_dataflow_rejected_paths_do_not_drop_the_finding(tmp_path):
    import json
    from core.sarif.parser import parse_sarif_findings

    report = tmp_path / 'rejected-flow.sarif'
    report.write_text(json.dumps({'runs': [{
        'results': [{'ruleId': 'flow',
                     'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'inside.c'}}}],
                     'codeFlows': _flows(_loc('../outside.c', 1), _loc('inside.c', 2))}],
    }]}))
    finding = parse_sarif_findings(report, source_root=tmp_path)[0]
    assert finding['file'] == 'inside.c'
    assert finding['has_dataflow'] is False
    assert finding['dataflow_path'] is None


def test_invalid_artifact_index_omits_path_without_borrowing_a_file(tmp_path):
    import json
    from core.sarif.parser import parse_sarif_findings

    source = _loc('unused', 1)
    source['location']['physicalLocation']['artifactLocation'] = {'index': True}
    sink = _loc('explicit.c', 2)
    sink['location']['physicalLocation']['artifactLocation']['index'] = 99
    report = tmp_path / 'invalid-index.sarif'
    report.write_text(json.dumps({'runs': [{
        'artifacts': [{'location': {'uri': 'not-the-source.c'}}],
        'results': [{'ruleId': 'flow', 'codeFlows': _flows(source, sink)}],
    }]}))
    finding = parse_sarif_findings(report)[0]
    assert finding['dataflow_path'] is None
    assert finding['has_dataflow'] is False
    # The valid explicit sink URI still wins over its invalid index; only
    # the unresolved source reference invalidates this path.
    from core.sarif.parser import ArtifactUriResolver
    assert ArtifactUriResolver({}).resolve(sink['location']['physicalLocation']['artifactLocation']) == 'explicit.c'


@pytest.mark.parametrize('malformed_threads', ['x' * 1000, [None] * 1000],
                         ids=['non-array', 'many-invalid-entries'])
def test_malformed_thread_warnings_are_bounded_per_flow(caplog, malformed_threads):
    valid = {'threadFlows': [{'locations': [_loc('source.c', 1), _loc('sink.c', 2)]}]}
    path = extract_dataflow_path([{'threadFlows': malformed_threads}, valid])
    assert path['source']['file'] == 'source.c'
    warnings = [record for record in caplog.records if 'skipping malformed' in record.message]
    assert len(warnings) == 1
