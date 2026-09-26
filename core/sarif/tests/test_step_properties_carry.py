"""Per-step ``properties`` carry through the SARIF dataflow parser.

ThreadFlow locations may carry a ``properties`` bag (the cross-file
taint engine's per-hop tier/kind/tags surface). ``extract_dataflow_path``
carries a sanitized, bounded copy onto each step so tier-aware
consumers get mechanical per-hop input from a SARIF re-parse — and
steps from locations WITHOUT properties keep the exact pre-existing
shape.
"""

from __future__ import annotations

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
