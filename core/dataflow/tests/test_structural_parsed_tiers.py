"""SARIF metadata loss must not turn a non-static hop into a refutation."""
from core.dataflow.structural_validator import validate_structurally
from core.sarif.parser import extract_dataflow_path


def _path(properties):
    locations = []
    for line in (2, 5):
        locations.append({"location": {"physicalLocation": {
            "artifactLocation": {"uri": "app.py"}, "region": {"startLine": line},
        }}})
    locations[0]["properties"] = properties
    return extract_dataflow_path([{"threadFlows": [{"locations": locations}]}])


def test_explicit_unverified_tiers_survive_parsing(tmp_path):
    (tmp_path / "app.py").write_text(
        "def first(value):\n    return value\n\n"
        "def second(value):\n    return value\n"
    )
    for properties in ({}, {"tier": "resolved_static"},
                       {"tier": "resolved_static", "tags": ["ordinary"] * 16}):
        assert validate_structurally(_path(properties), tmp_path, language="python").refuted
    for properties in (
        {"tier": None}, {"tier": 1.5}, {"tier": {}},
        {**{f"extra{i}": i for i in range(16)}, "tier": "heuristic_dynamic"},
        {**{f"extra{i}": i for i in range(15)},
         "tags": ["assumed_propagation"], "tier": "resolved_static"},
        {"tier": "resolved_static", "tags": ["ordinary"] * 16 + ["binding_approx"]},
        {"tags": ["ordinary"] * 16 + ["binding_approx"]},
    ):
        path = _path(properties)
        result = validate_structurally(path, tmp_path, language="python")
        assert result.verdict == "inconclusive", repr(properties)
        assert not result.refuted
        assert "tier" in path["source"]["properties"]
        assert len(path["source"]["properties"]) <= 16
