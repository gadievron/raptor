"""Provider schema instructions survive conversion without new admission rules."""

import pytest
from pydantic import ValidationError

from core.llm.providers import _dict_schema_to_pydantic


def test_required_optional_and_nested_descriptions_reach_wire_schema():
    schema = {"type": "object", "properties": {
        "required_value": {"type": "string", "description": "Required caller instruction"},
        "requests": {"type": "array", "description": "Optional bounded request instructions",
                     "items": {"type": "object", "properties": {
                         "choice": {"type": "string", "enum": ["one"],
                                    "description": "Independent choice, never authority"}},
                               "required": ["choice"]}}}, "required": ["required_value"]}
    model = _dict_schema_to_pydantic(schema)
    wire = model.model_json_schema()
    assert wire["properties"]["required_value"]["description"] == "Required caller instruction"
    assert wire["properties"]["requests"]["description"] == "Optional bounded request instructions"
    item = next(value for value in wire["$defs"].values() if "choice" in value.get("properties", {}))
    assert item["properties"]["choice"]["description"] == "Independent choice, never authority"
    assert wire["required"] == ["required_value"]
    assert model(required_value="ok").model_dump() == {"required_value": "ok", "requests": None}
    with pytest.raises(ValidationError):
        model.model_validate({})
    with pytest.raises(ValidationError):
        model(required_value="ok", requests=[{"choice": "unissued"}])


def test_description_absence_and_required_nullable_semantics_are_unchanged():
    model = _dict_schema_to_pydantic({"type": "object", "properties": {
        "value": {"type": ["string", "null"]},
        "optional": {"type": "integer", "default": 7}}, "required": ["value"]})
    assert "description" not in model.model_json_schema()["properties"]["value"]
    assert model(value=None).model_dump() == {"value": None, "optional": 7}
    with pytest.raises(ValidationError):
        model.model_validate({})
