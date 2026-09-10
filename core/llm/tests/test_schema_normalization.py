"""Tests for shared descriptive-to-JSON-Schema normalization."""

from __future__ import annotations

import pytest

from core.llm.schema_normalization import normalize_json_schema


def test_descriptive_mapping_becomes_constraining_object_schema() -> None:
    schema = normalize_json_schema({
        "reasoning": "detailed explanation",
        "score": "float (0.0-1.0)",
        "path_conditions": "list of strings or null - branch conditions",
        "notes": "string optional - extra context",
        "verdict": {
            "type": "string",
            "enum": ["confirmed", "rejected"],
        },
    })

    assert schema == {
        "type": "object",
        "properties": {
            "reasoning": {
                "type": "string",
                "description": "detailed explanation",
            },
            "score": {
                "type": "number",
                "description": "(0.0-1.0)",
            },
            "path_conditions": {
                "type": ["array", "null"],
                "items": {"type": "string"},
                "description": "branch conditions",
            },
            "notes": {
                "type": "string",
                "description": "extra context",
            },
            "verdict": {
                "type": "string",
                "enum": ["confirmed", "rejected"],
            },
        },
        "required": ["reasoning", "score", "verdict"],
    }


@pytest.mark.parametrize(
    ("field_name", "descriptor"),
    [
        ("type", "string - output category"),
        ("required", "list"),
        ("enum", "list of strings"),
    ],
)
def test_descriptive_schema_keyword_field_is_not_mistaken_for_root_schema(
    field_name,
    descriptor,
) -> None:
    schema = normalize_json_schema({field_name: descriptor})

    assert schema["type"] == "object"
    assert field_name in schema["properties"]
    assert schema["required"] == [field_name]


def test_hybrid_descriptive_mapping_with_items_field_is_normalized() -> None:
    schema = normalize_json_schema({
        "items": {
            "type": "array",
            "items": {"type": "string"},
        },
        "summary": "string",
    })

    assert schema["type"] == "object"
    assert schema["properties"]["items"]["type"] == "array"
    assert schema["properties"]["summary"]["type"] == "string"


@pytest.mark.parametrize(
    "schema",
    [
        {
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "kind": {
                                "type": "string",
                                "enum": ["source", "sink"],
                            },
                            "value": {
                                "oneOf": [
                                    {"type": "integer"},
                                    {"type": "null"},
                                ],
                            },
                        },
                        "required": ["kind"],
                        "additionalProperties": False,
                    },
                },
            },
            "required": ["items"],
            "additionalProperties": False,
        },
        {
            "type": "array",
            "items": {
                "anyOf": [
                    {"type": "string"},
                    {"type": "number"},
                ],
            },
        },
        {
            "oneOf": [
                {"type": "string", "enum": ["yes", "no"]},
                {"type": "null"},
            ],
        },
        {
            "type": ["string", "null"],
            "enum": ["confirmed", None],
        },
        {
            "type": "object",
            "properties": {"forbidden": False},
            "additionalProperties": True,
        },
        True,
        False,
    ],
)
def test_valid_json_schema_passes_through_unchanged(schema) -> None:
    assert normalize_json_schema(schema) is schema
