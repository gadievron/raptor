"""Normalize RAPTOR's descriptive output schemas to JSON Schema."""

from __future__ import annotations

from typing import Any

JsonSchema = dict[str, Any] | bool

_JSON_SCHEMA_TYPES = frozenset({
    "array",
    "boolean",
    "integer",
    "null",
    "number",
    "object",
    "string",
})

_JSON_SCHEMA_KEYWORDS = frozenset({
    "$anchor",
    "$comment",
    "$defs",
    "$dynamicAnchor",
    "$dynamicRef",
    "$id",
    "$ref",
    "$schema",
    "$vocabulary",
    "additionalProperties",
    "allOf",
    "anyOf",
    "const",
    "contains",
    "contentEncoding",
    "contentMediaType",
    "contentSchema",
    "default",
    "definitions",
    "dependentRequired",
    "dependentSchemas",
    "deprecated",
    "description",
    "else",
    "enum",
    "examples",
    "exclusiveMaximum",
    "exclusiveMinimum",
    "format",
    "if",
    "items",
    "maxContains",
    "maximum",
    "maxItems",
    "maxLength",
    "maxProperties",
    "minContains",
    "minimum",
    "minItems",
    "minLength",
    "minProperties",
    "multipleOf",
    "not",
    "oneOf",
    "pattern",
    "patternProperties",
    "prefixItems",
    "properties",
    "propertyNames",
    "readOnly",
    "required",
    "then",
    "title",
    "type",
    "unevaluatedItems",
    "unevaluatedProperties",
    "uniqueItems",
    "writeOnly",
})

_ANNOTATION_KEYWORDS = frozenset({
    "contentEncoding",
    "contentMediaType",
    "default",
    "deprecated",
    "description",
    "examples",
    "format",
    "readOnly",
    "title",
    "writeOnly",
})

_TYPE_ALIASES = {
    "bool": "boolean",
    "dict": "object",
    "float": "number",
    "int": "integer",
    "list": "array",
    "str": "string",
}


def _is_type_declaration(value: Any) -> bool:
    if isinstance(value, str):
        return value in _JSON_SCHEMA_TYPES
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(item, str) and item in _JSON_SCHEMA_TYPES for item in value)
    )


def _is_extension_keyword(key: str) -> bool:
    return key.startswith(("x-", "x_"))


def _looks_like_json_schema(schema: dict[str, Any]) -> bool:
    """Distinguish a JSON Schema document from RAPTOR's field map.

    Unknown JSON Schema extension keywords are legal, so this is
    necessarily structural rather than validator-based: descriptive
    mappings use output field names as keys, while schema documents
    carry at least one correctly shaped JSON Schema keyword.
    """
    if not schema:
        return True

    if any(key.startswith("$") for key in schema):
        return True

    if not all(
        key in _JSON_SCHEMA_KEYWORDS or _is_extension_keyword(key)
        for key in schema
    ):
        return False

    properties = schema.get("properties")
    if isinstance(properties, dict):
        return True

    schema_type = schema.get("type")
    if _is_type_declaration(schema_type):
        return all(
            key in _JSON_SCHEMA_KEYWORDS or _is_extension_keyword(key)
            for key in schema
        )

    list_keywords = (
        "allOf",
        "anyOf",
        "enum",
        "oneOf",
        "prefixItems",
        "required",
    )
    if any(isinstance(schema.get(key), list) for key in list_keywords):
        return True

    schema_keywords = (
        "additionalProperties",
        "contentSchema",
        "contains",
        "dependentRequired",
        "dependentSchemas",
        "else",
        "if",
        "items",
        "not",
        "patternProperties",
        "propertyNames",
        "then",
        "unevaluatedItems",
        "unevaluatedProperties",
    )
    if any(isinstance(schema.get(key), (dict, bool)) for key in schema_keywords):
        return True

    if "const" in schema:
        return True

    numeric_keywords = (
        "exclusiveMaximum",
        "exclusiveMinimum",
        "maxContains",
        "maximum",
        "maxItems",
        "maxLength",
        "maxProperties",
        "minContains",
        "minimum",
        "minItems",
        "minLength",
        "minProperties",
        "multipleOf",
    )
    if any(
        isinstance(schema.get(key), (int, float))
        and not isinstance(schema.get(key), bool)
        for key in numeric_keywords
    ):
        return True

    if isinstance(schema.get("pattern"), str):
        return True
    if isinstance(schema.get("uniqueItems"), bool):
        return True

    return bool(set(schema) & _ANNOTATION_KEYWORDS) and all(
        key in _ANNOTATION_KEYWORDS or _is_extension_keyword(key)
        for key in schema
    )


def _description_from_descriptor(
    descriptor: str,
    *,
    inferred_type: bool,
) -> str | None:
    if " - " in descriptor:
        return descriptor.split(" - ", 1)[1].strip()
    if " \u2014 " in descriptor:
        return descriptor.split(" \u2014 ", 1)[1].strip()
    if "(" in descriptor:
        return descriptor[descriptor.find("("):].strip()
    if not inferred_type and descriptor:
        return descriptor
    return None


def normalize_json_schema(schema: JsonSchema) -> JsonSchema:
    """Return a valid JSON Schema for a structured-output request.

    RAPTOR's compact form maps output field names to type descriptions,
    for example ``{"score": "float (0.0-1.0)"}``. JSON Schema documents,
    including non-object roots and boolean schemas, pass through unchanged.
    """
    if isinstance(schema, bool) or _looks_like_json_schema(schema):
        return schema

    properties: dict[str, Any] = {}
    required: list[str] = []

    for field_name, field_desc in schema.items():
        if isinstance(field_desc, (dict, bool)):
            properties[field_name] = field_desc
            required.append(field_name)
            continue

        descriptor = str(field_desc)
        parts = descriptor.split()
        raw_type = parts[0].strip() if parts else "string"
        field_type = _TYPE_ALIASES.get(raw_type, raw_type)
        inferred_type = field_type in _JSON_SCHEMA_TYPES
        if not inferred_type:
            field_type = "string"

        desc_lower = descriptor.lower()
        if " or null" in desc_lower:
            prop: dict[str, Any] = {"type": [field_type, "null"]}
        elif desc_lower.startswith("null or "):
            actual = parts[2].strip() if len(parts) > 2 else "string"
            actual = _TYPE_ALIASES.get(actual, actual)
            if actual not in _JSON_SCHEMA_TYPES:
                actual = "string"
            prop = {"type": [actual, "null"]}
        else:
            prop = {"type": field_type}

        if field_type == "array":
            prop["items"] = {"type": "string"}

        description = _description_from_descriptor(
            descriptor,
            inferred_type=inferred_type,
        )
        if description:
            prop["description"] = description

        properties[field_name] = prop
        if "optional" not in desc_lower and "or null" not in desc_lower:
            required.append(field_name)

    return {
        "type": "object",
        "properties": properties,
        "required": required,
    }
