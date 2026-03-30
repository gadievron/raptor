"""Tests for structured output: schema conversion and fallback parsing.

Replaces the old LiteLLM+Instructor callback compatibility tests. Now tests
_dict_schema_to_pydantic conversion and _structured_fallback JSON parsing
without any LiteLLM dependency.
"""

import json
import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
from pydantic import BaseModel

# Add parent directories to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from packages.llm_analysis.llm.providers import (
    _dict_schema_to_pydantic,
    _coerce_to_schema,
    LLMProvider,
    LLMResponse,
)
from packages.llm_analysis.llm.config import ModelConfig


class TestDictSchemaToPydanticSimple:
    """Verify _dict_schema_to_pydantic converts simple dict schemas."""

    def test_simple_string_field(self):
        """Simple format: {"name": "string"} produces str field."""
        schema = {"name": "string"}
        model = _dict_schema_to_pydantic(schema)
        instance = model(name="hello")
        assert instance.name == "hello"

    def test_simple_boolean_field(self):
        """Simple format: {"is_exploitable": "boolean"} produces bool field."""
        schema = {"is_exploitable": "boolean"}
        model = _dict_schema_to_pydantic(schema)
        instance = model(is_exploitable=True)
        assert instance.is_exploitable is True

    def test_simple_float_field(self):
        """Simple format: {"score": "float (0.0-1.0)"} produces float field."""
        schema = {"score": "float (0.0-1.0)"}
        model = _dict_schema_to_pydantic(schema)
        instance = model(score=0.85)
        assert instance.score == 0.85

    def test_simple_int_field(self):
        """Simple format: {"count": "int"} produces int field."""
        schema = {"count": "int"}
        model = _dict_schema_to_pydantic(schema)
        instance = model(count=42)
        assert instance.count == 42

    def test_multiple_fields(self):
        """Multiple fields in simple format."""
        schema = {
            "is_exploitable": "boolean",
            "score": "float (0.0-1.0)",
            "reason": "string - explanation",
        }
        model = _dict_schema_to_pydantic(schema)
        instance = model(is_exploitable=True, score=0.9, reason="buffer overflow")
        assert instance.is_exploitable is True
        assert instance.score == 0.9
        assert instance.reason == "buffer overflow"

    def test_type_aliases(self):
        """Python type names (str, bool, int, list, dict) are accepted."""
        schema = {
            "name": "str",
            "active": "bool",
            "count": "int",
            "items": "list",
            "metadata": "dict",
        }
        model = _dict_schema_to_pydantic(schema)
        instance = model(name="x", active=True, count=1, items=[1], metadata={"a": 1})
        assert instance.name == "x"
        assert instance.active is True


class TestDictSchemaToPydanticJsonSchema:
    """Verify _dict_schema_to_pydantic converts JSON Schema format."""

    def test_json_schema_with_properties(self):
        """JSON Schema format with properties and required."""
        schema = {
            "properties": {
                "result": {"type": "string"},
                "confidence": {"type": "number"},
            },
            "required": ["result", "confidence"],
        }
        model = _dict_schema_to_pydantic(schema)
        instance = model(result="yes", confidence=0.95)
        assert instance.result == "yes"
        assert instance.confidence == 0.95

    def test_json_schema_optional_fields(self):
        """Fields not in required list become Optional."""
        schema = {
            "properties": {
                "result": {"type": "string"},
                "notes": {"type": "string"},
            },
            "required": ["result"],
        }
        model = _dict_schema_to_pydantic(schema)
        # Should work without notes (it's optional)
        instance = model(result="done")
        assert instance.result == "done"
        assert instance.notes is None

    def test_json_schema_with_defaults(self):
        """Fields with defaults use them."""
        schema = {
            "properties": {
                "name": {"type": "string"},
                "score": {"type": "number", "default": 0.5},
            },
            "required": ["name"],
        }
        model = _dict_schema_to_pydantic(schema)
        instance = model(name="test")
        assert instance.score == 0.5

    def test_pydantic_model_passthrough(self):
        """Pydantic BaseModel class passes through unchanged."""
        class MyModel(BaseModel):
            name: str
            value: int

        result = _dict_schema_to_pydantic(MyModel)
        assert result is MyModel

    def test_nullable_type_becomes_optional(self):
        """JSON Schema ["string", "null"] produces Optional[str]."""
        schema = {
            "properties": {
                "name": {"type": "string"},
                "notes": {"type": ["string", "null"]},
            },
            "required": ["name", "notes"],
        }
        model = _dict_schema_to_pydantic(schema)
        instance = model(name="test", notes=None)
        assert instance.name == "test"
        assert instance.notes is None

    def test_invalid_schema_type_raises(self):
        """Non-dict, non-Pydantic schema raises ValueError."""
        with pytest.raises(ValueError, match="must be dict or Pydantic"):
            _dict_schema_to_pydantic("not a schema")

    def test_invalid_schema_list_raises(self):
        """List schema raises ValueError."""
        with pytest.raises(ValueError, match="must be dict or Pydantic"):
            _dict_schema_to_pydantic(["field1", "field2"])


class TestCoerceToSchema:
    """Verify _coerce_to_schema normalises LLM output before Pydantic validation."""

    def test_string_boolean_true(self):
        schema = {"properties": {"flag": {"type": "boolean"}}}
        assert _coerce_to_schema({"flag": "true"}, schema) == {"flag": True}

    def test_string_boolean_false(self):
        schema = {"properties": {"flag": {"type": "boolean"}}}
        assert _coerce_to_schema({"flag": "false"}, schema) == {"flag": False}

    def test_non_boolean_string_becomes_false(self):
        schema = {"properties": {"flag": {"type": "boolean"}}}
        assert _coerce_to_schema({"flag": "not_a_bool"}, schema) == {"flag": False}

    def test_string_number(self):
        schema = {"properties": {"score": {"type": "number"}}}
        assert _coerce_to_schema({"score": "0.85"}, schema) == {"score": 0.85}

    def test_invalid_number_becomes_zero(self):
        schema = {"properties": {"score": {"type": "number"}}}
        assert _coerce_to_schema({"score": "not_a_number"}, schema) == {"score": 0.0}

    def test_null_string_becomes_empty(self):
        schema = {"properties": {"text": {"type": "string"}}}
        assert _coerce_to_schema({"text": None}, schema) == {"text": ""}

    def test_nullable_type_allows_null(self):
        schema = {"properties": {"text": {"type": ["string", "null"]}}}
        assert _coerce_to_schema({"text": None}, schema) == {"text": None}

    def test_correct_types_unchanged(self):
        schema = {"properties": {"flag": {"type": "boolean"}, "score": {"type": "number"}}}
        data = {"flag": True, "score": 0.9}
        assert _coerce_to_schema(data, schema) == data

    def test_extra_fields_preserved(self):
        schema = {"properties": {"flag": {"type": "boolean"}}}
        result = _coerce_to_schema({"flag": "yes", "extra": "kept"}, schema)
        assert result["flag"] is True
        assert result["extra"] == "kept"

    def test_empty_schema_noop(self):
        assert _coerce_to_schema({"anything": "here"}, {}) == {"anything": "here"}


class TestStructuredFallback:
    """Verify _structured_fallback strips markdown and validates with Pydantic."""

    def _make_provider(self, response_content: str):
        """Create a mock provider that returns the given content."""
        config = ModelConfig(
            provider="openai",
            model_name="gpt-5.2",
            api_key="sk-test",
            api_base="https://api.openai.com/v1",
        )
        mock_response = LLMResponse(
            content=response_content,
            model="gpt-5.2",
            provider="openai",
            tokens_used=100,
            cost=0.001,
            finish_reason="stop",
        )

        # We need a concrete provider instance for _structured_fallback.
        # Patch the abstract methods and the generate method.
        with patch.multiple(LLMProvider, __abstractmethods__=set()):
            provider = LLMProvider.__new__(LLMProvider)
            provider.config = config
            provider.total_tokens = 0
            provider.total_cost = 0.0

        provider.generate = MagicMock(return_value=mock_response)
        return provider

    def test_strips_markdown_json_fences(self):
        """Markdown ```json fences are stripped before parsing."""
        content = '```json\n{"result": "yes", "confidence": 0.9}\n```'
        provider = self._make_provider(content)

        schema = {"result": "string", "confidence": "float"}
        pydantic_model = _dict_schema_to_pydantic(schema)

        result_dict, full_response = provider._structured_fallback(
            prompt="test", schema=schema,
            pydantic_model=pydantic_model,
        )

        assert result_dict["result"] == "yes"
        assert result_dict["confidence"] == 0.9

    def test_strips_plain_backtick_fences(self):
        """Plain ``` fences (no language tag) are stripped."""
        content = '```\n{"result": "no", "confidence": 0.1}\n```'
        provider = self._make_provider(content)

        schema = {"result": "string", "confidence": "float"}
        pydantic_model = _dict_schema_to_pydantic(schema)

        result_dict, _ = provider._structured_fallback(
            prompt="test", schema=schema,
            pydantic_model=pydantic_model,
        )

        assert result_dict["result"] == "no"

    def test_parses_raw_json(self):
        """Raw JSON (no fences) is parsed directly."""
        content = '{"result": "maybe", "confidence": 0.5}'
        provider = self._make_provider(content)

        schema = {"result": "string", "confidence": "float"}
        pydantic_model = _dict_schema_to_pydantic(schema)

        result_dict, _ = provider._structured_fallback(
            prompt="test", schema=schema,
            pydantic_model=pydantic_model,
        )

        assert result_dict["result"] == "maybe"
        assert result_dict["confidence"] == 0.5

    def test_validates_with_pydantic(self):
        """Pydantic validation catches type mismatches."""
        # Return a string where a boolean is expected
        content = '{"is_exploitable": "not_a_bool"}'
        provider = self._make_provider(content)

        class StrictSchema(BaseModel):
            is_exploitable: bool

        # Pydantic v2 may coerce some values, but "not_a_bool" should fail
        with pytest.raises(Exception):
            provider._structured_fallback(
                prompt="test",
                schema={"is_exploitable": "boolean"},
                pydantic_model=StrictSchema,
            )

    def test_invalid_json_raises(self):
        """Invalid JSON in response raises json.JSONDecodeError."""
        content = "This is not JSON at all"
        provider = self._make_provider(content)

        schema = {"result": "string"}
        pydantic_model = _dict_schema_to_pydantic(schema)

        with pytest.raises(json.JSONDecodeError):
            provider._structured_fallback(
                prompt="test", schema=schema,
                pydantic_model=pydantic_model,
            )

    def test_returns_model_dump(self):
        """Return value is a dict from model_dump, not raw parsed JSON."""
        content = '{"name": "test", "value": 42}'
        provider = self._make_provider(content)

        schema = {
            "properties": {
                "name": {"type": "string"},
                "value": {"type": "integer"},
            },
            "required": ["name", "value"],
        }
        pydantic_model = _dict_schema_to_pydantic(schema)

        result_dict, full_response = provider._structured_fallback(
            prompt="test", schema=schema,
            pydantic_model=pydantic_model,
        )

        assert isinstance(result_dict, dict)
        assert result_dict["name"] == "test"
        assert result_dict["value"] == 42
        # full_response should be valid JSON
        parsed_response = json.loads(full_response)
        assert parsed_response["name"] == "test"
