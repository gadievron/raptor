"""Token-level nullability detection in simple field specs.

A substring check on "null" also matched words that merely contain it
("nullify", "annulled"), silently marking a field nullable from
unrelated description prose — a None value then sailed through
validation for a field the schema meant to require.
"""

from __future__ import annotations

from core.llm.response_validation import _is_nullable


class TestNullableTokens:

    def test_or_null_description_is_nullable(self):
        assert _is_nullable("string or null") is True
        assert _is_nullable("int or NULL (optional)") is True

    def test_nullable_token_is_nullable(self):
        assert _is_nullable("string, nullable") is True

    def test_json_schema_type_list_is_nullable(self):
        assert _is_nullable({"type": ["string", "null"]}) is True

    def test_embedded_null_words_are_not_nullable(self):
        assert _is_nullable("string — set to nullify prior value") is False
        assert _is_nullable("boolean; true when annulled") is False

    def test_plain_specs_are_not_nullable(self):
        assert _is_nullable("string") is False
        assert _is_nullable({"type": "string"}) is False
