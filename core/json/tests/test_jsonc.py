"""Tests for core.json.jsonc — the string-aware JSONC loader."""

from __future__ import annotations

import json

import pytest

from core.json.jsonc import load_jsonc, strip_jsonc_comments


def test_url_in_string_value_not_mangled():
    """The bug this exists to prevent: a // inside a string value (a URL)
    must survive comment stripping."""
    text = '{\n  // a comment\n  "repo": "https://github.com/o/r"\n}\n'
    data = load_jsonc(text)
    assert data == {"repo": "https://github.com/o/r"}


def test_block_comment_and_trailing_comma():
    text = '{\n  /* block\n     comment */\n  "a": 1,\n  "b": [1, 2,],\n}\n'
    assert load_jsonc(text) == {"a": 1, "b": [1, 2]}


def test_comment_markers_inside_strings_preserved():
    assert strip_jsonc_comments('"a/*b*/c"') == '"a/*b*/c"'
    assert strip_jsonc_comments('"x // y"') == '"x // y"'
    # Escaped quote inside a string must not end the string early.
    assert strip_jsonc_comments('"he said \\"hi//\\" ok"') == \
        '"he said \\"hi//\\" ok"'


def test_plain_json_round_trips():
    obj = {"k": ["v", 1, True, None]}
    assert load_jsonc(json.dumps(obj)) == obj


def test_malformed_raises_like_json_loads():
    with pytest.raises(ValueError):   # JSONDecodeError is a ValueError
        load_jsonc("{not valid")
