"""Tests for _classify_role in core.audit.context."""

from __future__ import annotations

from core.audit.context import _classify_role


def test_entry_point_from_context_map():
    cm = {"entry_points": [{"file": "a.c", "name": "main"}]}
    result = _classify_role(
        cm, "a.c", "main", callers=[], callees=[], source="",
    )
    assert result["role"] == "entry_point"


def test_sink_from_context_map():
    cm = {"sink_details": [{"file": "a.c", "function": "do_exec"}]}
    result = _classify_role(
        cm, "a.c", "do_exec", callers=[], callees=[], source="",
    )
    assert result["role"] == "sink"


def test_sanitizer_by_name():
    result = _classify_role(
        None, "a.c", "validate_input", callers=[], callees=[{"name": "strlen"}],
        source="",
    )
    assert result["role"] == "sanitizer"


def test_leaf_no_callees():
    result = _classify_role(
        None, "a.c", "get_count", callers=[], callees=[], source="",
    )
    assert result["role"] == "leaf"


def test_relay_with_dangerous_api():
    result = _classify_role(
        None, "a.c", "copy_buffer", callers=[], callees=[{"name": "memcpy"}],
        source="memcpy(dst, src, n);",
    )
    assert result["role"] == "relay"
    assert "memcpy" in result["dangerous_apis"]


def test_internal_default():
    result = _classify_role(
        None, "a.c", "helper",
        callers=[{"file": "b.c", "name": "caller", "line_start": 1}],
        callees=[{"name": "strlen"}],
        source="strlen(s);",
    )
    assert result["role"] == "internal"


def test_reachability_note_warns_no_callers():
    result = _classify_role(
        None, "a.c", "orphan", callers=[], callees=[{"name": "strlen"}],
        source="strlen(s);",
    )
    assert "No callers" in result["reachability_note"]


def test_leaf_note_checks_for_unsafe_ops():
    """Leaf/internal without named dangerous APIs should tell the LLM to
    check for language-level unsafe operations, not dismiss the function."""
    result = _classify_role(
        None, "a.c", "helper",
        callers=[{"file": "b.c", "name": "caller", "line_start": 1}],
        callees=[{"name": "strlen"}],
        source="strlen(s);",
    )
    note = result["reachability_note"]
    assert "missing bounds check" in note.lower() or "indexing" in note.lower()
    assert "validation responsibility lies with the caller" in note


def test_on_flow_path_from_unchecked_flows():
    cm = {
        "unchecked_flows": [
            {"source": {"file": "a.c", "name": "recv_data"},
             "sink": {"file": "b.c", "name": "exec_cmd"}},
        ],
    }
    result = _classify_role(
        cm, "a.c", "recv_data", callers=[], callees=[], source="",
    )
    assert result["is_on_flow_path"] is True


def test_on_flow_path_skips_leaf_dismissal():
    """Functions on a flow path should not get the leaf/internal guidance."""
    cm = {
        "unchecked_flows": [
            {"source": {"file": "a.c", "name": "get_item"},
             "sink": {"file": "b.c", "name": "exec_cmd"}},
        ],
    }
    result = _classify_role(
        cm, "a.c", "get_item",
        callers=[{"file": "b.c", "name": "caller", "line_start": 1}],
        callees=[],
        source="return buf[i];",
    )
    assert "absence of validation" not in result["reachability_note"]
