"""Primitive input receipts must describe the call's execution epoch."""
import pytest

from core.dataflow.string_type_evidence import exact_str_default_call_evidence


def test_deferred_alias_cannot_borrow_an_adjacent_string_fact():
    for preceding in ('x = "safe"', 'if type(x) is not str: return'):
        source = (
            "import html\n"
            "def make_alias(x):\n"
            f"    {preceding}\n"
            "    type Alias = html.escape(x)\n"
            "    x = 42\n"
            "    return Alias\n"
        )
        namespace = {}
        exec(compile(source, "owned_alias.py", "exec"), namespace)
        alias = namespace["make_alias"]("safe")
        # The call runs after the local string fact has ceased to hold.
        with pytest.raises(AttributeError):
            _ = alias.__value__
        assert exact_str_default_call_evidence(source, 4, "x", "html.escape") is None


def test_immediate_call_keeps_adjacent_string_evidence():
    source = (
        "import html\n"
        "def clean(x):\n"
        '    x = "safe"\n'
        "    safe = html.escape(x)\n"
        "    return safe\n"
    )
    receipt = exact_str_default_call_evidence(source, 4, "x", "html.escape")
    assert receipt is not None
    assert receipt.origin == "adjacent-literal-binding"
