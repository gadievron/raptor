"""Review-provided CWE titles must preserve dispatch and policy decisions."""

import pytest

from core.audit.cwe_dispatch import (
    CWE_NOT_TOOL_VERIFIABLE,
    CWE_TO_TOOL_DISPATCH,
    is_placeholder_cwe,
    lookup,
    not_tool_verifiable_reason,
    tool_scope_for_cwe,
)


@pytest.mark.parametrize(
    'label,canonical',
    [
        ('CWE-122: HEAP-BASED BUFFER OVERFLOW', 'CWE-122'),
        ('CWE-287: IMPROPER AUTHENTICATION', 'CWE-287'),
        ('CWE-416: Use After Free', 'CWE-416'),
        (' cwe-78 : OS Command Injection ', 'CWE-78'),
        ('78: OS Command Injection', 'CWE-78'),
        ('78', 'CWE-78'),
    ],
)
def test_review_label_preserves_routing(label, canonical):
    assert lookup(label) is lookup(canonical)
    assert lookup(label) is not None
    assert not is_placeholder_cwe(label)
    assert tool_scope_for_cwe(label) == tool_scope_for_cwe(canonical)


def test_titles_preserve_all_dispatch_and_policy_entries():
    for cwe, entry in CWE_TO_TOOL_DISPATCH.items():
        assert lookup(f'{cwe}: Descriptive title') is entry
    for cwe, reason in CWE_NOT_TOOL_VERIFIABLE.items():
        label = f'{cwe}: Descriptive title'
        assert not_tool_verifiable_reason(label) == reason
        assert lookup(label) is None


@pytest.mark.parametrize('label', [
    'CWE-122garbage', 'CWE-122.5', 'CWE-122/CWE-287',
    'CWE-122: Overflow; CWE-287: Authentication',
    'CWE-122: Overflow\nCWE-287', 'possibly CWE-122',
    'CWE-122:', 'CWE-Other: Unknown', 'CWE-000: Unknown',
])
def test_malformed_ambiguous_and_placeholder_labels_do_not_route(label):
    assert lookup(label) is None
    assert tool_scope_for_cwe(label) is None
    assert not_tool_verifiable_reason(label) == ''
    assert is_placeholder_cwe(label)


@pytest.mark.parametrize('label', ['', '   '])
def test_absent_label_remains_absent(label):
    assert lookup(label) is None
    assert not is_placeholder_cwe(label)
