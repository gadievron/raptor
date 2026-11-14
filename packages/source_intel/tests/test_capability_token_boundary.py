"""Privileged capability names must be complete identifiers."""

import pytest

import packages.source_intel.adapter as adapter
from packages.source_intel import _source_view
from packages.source_intel.analyze import _local_line_uses_privileged_cap


@pytest.mark.parametrize("token,expected", [
    ("CAP_SYS_ADMIN", True), ("CAP_SYS_MODULE", True),
    ("CAP_SYS_ADMIN_SUFFIX", False), ("MY_CAP_SYS_ADMIN", False),
    ("CAP_SYS_ADMIN0", False), ("CAP_NET_ADMIN", False),
])
def test_capability_constants_require_token_boundaries(token, expected, monkeypatch):
    lines = [f"if (!capable({token})) return -EPERM;"]
    monkeypatch.setattr(adapter, "_sanitized_lines", lambda _: lines)
    monkeypatch.setattr(_source_view, "sanitized_lines", lambda _: lines)
    assert adapter._line_uses_privileged_cap("owned.c", 1) is expected
    assert _local_line_uses_privileged_cap("owned.c", 1) is expected


@pytest.mark.parametrize("lines", [None, []])
def test_unavailable_capability_view_retains_refusal(lines, monkeypatch):
    monkeypatch.setattr(adapter, "_sanitized_lines", lambda _: lines)
    monkeypatch.setattr(_source_view, "sanitized_lines", lambda _: lines)
    assert adapter._line_uses_privileged_cap("owned.c", 1) is False
    assert _local_line_uses_privileged_cap("owned.c", 1) is False
