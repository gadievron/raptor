"""Check hexadecimal capture spans before materialising matched digits."""

import re
from types import SimpleNamespace

import pytest

from core.sandbox import _daemon as daemon
from core.testing.module_views import module_function_view


def _private():
    groups = []

    class Match:
        def __init__(self, match):
            self.match = match

        def start(self, index):
            return self.match.start(index)

        def end(self, index):
            return self.match.end(index)

        def group(self, index):
            size = self.end(index) - self.start(index)
            groups.append(size)
            if size > 2:
                raise AssertionError("over-budget hexadecimal group materialised")
            return self.match.group(index)

    def search(pattern, text):
        result = re.search(pattern, text)
        return Match(result) if result is not None and pattern.startswith("0x") else result

    private = module_function_view(daemon, bindings={
        "re": SimpleNamespace(search=search), "_MAX_HEX_DIGITS": 2,
    })
    return private, groups


def test_over_budget_hex_does_not_materialise_capture_group():
    private, groups = _private()
    assert private._parse_bytes_to_int(b"prefix 0xAAAA suffix") is None
    assert groups == []


@pytest.mark.parametrize("raw,expected", [
    (b"prefix 0xFF suffix", 255),
    (b"0xf", 15),
    (b"0xAAAA then -42", -42),
    (b"0x1234", 1234),
    (b"0xAAA 0xff", None),
    (b"no number", None),
    (b"\xff 0xff", 255),
])
def test_span_admission_keeps_small_hex_and_decimal_fallback(raw, expected):
    private, groups = _private()
    assert private._parse_bytes_to_int(raw) == expected
    assert all(size <= 2 for size in groups)
