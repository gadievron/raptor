"""Decimal capture admission honours the active interpreter digit limit."""

import re
from types import SimpleNamespace

import pytest

from core.sandbox import _daemon as daemon
from core.testing.module_views import module_function_view


def _private(limit=640, converter=int):
    groups = []

    class Match:
        def __init__(self, match):
            self.match = match

        def start(self, index):
            return self.match.start(index)

        def end(self, index):
            return self.match.end(index)

        def group(self, index):
            digits = self.end(index) - self.start(index)
            if self.match.string[self.start(index)] == "-":
                digits -= 1
            groups.append(digits)
            if limit and digits > limit:
                raise AssertionError("decimal group copied before digit refusal")
            return self.match.group(index)

    def search(pattern, text):
        match = re.search(pattern, text)
        return Match(match) if match is not None and pattern.startswith("(-?") else match

    private = module_function_view(daemon, bindings={
        "re": SimpleNamespace(search=search),
        "sys": SimpleNamespace(get_int_max_str_digits=lambda: limit),
        "int": converter,
    })
    return private, groups


def test_over_limit_decimal_refuses_before_group_copy():
    private, groups = _private()
    assert private._parse_bytes_to_int(b"prefix " + b"9" * 641 + b" suffix") is None
    assert groups == []


@pytest.mark.parametrize("digits", ["1" * 640, "١" * 640, "0" * 640])
@pytest.mark.parametrize("sign", ["", "-"])
def test_active_boundary_counts_digits_without_sign_or_utf8_bytes(digits, sign):
    private, groups = _private()
    text = sign + digits
    assert private._parse_bytes_to_int(("prefix " + text + " suffix").encode()) == int(text)
    assert groups == [640]


@pytest.mark.parametrize("text", ["-" + "9" * 641, "١" * 641, "0" * 641])
def test_active_limit_refuses_over_budget_digit_run(text):
    private, groups = _private()
    assert private._parse_bytes_to_int(("prefix " + text).encode()) is None
    assert groups == []


def test_disabled_limit_does_not_introduce_a_new_threshold():
    converted = []

    def convert(value):
        converted.append(value)
        return 7

    private, groups = _private(limit=0, converter=convert)
    text = "9" * 641
    assert private._parse_bytes_to_int(("prefix " + text).encode()) == 7
    assert converted == [text]
    assert groups == [641]


def test_over_limit_first_match_does_not_fall_through_to_later_number():
    private, groups = _private()
    assert private._parse_bytes_to_int(b"prefix " + b"9" * 641 + b" then 42") is None
    assert groups == []


def test_hex_priority_stays_independent_of_decimal_limit():
    private, groups = _private()
    assert private._parse_bytes_to_int(b"0xff then " + b"9" * 641) == 255
    assert groups == []
