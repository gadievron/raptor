"""Opaque sizeof identities keep type spacing and reject unsupported operands."""

import pytest

from core.audit.invariant_expression import ParseError, parse_expr


@pytest.mark.parametrize(("operand", "expected"), [
    ("State -> Count", "State->Count"),
    ("State-> Count . Value", "State->Count.Value"),
    ("\u2003State\t->\nCount\u00a0", "State->Count"),
    ("unsigned\t long  * * ", "unsigned long**"),
    ("char**", "char**"),
    ("char *\n*", "char**"),
    ("struct Record *", "struct Record*"),
    (" Data ", "Data"),
])
def test_normalizes_supported_operand_identity(operand, expected):
    assert parse_expr(f"sizeof({operand})") == ("sizeof", f"sizeof({expected})")


@pytest.mark.parametrize("operand", [
    "State . -> Count", "char * value", "char * *value", "Count + Step",
    "char[Count]", "char * [4]", "", "State - > Count",
])
def test_normalization_does_not_admit_unsupported_operands(operand):
    with pytest.raises(ParseError):
        parse_expr(f"sizeof({operand})")
