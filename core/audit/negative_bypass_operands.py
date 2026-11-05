"""Explicit value and limit roles for diagnostic negative-bypass models."""

import re

from .operand_roles import SYMBOLIC_ATOM, unique_source_operand

_VALUE_ROLE = re.compile(
    rf"(?<![\w-])negative\s+(?:value\s+(?:for\s+)?)?(?:the\s+)?(?P<atom>{SYMBOLIC_ATOM})",
    re.IGNORECASE,
)
_LIMIT_ROLE = re.compile(
    r"\b(?:bypass(?:es|ed|ing)?|exceed(?:s|ed|ing)?|circumvent(?:s|ed|ing)?)\s+"
    rf"(?:the\s+)?(?P<atom>{SYMBOLIC_ATOM})\s+(?:check|limit|bound)\b",
    re.IGNORECASE,
)


def extract_negative_bypass_operands(hypothesis: str, code: str) -> tuple[str | None, str | None]:
    """Read unique source identifiers without guessing a limit from names."""
    return (
        unique_source_operand(_VALUE_ROLE, hypothesis, code),
        unique_source_operand(_LIMIT_ROLE, hypothesis, code),
    )
