"""Explicit symbolic roles for diagnostic bounds models, never source proof.

Identifiers retain case and must occur as code tokens in the selected function.
Object extents, access sites, conversions and path coverage remain unmodeled.
"""

import re

from .operand_roles import SYMBOLIC_ATOM, unique_source_operand

_INDEX_ROLE = re.compile(
    rf'''(?<!\S)(?P<atom>{SYMBOLIC_ATOM})\s+'''
    r"(?:is\s+(?:used\s+as\s+)?|used\s+as\s+|as\s+)"
    r"(?:an?\s+)?(?:array\s+)?index\b", re.IGNORECASE,
)
_SIZE_ROLE = re.compile(
    rf"\b(?:array|buffer)\s+(?:of\s+)?size\s+(?P<atom>{SYMBOLIC_ATOM})", re.IGNORECASE,
)


def extract_bounds_operands(hypothesis: str, code: str) -> tuple[str | None, str | None]:
    """Read unique index/capacity roles from a claim and comment-free code.

    Missing, conflicting or unsupported roles stay unknown. In particular,
    source names resembling sizes do not choose a capacity on their own.
    """
    return (
        unique_source_operand(_INDEX_ROLE, hypothesis, code),
        unique_source_operand(_SIZE_ROLE, hypothesis, code),
    )
