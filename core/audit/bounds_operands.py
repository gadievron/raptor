"""Explicit symbolic roles for diagnostic bounds models, never source proof.

Identifiers retain case and must occur as code tokens in the selected function.
Object extents, access sites, conversions and path coverage remain unmodeled.
"""

import re

from ._util import IDENTIFIER_RE

# Capture whole quoted/compound candidates before validating atomicity. This
# prevents accepting an identifier borrowed from inside a field or expression.
_ATOM = r'''(?:`[^`\r\n]+`|'[^'\r\n]+'|"[^"\r\n]+"|[A-Za-z_][^\s`'";,().]*)'''
_INDEX_ROLE = re.compile(
    rf'''(?<!\S)(?P<atom>{_ATOM})\s+'''
    r"(?:is\s+(?:used\s+as\s+)?|used\s+as\s+|as\s+)"
    r"(?:an?\s+)?(?:array\s+)?index\b", re.IGNORECASE,
)
_SIZE_ROLE = re.compile(
    rf"\b(?:array|buffer)\s+(?:of\s+)?size\s+(?P<atom>{_ATOM})", re.IGNORECASE,
)
_CONTINUATION = re.compile(r"\s*(?:->|::|\.[A-Za-z_]|[+\-*/%\[(])")


def _unique_operand(pattern, hypothesis, code):
    selected = None
    for match in pattern.finditer(hypothesis):
        atom = match.group("atom")
        if atom[0] in "`'\"":
            atom = atom[1:-1]
        if not IDENTIFIER_RE.fullmatch(atom):
            return None
        # A symbolic term following an operator is part of an unsupported
        # expression, even when whitespace separates it from that operator.
        before = match.start("atom") - 1
        while before >= 0 and hypothesis[before].isspace():
            before -= 1
        if before >= 0 and (
            hypothesis[before] in "+-*/%>.[(&|^"
            or hypothesis[max(0, before - 1):before + 1] == "::"
        ):
            return None
        if _CONTINUATION.match(hypothesis, match.end("atom")):
            return None
        if selected is not None:
            if selected != atom:
                return None
            continue
        if not re.search(rf"(?<!\w){re.escape(atom)}(?!\w)", code):
            return None
        selected = atom
    return selected


def extract_bounds_operands(hypothesis: str, code: str) -> tuple[str | None, str | None]:
    """Read unique index/capacity roles from a claim and comment-free code.

    Missing, conflicting or unsupported roles stay unknown. In particular,
    source names resembling sizes do not choose a capacity on their own.
    """
    return (
        _unique_operand(_INDEX_ROLE, hypothesis, code),
        _unique_operand(_SIZE_ROLE, hypothesis, code),
    )
