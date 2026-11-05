"""Shared symbolic-role admission for diagnostic arithmetic models.

Callers supply comment/string-free code from the requested function.
Token occurrence establishes neither a type nor an access/conversion site.
"""

import re

from ._util import IDENTIFIER_RE

# Capture whole quoted/compound candidates before validating atomicity. This
# prevents accepting an identifier borrowed from inside a field or expression.
SYMBOLIC_ATOM = r'''(?:`[^`\r\n]+`|'[^'\r\n]+'|"[^"\r\n]+"|[A-Za-z_][^\s`'";,().]*)'''
_CONTINUATION = re.compile(r"\s*(?:->|::|\.[A-Za-z_]|[+\-*/%\[(])")


def unique_source_operand(pattern, hypothesis, code):
    """Return one atomic code identifier for a role, or no candidate."""
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
