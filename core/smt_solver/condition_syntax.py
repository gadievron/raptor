"""Bounded lexical candidates for optional objectives, not expression parsing."""

import re

from core.smt_solver.call_arguments import find_call_end
from core.smt_solver.canonicalise import canonicalise

# Shared with the condition parser: cap lexical work before rewriting or scanning.
MAX_CONDITION_CHARS = 2048
_IDENTIFIER = re.compile(r"(?<![0-9A-Za-z_])[A-Za-z_][A-Za-z0-9_]*")


def plain_condition_identifiers(text: str) -> tuple[str, ...]:
    """Preserve source names; skip opaque calls and quoted spans.

    Candidate membership must still be checked against the parser's registry.
    Only uppercase NULL denotes the shared grammar's literal zero.
    """
    if len(text) > MAX_CONDITION_CHARS:
        return ()
    text = canonicalise(text)
    names: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char in {"'", '"'}:
            quote = char
            index += 1
            while index < len(text) and text[index] != quote:
                index += 2 if text[index] == "\\" else 1
            if index >= len(text):
                return ()
            index += 1
            continue
        match = _IDENTIFIER.match(text, index)
        if match is None:
            index += 1
            continue
        end = match.end()
        opening = end
        while opening < len(text) and text[opening].isspace():
            opening += 1
        if opening < len(text) and text[opening] == "(":
            call_end = find_call_end(text, opening)
            if call_end is None:
                return ()
            index = call_end
            continue
        name = match.group()
        if name != "NULL" and name not in names:
            names.append(name)
        index = end
    return tuple(names)
