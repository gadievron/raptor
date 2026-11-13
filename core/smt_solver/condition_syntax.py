"""Bounded lexical candidates for optional objectives, not expression parsing."""

import re

from core.smt_solver.call_arguments import find_call_end, non_code_spans
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
    original = text
    visible = list(text)
    for span in non_code_spans(text):
        if not span.closed:
            return ()
        start = span.start
        if not span.comment and text[start] in {"'", '"'}:
            for prefix in ("u8", "u", "U", "L"):
                begin = start - len(prefix)
                if begin >= 0 and text[begin:start] == prefix and (
                    begin == 0 or not (text[begin - 1].isascii() and (
                        text[begin - 1].isalnum() or text[begin - 1] == "_"
                    ))
                ):
                    start = begin
                    break
        visible[start:span.end] = [" "] * (span.end - start)
    text = "".join(visible)
    names: list[str] = []
    index = 0
    while index < len(text):
        match = _IDENTIFIER.match(text, index)
        if match is None:
            index += 1
            continue
        end = match.end()
        opening = end
        while opening < len(text) and text[opening].isspace():
            opening += 1
        if opening < len(text) and text[opening] == "(":
            call_end = find_call_end(original, opening)
            if call_end is None:
                return ()
            index = call_end
            continue
        name = match.group()
        if name != "NULL" and name not in names:
            names.append(name)
        index = end
    return tuple(names)
