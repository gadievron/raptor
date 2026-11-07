"""Complete, bounded conjunctions for the legacy mathematical-integer bridge.

This grammar has no C type/conversion semantics. Unsupported expressions
must not contribute comparison fragments or numeric literal prefixes.
"""

import re

_MAX_CHARS = 8192
_MAX_TOKENS = 512
_MAX_DEPTH = 64
_IDENT = r"[A-Za-z_]\w*(?:\.\w+){0,32}"
_INTEGER = r"-?(?:0[xX][0-9a-fA-F]+|0|[1-9][0-9]*)"
_TOKEN = re.compile(rf"{_IDENT}|{_INTEGER}|==|!=|<=|>=|&&|[<>()]")
_FLIP = {"<": ">", "<=": ">=", ">": "<", ">=": "<=", "==": "==", "!=": "!="}


def integer_conjunction(text, constants=None):
    """Return (name, operator, integer) atoms, or None for incomplete input.

    Parenthesized conjunctions, literal bounds, reversed comparisons and
    numeric constant substitution are supported. Every byte and every atom
    must be consumed. Constants are integer atoms, never replacement code.
    Leading-zero literals, suffixes, casts and arithmetic decline rather
    than guessing source semantics. Empty input is unmodeled too.
    """
    if not isinstance(text, str) or len(text) > _MAX_CHARS:
        return None
    constants = {} if constants is None else constants
    tokens = []
    position = 0
    while position < len(text):
        if text[position].isspace():
            position += 1
            continue
        match = _TOKEN.match(text, position)
        if match is None or len(tokens) >= _MAX_TOKENS:
            return None
        tokens.append(match.group())
        position = match.end()
    position = 0
    atoms = []

    def operand():
        nonlocal position
        if position >= len(tokens):
            raise ValueError
        token = tokens[position]
        position += 1
        if token in constants:
            token = constants[token]
            if not isinstance(token, str) or len(token) > _MAX_CHARS or re.fullmatch(_INTEGER, token) is None:
                raise ValueError
        if not isinstance(token, str):
            raise ValueError
        if re.fullmatch(_INTEGER, token):
            magnitude = token.removeprefix("-")
            value = int(magnitude, 16 if magnitude.lower().startswith("0x") else 10)
            return None, -value if token.startswith("-") else value
        if re.fullmatch(_IDENT, token) and token not in {"and", "or", "not"}:
            return token, None
        raise ValueError

    def conjunction(depth=0):
        nonlocal position
        if depth > _MAX_DEPTH:
            raise ValueError
        while True:
            if position < len(tokens) and tokens[position] == "(":
                position += 1
                conjunction(depth + 1)
                if position >= len(tokens) or tokens[position] != ")":
                    raise ValueError
                position += 1
            else:
                left, left_value = operand()
                if position >= len(tokens) or tokens[position] not in _FLIP:
                    raise ValueError
                op = tokens[position]
                position += 1
                right, right_value = operand()
                if left is not None and right is None:
                    atoms.append((left, op, right_value))
                elif left is None and right is not None:
                    atoms.append((right, _FLIP[op], left_value))
                else:
                    raise ValueError
            if position >= len(tokens) or tokens[position] not in {"&&", "and"}:
                return
            position += 1

    try:
        conjunction()
    except (ValueError, TypeError):
        return None
    return atoms if position == len(tokens) else None
