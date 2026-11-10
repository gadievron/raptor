"""One explicit atomic arithmetic expression per overflow claim.

Quotes may surround the expression or individual operands. The parser never
supplies a missing operator or takes a prefix of a compound expression.
Source occurrence, guards and types are admitted separately by the caller.
"""

from dataclasses import dataclass
import re

from ._util import IDENTIFIER_RE
from .arithmetic_operation import _INTEGER_LITERAL_RE

_MAX_CHARS = 8192
_MAX_TOKENS = 512
_MAX_DEPTH = 8
_WORD_OPERATORS = {"plus": "+", "minus": "-", "times": "*"}
_INTEGER_SUBJECT = re.compile(r"\b(?:integer|int)\s*(?:overflow|underflow|wraparound)\b", re.IGNORECASE)
# Bare CWE labels and width modifiers are prose; code quotes retain the
# arithmetic interpretation of the same characters.
_TOKEN = re.compile(
    r"(?P<quoted>`[^`\r\n]*`)"
    r"|(?P<prose>(?i:CWE-[0-9]+|[0-9]+-bit)\b)"
    r"|(?P<identifier>(?:[^\W\d]|[$])[\w$]*)"
    r"|(?P<number>0[xX][0-9a-fA-F]+|[0-9]+)"
    r"|(?P<symbol>[^\s])"
)


@dataclass(frozen=True)
class ArithmeticClaim:
    operands: tuple[str, str]
    operator: str


@dataclass(frozen=True)
class _Token:
    kind: str
    value: str
    start: int
    end: int
    expression: ArithmeticClaim | None = None


def _operator(token):
    if token.kind == "symbol" and token.value in {"+", "-", "*"}:
        return token.value
    return _WORD_OPERATORS.get(token.value.lower()) if token.kind == "identifier" else None


def _atom(tokens, index, step=1, depth=0, *, negative_literals=False):
    if depth > _MAX_DEPTH or not 0 <= index < len(tokens):
        return None
    token = tokens[index]
    if negative_literals and step == 1 and token.value == "-":
        inner = _atom(tokens, index + 1, step, depth + 1, negative_literals=False)
        if inner is not None and _INTEGER_LITERAL_RE.fullmatch(inner[0]):
            from .integer_literals import integer_literal_value
            value = integer_literal_value(inner[0])
            if value is not None:
                return str(-value), inner[1]
        return None
    if token.kind in {"atom", "identifier", "number"}:
        if IDENTIFIER_RE.fullmatch(token.value) or _INTEGER_LITERAL_RE.fullmatch(token.value):
            return token.value, index + step
    opening, closing = ("(", ")") if step == 1 else (")", "(")
    if token.value == opening:
        inner = _atom(tokens, index + step, step, depth + 1, negative_literals=negative_literals)
        if inner is not None:
            value, after = inner
            if 0 <= after < len(tokens) and tokens[after].value == closing:
                return value, after + step
    return None


def _binary(tokens, *, operators=None, negative_literals=False):
    # Strip only parentheses enclosing the complete expression.
    for _ in range(_MAX_DEPTH):
        if not tokens or tokens[0].value != "(":
            break
        depth = 0
        for index, token in enumerate(tokens):
            depth += (token.value == "(") - (token.value == ")")
            if depth == 0:
                break
        if depth != 0 or index != len(tokens) - 1:
            break
        tokens = tokens[1:-1]
    first = _atom(tokens, 0, negative_literals=negative_literals)
    if first is None:
        return None
    left, index = first
    if index >= len(tokens):
        return None
    token = tokens[index]
    after_operator = index + 1
    operator = (_operator(token) if operators is None else
                token.value if token.kind == "symbol" and token.value in operators else None)
    if operator is None and operators is not None and index + 1 < len(tokens):
        following = tokens[index + 1]
        combined = token.value + following.value
        if token.kind == following.kind == "symbol" and token.end == following.start and combined in operators:
            operator = combined
            after_operator += 1
    if operator is None:
        return None
    second = _atom(tokens, after_operator, negative_literals=negative_literals)
    if second is None or second[1] != len(tokens):
        return None
    return ArithmeticClaim((left, second[0]), operator)


def _tokens(text, *, code=False):
    result = []
    for match in _TOKEN.finditer(text):
        kind, value = match.lastgroup, match.group()
        if kind is None:
            return None
        expression = None
        if len(result) >= _MAX_TOKENS or value == "`":
            return None
        if kind == "prose" and code:
            # In code quotes, a hyphen denotes subtraction, even in text
            # which would otherwise look like a CWE label or width modifier.
            parts = _tokens(value.replace("-", " - "), code=True)
            if parts is None:
                return None
            result.extend(parts)
            if len(result) > _MAX_TOKENS:
                return None
            continue
        if kind == "quoted":
            if code:
                return None
            inner = _tokens(value[1:-1], code=True)
            if inner is None:
                return None
            expression = _binary(inner)
            if expression is not None:
                kind = "expression"
            else:
                atom = _atom(inner, 0)
                if atom is not None and atom[1] == len(inner):
                    kind, value = "atom", atom[0]
                elif any(_operator(token) for token in inner):
                    return None
                else:
                    kind = "other"
        result.append(_Token(kind, value, match.start(), match.end(), expression))
    return result


def _bad_boundary(tokens, start, end):
    before = tokens[start - 1] if start else None
    after = tokens[end] if end < len(tokens) else None
    if before is not None:
        if _operator(before) or before.value in {".", ">", "[", "]", ")", "/", "%", "&", "|", "^", "=", "!", "?"}:
            return True
        if tokens[start].value == "(" and before.kind in {"identifier", "atom"}:
            return True  # a function call cannot be reduced to its argument
        if before.end == tokens[start].start and (
            before.kind in {"atom", "identifier", "number"} or ("_" + before.value[-1]).isidentifier()
        ):
            return True
    if after is not None:
        if _operator(after) or after.value in {"(", "[", "]", "/", "%", "&", "|", "^", "=", "!", "?", ":", "<", ">"}:
            return True
        if tokens[end - 1].end == after.start and (
            after.kind in {"atom", "identifier", "number"} or ("_" + after.value[0]).isidentifier()
        ):
            return True
        if after.value == "." and end + 1 < len(tokens) and after.end == tokens[end + 1].start:
            return True
    return False


def parse_arithmetic_claim(hypothesis: str) -> ArithmeticClaim | None:
    """Select one explicit binary expression, declining ambiguous input."""
    if not isinstance(hypothesis, str) or len(hypothesis) > _MAX_CHARS:
        return None
    tokens = _tokens(hypothesis)
    if tokens is None:
        return None
    selected = None
    selected_key = None
    for index, token in enumerate(tokens):
        if token.expression is not None:
            expression = token.expression
            start, end = index, index + 1
        elif (operator := _operator(token)) is not None:
            left, right = _atom(tokens, index - 1, -1), _atom(tokens, index + 1)
            if left is None or right is None:
                if token.kind == "identifier":
                    continue  # an operator word alone does not supply operands
                return None
            expression = ArithmeticClaim((left[0], right[0]), operator)
            start, end = left[1] + 1, right[1]
        else:
            continue
        if _bad_boundary(tokens, start, end):
            return None
        operands = expression.operands
        key = (expression.operator, tuple(sorted(operands)) if expression.operator in {"+", "*"} else operands)
        if selected is not None and key != selected_key:
            return None
        selected, selected_key = expression, key
    return selected


def has_integer_overflow_subject(hypothesis: str) -> bool:
    """The auxiliary disproof API must not reinterpret another bug class."""
    return isinstance(hypothesis, str) and len(hypothesis) <= _MAX_CHARS and bool(_INTEGER_SUBJECT.search(hypothesis))


def _quoted_arithmetic_claim(hypothesis, operators, *, negative_literals=False):
    """One explicitly quoted atomic division/remainder; never a compound prefix."""
    if not isinstance(hypothesis, str) or len(hypothesis) > _MAX_CHARS:
        return None
    if hypothesis.count("`") % 2:
        return None
    selected = None
    for match in _TOKEN.finditer(hypothesis):
        if match.lastgroup != "quoted":
            continue
        text = match.group()[1:-1]
        if not any(operator in text for operator in operators):
            continue
        tokens = _tokens(text, code=True)
        expression = _binary(tokens, operators=operators, negative_literals=negative_literals) if tokens else None
        if expression is None or (selected is not None and selected != expression):
            return None
        selected = expression
    return selected


def parse_division_claim(hypothesis: str) -> ArithmeticClaim | None:
    """One quoted atomic quotient/remainder, preserving the existing grammar."""
    return _quoted_arithmetic_claim(hypothesis, {"/", "%"})


def parse_shift_claim(hypothesis: str) -> ArithmeticClaim | None:
    """One quoted atomic shift with an independently typed count operand."""
    return _quoted_arithmetic_claim(hypothesis, {"<<", ">>"}, negative_literals=True)
