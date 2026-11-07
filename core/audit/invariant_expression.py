"""Bounded mathematical-integer expressions and independent witness replay.

No Z3 objects, source execution, C conversion rules or reachability claims.
"""

import operator
import re

IDENTIFIER = r"[A-Za-z_]\w*(?:(?:->|\.)\w+)*"
SIZEOF = r"sizeof\s*\([^()]*\)"
MAX_TEXT_CHARS = 8192
MAX_TOKENS = 512
MAX_DEPTH = 64
MAX_INTEGER_DIGITS = 1024

_TOKEN_RE = re.compile(rf"\s*({SIZEOF}|{IDENTIFIER}|[0-9]+|[()+\-,])")


class ParseError(Exception):
    pass


def _sizeof_symbol(text):
    """Canonical opaque identity for simple object/type operands only.

    Array declarators can contain evaluated runtime extents. A frozen
    symbol cannot represent them; resolving even fixed arrays needs a
    separate source/type admission path rather than opaque token capture.
    """
    if re.fullmatch(SIZEOF, text) is None:
        raise ParseError("invalid sizeof expression")
    operand = " ".join(text[text.index("(") + 1 : -1].split())
    operand = "".join(part.strip() for part in re.split(r"(->|\.)", operand))
    if (
        re.fullmatch(IDENTIFIER, operand) is None
        and re.fullmatch(r"[A-Za-z_]\w*(?:\s+[A-Za-z_]\w*)*(?:\s*\*)*", operand) is None
    ):
        raise ParseError(
            "sizeof operand requires source/type or runtime-extent modeling"
        )
    # split() above has already reduced every whitespace run to one ASCII
    # space. Validation permits stars only at the end of a type operand.
    operand = operand.replace(" *", "*").replace("* ", "*")
    return f"sizeof({operand})"


def _tokenize(text: str) -> list[str]:
    if not isinstance(text, str) or len(text) > MAX_TEXT_CHARS:
        raise ParseError("expression exceeds text budget")
    tokens: list[str] = []
    pos = 0
    while pos < len(text):
        if text[pos].isspace():
            pos += 1
            continue
        m = _TOKEN_RE.match(text, pos)
        if not m:
            msg = f"unparseable at {text[pos : pos + 12]!r}"
            raise ParseError(msg)
        tokens.append(m.group(1).strip())
        if len(tokens) > MAX_TOKENS:
            raise ParseError("expression exceeds token budget")
        pos = m.end()
    # Without a type environment, `(Alias) + Value` could be a cast of
    # unary +Value or a parenthesized scalar addition. Do not choose one.
    for i in range(len(tokens) - 3):
        if (
            tokens[i] == "("
            and re.fullmatch(IDENTIFIER, tokens[i + 1])
            and tokens[i + 2] == ")"
            and tokens[i + 3] in {"+", "-"}
        ):
            raise ParseError(
                "ambiguous cast or grouped identifier requires source types"
            )
    return tokens


class _ExprParser:
    """Recursive-descent parser for the supported linear fragment:

    expr   := term (('+'|'-') term)*
    term   := IDENT | INT | 'min(' expr ',' expr ')'
            | 'max(' expr ',' expr ')' | 'sizeof(...)' | '(' expr ')'
    """

    def __init__(self, tokens: list[str]) -> None:
        self._toks = tokens
        self._pos = 0

    def _peek(self) -> str | None:
        return self._toks[self._pos] if self._pos < len(self._toks) else None

    def _next(self) -> str:
        tok = self._peek()
        if tok is None:
            msg = "unexpected end of expression"
            raise ParseError(msg)
        self._pos += 1
        return tok

    def _expect(self, tok: str) -> None:
        got = self._next()
        if got != tok:
            msg = f"expected {tok!r}, got {got!r}"
            raise ParseError(msg)

    def parse(self) -> tuple:
        node = self._expr()
        if self._peek() is not None:
            msg = f"trailing tokens: {self._toks[self._pos :]}"
            raise ParseError(msg)
        validate_expression(node)
        return node

    def _expr(self, depth=0) -> tuple:
        node = self._parse_term(depth)
        while self._peek() in ("+", "-"):
            op = self._next()
            rhs = self._parse_term(depth)
            node = ("add" if op == "+" else "sub", node, rhs)
        return node

    def _parse_term(self, depth=0) -> tuple:
        if depth > MAX_DEPTH:
            raise ParseError("expression exceeds depth budget")
        tok = self._next()
        if tok == "(":
            node = self._expr(depth + 1)
            self._expect(")")
            return node
        if tok == "-":
            inner = self._parse_term(depth + 1)
            return ("sub", ("int", 0), inner)
        if tok in ("min", "max") and self._peek() == "(":
            self._expect("(")
            a = self._expr(depth + 1)
            self._expect(",")
            b = self._expr(depth + 1)
            self._expect(")")
            return (tok, a, b)
        if re.fullmatch(SIZEOF, tok):
            return ("sizeof", _sizeof_symbol(tok))
        if tok.isdigit():
            if len(tok) > MAX_INTEGER_DIGITS:
                raise ParseError("integer literal exceeds digit budget")
            if len(tok) > 1 and tok.startswith("0"):
                raise ParseError(
                    "leading-zero integer literals require source literal semantics"
                )
            return ("int", int(tok))
        if re.fullmatch(IDENTIFIER, tok):
            return ("var", tok)
        msg = f"unexpected token {tok!r}"
        raise ParseError(msg)


def parse_expr(text: str) -> tuple:
    return _ExprParser(_tokenize(text)).parse()


def expression_vars(node: tuple) -> set[str]:
    kind = node[0]
    if kind == "var":
        return {node[1]}
    if kind in ("add", "sub", "min", "max"):
        return expression_vars(node[1]) | expression_vars(node[2])
    return set()


def validate_expression(root):
    """Bound and validate the entire tree before recursive encoders visit it."""
    pending = [(root, 0)]
    count = 0
    symbols = {}
    while pending:
        node, depth = pending.pop()
        count += 1
        if count > MAX_TOKENS or depth > MAX_DEPTH:
            raise ParseError("expression exceeds tree budget")
        if not isinstance(node, tuple) or not node or not isinstance(node[0], str):
            raise ParseError("invalid expression node")
        kind = node[0]
        if kind in {"add", "sub", "min", "max"} and len(node) == 3:
            pending.extend((child, depth + 1) for child in node[1:])
        elif (
            kind == "int"
            and len(node) == 2
            and type(node[1]) is int
            and node[1].bit_length() <= 4096
        ):
            continue
        elif kind in {"var", "sizeof"} and len(node) == 2 and isinstance(node[1], str):
            pattern = IDENTIFIER if kind == "var" else SIZEOF
            if len(node[1]) > MAX_TEXT_CHARS or re.fullmatch(pattern, node[1]) is None:
                raise ParseError("invalid expression symbol")
            if kind == "sizeof" and _sizeof_symbol(node[1]) != node[1]:
                raise ParseError("noncanonical sizeof identity")
            symbols[node[1]] = kind
        else:
            raise ParseError("unsupported expression node")
    return symbols


_COMPARISONS = {
    "<": operator.lt,
    "<=": operator.le,
    ">": operator.gt,
    ">=": operator.ge,
    "==": operator.eq,
    "!=": operator.ne,
}


def _evaluate(node, values):
    kind = node[0]
    if kind == "int":
        return node[1]
    if kind in {"var", "sizeof"}:
        return values[node[1]]
    left, right = (_evaluate(child, values) for child in node[1:])
    if kind == "add":
        return left + right
    if kind == "sub":
        return left - right
    return min(left, right) if kind == "min" else max(left, right)


def validate_counterexample(
    lhs, op, rhs, new_expr, var, conditions, model, *, nonnegative=False
):
    """Replay the exact pre-state, guards, assignment and violated post-state.

    Every required symbol must be present. Opaque sizes remain nonnegative and
    unchanged, as in the declared mathematical model. No native query or
    value completion is used to repair a bad counterexample.
    """
    if (
        not isinstance(var, str)
        or not isinstance(op, str)
        or op not in _COMPARISONS
        or type(nonnegative) is not bool
        or not isinstance(model, dict)
        or not isinstance(conditions, (list, tuple))
        or len(conditions) > 64
    ):
        return False
    if any(
        not isinstance(condition, (list, tuple))
        or len(condition) != 3
        or not isinstance(condition[1], str)
        for condition in conditions
    ):
        return False
    symbols = {}
    try:
        for node in (lhs, rhs, new_expr):
            symbols.update(validate_expression(node))
        for a, cmp, b in conditions:
            if cmp not in _COMPARISONS:
                return False
            symbols.update(validate_expression(a))
            symbols.update(validate_expression(b))
    except ParseError:
        return False
    post_name = var + "'"
    if var not in symbols or set(model) != set(symbols) | {post_name}:
        return False
    if any(
        type(value) is not int or value.bit_length() > 4096 for value in model.values()
    ):
        return False
    if any(kind == "sizeof" and model[name] < 0 for name, kind in symbols.items()):
        return False
    if nonnegative and any(model[name] < 0 for name in symbols):
        return False
    if not _COMPARISONS[op](_evaluate(lhs, model), _evaluate(rhs, model)):
        return False
    if any(
        not _COMPARISONS[cmp](_evaluate(a, model), _evaluate(b, model))
        for a, cmp, b in conditions
    ):
        return False
    if model[post_name] != _evaluate(new_expr, model):
        return False
    post_values = {**model, var: model[post_name]}
    return not _COMPARISONS[op](
        _evaluate(lhs, post_values), _evaluate(rhs, post_values)
    )
