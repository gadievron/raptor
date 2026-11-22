"""Exact printf-family format/argument arity counting (C).

Role: detection. A variadic printf-family call whose string-literal
format requires more arguments than the call supplies reads a missing
argument — undefined behaviour regardless of values (C11 7.21.6.1p2) —
so a counted deficit is a confirmed defect. A surplus is NOT a defect:
excess arguments are evaluated and ignored (C11 7.21.6.1p2 again).

The count is exact inside a closed grammar and the verdict declines on
anything outside it, because an over-count here would manufacture a
false positive:

- only direct calls to a seeded callee name with a known format
  position are counted; calls through pointers, macros, wrappers or
  with a non-literal / prefixed / concatenated format string decline;
  a same-file ``#define``/``#undef`` of a seeded name declines every
  call to that name (the call may expand to something else entirely),
  and a call anywhere under a preprocessor conditional declines (the
  region may be excluded from translation);
- the format the runtime sees ends at the first NUL: directives after
  an embedded ``\\0`` are never counted;
- the literal is unescaped with the full C escape grammar (simple
  escapes, 1-3 digit octal, ``\\x`` hex — ``\\x25`` IS a percent
  sign); any other escape (``\\u``, ``\\e``, spliced lines) declines;
- a directive consumes exactly one argument for conversions
  ``diouxXeEfFgGaAcspn``, plus one per ``*`` width/precision;
  ``%%`` consumes none and admits no flags; positional ``m$`` forms,
  ``%m``, wide ``%S``/``%C`` and every unknown flag, length modifier
  or conversion decline the whole call.

Under-counting is impossible within the admitted grammar, and every
unadmitted construct declines rather than guesses, so ``deficit_found``
never fires on a call the compiler would accept as correctly supplied.
"""

from __future__ import annotations

from dataclasses import dataclass, field

_MAX_SOURCE_CHARS = 1 << 20

#: Zero-based index of the format-string argument for each seeded
#: callee. va_list variants (vprintf, vsnprintf, ...) are deliberately
#: absent — their argument count is not visible at the call site.
_FORMAT_POSITIONS = {
    "printf": 0,
    "fprintf": 1,
    "dprintf": 1,
    "sprintf": 1,
    "snprintf": 2,
    "asprintf": 1,
}

_CONVERSIONS = frozenset("diouxXeEfFgGaAcspn")
_FLAGS = frozenset("-+ #0'")
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_OCTAL_DIGITS = frozenset("01234567")

_SIMPLE_ESCAPES = {
    "a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r",
    "t": "\t", "v": "\v", "\\": "\\", "'": "'", '"': '"', "?": "?",
}


@dataclass
class FormatArgsResult:
    deficit_found: bool = False
    applicable: bool = True
    call_name: str = ""
    line: int = 0
    format_string: str = ""
    required: int = -1
    supplied: int = -1
    analysed_calls: int = 0
    declined_calls: int = 0
    reasoning: str = ""
    deficits: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        out = {
            "deficit_found": self.deficit_found,
            "applicable": self.applicable,
            "analysed_calls": self.analysed_calls,
            "declined_calls": self.declined_calls,
            "reasoning": self.reasoning,
        }
        if self.deficit_found:
            out.update({
                "call_name": self.call_name,
                "line": self.line,
                "format_string": self.format_string,
                "required": self.required,
                "supplied": self.supplied,
                "deficits": list(self.deficits),
            })
        return out


def _unescape(body: str) -> str | None:
    """The byte content of a plain C string-literal body, or None when
    any escape falls outside the closed grammar."""
    out: list[str] = []
    i, n = 0, len(body)
    while i < n:
        c = body[i]
        if c != "\\":
            out.append(c)
            i += 1
            continue
        i += 1
        if i >= n:
            return None
        e = body[i]
        if e in _SIMPLE_ESCAPES:
            out.append(_SIMPLE_ESCAPES[e])
            i += 1
            continue
        if e == "x":
            i += 1
            j = i
            while j < n and body[j] in _HEX_DIGITS:
                j += 1
            if j == i:
                return None
            value = int(body[i:j], 16)
            if value > 0xFF:
                return None  # out-of-range hex escape is a constraint error
            out.append(chr(value))
            i = j
            continue
        if e in _OCTAL_DIGITS:
            j = i
            while j < n and j < i + 3 and body[j] in _OCTAL_DIGITS:
                j += 1
            out.append(chr(int(body[i:j], 8)))
            i = j
            continue
        return None  # \u, \U, \e, line splices, anything else
    return "".join(out)


def _count_required(fmt: str) -> int | None:
    """Arguments the directives of *fmt* consume, or None (decline)."""
    i, n, count = 0, len(fmt), 0
    while i < n:
        if fmt[i] != "%":
            i += 1
            continue
        i += 1
        if i >= n:
            return None  # trailing lone '%'
        if fmt[i] == "%":
            i += 1
            continue
        # Positional ``%m$`` — mixing rules make counting non-local.
        j = i
        while j < n and fmt[j].isdigit():
            j += 1
        if j > i and j < n and fmt[j] == "$":
            return None
        while i < n and fmt[i] in _FLAGS:
            i += 1
        if i < n and fmt[i] == "*":
            count += 1
            i += 1
        else:
            while i < n and fmt[i].isdigit():
                i += 1
        if i < n and fmt[i] == ".":
            i += 1
            if i < n and fmt[i] == "*":
                count += 1
                i += 1
            else:
                while i < n and fmt[i].isdigit():
                    i += 1
        if i < n and fmt[i] == "$":
            return None  # positional width/precision form
        if fmt.startswith(("hh", "ll"), i):
            i += 2
        elif i < n and fmt[i] in "hljzqtLZ":
            i += 1
        if i >= n:
            return None  # directive runs off the end
        if fmt[i] not in _CONVERSIONS:
            # %m, wide %S/%C, flagged '%', every unknown conversion.
            return None
        count += 1
        i += 1
    return count


def _has_preproc(node) -> bool:
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type.startswith("preproc"):
            return True
        stack.extend(n.named_children)
    return False


def _under_preproc(node) -> bool:
    """True when any ancestor is a preprocessor construct: the call may
    sit in a region the preprocessor excludes from translation."""
    cur = node.parent
    while cur is not None:
        if cur.type.startswith("preproc"):
            return True
        cur = cur.parent
    return False


def _redefined_names(root, text) -> set[str]:
    """Seeded callee names a same-file ``#define``/``#undef`` touches.

    A macro redefinition means the call expands to arbitrary other code,
    so counting its literal arguments would assert a deficit about a
    call the compiled program never makes."""
    redefined: set[str] = set()
    stack = [root]
    while stack:
        node = stack.pop()
        stack.extend(node.named_children)
        if node.type in ("preproc_def", "preproc_function_def"):
            name = node.child_by_field_name("name")
            if name is not None and text(name) in _FORMAT_POSITIONS:
                redefined.add(text(name))
        elif node.type == "preproc_call":
            directive = node.child_by_field_name("directive")
            argument = node.child_by_field_name("argument")
            if directive is not None and text(directive) == "#undef" \
                    and argument is not None:
                target = text(argument).split()
                if target and target[0] in _FORMAT_POSITIONS:
                    redefined.add(target[0])
    return redefined


def check_format_args(source: str) -> FormatArgsResult:
    """Count format directives against supplied arguments for every
    analysable printf-family call in *source* (C)."""
    if not isinstance(source, str) or not source.strip():
        return FormatArgsResult(
            applicable=False, reasoning="no source provided",
        )
    if len(source) > _MAX_SOURCE_CHARS:
        return FormatArgsResult(
            applicable=False, reasoning="source too large to analyse",
        )
    from .condition_extraction import _get_parser

    parser = _get_parser("c")
    if parser is None:
        return FormatArgsResult(
            applicable=False, reasoning="C parser unavailable",
        )
    data = source.encode("utf-8")
    root = parser.parse(data).root_node
    if root.has_error:
        return FormatArgsResult(
            applicable=False, reasoning="source does not parse as C",
        )

    def text(node) -> str:
        return data[node.start_byte:node.end_byte].decode(
            "utf-8", "replace",
        )

    analysed = 0
    declined = 0
    deficits: list[dict] = []
    redefined = _redefined_names(root, text)
    stack = [root]
    while stack:
        node = stack.pop()
        stack.extend(node.named_children)
        if node.type != "call_expression":
            continue
        callee = node.child_by_field_name("function")
        if callee is None or callee.type != "identifier":
            continue
        name = text(callee)
        position = _FORMAT_POSITIONS.get(name)
        if position is None:
            continue
        if name in redefined or _has_preproc(node) or _under_preproc(node):
            declined += 1
            continue
        arguments = node.child_by_field_name("arguments")
        args = ([] if arguments is None else
                [c for c in arguments.named_children
                 if c.type != "comment"])
        if position >= len(args):
            declined += 1
            continue
        fmt_node = args[position]
        if fmt_node.type != "string_literal":
            declined += 1  # non-literal / concatenated / macro format
            continue
        raw = text(fmt_node)
        if len(raw) < 2 or raw[0] != '"' or raw[-1] != '"':
            declined += 1  # encoding-prefixed literal (L"", u8"", ...)
            continue
        unescaped = _unescape(raw[1:-1])
        if unescaped is None:
            declined += 1
            continue
        # The runtime format ends at the first NUL; later directives
        # are never read and must not be counted.
        required = _count_required(unescaped.split("\0", 1)[0])
        if required is None:
            declined += 1
            continue
        analysed += 1
        supplied = len(args) - position - 1
        if supplied < required:
            deficits.append({
                "call_name": name,
                "line": node.start_point[0] + 1,
                "format_string": raw,
                "required": required,
                "supplied": supplied,
            })

    if deficits:
        deficits.sort(key=lambda d: d["line"])
        first = deficits[0]
        return FormatArgsResult(
            deficit_found=True,
            applicable=True,
            call_name=first["call_name"],
            line=first["line"],
            format_string=first["format_string"],
            required=first["required"],
            supplied=first["supplied"],
            analysed_calls=analysed,
            declined_calls=declined,
            deficits=deficits,
            reasoning=(
                f"{first['call_name']} at line {first['line']} supplies "
                f"{first['supplied']} variadic argument(s) but its format "
                f"string requires {first['required']} — reading a missing "
                f"argument is undefined behaviour"
            ),
        )
    if analysed:
        extra = (
            f"; {declined} call(s) declined (unmodeled format or "
            f"non-literal)" if declined else ""
        )
        return FormatArgsResult(
            deficit_found=False,
            applicable=True,
            analysed_calls=analysed,
            declined_calls=declined,
            reasoning=(
                f"no format-argument deficit in {analysed} analysable "
                f"printf-family call(s){extra} — surplus arguments are "
                f"evaluated and ignored, not a defect"
            ),
        )
    extra = f" ({declined} call(s) declined)" if declined else ""
    return FormatArgsResult(
        deficit_found=False,
        applicable=False,
        analysed_calls=0,
        declined_calls=declined,
        reasoning=(
            "no printf-family call with an analysable literal format "
            f"string{extra}"
        ),
    )
