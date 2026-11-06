"""Conservative argument boundaries for optional SMT call summaries."""


def split_call_arguments(text: str) -> tuple[str, ...] | None:
    """Split top-level commas, declining malformed delimiters or empty slots.

    Arguments remain opaque source text. Quoted commas and delimiters do not
    split arguments; backslash escapes are consumed only inside quotes. This
    does not resolve C types, declarations, templates, or callee identity.
    """
    if not text.strip():
        return ()
    closing = {"(": ")", "[": "]", "{": "}"}
    stack: list[str] = []
    quote = ""
    escaped = False
    parts: list[str] = []
    start = 0
    for index, char in enumerate(text):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
        elif char in {"'", '"'}:
            quote = char
        elif char in closing:
            stack.append(closing[char])
        elif char in closing.values():
            if not stack or stack.pop() != char:
                return None
        elif char == "," and not stack:
            part = text[start:index].strip()
            if not part:
                return None
            parts.append(part)
            start = index + 1
    tail = text[start:].strip()
    if stack or quote or not tail:
        return None
    return (*parts, tail)


def find_call_end(text: str, opening: int) -> int | None:
    """Return the exclusive end of a balanced call, respecting quoted text.

    The opening index must name '('. Delimiters inside string or character
    literals do not change nesting; malformed or incomplete calls decline.
    This is structural recognition, not a C expression or type checker.
    """
    if not 0 <= opening < len(text) or text[opening] != "(":
        return None
    closing = {"(": ")", "[": "]", "{": "}"}
    stack = [")"]
    quote = ""
    escaped = False
    for index in range(opening + 1, len(text)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
        elif char in {"'", '"'}:
            quote = char
        elif char in closing:
            stack.append(closing[char])
        elif char in closing.values():
            if not stack or stack.pop() != char:
                return None
            if not stack:
                return index + 1
    return None
