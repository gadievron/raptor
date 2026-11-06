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
