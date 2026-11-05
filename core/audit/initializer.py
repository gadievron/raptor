"""Bound declaration initializers in a sanitized C-family source line."""


def initializer_text(text: str) -> str:
    """Stop before the next declarator or statement, keeping nested expressions.

    The caller supplies a comment/literal-blanked view starting after '='.
    This is a lexical boundary, not expression typing or a range proof.
    """
    stack: list[str] = []
    closers = {"(": ")", "[": "]", "{": "}"}
    for index, char in enumerate(text):
        if char in closers:
            stack.append(closers[char])
        elif char in ")]}":
            if not stack or stack[-1] != char:
                return text[:index]
            stack.pop()
        elif char in ",;" and not stack:
            return text[:index]
    return text
