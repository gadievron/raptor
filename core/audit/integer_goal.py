"""Closed source-integer objectives, distinct from arbitrary claim prose."""

DIVISION_GOALS = {
    "division by zero": "zero-divisor", "division by 0": "zero-divisor",
    "divide by zero": "zero-divisor", "divide by 0": "zero-divisor",
    "remainder by zero": "zero-divisor", "remainder by 0": "zero-divisor",
    "modulo by zero": "zero-divisor", "modulo by 0": "zero-divisor",
    "zero divisor": "zero-divisor",
    "division overflow": "signed-division-overflow",
    "remainder overflow": "signed-division-overflow",
    "undefined integer division": "any", "undefined integer remainder": "any",
}
SHIFT_GOALS = {
    "negative shift count": "negative", "oversized shift count": "oversized",
    "shift count too large": "oversized", "invalid shift count": "any",
    "shift count out of range": "any",
}
COMPARISON_GOALS = {
    "comparison is always true": "true", "comparison is always false": "false",
}
ARRAY_READ_GOALS = {
    "": "read", "out of bounds": "read", "out of bounds read": "read",
    "read out of bounds": "read", "is out of bounds": "read",
    "array read out of bounds": "read",
}


def _cwe_tag(text):
    text = text.strip().lower()
    digits = text.removeprefix("cwe-")
    return (text.startswith("cwe-") and 1 <= len(digits) <= 6
            and digits.isascii() and digits.isdecimal())


def parse_integer_goal(hypothesis, goals):
    """Admit one inline expression and a complete known objective label.

    Optional CWE, potential/possible, separator and final-period metadata
    do not change the goal. Other prose may negate or qualify it and is
    deliberately retained, so an unknown complete label is refused.
    """
    if not isinstance(hypothesis, str) or len(hypothesis) > 8192:
        return None
    pieces = hypothesis.split("`")
    if len(pieces) != 3:
        return None
    before, after = pieces[0].strip(), pieces[2].strip()
    if after.endswith("."):
        after = after[:-1].strip()
    if before and after:
        if before.lower() not in {"potential", "possible"}:
            return None
        label = before + " " + after
    else:
        label = before or after
    header, separator, rest = label.partition(":")
    if separator and _cwe_tag(header):
        label = rest.strip()
    else:
        header, separator, rest = label.partition(" ")
        if separator and _cwe_tag(header):
            label = rest.strip()
    words = label.lower().removesuffix(":").strip().split()
    if words and words[0] in {"potential", "possible"}:
        words = words[1:]
    if words and words[-1] in {"in", "at"}:
        words = words[:-1]
    label = " ".join(" ".join(words).replace("-", " ").split())
    return goals.get(label)
