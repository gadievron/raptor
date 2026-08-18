"""Mechanical spot-checks for study questions.

Where a reading-list question is decidable without an LLM — constant
values, return-code enum members, size/limit definitions — the answer
is derived directly from the extracted study corpus (grep/extractor
channel) and preferred over any LLM summary.  Spot-check answers are
tier ``mechanical`` with a receipt built from the definition line.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .receipts import Receipt, mechanical_receipt

# ------------------------------------------------------------------
# Value extraction from definitions
# ------------------------------------------------------------------

_VALUE = r"([-+]?0[xX][0-9a-fA-F]+|[-+]?\d+(?:\.\d+)?|\"[^\"]*\"|'[^']*')"


def _value_patterns(name: str) -> list[re.Pattern]:
    esc = re.escape(name)
    return [
        # #define NAME value
        re.compile(rf"#\s*define\s+{esc}\s+\(?\s*{_VALUE}"),
        # NAME = value  (C/Go/Python/Rust/TS const forms all reduce
        # to this once the definition line is isolated)
        re.compile(rf"\b{esc}\b[^=\n]*=\s*{_VALUE}"),
        # enum member: NAME = value or bare position not decidable
        re.compile(rf"\b{esc}\s*=\s*{_VALUE}\s*[,;}}]"),
    ]


def extract_constant_value(name: str, definition: str) -> str | None:
    """The literal assigned to *name* in *definition*, or None."""
    if not definition:
        return None
    for pat in _value_patterns(name):
        m = pat.search(definition)
        if m:
            return m.group(1)
    return None


def _normalise_literal(text: str) -> str | None:
    """Canonical form for comparison: ints canonicalised (hex ==
    decimal), strings unquoted."""
    text = text.strip()
    if not text:
        return None
    if text[0] in "\"'" and text[-1] == text[0] and len(text) >= 2:
        return text[1:-1]
    try:
        return str(int(text, 0))
    except ValueError:
        pass
    try:
        return repr(float(text))
    except ValueError:
        return text


# ------------------------------------------------------------------
# Question parsing
# ------------------------------------------------------------------

# "Is MAX_FRAME 4096?", "Does MAX_FRAME equal 4096?",
# "Is the value of MAX_FRAME == 0x1000?"  The verb is optional so
# both "MAX_FRAME equals 4096" and the fronted "Is MAX_FRAME 4096"
# shapes parse; a false identifier match is harmless because the
# corpus lookup gates the result.
_QUESTION_VALUE_RE = re.compile(
    r"[`'\"]?([A-Za-z_][\w.:]*)[`'\"]?\s*"
    r"(?:is|==|equals?|equal to|set to|defined as)?\s*"
    rf"[`'\"]?{_VALUE}[`'\"]?",
    re.IGNORECASE,
)


@dataclass
class SpotCheckResult:
    """A mechanically decided study answer."""

    identifier: str
    value: str
    answer: str
    receipt: Receipt
    #: The value the question asserted, when it asserted one.
    expected: str | None = None
    #: True/False when the question asserted a value; None otherwise.
    matches: bool | None = None
    notes: list[str] = field(default_factory=list)


def spot_check_question(
    question: str,
    study_items: list[dict],
) -> SpotCheckResult | None:
    """Decide a constant-value question mechanically, if possible.

    *study_items* are study-list.json item dicts.  Returns None when
    the question does not name a constant present in the corpus with
    an extractable literal value.
    """
    if not question or not study_items:
        return None

    expected: str | None = None
    candidates: list[str] = []
    m = _QUESTION_VALUE_RE.search(question)
    if m:
        candidates.append(m.group(1))
        expected = m.group(2)
    # Fall back to any identifier-shaped token that names a corpus item
    for tok in re.findall(r"[`'\"]?([A-Za-z_][\w.:]*)[`'\"]?", question):
        if tok not in candidates:
            candidates.append(tok)

    by_name: dict[str, dict] = {}
    for item in study_items:
        if isinstance(item, dict) and item.get("name"):
            by_name.setdefault(item["name"], item)

    for cand in candidates:
        tail = re.split(r"\.|::", cand)[-1]
        item = by_name.get(tail)
        if item is None:
            continue
        value = extract_constant_value(
            tail, item.get("definition") or "",
        )
        if value is None:
            continue
        # Receipt: the definition line carrying the assignment
        def_line: str | None = None
        for line in (item.get("definition") or "").splitlines():
            if tail in line and value in line:
                def_line = line
                break
        receipt = mechanical_receipt(
            item.get("file") or "",
            item.get("line"),
            def_line or (item.get("definition") or "")[:200],
        )
        result = SpotCheckResult(
            identifier=tail,
            value=value,
            answer=f"{tail} = {value} (mechanical extraction from "
                   f"{item.get('file')}:{item.get('line')})",
            receipt=receipt,
            expected=expected if cand == candidates[0] and expected else None,
        )
        if result.expected is not None:
            got = _normalise_literal(value)
            want = _normalise_literal(result.expected)
            result.matches = (
                got is not None and want is not None and got == want
            )
            verdict = "matches" if result.matches else "DOES NOT match"
            result.answer += (
                f"; the question's asserted value {result.expected} "
                f"{verdict} the source"
            )
        return result
    return None
