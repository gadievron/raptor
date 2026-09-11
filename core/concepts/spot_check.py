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

# Literal grammar covers the forms real definitions use: hex / binary
# / octal base prefixes, digit-group underscores (1_000_000), and
# scientific notation (1e6, 1.5e-3).  A grammar that stopped at the
# first non-digit character extracted '1' from '1_000_000' and '1e6'
# — and that wrong value was trusted unconditionally as a mechanical
# answer.
_VALUE = (
    r"([-+]?0[xX][0-9a-fA-F][0-9a-fA-F_]*"
    r"|[-+]?0[bB][01][01_]*"
    r"|[-+]?0[oO][0-7][0-7_]*"
    r"|[-+]?\d[\d_]*(?:\.[\d_]+)?(?:[eE][-+]?\d+)?"
    r"|\"[^\"]*\"|'[^']*')"
)

# C-style octal: leading zero, octal digits only (0755). Distinct
# from Python's 0o755 form, which int(text, 0) already handles.
_C_OCTAL_RE = re.compile(r"^[-+]?0[0-7]+$")


def _value_patterns(name: str) -> list[re.Pattern]:
    esc = re.escape(name)
    return [
        # #define NAME value
        re.compile(rf"#\s*define\s+{esc}\s+\(?\s*{_VALUE}"),
        # NAME [: type] = value  (C/Go/Python/Rust/TS const forms all
        # reduce to this once the definition line is isolated).  The
        # '=' must directly follow the identifier or a ': type'
        # annotation — the previous [^=\n]* filler crossed comparison
        # operators and statement boundaries, so ``assert(NAME != 0)``
        # read as NAME=0 and ``buf[NAME]; int other = 42;`` read as
        # NAME=42, and those wrong values were trusted unconditionally
        # as mechanical answers.
        re.compile(rf"\b{esc}\b\s*(?::[^=;\n]*)?=(?!=)\s*{_VALUE}"),
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
    # C-style leading-zero octal BEFORE int(text, 0): Python rejects
    # '0755' outright, and the float fallback would have asserted it
    # as decimal 755 instead of 493.
    if _C_OCTAL_RE.match(text):
        return str(int(text, 8))
    try:
        return str(int(text, 0))
    except ValueError:
        pass
    try:
        f = float(text)
    except ValueError:
        return text
    # Integral floats canonicalise to the int form so '1e6' and
    # '1000000' compare equal across notation styles.
    if f.is_integer():
        return str(int(f))
    return repr(f)


# Prose words that also commonly name corpus symbols.  The fallback
# candidate scan treats every question token as a potential
# identifier; without this filter a question like "what version
# constraint governs replay?" resolved against an unrelated
# `version = "1.2"` global and injected the wrong constant as a
# trusted mechanical answer.  Blocklist; applied to plain lowercase
# tokens only, so identifier-cased tokens always pass through.
_FALLBACK_STOPWORDS = frozenset({
    "a", "an", "and", "any", "are", "as", "at", "be", "buffer", "by",
    "can", "code", "constraint", "count", "data", "default", "define",
    "defined", "do", "does", "each", "equal", "equals", "error",
    "field", "file", "flag", "for", "from", "function", "get",
    "governs", "has", "have", "how", "if", "in", "index", "is", "it",
    "item", "key", "length", "level", "limit", "line", "list", "max",
    "min", "mode", "name", "no", "not", "of", "offset", "on", "or",
    "result", "return", "returns", "set", "size", "state", "status",
    "string", "that", "the", "this", "time", "to", "type", "used",
    "value", "version", "what", "when", "where", "which", "why",
    "with",
})


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
    # Fall back to identifier-shaped tokens that name a corpus item —
    # excluding common English / generic-programming words, which
    # would otherwise match same-named corpus globals and answer the
    # wrong question (the corpus lookup below still gates every
    # candidate to exact symbol names).  Only plain lowercase words
    # can be prose: tokens carrying identifier conventions (an
    # underscore, a dot/colon qualifier, or any uppercase — MAX_FRAME,
    # json.loads, Version) are never filtered.
    for tok in re.findall(r"[`'\"]?([A-Za-z_][\w.:]*)[`'\"]?", question):
        if tok.isalpha() and tok.islower() and tok in _FALLBACK_STOPWORDS:
            continue
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
