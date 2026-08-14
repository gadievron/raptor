"""Classify LLM hypothesis confidence for semantic bug claims.

Semantic bugs (wrong operator, wrong comparison direction, missing
cleanup) have no mechanical tool that can corroborate them.  The G2
gate demotes these findings to suspicious, and _resolve_gate_demoted
may then resolve them to clean (if the CWE class is tool-covered) or
dark (if not).

This module rescues high-confidence semantic hypotheses: ones where the
LLM names a specific wrong value AND that value is mechanically
confirmed in the source.  The LLM can still be wrong about whether
it's a bug, but it cannot hallucinate a symptom that isn't there.
"""

from __future__ import annotations

import re
from typing import Optional

_CORRECTION_PATTERNS = [
    # "uses `=` instead of `==`"  /  "uses `=` but should be `==`"
    re.compile(
        r"uses?\s+[`'\"]([^`'\"]+)[`'\"]"
        r"\s+(?:instead\s+of|but\s+should\s+be|rather\s+than|not)\s+"
        r"[`'\"]([^`'\"]+)[`'\"]",
        re.I,
    ),
    # "`=` should be `==`"
    re.compile(
        r"[`'\"]([^`'\"]+)[`'\"]"
        r"\s+(?:should|must|needs?\s+to)\s+be\s+"
        r"[`'\"]([^`'\"]+)[`'\"]",
        re.I,
    ),
    # "should be `==` not `=`"  /  "should use `==` instead of `=`"
    re.compile(
        r"(?:should|must)\s+(?:be|use)\s+"
        r"[`'\"]([^`'\"]+)[`'\"]"
        r"\s+(?:not|instead\s+of|rather\s+than)\s+"
        r"[`'\"]([^`'\"]+)[`'\"]",
        re.I,
    ),
]

_LINE_REF_RE = re.compile(r"\blines?\s+(\d+)\b", re.I)


def _value_present_not_as_correct(
    wrong: str, correct: str, lines: list[str],
) -> bool:
    """Check that ``wrong`` appears in at least one line but is NOT
    just a substring of ``correct`` at every occurrence.

    Example: wrong="=", correct="==" — a line containing only "=="
    has no standalone "=", so returns False.  A line with "x = 0"
    has a standalone "=", so returns True.
    """
    correct_esc = re.escape(correct)
    for line in lines:
        if wrong not in line:
            continue
        stripped = re.sub(correct_esc, "", line)
        if wrong in stripped:
            return True
    return False


def classify_semantic_confidence(
    hypothesis: str,
    source: str,
    line_start: int = 0,
) -> str:
    """Classify hypothesis confidence for semantic bug claims.

    Returns ``"high"`` only when the hypothesis proposes a concrete
    correction AND the claimed wrong value is mechanically confirmed
    in the source at or near the claimed line.

    Args:
        hypothesis: The LLM's hypothesis text.
        source: The function's source code.
        line_start: 1-indexed line number where the function starts
            in the original file (used to translate absolute line
            references to source-relative offsets).

    Returns:
        ``"high"`` if the symptom is source-verified, ``"low"``
        otherwise.
    """
    if not hypothesis or not source:
        return "low"

    for pat in _CORRECTION_PATTERNS:
        m = pat.search(hypothesis)
        if not m:
            continue

        wrong_value, correct_value = m.group(1), m.group(2)
        # Pattern 3 has (correct, wrong) order
        if pat is _CORRECTION_PATTERNS[2]:
            wrong_value, correct_value = correct_value, wrong_value

        if not wrong_value or not correct_value:
            continue
        if wrong_value == correct_value:
            continue

        lines = source.splitlines()

        line_match = _LINE_REF_RE.search(hypothesis)
        if line_match:
            claimed_line = int(line_match.group(1))
            rel_line = claimed_line - line_start if line_start > 0 else claimed_line - 1
            window_start = max(0, rel_line - 2)
            window_end = min(len(lines), rel_line + 3)
            window = lines[window_start:window_end]
        else:
            window = lines

        if _value_present_not_as_correct(wrong_value, correct_value, window):
            return "high"

    return "low"


def source_confirms_correction(
    hypothesis: str,
    source: str,
    line_start: int = 0,
) -> Optional[dict]:
    """If the hypothesis proposes a concrete correction verified in source,
    return details.  Otherwise return None.

    Useful for audit logging and diagnostics.
    """
    if classify_semantic_confidence(hypothesis, source, line_start) != "high":
        return None

    for pat in _CORRECTION_PATTERNS:
        m = pat.search(hypothesis)
        if not m:
            continue
        wrong_value, correct_value = m.group(1), m.group(2)
        if pat is _CORRECTION_PATTERNS[2]:
            wrong_value, correct_value = correct_value, wrong_value
        if wrong_value and correct_value and wrong_value != correct_value:
            line_match = _LINE_REF_RE.search(hypothesis)
            return {
                "wrong_value": wrong_value,
                "correct_value": correct_value,
                "claimed_line": int(line_match.group(1)) if line_match else None,
            }
    return None
