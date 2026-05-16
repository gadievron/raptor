"""Semantic validation of LLM analysis responses.

Pure text analysis — no LLM calls. Flags findings where the reasoning
text contradicts the boolean verdict fields.
"""

import logging
import re
from typing import Dict

logger = logging.getLogger(__name__)


# Pre-compile word-boundary patterns. Pre-fix the check used plain
# `signal in reasoning` substring containment, which produced
# false positives at scale: `"safe"` matched `"unsafe"`,
# `"thread-safe"`, `"make sure it's safe"`, `"safe_API"`. Word-
# boundary `\b` ensures the match aligns with token boundaries.
# `\b` doesn't span hyphens (so `"thread-safe"` correctly counts
# `"safe"` as a separate token) — that's a known quirk; if it
# becomes a problem in practice, switch to a custom boundary
# class. For now `\b` matches Python's `re` module's default
# tokenisation which is what most LLM-generated reasoning
# follows.
_CONTRADICTION_SIGNALS = {
    "false_positive": [
        "false positive", "not a real", "scanner error",
        "not actually vulnerable", "not a vulnerability",
    ],
    "not_exploitable": [
        "not exploitable", "cannot be exploited",
        "no realistic attack", "unexploitable",
    ],
    "safe": [
        "safe", "harmless", "benign", "no security impact",
    ],
}

# Each signal precompiled with `\b` boundary on each side.
_SIGNAL_PATTERNS = {
    cat: [(s, re.compile(r"\b" + re.escape(s) + r"\b", re.IGNORECASE))
          for s in signals]
    for cat, signals in _CONTRADICTION_SIGNALS.items()
}


def check_self_consistency(results_by_id: Dict[str, Dict]) -> int:
    """Check for contradictions between LLM reasoning and verdict fields.

    Two kinds of contradictions:

    1. Text vs. verdict: reasoning text says "false positive" /
       "not exploitable" but verdict fields say otherwise.
       Word-boundary matched.
    2. Structured field vs. verdict: a sibling structured field
       (`ruling`, `false_positive_reason`) directly contradicts
       the boolean verdict — no NLP fuzziness, just a typed
       disagreement the LLM emitted in the same response.

    Sets `self_contradictory=True` and `contradictions=[...]` on
    flagged findings (mutates in place). Returns the number of
    flagged findings.
    """
    flagged = 0
    for fid, r in results_by_id.items():
        if "error" in r:
            continue
        reasoning = (r.get("reasoning") or "")
        is_tp = r.get("is_true_positive", True)
        is_exp = r.get("is_exploitable", False)
        ruling = (r.get("ruling") or "").lower()
        fp_reason = r.get("false_positive_reason")

        contradictions = []

        # Structured-field contradictions — most reliable signal,
        # check first. Pre-fix these were ignored entirely; the
        # check only looked at reasoning text. A finding with
        # `is_true_positive=True` but `ruling="false_positive"`
        # is a clear typed contradiction the LLM generated —
        # higher signal than any text heuristic.
        if is_tp and ruling in {"false_positive", "false positive"}:
            contradictions.append(
                f"ruling='{ruling}' but is_true_positive=True"
            )
        if is_tp and fp_reason and str(fp_reason).strip():
            contradictions.append(
                f"false_positive_reason set ({str(fp_reason)[:60]!r}) but "
                "is_true_positive=True"
            )
        if is_exp and ruling in {
            "false_positive", "false positive", "unreachable",
            "dead_code", "test_code", "mitigated",
        }:
            contradictions.append(
                f"ruling='{ruling}' but is_exploitable=True"
            )

        # Text contradictions — word-boundary matched (see module
        # docstring for the rationale on `\b`).
        if reasoning:
            if is_tp:
                for signal, pat in _SIGNAL_PATTERNS["false_positive"]:
                    if pat.search(reasoning):
                        contradictions.append(
                            f"reasoning says '{signal}' but is_true_positive=True"
                        )
                        break
            if is_exp:
                for signal, pat in (_SIGNAL_PATTERNS["not_exploitable"]
                                    + _SIGNAL_PATTERNS["safe"]):
                    if pat.search(reasoning):
                        contradictions.append(
                            f"reasoning says '{signal}' but is_exploitable=True"
                        )
                        break

        if contradictions:
            r["self_contradictory"] = True
            r["contradictions"] = contradictions
            flagged += 1
            logger.warning(f"Self-contradiction in {fid}: {contradictions[0]}")
        else:
            # Pre-fix this branch was missing — once a finding had
            # `self_contradictory=True` set, it persisted across
            # re-runs of `_check_self_consistency` even when a
            # successful retry resolved the contradiction. The
            # downstream consensus / judge logic still saw the
            # stale flag and treated the (now-clean) finding as
            # uncertain.
            #
            # Real failure mode: RetryTask issues a fresh LLM call
            # whose response IS internally consistent; the
            # finding's previous self_contradictory=True from the
            # original call leaks through unchanged. Operators
            # see "self-contradictory" annotations on findings
            # whose actual reasoning is fine.
            #
            # Clear the flag (and the contradictions list) when
            # the current pass finds none. dict.pop with default
            # so this is a no-op for findings that were never
            # flagged.
            if r.pop("self_contradictory", False):
                r.pop("contradictions", None)

    if flagged:
        logger.info(f"Self-consistency check: {flagged} finding(s) flagged as contradictory")

    return flagged
