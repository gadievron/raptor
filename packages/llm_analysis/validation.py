"""Semantic validation of LLM analysis responses.

Pure text analysis — no LLM calls. Flags findings where the reasoning
text contradicts the boolean verdict fields.
"""

import logging
from typing import Dict

logger = logging.getLogger(__name__)


def check_self_consistency(results_by_id: Dict[str, Dict]) -> int:
    """Check for contradictions between LLM reasoning and verdict fields.

    Flags findings where reasoning text says "false positive" / "not exploitable"
    but verdict fields say otherwise. Sets `self_contradictory=True` and
    `contradictions=[...]` on flagged findings (mutates in place).

    Returns the number of flagged findings.
    """
    contradiction_signals = {
        "false_positive": ["false positive", "not a real", "scanner error",
                           "not actually vulnerable", "not a vulnerability"],
        "not_exploitable": ["not exploitable", "cannot be exploited",
                            "no realistic attack", "unexploitable"],
        "safe": ["safe", "harmless", "benign", "no security impact"],
    }

    flagged = 0
    for fid, r in results_by_id.items():
        if "error" in r:
            continue
        reasoning = (r.get("reasoning") or "").lower()
        if not reasoning:
            continue

        is_tp = r.get("is_true_positive", True)
        is_exp = r.get("is_exploitable", False)

        contradictions = []

        # Reasoning says false positive but verdict says true positive
        if is_tp:
            for signal in contradiction_signals["false_positive"]:
                if signal in reasoning:
                    contradictions.append(f"reasoning says '{signal}' but is_true_positive=True")
                    break

        # Reasoning says not exploitable but verdict says exploitable
        if is_exp:
            for signal in contradiction_signals["not_exploitable"] + contradiction_signals["safe"]:
                if signal in reasoning:
                    contradictions.append(f"reasoning says '{signal}' but is_exploitable=True")
                    break

        if contradictions:
            r["self_contradictory"] = True
            r["contradictions"] = contradictions
            flagged += 1
            logger.warning(f"Self-contradiction in {fid}: {contradictions[0]}")

    if flagged:
        logger.info(f"Self-consistency check: {flagged} finding(s) flagged as contradictory")

    return flagged
