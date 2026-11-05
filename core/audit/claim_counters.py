"""Claim identity and existing counter policy, independent of orchestration."""

from collections.abc import Iterable


_DISMISSIVE_COUNTERS = frozenset({
    "no plausible", "cannot construct", "no realistic", "no viable",
    "function is safe", "no vulnerability", "none", "n/a", "not applicable",
})


def matching_claims(mechanism: str, collections: Iterable) -> list[dict]:
    """Select exact mechanism identities; never borrow a nearby claim.

    Leading/trailing whitespace is immaterial. Prefixes, case changes,
    and confidence ranks do not identify the same mechanism.
    """
    if not isinstance(mechanism, str) or not mechanism.strip():
        return []
    target = mechanism.strip()
    return [claim for collection in collections if isinstance(collection, (list, tuple))
            for claim in collection if isinstance(claim, dict)
            and isinstance(claim.get("mechanism"), str)
            and claim["mechanism"].strip() == target]


def has_claim_counter(mechanism: str, collections: Iterable) -> bool:
    """Apply the existing specific-counter gate only to this mechanism."""
    for claim in matching_claims(mechanism, collections):
        confidence = claim.get("confidence")
        if isinstance(confidence, str) and confidence.lower() == "refuted":
            continue
        counter = claim.get("counter")
        if not isinstance(counter, str) or len(counter) < 20:
            continue
        lower = counter.lower().strip()
        if not any(d in lower for d in _DISMISSIVE_COUNTERS):
            return True
    return False
