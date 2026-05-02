"""Source-class taxonomy for the agent stage.

The agent has 17 tools. They cluster into a small number of *source
classes* — categorically distinct ways to acquire information about a
CVE's fix commit. The agent's discovery cascade is "try sources until
one yields a verified candidate or all are exhausted."

Modeled on `acquisition/layers.py`'s explicit layer cascade — the
acquire stage cascades through TargetedFetch → ShallowClone → FullClone;
the agent stage now cascades through OSV → NVD → distro → forge → search.

Used by `agent/loop.py` to:
1. Track which source classes the agent has already tried.
2. Surrender no_evidence when ALL applicable classes are exhausted AND
   no verification call has succeeded.

Distinct from the no-lists mandate: this is a tool-name → source-class
mapping (intrinsic to the tools we built, not a discovery list of
slugs / vendors / patterns).
"""
from __future__ import annotations

import os

# Each source class names one *kind* of information acquisition. A tool
# call against any tool in the class counts the class as "tried".
SOURCE_CLASSES: dict[str, frozenset[str]] = {
    "osv": frozenset({"osv_raw", "osv_expand_aliases"}),
    "nvd": frozenset({"nvd_raw"}),
    "deterministic_hints": frozenset({"deterministic_hints"}),
    "github_search": frozenset({
        "gh_search_repos", "gh_search_commits", "gh_list_commits_by_path",
    }),
    "distro_trackers": frozenset({"fetch_distro_advisory"}),
    "non_github_forge": frozenset({"git_ls_remote", "gitlab_commit", "cgit_fetch"}),
    "generic_http": frozenset({"http_fetch"}),
}

# Tools that count as "verification" of a candidate (slug, sha). Any
# call here means the agent confirmed at least one candidate; the
# surrender-when-exhausted rule does NOT fire.
VERIFICATION_TOOLS: frozenset[str] = frozenset({
    "gh_commit_detail", "gitlab_commit", "cgit_fetch",
})

# Cost floor for the surrender-when-exhausted rule. CVEs the agent
# solves cheaply (e.g., OSV + gh_commit_detail at $0.20) shouldn't
# trip the rule even when only OSV is "tried" — the cost shows real
# work happened. Above this floor, source exhaustion is the signal.
#
# Tightened from $0.50 → $0.80 on 2026-04-28 after v7 measurement: the
# v7 cascade rule (cost ≥ $0.50 + all-7-classes) fired 0 times in 200
# CVEs because no real walker ever touches all 7 classes. The
# count-based threshold (`>= MIN_CLASSES_FOR_SURRENDER`) catches our
# walker pattern (5 of 7) at the cost floor where real work has been
# done but no candidate verified. Verified empirically: catches all 5
# v7 walkers, harms 0 source-PASSes.
SURRENDER_COST_FLOOR_USD: float = float(
    os.environ.get("CVE_DIFF_SURRENDER_COST_FLOOR_USD") or 0.80
)

# Number of distinct source classes that must be tried before the
# loop force-surrenders no_evidence. Calibrated on v7 walker data:
# walkers reach 5-6 classes with zero verification; legit PASSes
# almost always reach a verification call (gh_commit_detail / forge
# verifier) before touching 5 classes.
MIN_CLASSES_FOR_SURRENDER: int = int(
    os.environ.get("CVE_DIFF_MIN_CLASSES_FOR_SURRENDER") or 5
)


def tried_classes(tool_call_log: list[str]) -> frozenset[str]:
    """Set of source classes the agent has already invoked."""
    tried: set[str] = set()
    for call in tool_call_log:
        for cls, tools in SOURCE_CLASSES.items():
            if call in tools:
                tried.add(cls)
                break
    return frozenset(tried)


def has_verified(tool_call_log: list[str]) -> bool:
    """True if the agent has called any verification tool."""
    return any(call in VERIFICATION_TOOLS for call in tool_call_log)


def enough_classes_tried(tool_call_log: list[str]) -> bool:
    """True when the agent has tried at least ``MIN_CLASSES_FOR_SURRENDER``
    distinct source classes. Used together with cost floor + zero-
    verification check to decide surrender. Replaces an earlier
    "all 7 classes" rule that was empirically too loose (fired 0 times
    in v7's 200-CVE bench)."""
    return len(tried_classes(tool_call_log)) >= MIN_CLASSES_FOR_SURRENDER


def should_surrender_no_evidence(
    tool_call_log: list[str],
    cost_usd: float,
) -> bool:
    """Hard-stop check for the agent loop. Fires when:
      - cost ≥ SURRENDER_COST_FLOOR_USD (real work happened), AND
      - zero verification calls so far, AND
      - at least MIN_CLASSES_FOR_SURRENDER (5 of 7) source classes
        have been tried.
    """
    if cost_usd < SURRENDER_COST_FLOOR_USD:
        return False
    if has_verified(tool_call_log):
        return False
    return enough_classes_tried(tool_call_log)


def untried_classes(tool_call_log: list[str]) -> frozenset[str]:
    """Source classes the agent hasn't invoked yet — used by the
    cascade rule's tried-set logic."""
    return frozenset(SOURCE_CLASSES.keys()) - tried_classes(tool_call_log)
