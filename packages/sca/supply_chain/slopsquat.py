"""Slopsquat candidate detector — LLM-hallucinated package names
that attackers pre-register as bait.

Background
~~~~~~~~~~

LLMs reliably invent package names that don't exist in the
registry: ``python-requests-pro``, ``react-toastr-pro``,
``axios-utils``, ``lodahs``. The hallucinations are *systematic*
across models — they prefer compound-noun shapes with generic
suffixes (``-utils``, ``-helper``, ``-pro``, ``-core``), use
language-suffix conventions that aren't actually conventions
(``-py``, ``-js``, ``-ts``), and occasionally collapse confusable
characters (``l`` → ``1``, ``O`` → ``0``).

Attackers register the exact hallucinated names and embed malware
in install scripts (npm postinstall, Python setup.py, Cargo
build.rs, Ruby extconf.rb). A developer pasting LLM-generated code
and running ``npm install`` / ``pip install`` / ``cargo add``
triggers the install hook before any of their own code runs.

This is **distinct from typosquatting** (``parsers/typosquat.py``)
because LLM hallucinations are *systematic and recurring*, not
character-flip mistakes. ``requets`` is a human typo of
``requests``; ``python-requests-pro`` is an LLM hallucination.
The attacker can pre-register a high-yield list because the same
hallucinations recur across models, sessions, and prompts.

What this module does
~~~~~~~~~~~~~~~~~~~~~

Pure-heuristic — no network. For each direct dep:

  1. **Skip the legit-popular case** — exact match in the popular-
     names list means the dep IS that popular package.
  2. **Lookalike-character collapse** — map ``{l, I, 1}`` → ``i``
     and ``{0, O}`` → ``o``; check if the collapsed query matches
     a collapsed popular name. Catches ``1odash`` (looks like
     ``lodash``).
  3. **Generic suffix on a popular prefix** — split the name on
     ``-`` / ``_``; if the prefix is a popular name AND the
     suffix is a "generic" word (``-pro``, ``-utils``, ``-helper``,
     etc.), flag. Catches the canonical LLM hallucination shape.
  4. **Language-suffix mismatch** — for npm: ``-py`` is a Python-
     language suffix that LLMs sometimes append to npm package
     names; for PyPI: ``-js`` / ``-ts`` are the inverse. These
     are weak signals on their own but stack with other reasons.
  5. **Untrusted-scope** (npm only) — scoped names like
     ``@cool-utils/lodash-pro`` where the scope isn't on the
     well-known trusted-org allowlist contribute a weak signal.
     A scope alone isn't enough to flag, but combined with
     reason 3 it's strong.

Each match contributes a "reason tag" + a small score. Total
score in [0, 1] drives severity: 0.5+ → medium, 0.7+ → high.

Co-occurrence escalation (in registry_metadata._escalate_severity):
when a slopsquat finding stacks with ``recent_publish`` (package
< 30 days old) AND/OR ``low_bus_factor`` (single maintainer), the
severity escalates further. That's where the heuristic transitions
from "looks like LLM hallucination" to "looks like LLM
hallucination AND was just registered by a single anonymous
publisher" — the canonical bait shape.

Limits
~~~~~~

False positives exist for legitimate generic-suffix packages
(``lodash-utils`` IS a real package; ``aws-helpers`` likely is).
The heuristic alone produces too much noise for an SBOM-scan use
case; combine with registry metadata via the co-occurrence rule.
Operators who want the heuristic-alone view get it via the
``slopsquat_suspect`` finding kind — the severity stays low when
no co-occurring signals fire.

The popular-name list (``data/popular/<eco>.json``) ships ~80-100
names per ecosystem. False negatives are inevitable for less-
trafficked names — the heuristic only catches slopsquats targeting
ecosystem-top packages. Extending the popular list (or adding a
training-cutoff witness) is a follow-up; the current shape catches
the highest-yield attacks.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, replace
from typing import Dict, FrozenSet, Iterable, List, Optional, Tuple

from ..models import Confidence, Dependency

# Reuse the popular-list loader + length-bucket index from the
# typosquat detector. They're private (leading underscore), but
# they're sibling modules within the same package — importing
# private functions across siblings is acceptable here. A future
# refactor could extract them to a shared ``_popular.py``; doing
# so today would expand the diff for no functional gain.
from .typosquat import _load_popular, _popular_set

logger = logging.getLogger(__name__)


# Generic word suffixes that LLMs commonly hallucinate when
# inventing package names. Stripped of any leading ``-`` / ``_``;
# the matcher handles both separators.
_GENERIC_WORDS = frozenset({
    "pro", "utils", "util", "helper", "helpers", "core",
    "cli", "tool", "tools", "toolkit", "kit", "extra",
    "extras", "extended", "plus", "next", "new", "modern",
    "improved", "master", "client", "api", "lib", "library",
    "module", "package", "wrapper", "framework",
})

# Language-suffix words. LLMs sometimes append a wrong language
# suffix (``-py`` to an npm package, ``-js`` to a PyPI package).
# Weaker signal than generic words — many legitimate packages
# use language suffixes correctly (``boto3-py-typed`` is real).
_LANGUAGE_SUFFIXES_BY_ECO: Dict[str, FrozenSet[str]] = {
    "npm": frozenset({"py", "python", "rust", "go", "rb", "ruby"}),
    "PyPI": frozenset({"js", "ts", "node", "rust", "go", "rb"}),
    "Cargo": frozenset({"js", "ts", "py", "python", "rb"}),
    "RubyGems": frozenset({"js", "ts", "py", "python", "rs"}),
    "Maven": frozenset({"js", "py", "rb", "rs"}),
    "Packagist": frozenset({"js", "py", "rb", "rs"}),
}

# npm scopes belonging to well-known organisations. A scoped
# package whose scope isn't on this list contributes a weak slop-
# squat signal — the LLM-hallucination pattern often invents a
# plausible-sounding scope (``@cool-utils/...``) that no real
# vendor owns.
#
# List is intentionally small + conservative. False positives
# (legitimate small-org scopes flagged) are tolerated because the
# untrusted-scope signal is ONLY ever a weak contributor; it
# never flags on its own.
_TRUSTED_NPM_SCOPES = frozenset({
    "@types", "@typescript-eslint",
    "@aws-sdk", "@aws-cdk", "@azure", "@google-cloud",
    "@anthropic-ai", "@openai", "@huggingface",
    "@angular", "@vue", "@nuxt", "@nestjs", "@nx",
    "@babel", "@swc", "@vitejs", "@vitest",
    "@radix-ui", "@tanstack", "@trpc", "@tailwindcss",
    "@mui", "@chakra-ui", "@react-native", "@expo",
    "@stripe", "@supabase", "@vercel", "@cloudflare",
    "@playwright", "@storybook",
    "@grafana", "@redhat", "@microsoft", "@fluentui",
    "@eslint", "@prettier", "@parcel", "@rollup",
    "@docusaurus", "@octokit", "@graphql-tools",
})

# Lookalike-character normalisation table. Both the dep name and
# the popular list go through ``_collapse_lookalikes`` before the
# equality check.
_LOOKALIKE_TABLE = str.maketrans({
    "l": "i", "I": "i", "1": "i",
    "0": "o", "O": "o",
})

# Score weights — each contributing reason adds this much. Capped
# at 1.0; total drives severity per the ladder in ``_severity``.
_SCORE_WEIGHTS = {
    "lookalike_collapse_match": 0.7,
    "popular_prefix_generic_suffix": 0.6,
    "popular_prefix_language_suffix": 0.4,
    "untrusted_scope": 0.2,
}


@dataclass(frozen=True)
class SlopsquatFinding:
    """One slopsquat-candidate hit."""

    dependency: Dependency
    score: float                       # 0.0–1.0, sum of reason weights
    reasons: Tuple[str, ...]           # reason tags
    suspected_root: Optional[str]      # nearest popular package
    severity: str                      # "info" / "low" / "medium" / "high"
    confidence: Confidence


def scan_deps(deps: Iterable[Dependency]) -> List[SlopsquatFinding]:
    """Run the heuristic on every direct dep.

    Like the typosquat detector, the verdict is a pure function of
    ``(ecosystem, name)``, so it is memoised per unique name and
    fanned back out to each declaring dep object — a monorepo that
    repeats a dep across N manifests pays one ``check_dep`` instead
    of N. Output is unchanged (each dep keeps its own ``declared_in``
    in the downstream finding id)."""
    out: List[SlopsquatFinding] = []
    memo: Dict[Tuple[str, str], Optional[SlopsquatFinding]] = {}
    for d in deps:
        if not d.direct:
            continue
        key = (d.ecosystem, d.name)
        if key in memo:
            verdict = memo[key]
            if verdict is not None:
                out.append(replace(verdict, dependency=d))
            continue
        verdict = check_dep(d)
        memo[key] = verdict
        if verdict is not None:
            out.append(verdict)
    return out


def check_dep(dep: Dependency) -> Optional[SlopsquatFinding]:
    """Run the slopsquat heuristic against a single dependency.

    Returns the :class:`SlopsquatFinding` when at least one reason
    fires AND the cumulative score clears the info-severity floor;
    ``None`` otherwise. No network. Safe to call on a direct dep
    or a transitive dep — the caller decides whether ``dep.direct``
    matters (``scan_deps`` filters by it; per-dep query callers
    like ``raptor-sca check`` typically don't have ``direct`` set
    meaningfully and want the check regardless).

    Public companion to :func:`scan_deps` for single-package
    consumers — ``raptor-sca check`` for pre-install evaluation,
    the bumper for candidate-name vetting, etc.
    """
    return _check_one(dep)


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _check_one(dep: Dependency) -> Optional[SlopsquatFinding]:
    name = dep.name.lower()
    eco = dep.ecosystem
    popular_list = _load_popular(eco)
    if not popular_list:
        return None
    popular = _popular_set(eco)
    # Legit-popular dep — no further checks needed.
    if name in popular:
        return None

    reasons: List[str] = []
    suspected_root: Optional[str] = None

    # --- 1. Lookalike-character collapse against popular names.
    collapsed = _collapse_lookalikes(name)
    if collapsed != name:
        # Index built once per ecosystem: ``{collapsed_form: first_pop}``.
        # Pre-fix this re-collapsed every popular name on every dep —
        # O(deps × list) ``str.translate`` calls (24s of the 10k-dep
        # monorepo scan after #686 grew the lists ~40×). The index keeps
        # the first popular name per collapsed form, matching the prior
        # ``for pop in popular_list: … break`` first-hit-wins order.
        match = _collapsed_index(eco).get(collapsed)
        if match is not None:
            reasons.append("lookalike_collapse_match")
            suspected_root = match

    # --- 2. Generic suffix on a popular prefix.
    prefix, suffix = _split_suffix(name)
    if prefix and suffix:
        if prefix in popular and suffix in _GENERIC_WORDS:
            reasons.append("popular_prefix_generic_suffix")
            if suspected_root is None:
                suspected_root = prefix

    # --- 3. Language-suffix on a popular prefix.
    if prefix and suffix:
        lang_suffixes = _LANGUAGE_SUFFIXES_BY_ECO.get(eco, frozenset())
        if prefix in popular and suffix in lang_suffixes:
            reasons.append("popular_prefix_language_suffix")
            if suspected_root is None:
                suspected_root = prefix

    # --- 4. Untrusted scope (npm only). Always a weak contributor;
    #        never flags on its own (score 0.2 stays below the
    #        info threshold).
    if eco == "npm" and name.startswith("@") and "/" in name:
        scope = name.split("/", 1)[0]
        if scope not in _TRUSTED_NPM_SCOPES:
            reasons.append("untrusted_scope")

    if not reasons:
        return None

    score = min(1.0, sum(_SCORE_WEIGHTS[r] for r in reasons))
    severity = _severity(score)
    if severity is None:
        return None
    confidence = _confidence(reasons, score)
    return SlopsquatFinding(
        dependency=dep,
        score=score,
        reasons=tuple(reasons),
        suspected_root=suspected_root,
        severity=severity,
        confidence=confidence,
    )


# Per-ecosystem ``{collapsed_form: first_popular_name}`` index, built
# lazily from the popular list. Re-used across every dep in a scan.
_COLLAPSED_INDEX: Dict[str, Dict[str, str]] = {}


def _collapsed_index(ecosystem: str) -> Dict[str, str]:
    """Map each popular name's lookalike-collapsed form to the first
    popular name that produces it (list order = first-hit-wins)."""
    cached = _COLLAPSED_INDEX.get(ecosystem)
    if cached is not None:
        return cached
    index: Dict[str, str] = {}
    for pop in _load_popular(ecosystem):
        index.setdefault(_collapse_lookalikes(pop), pop)
    _COLLAPSED_INDEX[ecosystem] = index
    return index


def _collapse_lookalikes(s: str) -> str:
    """Map confusable characters to canonical forms.

    ``{l, I, 1}`` → ``i``; ``{0, O}`` → ``o``. Used to detect
    visually-similar package names that an attacker might register
    to fool a casual reviewer of LLM-generated code.

    Note: ``str.maketrans`` returns int-keyed dict so the translate
    is one C-level pass per call. ``s.lower()`` is applied upstream
    in ``_check_one``; we only need the ``str.maketrans`` table to
    cover lowercased input plus the digits + uppercase-I edge
    case (since ``l.upper() == "L"`` but ``I.lower() == "i"``).
    """
    return s.translate(_LOOKALIKE_TABLE)


def _split_suffix(name: str) -> Tuple[Optional[str], Optional[str]]:
    """Split ``<prefix>-<suffix>`` or ``<prefix>_<suffix>``.

    Splits on the LAST separator so multi-word prefixes stay
    grouped (e.g. ``aws-sdk-helpers`` → ``("aws-sdk", "helpers")``,
    not ``("aws", "sdk-helpers")``). For scoped names
    (``@scope/name``), splits on the unscoped part.

    Returns ``(None, None)`` when no separator is present.
    """
    # For scoped npm names, work on the unscoped portion.
    work = name
    if work.startswith("@") and "/" in work:
        work = work.split("/", 1)[1]

    # Pick the LAST separator (- or _) so multi-word prefixes
    # stay together.
    sep_idx = max(work.rfind("-"), work.rfind("_"))
    if sep_idx <= 0 or sep_idx >= len(work) - 1:
        return None, None
    return work[:sep_idx], work[sep_idx + 1:]


def _severity(score: float) -> Optional[str]:
    """Map score to severity. Below ``_INFO_THRESHOLD`` produces
    no finding (the untrusted-scope-alone case)."""
    if score >= 0.7:
        return "high"
    if score >= 0.5:
        return "medium"
    if score >= 0.3:
        return "low"
    return None


def _confidence(reasons: List[str], score: float) -> Confidence:
    """Confidence reflects the strength of the heuristic match, not
    the certainty that the dep is malicious — even a high-score
    finding requires registry metadata to ROUTE to actionable."""
    if len(reasons) >= 2:
        return Confidence(
            "medium",
            reason=(
                f"multiple slopsquat-shaped signals (score "
                f"{score:.2f}): {', '.join(reasons)}"
            ),
        )
    return Confidence(
        "low",
        reason=(
            f"single slopsquat signal (score {score:.2f}): "
            f"{reasons[0]}"
        ),
    )


__all__ = ["SlopsquatFinding", "check_dep", "scan_deps"]
