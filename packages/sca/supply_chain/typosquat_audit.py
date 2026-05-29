"""Typosquat-denylist curation: candidate generation (Stages 1–2).

The denylist (`data/typosquat_denylist.json`) is the sound fix for typosquats
that ride the popularity feeds into the trusted list (npm ``loadash``), but it
is hand-curated — so it needs a *discovery* loop to stay current without
sacrificing the property that makes it sound (every entry is confirmed → zero
false positives). This module is the mechanical, **LLM-free** half of that loop
(see ``~/design/typosquat-denylist-curation.md``):

  Stage 1 — generate near-name candidates from the rank-ordered feeds (a name
            one edit from a *much-higher-ranked* name is a candidate). This is
            the rank+distance heuristic — validated as ~10:1 false-positive for
            *auto-dropping*, but exactly right for *generating candidates* a
            human/LLM then triages.
  Stage 2 — subtract the denylist (confirmed squats) and the reviewed-legit list
            (confirmed-legit near-names, ``data/typosquat_reviewed_legit.json``)
            so the recurring delta de-noises to ~empty and a genuinely-new
            near-name stands out.

Runs in two homes, both LLM-free:
  - the weekly ``refresh-sca-data`` workflow, which has the live rank-ordered
    feeds and emits the pending delta as a nudge in the refresh PR body;
  - the operator command ``raptor-sca triage``, run when reviewing that PR.

The judgement step (Stage 3 evidence + Stage A LLM triage + the gate) is the
*next* build and runs operator-side where an LLM is available — never in CI.
"""

from __future__ import annotations

import argparse
import json as _json
import logging
import sys
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional, Sequence

from core.http import HttpClient
from core.http.urllib_backend import UrllibClient

from ..refresh_typosquat_lists import (
    _DEFAULT_TOP_N,
    _fetch_crates_ranked,
    _fetch_npm_ranked,
    _fetch_packagist_ranked,
    _fetch_pypi_ranked,
)
from .typosquat import _DENYLIST_PATH, _MAX_DISTANCE, _damerau_levenshtein

logger = logging.getLogger(__name__)

_REVIEWED_LEGIT_PATH = _DENYLIST_PATH.parent / "typosquat_reviewed_legit.json"

# Candidate-generation knobs (validated 2026-05-28 against live npm/PyPI feeds).
# A name P is a candidate when a name Q ranked >= ``_RATIO``x higher is within
# Damerau distance 1. The ratio (not a fixed cutoff) keeps similar-rank legit
# pairs out; ``_MIN_POS`` never flags the very top; ``_MIN_LEN`` skips short
# names, whose distance-1 neighbours are dominated by natural collisions
# (``fs``/``ms``, ``id``/``six``) rather than typosquats — npm at len>=6 yielded
# 15 candidates (the real one, ``loadash``, plus legit near-names) vs 88 at
# len>=0. All three are tunable from the CLI.
_RATIO = 20
_MIN_POS = 50
_MIN_LEN = 6

# eco display-name → rank-ordered fetcher. Keys match the popular-list and
# denylist/reviewed-legit ecosystem keys.
_RANKED_FETCHERS = {
    "PyPI": _fetch_pypi_ranked,
    "npm": _fetch_npm_ranked,
    "Cargo": _fetch_crates_ranked,
    "Packagist": _fetch_packagist_ranked,
}


class Candidate(NamedTuple):
    name: str
    near_twin: str
    rank: int        # 1-based rank of the candidate in the feed
    twin_rank: int   # 1-based rank of the much-more-popular near-twin
    distance: int


def generate_candidates(
    ranked: Sequence[str],
    *,
    ratio: int = _RATIO,
    min_pos: int = _MIN_POS,
    min_len: int = _MIN_LEN,
) -> List[Candidate]:
    """Stage 1. ``ranked`` is most-popular-first. Emit a candidate for each name
    that is Damerau distance ≤1 from a name ranked at least ``ratio``× higher.
    Uses the detector's own metric so build-time and scan-time agree."""
    ratio = max(1, ratio)
    # Dedup, preserving rank order (first occurrence = best rank).
    seen: set = set()
    names: List[str] = []
    for n in ranked:
        if n not in seen:
            seen.add(n)
            names.append(n)

    out: List[Candidate] = []
    # references that out-rank P by >= ratio, bucketed by length, with their rank
    ref_by_len: Dict[int, List[tuple]] = {}
    next_ref = 0
    for i, p in enumerate(names):
        cutoff = i // ratio
        while next_ref < cutoff:
            q = names[next_ref]
            ref_by_len.setdefault(len(q), []).append((q, next_ref))
            next_ref += 1
        if i < min_pos or len(p) < min_len:
            continue
        lp = len(p)
        twin: Optional[str] = None
        twin_idx = -1
        for length in (lp - 1, lp, lp + 1):
            for q, qi in ref_by_len.get(length, ()):
                if _damerau_levenshtein(p, q, _MAX_DISTANCE) <= 1:
                    twin, twin_idx = q, qi
                    break
            if twin is not None:
                break
        if twin is not None:
            out.append(Candidate(
                name=p, near_twin=twin, rank=i + 1, twin_rank=twin_idx + 1,
                distance=_damerau_levenshtein(p, twin, _MAX_DISTANCE)))
    return out


def _load_name_set(path: Path, ecosystem: str) -> set:
    """Lowercased name set for ``ecosystem`` from a curation file. Tolerant of
    both the bare ``{eco: [name, ...]}`` and enriched ``{eco: {name: {...}}}``
    shapes; a missing/malformed file (or absent ecosystem) → empty set."""
    try:
        raw = _json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, _json.JSONDecodeError):
        return set()
    if not isinstance(raw, dict):
        return set()
    entry = raw.get(ecosystem)
    if isinstance(entry, list):
        return {n.lower() for n in entry if isinstance(n, str)}
    if isinstance(entry, dict):
        return {k.lower() for k in entry if isinstance(k, str)}
    return set()


def _load_name_meta(path: Path, ecosystem: str) -> Dict[str, dict]:
    """``{name: metadict}`` for ``ecosystem`` — like :func:`_load_name_set` but
    keeps the per-name provenance (e.g. ``near_twin``). Bare-list entries map to
    ``{}``."""
    try:
        raw = _json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, _json.JSONDecodeError):
        return {}
    if not isinstance(raw, dict):
        return {}
    entry = raw.get(ecosystem)
    if isinstance(entry, list):
        return {n.lower(): {} for n in entry if isinstance(n, str)}
    if isinstance(entry, dict):
        return {k.lower(): (v if isinstance(v, dict) else {})
                for k, v in entry.items() if isinstance(k, str)}
    return {}


def pending_candidates(
    ranked: Sequence[str],
    ecosystem: str,
    *,
    denylist_path: Path = _DENYLIST_PATH,
    reviewed_legit_path: Path = _REVIEWED_LEGIT_PATH,
    **gen_kwargs,
) -> List[Candidate]:
    """Stage 2. Candidates minus already-classified names (denylist ∪
    reviewed-legit) — the delta a human/LLM still needs to decide."""
    skip = (_load_name_set(denylist_path, ecosystem)
            | _load_name_set(reviewed_legit_path, ecosystem))
    return [c for c in generate_candidates(ranked, **gen_kwargs)
            if c.name not in skip]


def audit(
    http: HttpClient,
    ecosystems: Optional[Sequence[str]] = None,
    *,
    top_n: int = _DEFAULT_TOP_N,
    **gen_kwargs,
) -> Dict[str, List[Candidate]]:
    """Fetch each ecosystem's rank-ordered feed and return its pending delta.
    A feed that fails to fetch is logged and skipped (fail-soft)."""
    ecos = list(ecosystems) if ecosystems else list(_RANKED_FETCHERS)
    results: Dict[str, List[Candidate]] = {}
    for eco in ecos:
        fetch = _RANKED_FETCHERS.get(eco)
        if fetch is None:
            logger.warning("no rank feed for ecosystem %r; skipping", eco)
            continue
        try:
            ranked = fetch(http, top_n)
        except Exception as e:                   # noqa: BLE001
            logger.warning("%s feed fetch failed: %s", eco, e)
            continue
        results[eco] = pending_candidates(ranked, eco, **gen_kwargs)
    return results


def render_markdown(results: Dict[str, List[Candidate]]) -> str:
    """Markdown for the refresh PR body. Returns ``""`` when nothing is pending
    (so the workflow can skip the nudge entirely)."""
    total = sum(len(v) for v in results.values())
    if total == 0:
        return ""
    lines = [
        f"### ⚠️ {total} new typosquat candidate(s) pending triage",
        "",
        "Near-names that rode the popularity feed in and are not yet classified "
        "(in neither `typosquat_denylist.json` nor `typosquat_reviewed_legit.json`). "
        "Triage with `raptor-sca triage` (fetches evidence + proposes a verdict); "
        "confirm squats into the denylist, legit near-names into reviewed-legit.",
        "",
    ]
    for eco in sorted(results):
        cands = results[eco]
        if not cands:
            continue
        lines.append(f"**{eco}** ({len(cands)}):")
        lines.append("")
        lines.append("| candidate | rank | near-twin | twin rank | dist |")
        lines.append("|---|--:|---|--:|--:|")
        for c in cands:
            lines.append(
                f"| `{c.name}` | {c.rank} | `{c.near_twin}` "
                f"| {c.twin_rank} | {c.distance} |")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_text(results: Dict[str, List[Candidate]]) -> str:
    total = sum(len(v) for v in results.values())
    if total == 0:
        return "No pending typosquat candidates.\n"
    lines = [f"{total} pending typosquat candidate(s):"]
    for eco in sorted(results):
        for c in results[eco]:
            lines.append(
                f"  [{eco}] {c.name} (#{c.rank}) ~ {c.near_twin} "
                f"(#{c.twin_rank}, dist {c.distance})")
    return "\n".join(lines) + "\n"


def _registry_clients(http, cache) -> Dict[str, object]:
    """Registry clients for the evidence fetch (Stage 3), built the SAME way as
    the scan pipeline: through the SCA egress-controlled client (``default_client``
    routes via the in-process proxy with ``SCA_ALLOWED_HOSTS`` enforced — the
    registry-metadata hosts are on that allowlist) and the shared SCA cache. This
    keeps triage inside the same egress boundary + cache as ``run_sca`` rather
    than a bare client. (The popularity-FEED fetch in ``audit()`` stays on a
    plain client — those feed hosts are deliberately NOT on the SCA allowlist;
    see ``refresh_typosquat_lists``.)"""
    from ..registries.crates import CratesClient
    from ..registries.npm import NpmClient
    from ..registries.packagist import PackagistClient
    from ..registries.pypi import PyPIClient
    return {
        "npm": NpmClient(http, cache),
        "PyPI": PyPIClient(http, cache),
        "Cargo": CratesClient(http, cache),
        "Packagist": PackagistClient(http, cache),
    }


def run_llm_triage(
    results: Dict[str, List[Candidate]],
    *,
    reviewed_legit_path,
) -> str:
    """Stage 3→A→4 over the pending candidates (operator-side, needs an LLM).
    Auto-files legit verdicts to reviewed-legit; renders the squat-confirm +
    review queues for the human. Falls back to the list when no LLM is set."""
    from core.json import JsonCache

    from .. import SCA_CACHE_ROOT, default_client
    from ..llm import get_llm_client
    from .typosquat_triage import (
        Disposition, collect_evidence_rich, make_llm_verdict_fn,
        triage_ecosystem,
    )
    llm = get_llm_client()
    if llm is None:
        return ("No LLM model configured — cannot triage; listing candidates "
                "only.\n\n" + render_text(results))
    model_label = "llm"
    try:                                          # best-effort provenance
        model_label = str(llm.config.primary_model.model_id) or "llm"
    except Exception:                             # noqa: BLE001
        pass
    http = default_client()
    cache = JsonCache(root=SCA_CACHE_ROOT)
    clients = _registry_clients(http, cache)
    auto: List[str] = []
    confirm: List[str] = []
    review: List[str] = []
    for eco, cands in sorted(results.items()):
        client = clients.get(eco)
        if not cands or client is None:
            continue
        # Rich evidence (description/README) for npm/PyPI via raw fetch through
        # the same egress-controlled client; crates/Packagist via get_metadata.
        def _ev(c, eco=eco, cl=client):
            return collect_evidence_rich(c, eco, http, cl.get_metadata)
        outcomes = triage_ecosystem(
            cands, eco, evidence_fn=_ev,
            verdict_fn=make_llm_verdict_fn(llm, eco),
            reviewed_legit_path=reviewed_legit_path, model=model_label,
        )
        for o in outcomes:
            line = (f"[{eco}] {o.candidate.name} ~ {o.candidate.near_twin} "
                    f"— {o.gate_result.reason}")
            if o.gate_result.disposition is Disposition.AUTO_LEGIT:
                auto.append(line)
            elif o.gate_result.disposition is Disposition.CONFIRM_SQUAT:
                confirm.append(line)
            else:
                review.append(line)
    lines = [f"Auto-filed legit → reviewed_legit.json ({len(auto)}):"]
    lines += [f"  {x}" for x in auto] or ["  (none)"]
    lines += ["", f"CONFIRM before denylisting ({len(confirm)}) — "
              "add to typosquat_denylist.json if a squat:"]
    lines += [f"  {x}" for x in confirm] or ["  (none)"]
    lines += ["", f"Review ({len(review)}):"]
    lines += [f"  {x}" for x in review] or ["  (none)"]
    return "\n".join(lines) + "\n"


def _render_reaudit(flagged: Dict[str, list]) -> str:
    total = sum(len(v) for v in flagged.values())
    if total == 0:
        return ""        # nothing flagged → workflow's [ -s ] skips the issue
    lines = [f"### ⚠️ {total} reviewed-legit entr(ies) flagged for re-review", "",
             "Names previously filed as legitimate whose CURRENT registry state "
             "contradicts that (removed / now deprecated / now carrying a "
             "malicious advisory). Re-review each: move to "
             "`typosquat_denylist.json` if it should now be flagged, or drop "
             "from `typosquat_reviewed_legit.json` to re-surface it as a "
             "candidate.", ""]
    for eco in sorted(flagged):
        lines.append(f"**{eco}:**")
        lines += [f"- `{n}` — {reason}" for n, reason in flagged[eco]]
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _render_reaudit_llm(enriched: Dict[str, list]) -> str:
    total = sum(len(v) for v in enriched.values())
    if total == 0:
        return "No reviewed-legit entries flagged.\n"
    lines = [f"### {total} reviewed-legit entr(ies) flagged + LLM re-examined",
             ""]
    for eco in sorted(enriched):
        lines.append(f"**{eco}:**")
        for name, reason, verdict, rec in enriched[eco]:
            lines.append(f"- `{name}` — flag: {reason}")
            lines.append(f"    LLM: {verdict.verdict} ({verdict.confidence})"
                         + (f" — {verdict.rationale}" if verdict.rationale else ""))
            lines.append(f"    → {rec}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def run_reaudit(reviewed_legit_path, *, use_llm: bool = False) -> str:
    """Step-3 re-audit. Tier 1 (mechanical, no LLM): re-check every
    reviewed-legit entry's current registry state and flag contradictions.
    Tier 2 (``use_llm``, operator-side): re-examine the flagged entries with the
    LLM and attach a suggested action. Returns markdown (empty/none when
    nothing is flagged)."""
    from core.json import JsonCache

    from .. import SCA_CACHE_ROOT, default_client
    from .typosquat_triage import (
        collect_evidence_rich, make_llm_verdict_fn, osv_malicious,
        reaudit_recommendation, reaudit_reviewed_legit,
    )
    http = default_client()
    cache = JsonCache(root=SCA_CACHE_ROOT)
    clients = _registry_clients(http, cache)

    def _gm(eco, name):
        cl = clients.get(eco)
        return cl.get_metadata(name) if cl is not None else None

    flagged = reaudit_reviewed_legit(
        reviewed_legit_path, list(clients),
        get_metadata=_gm, osv_malicious_fn=lambda e, n: osv_malicious(http, e, n))

    if not use_llm:
        return _render_reaudit(flagged)

    # Tier 2 — LLM re-examination of just the flagged entries (cheap; usually 0).
    from ..llm import get_llm_client
    llm = get_llm_client()
    if llm is None:
        return (_render_reaudit(flagged)
                + "\n(no LLM configured — Tier-1 mechanical flags only)\n")
    enriched: Dict[str, list] = {}
    for eco, items in flagged.items():
        meta = _load_name_meta(reviewed_legit_path, eco)
        verdict_fn = make_llm_verdict_fn(llm, eco)
        client = clients.get(eco)
        rows = []
        for name, reason in items:
            twin = (meta.get(name) or {}).get("near_twin", "")
            cand = Candidate(name=name, near_twin=twin, rank=0, twin_rank=0,
                             distance=1)
            ev = collect_evidence_rich(cand, eco, http,
                                       client.get_metadata if client else None)
            verdict = verdict_fn(cand, ev)
            rows.append((name, reason, verdict,
                         reaudit_recommendation(reason, verdict)))
        enriched[eco] = rows
    return _render_reaudit_llm(enriched)


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="raptor-sca triage",
        description=("List typosquat-denylist candidates pending triage: "
                     "near-names that rode the popularity feeds in and are not "
                     "yet in the denylist or the reviewed-legit list."),
    )
    p.add_argument("--only", action="append", metavar="ECO",
                   help="restrict to one or more ecosystems "
                        "(PyPI, npm, Cargo, Packagist). Repeatable.")
    p.add_argument("--top-n", type=int, default=_DEFAULT_TOP_N,
                   help=f"feed depth per ecosystem (default {_DEFAULT_TOP_N})")
    p.add_argument("--ratio", type=int, default=_RATIO,
                   help=f"min rank ratio twin:candidate (default {_RATIO})")
    p.add_argument("--min-pos", type=int, default=_MIN_POS,
                   help=f"never flag names above this rank (default {_MIN_POS})")
    p.add_argument("--min-len", type=int, default=_MIN_LEN,
                   help=f"skip names shorter than this (default {_MIN_LEN})")
    p.add_argument("--reaudit", action="store_true",
                   help="step-3 re-audit (mechanical, no LLM): re-check every "
                        "reviewed-legit entry's current registry state and flag "
                        "any now removed / deprecated / carrying a MAL- advisory. "
                        "Ignores the candidate feeds.")
    p.add_argument("--llm", action="store_true",
                   help="triage each candidate with an LLM (Stage A): fetch "
                        "registry evidence, propose a verdict, auto-file legit "
                        "near-names to reviewed-legit, and surface suspected "
                        "squats for confirmation. Needs a configured LLM; "
                        "without --llm this just lists the candidates.")
    p.add_argument("--format", choices=("text", "markdown"), default="text")
    p.add_argument("--out", type=Path,
                   help="write the report here instead of stdout "
                        "(nothing written when there are no candidates)")
    p.add_argument("-v", "--verbose", action="count", default=0)
    args = p.parse_args(argv if argv is not None else sys.argv[1:])

    logging.basicConfig(
        level=logging.WARNING - 10 * min(args.verbose, 2),
        format="%(levelname)s %(name)s: %(message)s")

    if args.reaudit:
        # Re-audit re-checks the reviewed-legit list, not the candidate feeds,
        # so it skips the feed fetch entirely. ``--llm`` adds the Tier-2
        # re-examination of flagged entries.
        report = run_reaudit(_REVIEWED_LEGIT_PATH, use_llm=args.llm)
    else:
        http = UrllibClient()
        results = audit(http, args.only, top_n=args.top_n, ratio=args.ratio,
                        min_pos=args.min_pos, min_len=args.min_len)
        if args.llm:
            report = run_llm_triage(results,
                                    reviewed_legit_path=_REVIEWED_LEGIT_PATH)
        else:
            report = (render_markdown if args.format == "markdown"
                      else render_text)(results)
    if args.out is not None:
        # Empty markdown (no candidates) → write nothing so the workflow's
        # ``[ -s file ]`` check skips the PR-body nudge.
        args.out.write_text(report, encoding="utf-8")
    else:
        sys.stdout.write(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
