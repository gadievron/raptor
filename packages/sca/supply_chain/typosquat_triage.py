"""Typosquat-denylist curation: triage (Stage 3 evidence + Stage A LLM + Stage 4 gate).

Step 2 of the curation loop (``~/design/typosquat-denylist-curation.md``), run
OPERATOR-side by ``raptor-sca triage --llm`` where an LLM is available — never
in CI. Step 1 (``typosquat_audit.py``) generates the pending candidate delta;
this module decides what to do with each one:

  Stage 3 — collect registry evidence (description, age, releases, repo,
            deprecation, downloads) for the candidate.
  Stage A — an LLM proposes a verdict {typosquat | legit | unsure} with a
            rationale that *cites* the evidence (the LLM judges identity and
            purpose — the signal rank cannot see).
  Stage 4 — a GATE turns the verdict into a disposition, exploiting the
            false-positive asymmetry that keeps the whole loop sound:

              * ``legit``    → adding to reviewed-legit is FP-SAFE (a missed
                               squat is just a miss, == today), so the LLM may
                               AUTO-resolve it — but only past an evidence floor.
              * ``typosquat``→ adding to the denylist FLAGS the name for every
                               user, so a wrong call is a real FP. NEVER
                               auto-applied: a human confirms.
              * ``unsure`` / thin evidence → human.

This module is the pure, offline-testable core: the ``Evidence`` / ``Verdict``
types and ``gate``. Evidence *collection* (network, reuses the registry
clients) and the LLM *call* (Stage A) are separate seams layered on top, both
stubbable so the gate is tested without either.
"""

from __future__ import annotations

import datetime
import enum
import json as _json
import os
import tempfile
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

from .typosquat_audit import Candidate, _load_name_set

# Auto-legit floor. A name the LLM calls "legit" is only auto-filed to
# reviewed-legit when it looks like an established independent project; a YOUNG
# or THIN near-twin of a much-bigger package is the classic squat shape and is
# escalated to a human regardless of LLM confidence. These bound the one
# residual false-negative path (LLM mislabels a real squat "legit").
_MIN_AGE_DAYS = 180
_MIN_VERSIONS = 3


@dataclass(frozen=True)
class Evidence:
    """Registry facts about a candidate, normalised across ecosystems. Fields
    that an ecosystem doesn't expose are ``None`` / best-effort."""

    candidate: Candidate
    description: Optional[str] = None
    num_versions: int = 0
    age_days: Optional[int] = None        # since first publish
    has_repo: bool = False
    deprecated: bool = False
    downloads_per_month: Optional[int] = None
    readme: Optional[str] = None          # capped; only via collect_evidence_rich


@dataclass(frozen=True)
class Verdict:
    """An LLM (Stage A) proposal for one candidate."""

    name: str
    verdict: str                          # "typosquat" | "legit" | "unsure"
    confidence: str = "low"               # "high" | "medium" | "low"
    rationale: str = ""
    evidence_cited: List[str] = field(default_factory=list)


class Disposition(enum.Enum):
    """What Stage 4 decides to do with a (candidate, evidence, verdict)."""

    AUTO_LEGIT = "auto_legit"        # file to reviewed-legit automatically (FP-safe)
    CONFIRM_SQUAT = "confirm_squat"  # present to a human → denylist (FP-creating, gated)
    ESCALATE = "escalate"            # human review (unsure / evidence too weak)


@dataclass(frozen=True)
class GateResult:
    disposition: Disposition
    reason: str


def _passes_legit_floor(ev: Evidence, *, min_age_days: int,
                        min_versions: int) -> Optional[str]:
    """Return ``None`` if the evidence is strong enough to AUTO-file a "legit"
    verdict, else a short string naming the failing signal (→ escalate)."""
    if ev.deprecated:
        return "deprecated"            # e.g. an npm deprecation-holder (loadash)
    if not ev.has_repo:
        return "no source repository"
    if ev.num_versions < min_versions:
        return f"only {ev.num_versions} release(s)"
    if ev.age_days is None:
        return "unknown age"
    if ev.age_days < min_age_days:
        return f"only {ev.age_days}d old"
    return None


def gate(
    evidence: Evidence,
    verdict: Verdict,
    *,
    min_age_days: int = _MIN_AGE_DAYS,
    min_versions: int = _MIN_VERSIONS,
) -> GateResult:
    """Stage 4. Map an LLM verdict + registry evidence to a disposition.

    The asymmetry is deliberate: only the FP-safe direction (``legit`` →
    keep-trusted) is ever auto-applied, and only past the evidence floor; the
    FP-creating direction (``typosquat`` → flag) always routes to a human."""
    v = (verdict.verdict or "").lower()
    if v == "typosquat":
        # Adding to the denylist flags the name for every consumer → must be
        # human-confirmed (or, future, corroborated by a hard signal).
        return GateResult(Disposition.CONFIRM_SQUAT,
                          f"LLM: typosquat of {evidence.candidate.near_twin} "
                          f"({verdict.confidence}) — confirm before denylisting")
    if v == "legit":
        failing = _passes_legit_floor(evidence, min_age_days=min_age_days,
                                      min_versions=min_versions)
        if failing is not None:
            # FP-free direction, but evidence too weak to auto-trust a near-twin.
            return GateResult(Disposition.ESCALATE,
                              f"LLM: legit but {failing} — review before trusting")
        # Require HIGH confidence to AUTO-file. run_stage halves confidence to
        # medium when preflight sees injection indicators in the (attacker-
        # controlled) registry block, so a description crafted to steer the
        # verdict ("this is a legitimate package") drops to medium and
        # escalates rather than silently suppressing a squat from detection.
        if (verdict.confidence or "").lower() != "high":
            return GateResult(
                Disposition.ESCALATE,
                f"LLM: legit at {verdict.confidence or 'low'} confidence "
                "— review before trusting")
        return GateResult(Disposition.AUTO_LEGIT,
                          "LLM: legit (high confidence) + evidence floor "
                          "passed — auto-filed")
    return GateResult(Disposition.ESCALATE,
                      f"LLM: {v or 'unsure'} — needs human review")


# ---------------------------------------------------------------------------
# Orchestration — wire Stage 3 + A + 4 over a candidate set
# ---------------------------------------------------------------------------

# Seams: evidence collection (Stage 3, reuses the registry clients) and the LLM
# call (Stage A) are injected so the orchestration + gate are tested without
# network or an LLM. The CLI supplies the concrete implementations.
EvidenceFn = Callable[[Candidate], Evidence]
TriageFn = Callable[[Candidate, Evidence], Verdict]


@dataclass(frozen=True)
class TriageOutcome:
    candidate: Candidate
    evidence: Evidence
    verdict: Verdict
    gate_result: GateResult


def triage_pending(
    candidates: List[Candidate],
    evidence_fn: EvidenceFn,
    triage_fn: TriageFn,
    *,
    min_age_days: int = _MIN_AGE_DAYS,
    min_versions: int = _MIN_VERSIONS,
) -> List[TriageOutcome]:
    """Run Stage 3 → A → 4 for each candidate, returning the outcome per name.
    Pure given the injected seams."""
    out: List[TriageOutcome] = []
    for c in candidates:
        ev = evidence_fn(c)
        verdict = triage_fn(c, ev)
        gr = gate(ev, verdict, min_age_days=min_age_days,
                  min_versions=min_versions)
        out.append(TriageOutcome(c, ev, verdict, gr))
    return out


# ---------------------------------------------------------------------------
# Disposition writer — only the FP-safe AUTO_LEGIT direction is written here
# ---------------------------------------------------------------------------

def apply_auto_legit(
    outcomes: List[TriageOutcome],
    ecosystem: str,
    reviewed_legit_path: Path,
    *,
    model: str = "",
    now: Optional[str] = None,
) -> List[str]:
    """Append every ``AUTO_LEGIT`` outcome to ``reviewed_legit.json`` under
    ``ecosystem``, with provenance. CONFIRM_SQUAT / ESCALATE are deliberately
    NOT written — a human dispositions those (the denylist write is the
    FP-creating action and stays gated). Returns the names filed.

    Atomic (tempfile + ``os.replace``) so a crash can't truncate the file."""
    auto = [o for o in outcomes
            if o.gate_result.disposition is Disposition.AUTO_LEGIT]
    if not auto:
        return []
    try:
        raw = _json.loads(reviewed_legit_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, _json.JSONDecodeError):
        raw = {}
    if not isinstance(raw, dict):
        raw = {}
    entry = raw.get(ecosystem)
    if isinstance(entry, list):                 # tolerate the bare-list shape
        entry = {n: {} for n in entry if isinstance(n, str)}
    elif not isinstance(entry, dict):
        entry = {}
    date = now or datetime.date.today().isoformat()
    filed: List[str] = []
    for o in auto:
        entry[o.candidate.name] = {
            "near_twin": o.candidate.near_twin,
            "decided_by": "llm",
            "model": model,
            "date": date,
            "note": (o.verdict.rationale or "")[:200],
        }
        filed.append(o.candidate.name)
    raw[ecosystem] = entry
    _atomic_write_json(reviewed_legit_path, raw)
    return filed


def _atomic_write_json(path: Path, obj: object) -> None:
    text = _json.dumps(obj, indent=2) + "\n"
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


# ---------------------------------------------------------------------------
# Stage 3 — evidence collection (normalises registry get_metadata per ecosystem)
# ---------------------------------------------------------------------------
#
# Reuses the SCA registry clients' ``get_metadata`` (cached, negative-cached,
# offline-aware). NOTE: those clients strip descriptive fields (they're built
# for vuln scanning), so evidence richness varies — npm yields age / versions /
# deprecated / homepage; crates is fully rich (crate.*); PyPI / Packagist are
# thin (release count only). Thin evidence simply fails the auto-legit floor →
# the candidate escalates to a human, which is the safe direction.


def _age_days(iso: Optional[str]) -> Optional[int]:
    if not isinstance(iso, str) or not iso:
        return None
    try:
        dt = datetime.datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    now = datetime.datetime.now(datetime.timezone.utc)
    return max(0, (now - dt).days)


def _norm_npm(meta: dict) -> dict:
    versions = meta.get("versions") or {}
    latest = (meta.get("dist-tags") or {}).get("latest")
    vm = versions.get(latest, {}) if latest else {}
    return dict(
        description=vm.get("description"),     # often stripped → None
        num_versions=len(versions),
        age_days=_age_days((meta.get("time") or {}).get("created")),
        has_repo=bool(vm.get("repository") or vm.get("homepage")),
        deprecated=bool(vm.get("deprecated")),
        downloads_per_month=None,              # needs a separate npm API
    )


def _norm_crates(meta: dict) -> dict:
    crate = meta.get("crate") or {}
    return dict(
        description=crate.get("description"),
        num_versions=crate.get("num_versions") or len(meta.get("versions") or []),
        age_days=_age_days(crate.get("created_at")),
        has_repo=bool(crate.get("repository") or crate.get("homepage")),
        deprecated=bool(crate.get("yanked")),
        downloads_per_month=crate.get("recent_downloads"),
    )


def _norm_pypi(meta: dict) -> dict:
    info = meta.get("info") or {}
    return dict(
        description=info.get("summary"),       # often stripped → None
        num_versions=len(meta.get("releases") or {}),
        age_days=None,                          # upload_time stripped
        has_repo=bool(info.get("project_urls") or info.get("home_page")),
        deprecated=bool(info.get("yanked")),
        downloads_per_month=None,
    )


def _norm_packagist(meta: dict) -> dict:
    pkgs = meta.get("packages")
    vlist = next(iter(pkgs.values()), []) if isinstance(pkgs, dict) else []
    head = vlist[0] if vlist and isinstance(vlist[0], dict) else {}
    return dict(
        description=head.get("description"),
        num_versions=len(vlist),
        age_days=None,
        has_repo=bool(head.get("source") or head.get("homepage")),
        deprecated=bool(head.get("abandoned")),
        downloads_per_month=None,
    )


_NORMALIZERS = {
    "npm": _norm_npm,
    "Cargo": _norm_crates,
    "PyPI": _norm_pypi,
    "Packagist": _norm_packagist,
}


def collect_evidence(
    candidate: Candidate,
    ecosystem: str,
    get_metadata: Callable[[str], Optional[dict]],
) -> Evidence:
    """Stage 3. ``get_metadata`` is a ``name -> registry-doc`` callable (the
    registry client's method); injected so this is tested without network.
    A miss or unmapped ecosystem yields empty Evidence → the candidate
    escalates (never auto-trusted on no evidence)."""
    norm = _NORMALIZERS.get(ecosystem)
    try:
        meta = get_metadata(candidate.name)
    except Exception:                            # noqa: BLE001
        meta = None
    if meta is None or norm is None or not isinstance(meta, dict):
        return Evidence(candidate=candidate)
    return Evidence(candidate=candidate, **norm(meta))


# --- richer evidence: recover description/README the vuln-scan clients strip --
#
# The SCA registry clients strip ``description``/README (built for vuln
# scanning), but those are the LLM's strongest identity signal. For npm/PyPI we
# fetch the RAW registry doc directly (via the egress-controlled client) and
# pull description + a capped README + first-publish age (PyPI upload_time is
# also stripped from the client path). crates is already rich via get_metadata;
# Packagist stays on get_metadata.

_NPM_RAW = "https://registry.npmjs.org/"
_PYPI_RAW = "https://pypi.org/pypi/"
_RAW_MAX_BYTES = 64 * 1024 * 1024     # most candidates are small; huge → escalate
_README_CAP = 600                     # bound the (attacker-controlled) README


def _raw_doc(http, url: str) -> Optional[dict]:
    try:
        d = http.get_json(url, max_bytes=_RAW_MAX_BYTES)
    except Exception:                  # noqa: BLE001 — fail to thin evidence
        return None
    return d if isinstance(d, dict) else None


def _evidence_npm_rich(candidate: Candidate, http) -> Evidence:
    doc = _raw_doc(http, _NPM_RAW + urllib.parse.quote(candidate.name, safe="@"))
    if doc is None:
        return Evidence(candidate=candidate)
    versions = doc.get("versions") or {}
    latest = (doc.get("dist-tags") or {}).get("latest")
    vm = versions.get(latest, {}) if latest else {}
    repo = doc.get("repository") or vm.get("repository") or vm.get("homepage")
    return Evidence(
        candidate=candidate,
        description=doc.get("description") or vm.get("description"),
        readme=((doc.get("readme") or "")[:_README_CAP] or None),
        num_versions=len(versions),
        age_days=_age_days((doc.get("time") or {}).get("created")),
        has_repo=bool(repo),
        deprecated=bool(vm.get("deprecated")),
    )


def _evidence_pypi_rich(candidate: Candidate, http) -> Evidence:
    doc = _raw_doc(http, _PYPI_RAW + candidate.name.lower() + "/json")
    if doc is None:
        return Evidence(candidate=candidate)
    info = doc.get("info") or {}
    releases = doc.get("releases") or {}
    # Earliest upload across all release files = first-publish (raw doc keeps
    # upload_time, which the client strips → recovers PyPI age).
    times = [f.get("upload_time_iso_8601") or f.get("upload_time")
             for files in releases.values() if isinstance(files, list)
             for f in files if isinstance(f, dict)]
    times = [t for t in times if t]
    urls = info.get("project_urls") or {}
    return Evidence(
        candidate=candidate,
        description=info.get("summary"),
        readme=((info.get("description") or "")[:_README_CAP] or None),
        num_versions=len(releases),
        age_days=_age_days(min(times)) if times else None,
        has_repo=bool(urls or info.get("home_page")),
        deprecated=bool(info.get("yanked")),
    )


def collect_evidence_rich(
    candidate: Candidate, ecosystem: str, http,
    get_metadata: Callable[[str], Optional[dict]],
) -> Evidence:
    """Like :func:`collect_evidence` but recovers description/README for npm and
    PyPI via a raw-registry fetch (``http`` must be the egress-controlled
    client). crates/Packagist fall back to the stripped ``get_metadata``."""
    if ecosystem == "npm":
        return _evidence_npm_rich(candidate, http)
    if ecosystem == "PyPI":
        return _evidence_pypi_rich(candidate, http)
    return collect_evidence(candidate, ecosystem, get_metadata)


# ---------------------------------------------------------------------------
# Bridge — wire Stage A (LLM) to the gate + writer over one ecosystem
# ---------------------------------------------------------------------------

def render_evidence(ev: Evidence) -> str:
    """Render Evidence into the text block the LLM (Stage A) reasons over."""
    def f(v, unknown="unknown"):
        return unknown if v is None else v
    # Cap the (attacker-controlled) description + README so a package can't
    # blow the LLM prompt budget with a megabyte of text.
    desc = (ev.description or "")[:300]
    lines = [
        f"description: {desc or '(none in registry metadata)'}",
        f"release count: {ev.num_versions}",
        f"age (days since first publish): {f(ev.age_days)}",
        f"declares source repository: {'yes' if ev.has_repo else 'no'}",
        f"deprecated: {'yes' if ev.deprecated else 'no'}",
        f"downloads/month: {f(ev.downloads_per_month)}",
    ]
    if ev.readme:
        lines.append(f"README (excerpt):\n{ev.readme[:_README_CAP]}")
    return "\n".join(lines)


def _to_verdict(llm_verdict, candidate: Candidate) -> Verdict:
    """Map the LLM schema object (or ``None``) to the gate's ``Verdict``. A
    missing verdict becomes ``unsure`` → the gate escalates (never auto-trusts
    on no signal)."""
    if llm_verdict is None:
        return Verdict(name=candidate.name, verdict="unsure", confidence="low",
                       rationale="no LLM verdict (LLM unavailable or failed)")
    return Verdict(
        name=candidate.name,
        verdict=llm_verdict.verdict,
        confidence=llm_verdict.confidence,
        rationale=llm_verdict.rationale,
        evidence_cited=list(llm_verdict.evidence_cited),
    )


def make_llm_verdict_fn(llm_client, ecosystem: str) -> TriageFn:
    """Build the Stage-A ``triage_fn`` bound to an LLM client. Lazy-imports the
    llm module so the pure core (gate/orchestration) stays importable without
    pydantic / core.llm."""
    from ..llm.typosquat_triage import assess_typosquat

    def _fn(candidate: Candidate, evidence: Evidence) -> Verdict:
        v = assess_typosquat(
            llm_client, ecosystem, candidate.name, candidate.near_twin,
            candidate.rank, candidate.twin_rank, candidate.distance,
            render_evidence(evidence),
        )
        return _to_verdict(v, candidate)

    return _fn


def triage_ecosystem(
    candidates: List[Candidate],
    ecosystem: str,
    *,
    verdict_fn: TriageFn,
    evidence_fn: Optional[EvidenceFn] = None,
    get_metadata: Optional[Callable[[str], Optional[dict]]] = None,
    reviewed_legit_path: Optional[Path] = None,
    model: str = "",
    min_age_days: int = _MIN_AGE_DAYS,
    min_versions: int = _MIN_VERSIONS,
) -> List[TriageOutcome]:
    """Full pipeline for one ecosystem: collect evidence, get a verdict per
    candidate, gate, and (if a path is given) auto-file the AUTO_LEGIT names.
    Both seams are injected so this is tested without network or an LLM — pass
    either an ``evidence_fn`` (e.g. the rich one) or a ``get_metadata`` callable
    (built into the plain :func:`collect_evidence`)."""
    if evidence_fn is None:
        if get_metadata is None:
            raise ValueError("triage_ecosystem needs evidence_fn or get_metadata")
        gm = get_metadata
        evidence_fn = lambda c: collect_evidence(c, ecosystem, gm)  # noqa: E731
    outcomes = triage_pending(
        candidates, evidence_fn, verdict_fn,
        min_age_days=min_age_days, min_versions=min_versions,
    )
    if reviewed_legit_path is not None:
        apply_auto_legit(outcomes, ecosystem, reviewed_legit_path, model=model)
    return outcomes


# ---------------------------------------------------------------------------
# Step 3 — Tier-1 re-audit of reviewed-legit (mechanical, LLM-free, CI-runnable)
# ---------------------------------------------------------------------------
#
# Auto-filed 'legit' entries are suppressed from the candidate queue forever, so
# two things must be re-checked periodically: (a) a name we mis-classified as
# legit, and (b) a genuinely-legit name that LATER turned bad (compromised
# version / deprecation-holder — the litellm/node-ipc class). Both show up as a
# *change in current registry state* vs the 'legit' decision: removed, now
# deprecated, or now carrying a confirmed-malicious (MAL-) OSV advisory. This is
# all ground-truth signal — no LLM — so it runs in CI and opens an issue.

_OSV_ECOSYSTEM = {
    "PyPI": "PyPI", "npm": "npm", "Cargo": "crates.io", "Packagist": "Packagist",
}


def osv_malicious(http, ecosystem: str, names: List[str]) -> set:
    """Names (from ``names``) that currently carry a ``MAL-`` OSV advisory.
    Batched via OSV ``querybatch``; fail-soft (returns what it found, never
    raises). ``http`` should be the egress-controlled client (api.osv.dev is on
    SCA_ALLOWED_HOSTS)."""
    eco = _OSV_ECOSYSTEM.get(ecosystem)
    if eco is None or not names:
        return set()
    from ..osv import OSV_QUERY_BATCH_URL
    mal: set = set()
    try:
        for start in range(0, len(names), 1000):
            chunk = names[start:start + 1000]
            body = {"queries": [
                {"package": {"ecosystem": eco, "name": n}} for n in chunk]}
            resp = http.post_json(OSV_QUERY_BATCH_URL, body)
            for n, res in zip(chunk, (resp or {}).get("results") or []):
                vulns = (res or {}).get("vulns") or []
                if any(isinstance(v, dict) and isinstance(v.get("id"), str)
                       and v["id"].startswith("MAL-") for v in vulns):
                    mal.add(n)
    except Exception:                              # noqa: BLE001 — fail-soft
        pass
    return mal


def reaudit_reviewed_legit(
    reviewed_legit_path: Path,
    ecosystems: List[str],
    *,
    get_metadata: Callable[[str, str], Optional[dict]],
    osv_malicious_fn: Optional[Callable[[str, List[str]], set]] = None,
) -> "dict":
    """Tier-1 re-audit. For each reviewed-legit name, flag a contradiction with
    the 'legit' decision: removed/unreachable, now deprecated, or now carrying a
    MAL- advisory. Returns ``{ecosystem: [(name, reason), ...]}`` (only flagged
    names). ``get_metadata(eco, name)`` and ``osv_malicious_fn(eco, names)`` are
    injected so this is tested without network."""
    out: dict = {}
    for eco in ecosystems:
        names = sorted(_load_name_set(reviewed_legit_path, eco))
        if not names:
            continue
        flags: dict = {}
        for name in names:
            try:
                meta = get_metadata(eco, name)
            except Exception:                      # noqa: BLE001
                meta = None
            if meta is None:
                flags.setdefault(name, []).append(
                    "removed from registry or unreachable")
                continue
            ev = collect_evidence(Candidate(name, "", 0, 0, 0), eco,
                                  lambda _n: meta)
            if ev.deprecated:
                flags.setdefault(name, []).append("now deprecated")
        if osv_malicious_fn is not None:
            for name in osv_malicious_fn(eco, names):
                flags.setdefault(name, []).append(
                    "now carries a malicious (MAL-) advisory")
        if flags:
            out[eco] = [(n, "; ".join(rs)) for n, rs in sorted(flags.items())]
    return out


def reaudit_recommendation(flag_reason: str, verdict: Verdict) -> str:
    """Tier-2 suggested action for a flagged reviewed-legit entry, given its
    Tier-1 flag + a FRESH LLM verdict. A ``MAL-`` flag is ground truth and wins
    over the LLM; otherwise the LLM adjudicates whether the flag means the name
    should now be flagged (typosquat) or is a benign change (legit)."""
    if "malicious" in flag_reason:
        return ("MOVE TO DENYLIST — confirmed-malicious advisory (ground "
                "truth; LLM not required)")
    v = (verdict.verdict or "").lower()
    if v == "typosquat":
        return (f"MOVE TO DENYLIST (confirm) — LLM now rates it typosquat "
                f"({verdict.confidence})")
    if v == "legit":
        return ("LIKELY KEEP — LLM still rates it legit; the flag may be a "
                "benign deprecation. Verify, then keep or remove.")
    return "REVIEW — LLM unsure"
