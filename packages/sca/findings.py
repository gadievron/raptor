"""Combine OSV / KEV / EPSS / reachability into ``VulnFinding`` rows and
emit them to the shared ``findings.json`` schema.

Two stages:

1. ``build_vuln_findings`` — one ``VulnFinding`` per ``(dep, advisory)``
   pair. This is the granularity operators triage at: a single CVE
   against a single resolved dep, with KEV/EPSS context attached.

2. ``write_findings_json`` — serialises a mixed list of ``VulnFinding``
   and ``HygieneFinding`` records into the canonical ``findings.json``
   shape consumed by the rest of RAPTOR.

Why one finding per advisory (not one per dep):
- Reports rank by CVE/severity. Bundling all advisories under a single
  per-dep finding loses that granularity.
- Triage assigns a verdict per advisory; one finding per assignment
  keeps the triage <-> finding mapping one-to-one.

Dedup: callers pass a deduped dep list (lockfile-preferred) — see
``select_canonical_for_osv`` in the pipeline. The findings layer treats
its input as already deduped and does not re-collapse.
"""

from __future__ import annotations

import json as _json
import logging
from dataclasses import asdict, is_dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from core.cve import EpssClient
from core.cve import KevClient
from core.cve.vulnrichment import VulnrichmentClient
from .models import (
    Advisory,
    Confidence,
    Dependency,
    HygieneFinding,
    Reachability,
    Severity,
    SupplyChainFinding,
    VulnFinding,
)
from .osv import OsvResult
from .versions import VersionError, compare as version_compare

logger = logging.getLogger(__name__)

_SEVERITY_RANK: Dict[str, int] = {
    "info": 0, "none": 0,
    "low": 1, "medium": 2, "high": 3, "critical": 4,
}

_DEFAULT_REACHABILITY = Reachability(
    verdict="not_evaluated",
    confidence=Confidence(
        "low", reason="reachability stage skipped for this ecosystem",
    ),
)


# ---------------------------------------------------------------------------
# Building VulnFindings
# ---------------------------------------------------------------------------

def build_vuln_findings(
    deps: Sequence[Dependency],
    osv_results: Sequence[OsvResult],
    kev: Optional[KevClient] = None,
    epss: Optional[EpssClient] = None,
    reachability: Optional[Dict[str, Reachability]] = None,
    vulnrichment: Optional["VulnrichmentClient"] = None,
) -> List[VulnFinding]:
    """Combine signal layers into one ``VulnFinding`` per (dep, advisory).

    Args:
        deps: deduplicated input deps; expected to be the canonical
            (lockfile-preferred) view returned by the pipeline.
        osv_results: parallel-or-keyed OSV lookups; matched to deps via
            ``Dependency.key()``.
        kev: optional KEV lookup; ``None`` skips the KEV enrichment.
        epss: optional EPSS lookup; ``None`` skips the EPSS enrichment.
        reachability: optional per-dep-key reachability records.
        vulnrichment: optional CISA Vulnrichment SSVC lookup; closes
            the cold-start eco gap (Cargo / NuGet / Packagist) where
            KEV / EPSS / EDB / MSF / PoC return nothing for the
            majority of advisories. ``None`` skips the SSVC layer.
    """
    out: List[VulnFinding] = []

    # Pre-pass: dedup advisories that are aliases of the same CVE. OSV
    # routinely returns ``GHSA-…`` AND ``PYSEC-…`` for one underlying
    # CVE; emitting both produces visually-duplicate findings the
    # operator has to triage twice.
    deduped_results: Dict[str, List[Advisory]] = {}
    for r in osv_results:
        deduped_results[r.dep_key] = _dedup_alias_advisories(r.advisories)

    # First pass: compute related-finding IDs per dep so each finding can
    # carry the cross-references in one shot.
    related_by_dep: Dict[str, List[str]] = {}
    for d in deps:
        advisories = deduped_results.get(d.key())
        if advisories is None:
            continue
        related_by_dep[d.key()] = [
            _vuln_finding_id(d, a) for a in advisories
        ]

    for d in deps:
        advisories = deduped_results.get(d.key())
        if not advisories:
            continue
        sibling_ids = related_by_dep.get(d.key(), [])
        for adv in advisories:
            this_id = _vuln_finding_id(d, adv)
            related = [i for i in sibling_ids if i != this_id]
            out.append(_assemble_finding(
                dep=d,
                advisory=adv,
                this_id=this_id,
                related_ids=related,
                kev=kev,
                epss=epss,
                reachability=reachability,
                vulnrichment=vulnrichment,
            ))
    return out


def _dedup_alias_advisories(advisories: List[Advisory]) -> List[Advisory]:
    """Collapse advisories pointing at the same underlying CVE.

    Keys on the first ``CVE-*`` alias when present (the canonical name);
    falls back to the OSV id otherwise. Preference order when multiple
    OSV records share a CVE: GHSA-* > CVE-* > PYSEC-* > everything else
    (GHSA records are usually the most complete).
    """
    by_key: Dict[str, Advisory] = {}
    order: List[str] = []
    for a in advisories:
        cve = next((x for x in a.aliases
                    if isinstance(x, str) and x.upper().startswith("CVE-")),
                   None)
        key = cve.upper() if cve else a.osv_id
        if key not in by_key:
            by_key[key] = a
            order.append(key)
            continue
        if _advisory_priority(a) < _advisory_priority(by_key[key]):
            by_key[key] = a
    return [by_key[k] for k in order]


def _advisory_priority(a: Advisory) -> int:
    """Lower is preferred."""
    p = a.osv_id.upper() if isinstance(a.osv_id, str) else ""
    if p.startswith("GHSA-"):
        return 0
    if p.startswith("CVE-"):
        return 1
    if p.startswith("PYSEC-") or p.startswith("OSV-"):
        return 2
    return 3


def _assemble_finding(
    *,
    dep: Dependency,
    advisory: Advisory,
    this_id: str,
    related_ids: List[str],
    kev: Optional[KevClient],
    epss: Optional[EpssClient],
    reachability: Optional[Dict[str, Reachability]],
    vulnrichment: Optional[VulnrichmentClient] = None,
) -> VulnFinding:
    cve_aliases = [a for a in advisory.aliases if a.upper().startswith("CVE-")]
    in_kev = bool(kev and any(kev.contains(c) for c in cve_aliases))
    epss_score: Optional[float] = None
    if epss and cve_aliases:
        scores = epss.scores(cve_aliases)
        if scores:
            epss_score = max(scores.values())
    # CISA Vulnrichment SSVC — broadest cross-eco exploitation
    # signal, covering the ~60% of cold-start eco CVEs (Cargo /
    # NuGet / Packagist) that KEV / EPSS / EDB / MSF / PoC skip.
    # Pick the strongest signal across the advisory's CVE aliases:
    # ``active`` > ``poc`` > ``none``. Any miss (CISA hasn't
    # enriched, or no CVE aliases at all) leaves
    # ``ssvc_exploitation`` as ``None`` so the risk formula's
    # "no signal" branch fires.
    #
    # ``Automatable`` is captured independently. ``yes`` from
    # ANY alias attributes to the finding — a CVE chain where
    # one alias says "wormable potential" and another says "no"
    # is still wormable-potential in practice. The risk formula
    # consumes this as a small bonus multiplier on top of the
    # SSVC tier when Exploitation>=poc.
    ssvc_exploitation: Optional[str] = None
    ssvc_automatable: Optional[str] = None
    if vulnrichment is not None and cve_aliases:
        decisions = [
            vulnrichment.lookup(c) for c in cve_aliases
        ]
        decisions = [d for d in decisions if d is not None]
        if any(d.is_active for d in decisions):
            ssvc_exploitation = "active"
        elif any(d.has_exploit for d in decisions):
            ssvc_exploitation = "poc"
        elif decisions:
            ssvc_exploitation = "none"
        if any((d.automatable or "").lower() == "yes" for d in decisions):
            ssvc_automatable = "yes"
        elif any((d.automatable or "").lower() == "no" for d in decisions):
            ssvc_automatable = "no"

    fixed = _smallest_applicable_fix(
        dep.ecosystem, dep.version, advisory.fixed_versions,
    )
    severity_str = _severity_for_advisory(advisory)
    if dep.commented_out:
        # Commented-out lines (`# pkg==X` in requirements.txt) are
        # documentation, not active deps. Downgrade to ``info`` so the
        # gate doesn't block by default; the operator can opt in via
        # ``--fail-on-info`` when they want commented hints to fail CI.
        severity_str = "info"
    cvss_score = advisory.severity.score if advisory.severity else None
    cvss_vector = advisory.severity.vector if advisory.severity else None

    reach = (reachability or {}).get(dep.key()) or _DEFAULT_REACHABILITY

    # Version-match confidence: an exact match against an OSV affected
    # range uses the parser's confidence; if the parser was uncertain
    # (heuristic Gradle / unresolved property), we inherit that.
    vmc = dep.parser_confidence
    if vmc.level != "high":
        vmc = Confidence(
            vmc.level,
            reason=f"version-match: parser was {vmc.reason or vmc.level}",
        )

    f = VulnFinding(
        finding_id=this_id,
        dependency=dep,
        advisories=[advisory],
        in_kev=in_kev,
        epss=epss_score,
        fixed_version=fixed,
        reachability=reach,
        version_match_confidence=vmc,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        severity=severity_str,
        exposure_factor=0.0,        # populated by reachability layer
        transitive_depth=0 if dep.direct else 1,
        ssvc_exploitation=ssvc_exploitation,
        ssvc_automatable=ssvc_automatable,
        related_findings=related_ids,
    )
    # Composite risk estimate (calibration unverified — see
    # packages/sca/risk.py). Computed last so all the inputs are
    # already populated; carried alongside the components dict for
    # operator visibility.
    from .risk import compute_risk_estimate
    f.raptor_risk_estimate, f.risk_components = compute_risk_estimate(f, dep)
    return f


def _severity_for_advisory(advisory: Advisory) -> Severity:
    if advisory.severity:
        s = advisory.severity.severity
        if s in ("none", "low", "medium", "high", "critical"):
            return s             # type: ignore[return-value]
    # No CVSS — degrade to "medium" since the advisory exists at all.
    return "medium"


def _smallest_applicable_fix(
    ecosystem: str,
    installed_version: Optional[str],
    fixed_versions: List[str],
) -> Optional[str]:
    """Smallest fix version that *upgrades from* the installed version.

    OSV advisories often carry multiple fix versions across multiple
    ranges (e.g., a 1.x track with fix=1.10.13 AND a 2.x track with
    fix=2.4.0 for the same CVE). For an installed pydantic 2.0.0 the
    correct upgrade target is 2.4.0 — picking 1.10.13 globally would
    suggest a downgrade across a major version boundary.

    Strategy:
    1. Filter fix versions to those strictly greater than ``installed``.
    2. Return the smallest of that filtered set (the closest upgrade).
    3. If nothing is greater than installed (the installed dep is past
       every published fix), fall back to the global smallest so the
       user sees *something* sensible.
    """
    if not fixed_versions:
        return None
    if installed_version is None or len(fixed_versions) == 1:
        # No installed version to compare against, or only one fix —
        # nothing to filter; preserve OSV order on parse errors.
        try:
            return min(fixed_versions, key=_VersionKey(ecosystem))
        except VersionError:
            return fixed_versions[0]

    upgrades: List[str] = []
    for v in fixed_versions:
        try:
            if version_compare(ecosystem, v, installed_version) > 0:
                upgrades.append(v)
        except VersionError:
            continue

    target_pool = upgrades or fixed_versions
    try:
        return min(target_pool, key=_VersionKey(ecosystem))
    except VersionError:
        return target_pool[0]


class _VersionKey:
    """Functor that wraps the per-ecosystem version comparator into a
    sortable key. Avoids repeatedly capturing ``ecosystem`` in lambdas."""

    __slots__ = ("ecosystem",)

    def __init__(self, ecosystem: str) -> None:
        self.ecosystem = ecosystem

    def __call__(self, value: str) -> "_Sortable":
        return _Sortable(self.ecosystem, value)


class _Sortable:
    """Wrap a version string with the ecosystem so total ordering works
    via ``__lt__``. Falls back to string compare when the version is
    unparseable for the ecosystem."""

    __slots__ = ("eco", "v")

    def __init__(self, ecosystem: str, value: str) -> None:
        self.eco = ecosystem
        self.v = value

    def __lt__(self, other: "_Sortable") -> bool:
        try:
            return version_compare(self.eco, self.v, other.v) < 0
        except VersionError:
            return self.v < other.v


def _vuln_finding_id(dep: Dependency, advisory: Advisory) -> str:
    return (
        f"sca:vuln:{dep.ecosystem}:{dep.name}:{dep.version or '*'}:"
        f"{advisory.osv_id}"
    )


# ---------------------------------------------------------------------------
# Emitting findings.json
# ---------------------------------------------------------------------------

def write_findings_json(
    path: Path,
    *,
    vuln_findings: Iterable[VulnFinding] = (),
    hygiene_findings: Iterable[HygieneFinding] = (),
    supply_chain_findings: Iterable[SupplyChainFinding] = (),
    license_findings: Iterable[Any] = (),
) -> int:
    """Write the merged finding list to ``path`` and return its row count.

    Output shape: a top-level list of dicts, each tagged with one of
    ``sca:vulnerable_dependency`` / ``sca:hygiene:<kind>`` /
    ``sca:supply_chain:<kind>`` / ``sca:license:<kind>``.
    """
    rows: List[Dict[str, Any]] = []
    for f in vuln_findings:
        rows.append(_vuln_finding_to_row(f))
    for f in hygiene_findings:
        rows.append(_hygiene_finding_to_row(f))
    for f in supply_chain_findings:
        rows.append(_supply_chain_finding_to_row(f))
    for f in license_findings:
        rows.append(_license_finding_to_row(f))

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        _json.dump(rows, fh, indent=2, default=_json_default)
    tmp.replace(path)
    return len(rows)


def _vuln_finding_to_row(f: VulnFinding) -> Dict[str, Any]:
    primary = f.advisories[0] if f.advisories else None
    title = _vuln_title(f, primary)
    return {
        "id": f.finding_id,
        "finding_id": f.finding_id,
        "vuln_type": "sca:vulnerable_dependency",
        "tool": "sca",
        "file": str(f.dependency.declared_in),
        "function": f.dependency.name,
        "line": 0,
        "severity": f.severity,
        "suppressed": f.suppressed,
        "suppression_reason": f.suppression_reason,
        "title": title,
        "description": _describe_vuln(f),
        # SCA-specific extension fields. Consumers that don't know about
        # them ignore them; the schema explicitly allows extras.
        "sca": {
            "ecosystem": f.dependency.ecosystem,
            "name": f.dependency.name,
            "version": f.dependency.version,
            "purl": f.dependency.purl,
            "scope": f.dependency.scope,
            "is_lockfile": f.dependency.is_lockfile,
            "direct": f.dependency.direct,
            "pin_style": f.dependency.pin_style.value,
            "commented_out": f.dependency.commented_out,
            "declared_in": str(f.dependency.declared_in)
                            if f.dependency.declared_in else None,
            "source_kind": f.dependency.source_kind,
            "advisory": _advisory_summary(primary),
            "all_advisories": [_advisory_summary(a) for a in f.advisories],
            "in_kev": f.in_kev,
            "epss": f.epss,
            "fixed_version": f.fixed_version,
            "reachability": _reachability_summary(f.reachability),
            "cvss_score": f.cvss_score,
            "cvss_vector": f.cvss_vector,
            "version_match_confidence": _confidence_summary(
                f.version_match_confidence,
            ),
            "parser_confidence": _confidence_summary(
                f.dependency.parser_confidence,
            ),
            "exposure_factor": f.exposure_factor,
            "transitive_depth": f.transitive_depth,
            "raptor_risk_estimate": f.raptor_risk_estimate,
            "risk_components": f.risk_components,
            "exploit_evidence": _exploit_evidence_summary(f.exploit_evidence),
            "related_findings": list(f.related_findings),
        },
    }


def _exploit_evidence_summary(ev) -> Optional[Dict[str, Any]]:
    """Render :class:`ExploitEvidence` as the ``sca.exploit_evidence``
    block in findings.json. Emits None when annotation didn't run
    (e.g. corpus missing) so the field is absent rather than
    misleadingly-empty."""
    if ev is None:
        return None
    return {
        "kev_listed": ev.kev_listed,
        "edb_ids": list(ev.edb_ids),
        "msf_modules": list(ev.msf_modules),
        "github_poc_urls": list(ev.github_poc_urls),
        "has_any": ev.has_any,
    }


def _commented_severity(dep: Dependency, severity: str) -> str:
    """Downgrade hygiene / supply-chain / license severities on
    commented-out dep lines.

    Mirrors the vuln-finding downgrade in ``_vuln_finding_to_row``:
    a ``# pkg==X`` comment is documentation, not an active dep, so
    operators don't want CI gated on it. Floor at ``info``; the
    operator can opt back in with ``--fail-on-info`` when they
    want commented hints to fail the build.
    """
    if dep.commented_out and severity not in ("info",):
        return "info"
    return severity


def _hygiene_finding_to_row(f: HygieneFinding) -> Dict[str, Any]:
    severity = _commented_severity(f.dependency, f.severity)
    return {
        "id": f.finding_id,
        "finding_id": f.finding_id,
        "vuln_type": f"sca:hygiene:{f.kind}",
        "tool": "sca",
        "file": str(f.dependency.declared_in),
        "function": f.dependency.name,
        "line": 0,
        "severity": severity,
        "suppressed": f.suppressed,
        "suppression_reason": f.suppression_reason,
        "title": _kind_title(f.kind, f.dependency.name),
        "description": f.detail,
        "sca": {
            "kind": f.kind,
            "ecosystem": f.dependency.ecosystem,
            "name": f.dependency.name,
            "version": f.dependency.version,
            "purl": f.dependency.purl,
            "scope": f.dependency.scope,
            "is_lockfile": f.dependency.is_lockfile,
            "pin_style": f.dependency.pin_style.value,
            "commented_out": f.dependency.commented_out,
            "confidence": _confidence_summary(f.confidence),
        },
    }


def _supply_chain_finding_to_row(f: SupplyChainFinding) -> Dict[str, Any]:
    severity = _commented_severity(f.dependency, f.severity)
    return {
        "id": f.finding_id,
        "finding_id": f.finding_id,
        "vuln_type": f"sca:supply_chain:{f.kind}",
        "tool": "sca",
        "file": str(f.dependency.declared_in),
        "function": f.dependency.name,
        "line": 0,
        "severity": severity,
        "suppressed": f.suppressed,
        "suppression_reason": f.suppression_reason,
        "title": _kind_title(f.kind, f.dependency.name),
        "description": f.detail,
        "sca": {
            "kind": f.kind,
            "ecosystem": f.dependency.ecosystem,
            "name": f.dependency.name,
            "version": f.dependency.version,
            "commented_out": f.dependency.commented_out,
            "evidence": dict(f.evidence),
            "confidence": _confidence_summary(f.confidence),
        },
    }


def _license_finding_to_row(f: Any) -> Dict[str, Any]:
    kind_short = f.kind.replace('license_', '')
    severity = _commented_severity(f.dependency, f.severity)
    return {
        "id": f.finding_id,
        "finding_id": f.finding_id,
        "vuln_type": f"sca:license:{kind_short}",
        "tool": "sca",
        "file": str(f.dependency.declared_in),
        "function": f.dependency.name,
        "line": 0,
        "severity": severity,
        "suppressed": f.suppressed,
        "suppression_reason": f.suppression_reason,
        "title": _kind_title(kind_short, f.dependency.name),
        "description": f.detail,
        "sca": {
            "kind": f.kind,
            "ecosystem": f.dependency.ecosystem,
            "name": f.dependency.name,
            "version": f.dependency.version,
            "spdx": f.spdx,
            "purl": f.dependency.purl,
            "commented_out": f.dependency.commented_out,
            "confidence": _confidence_summary(f.confidence),
        },
    }


def _vuln_title(f: VulnFinding, primary: Optional[Advisory]) -> str:
    """Short human-readable title for a vuln finding.

    ``{name}@{version} — {advisory summary}`` when an advisory is
    present; ``{name}@{version} — vulnerable`` as the no-advisory
    fallback.  Consumers (GitHub Code Scanning UI, PR-comment
    renderers, ``raptor-sca diff``) display the title; the
    ``description`` field carries the richer one-liner already.
    """
    head = f"{f.dependency.name}@{f.dependency.version or '*'}"
    if primary is None or not primary.summary:
        return f"{head} — vulnerable"
    # Strip trailing periods so titles don't end with double-stops
    # when consumers append their own punctuation.
    return f"{head} — {primary.summary.rstrip('.')}"


def _kind_title(kind: str, name: str) -> str:
    """Short human-readable title for hygiene / supply_chain /
    license findings.

    Kinds are snake_case enums (``unpinned_dependency``,
    ``typosquat_domain``, ``low_bus_factor``, ``unknown`` …); we
    title-case the words and append the dep name so the title is
    self-describing without reading the longer ``description``."""
    pretty = kind.replace("_", " ").capitalize()
    return f"{pretty}: {name}"


def _describe_vuln(f: VulnFinding) -> str:
    primary = f.advisories[0] if f.advisories else None
    if primary is None:
        return f"{f.dependency.name}@{f.dependency.version or '*'}"
    head = primary.summary or primary.osv_id
    parts = [
        f"{f.dependency.name}@{f.dependency.version or '*'}: {head}",
    ]
    if primary.aliases:
        parts.append(f"({', '.join(primary.aliases[:3])})")
    if f.in_kev:
        parts.append("[KEV]")
    if f.epss is not None:
        parts.append(f"[EPSS {f.epss:.2f}]")
    return " ".join(parts)


def _advisory_summary(a: Optional[Advisory]) -> Optional[Dict[str, Any]]:
    if a is None:
        return None
    out: Dict[str, Any] = {
        "id": a.osv_id,
        "aliases": list(a.aliases),
        "summary": a.summary,
        "fixed_versions": list(a.fixed_versions),
        "references": list(a.references[:5]),     # cap noise in the JSON
        "severity": _cvss_summary(a),
        "published": a.published.isoformat() if a.published else None,
        "modified": a.modified.isoformat() if a.modified else None,
    }
    if a.informational:
        # RUSTSEC "unsound" / "unmaintained" / "notice" markers,
        # and similar non-security flags on other ecos. Surface
        # in the JSON so calibration tooling + future scan-time
        # severity gating can distinguish from real CVEs.
        out["informational"] = a.informational
    return out


def _cvss_summary(a: Advisory) -> Optional[Dict[str, Any]]:
    if a.severity is None:
        return None
    return {
        "score": a.severity.score,
        "vector": a.severity.vector,
        "severity": a.severity.severity,
    }


def _reachability_summary(r: Reachability) -> Dict[str, Any]:
    return {
        "verdict": r.verdict,
        "confidence": _confidence_summary(r.confidence),
        "evidence": list(r.evidence),
    }


def _confidence_summary(c: Confidence) -> Dict[str, Any]:
    return {"level": c.level, "numeric": c.numeric, "reason": c.reason}


def _json_default(obj: Any) -> Any:
    """Fallback JSON serialiser for dataclass / Path / Enum / datetime."""
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, datetime):
        return obj.isoformat()
    if is_dataclass(obj):
        return asdict(obj)
    raise TypeError(f"Cannot serialise {type(obj).__name__}: {obj!r}")


# ---------------------------------------------------------------------------
# Severity helpers (re-exported for the report layer)
# ---------------------------------------------------------------------------

def severity_rank(severity: Severity) -> int:
    """Return the rank for a severity string. Case-insensitive — LLM
    verdicts and hand-edited findings frequently capitalise (``Critical``,
    ``HIGH``); a case-sensitive lookup would silently treat them as 0
    and let CI gates pass when they shouldn't.
    """
    if not severity:
        return 0
    return _SEVERITY_RANK.get(severity.lower(), 0)


__all__ = [
    "build_vuln_findings",
    "write_findings_json",
    "severity_rank",
]
