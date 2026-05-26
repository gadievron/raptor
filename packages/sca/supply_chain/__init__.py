"""Mechanical supply-chain heuristics.

Each check emits a ``SupplyChainFinding`` consumed by the findings layer:

- ``install_hooks`` — npm ``package.json`` lifecycle scripts that fire
  at install time, with regex patterns for known-malicious shapes.
- ``typosquat`` — Damerau-Levenshtein distance against the bundled
  popular-name list per ecosystem.
- ``artefacts`` — four project-tree heuristics: ``.pth`` files,
  binary fixtures in test trees, ``disguised_filename`` (extension
  lies about content), ``large_obfuscated_artefact`` (minified /
  obfuscated source-tree files outside build dirs).
- ``python_imports`` — top-level executable code in ``.py`` files
  outside test trees (``subprocess`` / ``os.system`` / ``eval`` /
  ``__import__`` / network calls at import time).
- ``exfil_destinations`` — URLs in source matching curated lists of
  paste sites, anonymous file-share, URL shorteners, Tor, Discord
  webhooks, Telegram bots, raw-IP URLs.
- ``gha_drift`` — GitHub Actions workflows using mutable refs
  (``uses: foo/action@v1`` rather than 40-char SHA pins).
- ``git_drift`` — manifest-pinned git deps with branch/tag refs
  rather than SHAs.

Deferred to follow-ups:

- Recent-publish / maintainer-change checks (need registry metadata
  over the network — separate clients, separate cache).
- Walking ``node_modules`` for per-dep install hooks (most CI runs
  don't have ``node_modules`` materialised at scan time).
- LLM-assisted version-diff / postinstall / maintainer-trust reviews
  (Tier B; the curated lists in ``data/`` will be reused as exemplars).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, Iterable, List

from ..models import (
    Dependency,
    Manifest,
    SupplyChainFinding,
)
from . import artefacts as _artefacts
from . import exfil_destinations as _exfil
from . import gha_drift as _gha_drift
from . import gha_freshness as _gha_freshness
from . import gha_sunset as _gha_sunset
from . import git_drift as _git_drift
from . import cargo_build_scripts as _cargo_build
from . import install_hooks as _install_hooks
from . import orphan_commit_dep as _orphan_commit_dep
from . import python_imports as _python_imports
from . import registry_metadata as _registry_metadata
from . import sentinel as _sentinel
from . import slopsquat as _slopsquat
from . import typosquat as _typosquat
from . import typosquat_domain as _typosquat_domain
from . import branch_protection as _branch_protection
from . import workflow_signing as _workflow_signing

logger = logging.getLogger(__name__)


def evaluate(
    target: Path,
    manifests: Iterable[Manifest],
    deps: Iterable[Dependency],
    *,
    pypi_client=None,
    npm_client=None,
    github_actions_client=None,
    cache=None,
) -> List[SupplyChainFinding]:
    """Run every mechanical supply-chain check.

    Args:
        target: project root (used by artefact / source walks).
        manifests: the discovery output (manifests + lockfiles).
        deps: the joined dep list — typically post-``join.join``.
        pypi_client / npm_client / github_actions_client: optional
            registry clients used by detectors that need
            registry-side metadata. When absent, those detectors
            are no-ops so we don't make uncached HTTP calls from
            unit tests or in offline mode. ``github_actions_client``
            powers ``gha_freshness`` (major-version-behind
            detection); when None, only the curated sunset list
            fires.
    """
    manifests_list = list(manifests)
    deps_list = list(deps)
    out: List[SupplyChainFinding] = []

    for hit in _install_hooks.scan_manifests(manifests_list, deps_list):
        out.append(_install_hook_to_finding(hit))

    for och in _orphan_commit_dep.scan_manifests(manifests_list, deps_list):
        out.append(_orphan_commit_to_finding(och))

    for cbs in _cargo_build.scan_manifests(manifests_list, deps_list):
        out.append(SupplyChainFinding(
            finding_id=(
                f"sca:supply_chain:install_hook_suspicious:Cargo:"
                f"{cbs.dependency.declared_in}"
            ),
            kind="install_hook_suspicious",
            dependency=cbs.dependency,
            detail=cbs.detail,
            evidence={"file": "build.rs",
                      "ecosystem": "Cargo"},
            severity=cbs.severity,
            confidence=cbs.confidence,
        ))

    for sh in _sentinel.scan_deps(deps_list):
        out.append(_sentinel_to_finding(sh))

    for ts in _typosquat.scan_deps(deps_list):
        out.append(_typosquat_to_finding(ts))

    for ss in _slopsquat.scan_deps(deps_list):
        out.append(_slopsquat_to_finding(ss))

    for art in _artefacts.scan_target(target, manifests_list):
        out.append(_artefact_to_finding(art))

    for it in _python_imports.scan_target(
        target, manifests_list, cache=cache,
    ):
        out.append(_python_import_to_finding(it))

    for ex in _exfil.scan_target(target, manifests_list):
        out.append(_exfil_to_finding(ex))

    for gha in _gha_drift.scan_target(target, manifests_list):
        out.append(_gha_drift_to_finding(gha))

    # Sunset detector consumes the Dependency rows already emitted
    # by ``parsers.inline_installs.parse_gha_workflow`` (ecosystem
    # ``"GitHub Actions"``). No additional walk needed; the sunset
    # check is a pure dep-list filter against the curated list.
    out.extend(_gha_sunset.scan_dependencies(deps_list))

    # Major-version freshness — opt-in via ``github_actions_client``
    # (network-bound; pipeline wires it from default_client + cache).
    if github_actions_client is not None:
        out.extend(_gha_freshness.scan_dependencies(
            deps_list, client=github_actions_client,
        ))

    for gd in _git_drift.scan_deps(deps_list):
        out.append(_git_drift_to_finding(gd))

    for td in _typosquat_domain.scan_target(target, manifests_list):
        out.append(_typosquat_domain_to_finding(td))

    for ws in _workflow_signing.scan_target(target, manifests_list):
        out.append(_workflow_signing_to_finding(ws))

    if github_actions_client is not None:
        for bp in _branch_protection.scan_target(
            target, manifests_list, client=github_actions_client,
        ):
            out.append(_branch_protection_to_finding(bp))

    if pypi_client is not None or npm_client is not None:
        for rm in _registry_metadata.scan_deps(
            deps_list,
            pypi_client=pypi_client,
            npm_client=npm_client,
        ):
            out.append(_registry_meta_to_finding(rm))

    # Cross-detector severity escalation. registry_metadata has its
    # own per-dep escalation rule (line ~700 of registry_metadata.py)
    # that handles correlations WITHIN its own findings. This pass
    # handles correlations ACROSS detectors — specifically the
    # "slopsquat finding + recent_publish + low_bus_factor" stack
    # which is the canonical LLM-hallucination-bait shape:
    #   * Heuristic flags the name as slopsquat-shape.
    #   * Registry confirms the package was just published.
    #   * Single maintainer → newly-registered anonymous publisher.
    # Each signal alone is moderate noise; the conjunction is the
    # actual attack signature.
    _escalate_cross_detector(out)

    return out


# ---------------------------------------------------------------------------
# Cross-detector severity escalation
# ---------------------------------------------------------------------------
#
# When multiple detectors fire on the same dep, the combined signal
# is often stronger than the sum of its parts. registry_metadata's
# own ``_escalate_severity`` handles correlations within its
# detector family (recent_publish + maintainer_change + payload_size
# spike). This function handles correlations across families —
# specifically the slopsquat ladder, where heuristic-shape +
# registry-recency + low-bus-factor stack into the "newly registered
# bait by an anonymous publisher" archetype.

# Severity-rank table for clamping the escalation result so we
# can't accidentally DOWNGRADE a finding via a max() call.
_SEVERITY_RANK = {
    "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}


def _escalate_cross_detector(findings: List[SupplyChainFinding]) -> None:
    """Mutate ``findings`` in place: bump slopsquat-finding severity
    based on co-occurring registry-metadata signals for the same
    package.

    The conjunction is the actionable signal — heuristic alone
    is too noisy for non-LLM-paste use cases (legitimate
    ``lodash-utils`` would fire), but heuristic + "package was
    first published in the last 30 days" + "single maintainer"
    is the canonical bait signature.
    """
    # Index findings by (ecosystem, name) so co-occurrence is O(1).
    by_dep: Dict[
        "tuple[str, str]", List[SupplyChainFinding],
    ] = {}
    for f in findings:
        if f.dependency is None:
            continue
        key = (f.dependency.ecosystem, f.dependency.name)
        by_dep.setdefault(key, []).append(f)

    for slop in findings:
        if slop.kind != "slopsquat_suspect":
            continue
        if slop.dependency is None:
            continue
        key = (slop.dependency.ecosystem, slop.dependency.name)
        sibling_kinds = {
            f.kind for f in by_dep.get(key, [])
            if f is not slop
        }
        # Recent-publish (first publish < 30 days) OR fresh
        # version_publish on a previously-dormant package both
        # signal "just appeared." Either bumps slopsquat by one
        # severity tier.
        has_recent = (
            "recent_publish" in sibling_kinds
            or "version_publish" in sibling_kinds
        )
        # Single maintainer adds the "anonymous publisher"
        # dimension of the bait shape.
        has_lone_maintainer = "low_bus_factor" in sibling_kinds
        # Active maintainer-takeover signal (less likely on a
        # brand-new bait package but possible if the attacker
        # adopted an abandoned name).
        has_maint_change = (
            "maintainer_change" in sibling_kinds
            or "maintainer_account_change" in sibling_kinds
        )

        target_rank = _SEVERITY_RANK.get(slop.severity, 0)
        reasons: List[str] = []
        if has_recent and has_lone_maintainer:
            # Full bait shape: heuristic-shape + just-registered
            # + anonymous publisher. Critical regardless of the
            # heuristic's own score.
            target_rank = max(target_rank, _SEVERITY_RANK["critical"])
            reasons.append(
                "co-occurs with recent_publish + low_bus_factor "
                "(LLM-hallucination-bait archetype)"
            )
        elif has_recent or has_maint_change:
            target_rank = max(target_rank, _SEVERITY_RANK["high"])
            reasons.append(
                "co-occurs with "
                + ("recent_publish " if has_recent else "")
                + ("maintainer_change " if has_maint_change else "")
                + "— new-package risk amplifies slopsquat shape"
            )
        elif has_lone_maintainer:
            target_rank = max(target_rank, _SEVERITY_RANK["medium"])
            reasons.append(
                "co-occurs with low_bus_factor — single-publisher "
                "package matching slopsquat shape"
            )

        # Apply if it's actually an upgrade.
        new_severity = next(
            (s for s, r in _SEVERITY_RANK.items() if r == target_rank),
            slop.severity,
        )
        if (_SEVERITY_RANK.get(new_severity, 0)
                > _SEVERITY_RANK.get(slop.severity, 0)):
            slop.severity = new_severity      # type: ignore[assignment]
            existing_evidence = dict(slop.evidence)
            existing_evidence["escalation_reasons"] = reasons
            slop.evidence = existing_evidence


# ---------------------------------------------------------------------------
# Conversions
# ---------------------------------------------------------------------------

def _install_hook_to_finding(
    hit: _install_hooks.InstallHookFinding,
) -> SupplyChainFinding:
    why = ", ".join(hit.hit.reasons) if hit.hit.reasons else "hook present"
    return SupplyChainFinding(
        finding_id=(
            f"sca:supplychain:install_hook_suspicious:"
            f"{hit.dependency.ecosystem}:{hit.dependency.name}:"
            f"{hit.hit.script_key}:{hit.dependency.declared_in}"
        ),
        kind="install_hook_suspicious",
        dependency=hit.dependency,
        detail=(
            f"`scripts.{hit.hit.script_key}` runs at install time; "
            f"reason: {why}; body: {_truncate(hit.hit.script_body)}"
        ),
        evidence={
            "script_key": hit.hit.script_key,
            "script_body": _truncate(hit.hit.script_body),
            "reasons": list(hit.hit.reasons),
        },
        severity=hit.severity,             # type: ignore[arg-type]
        confidence=hit.confidence,
    )


def _orphan_commit_to_finding(
    och: _orphan_commit_dep.OrphanCommitFinding,
) -> SupplyChainFinding:
    """Convert an orphan-commit-dep hit. ``finding_id`` deliberately
    includes the dep-name + field so two refs from the same
    package.json (e.g. one in ``dependencies`` + one in
    ``optionalDependencies``) emit as distinct findings."""
    return SupplyChainFinding(
        finding_id=(
            f"sca:supplychain:orphan_commit_dep:"
            f"{och.dependency.ecosystem}:{och.dependency.name}:"
            f"{och.hit.field}:{och.hit.dep_name}:"
            f"{och.dependency.declared_in}"
        ),
        kind="orphan_commit_dep",
        dependency=och.dependency,
        detail=(
            f"`{och.hit.field}.{och.hit.dep_name}` references "
            f"git ref `{och.hit.owner}/{och.hit.repo}"
            f"{('#' + och.hit.ref) if och.hit.ref else ''}` "
            f"({_explain_ref_kind(och.hit.ref_kind)}). "
            f"Mini Shai-Hulud used this shape as a secondary "
            f"delivery channel — verify the ref is legitimate."
        ),
        evidence={
            "field": och.hit.field,
            "dep_name": och.hit.dep_name,
            "ref_spec": och.hit.ref_spec,
            "owner": och.hit.owner,
            "repo": och.hit.repo,
            "ref": och.hit.ref,
            "ref_kind": och.hit.ref_kind,
        },
        severity=och.severity,                # type: ignore[arg-type]
        confidence=och.confidence,
    )


def _explain_ref_kind(kind: str) -> str:
    return {
        "sha40": "pinned to a 40-char SHA",
        "tag_or_branch": "pinned to a tag or branch",
        "none": "no explicit ref — resolves to default branch",
    }.get(kind, kind)


def _workflow_signing_to_finding(
    ws: _workflow_signing.WorkflowSigningFinding,
) -> SupplyChainFinding:
    """Convert a workflow-signing finding. Two shapes:

      * per-commit anomaly — ``ws.unsigned_commit`` populated, the
        repo's signing norm is high enough that this unsigned
        commit reads as anomalous. Megalodon-attack-signature shape.
      * summary hygiene — ``ws.stats`` populated, the repo's signing
        rate is below the anomaly-detection threshold. One finding
        per scan describing the rate.
    """
    if ws.unsigned_commit is not None:
        hit = ws.unsigned_commit
        short_sha = hit.commit_sha[:12]
        return SupplyChainFinding(
            finding_id=(
                f"sca:supplychain:workflow_unsigned_commit:"
                f"{hit.commit_sha}"
            ),
            kind="workflow_unsigned_commit",
            dependency=ws.dependency,
            detail=(
                f"commit {short_sha} modifying .github/workflows/** "
                f"is unsigned (author: {hit.author_name} "
                f"<{hit.author_email}>, subject: "
                f"{_truncate(hit.subject, limit=80)}). The repo's "
                f"signing norm is high enough that this commit "
                f"stands out — Megalodon-class attacks push forged-"
                f"identity commits to ``main`` and would produce "
                f"exactly this signal."
            ),
            evidence={
                "commit_sha": hit.commit_sha,
                "sig_status": hit.sig_status,
                "author_name": hit.author_name,
                "author_email": hit.author_email,
                "subject": _truncate(hit.subject, limit=200),
                "finding_shape": "anomaly",
            },
            severity=ws.severity,                 # type: ignore[arg-type]
            confidence=ws.confidence,
        )
    if ws.stats is not None:
        stats = ws.stats
        rate_pct = round(stats.signing_rate * 100, 1)
        return SupplyChainFinding(
            finding_id=(
                f"sca:supplychain:workflow_unsigned_commit:"
                f"summary:{ws.dependency.declared_in}"
            ),
            kind="workflow_unsigned_commit",
            dependency=ws.dependency,
            detail=(
                f"{stats.unsigned_count} of the last "
                f"{stats.commits_walked} commits touching "
                f".github/workflows/** are unsigned "
                f"(signing rate {rate_pct}%). Below the "
                f"anomaly-detection threshold — individual "
                f"unsigned commits aren't flagged in this "
                f"regime. Enabling 'Require signed commits' "
                f"branch protection on ``main`` raises the "
                f"signing rate to 100% and turns future unsigned "
                f"pushes into hard blocks rather than hygiene "
                f"warnings."
            ),
            evidence={
                "commits_walked": stats.commits_walked,
                "signed_count": stats.signed_count,
                "unsigned_count": stats.unsigned_count,
                "signing_rate": stats.signing_rate,
                "finding_shape": "summary",
            },
            severity=ws.severity,                 # type: ignore[arg-type]
            confidence=ws.confidence,
        )
    # Both fields None — should not happen but bail safely.
    raise ValueError(
        "workflow_signing finding has neither unsigned_commit "
        "nor stats populated"
    )


def _branch_protection_to_finding(
    bp: _branch_protection.BranchProtectionFinding,
) -> SupplyChainFinding:
    """Repo posture: branch protection missing or not requiring
    signed commits. Companion to workflow_unsigned_commit — that
    detector says what already happened; this says whether
    anything can prevent it from happening again."""
    if bp.finding_shape == "missing_protection":
        detail = (
            f"{bp.owner_repo}'s default branch ({bp.branch}) has no "
            f"branch-protection rule at all — any account with write "
            f"access can push directly to it, signed or not. This is "
            f"the Megalodon (May 2026) exposure: attackers with "
            f"compromised PATs forge-identity commits to default "
            f"branches lacking review enforcement. Configure branch "
            f"protection requiring PR review + signed commits on the "
            f"default branch."
        )
    else:
        detail = (
            f"{bp.owner_repo}'s default branch ({bp.branch}) has a "
            f"branch-protection rule but doesn't require signed "
            f"commits. Enabling 'Require signed commits' on the rule "
            f"raises the attacker's bar from credential compromise "
            f"(stolen PAT alone) to credential + signing-key "
            f"compromise — meaningfully harder for the Megalodon-"
            f"class d-PPE attacks."
        )
    return SupplyChainFinding(
        finding_id=(
            f"sca:supplychain:branch_protection_missing_signed_commits:"
            f"{bp.owner_repo}:{bp.branch}"
        ),
        kind="branch_protection_missing_signed_commits",
        dependency=bp.dependency,
        detail=detail,
        evidence={
            "owner_repo": bp.owner_repo,
            "branch": bp.branch,
            "finding_shape": bp.finding_shape,
        },
        severity=bp.severity,                  # type: ignore[arg-type]
        confidence=bp.confidence,
    )


def _sentinel_to_finding(
    sh: _sentinel.SentinelHit,
) -> SupplyChainFinding:
    return SupplyChainFinding(
        finding_id=(
            f"sca:supplychain:sentinel_match:"
            f"{sh.dependency.ecosystem}:{sh.dependency.name}:"
            f"{sh.dependency.version or '*'}:{sh.ref}"
        ),
        kind="sentinel_match",
        dependency=sh.dependency,
        detail=(
            f"'{sh.dependency.name}' matches known-malicious package: "
            f"{sh.incident}"
        ),
        evidence={
            "incident": sh.incident,
            "ref": sh.ref,
        },
        severity=sh.severity,                 # type: ignore[arg-type]
        confidence=sh.confidence,
    )


def _typosquat_to_finding(
    ts: _typosquat.TyposquatFinding,
) -> SupplyChainFinding:
    return SupplyChainFinding(
        finding_id=(
            f"sca:supplychain:typosquat_candidate:"
            f"{ts.dependency.ecosystem}:{ts.dependency.name}:"
            f"{ts.dependency.declared_in}"
        ),
        kind="typosquat_candidate",
        dependency=ts.dependency,
        detail=(
            f"name '{ts.dependency.name}' is distance {ts.distance} from "
            f"popular package '{ts.nearest_popular}' — verify the spelling"
        ),
        evidence={
            "nearest_popular": ts.nearest_popular,
            "distance": ts.distance,
        },
        severity=ts.severity,              # type: ignore[arg-type]
        confidence=ts.confidence,
    )


def _slopsquat_to_finding(
    ss: _slopsquat.SlopsquatFinding,
) -> SupplyChainFinding:
    """LLM-hallucinated-name candidate. Distinct from typosquat
    (typosquat is character-flip; slopsquat is shape-of-name).
    Reasons + score are surfaced in evidence so an operator
    triaging the finding sees WHICH heuristic fired and how
    strong the cumulative signal is."""
    suspected = ss.suspected_root
    detail = (
        f"name '{ss.dependency.name}' matches the slopsquat shape "
        f"(LLM-hallucinated package name pattern) — score "
        f"{ss.score:.2f}, reasons: {', '.join(ss.reasons)}"
    )
    if suspected is not None:
        detail += f"; suspected imitation of '{suspected}'"
    return SupplyChainFinding(
        finding_id=(
            f"sca:supplychain:slopsquat_suspect:"
            f"{ss.dependency.ecosystem}:{ss.dependency.name}:"
            f"{ss.dependency.declared_in}"
        ),
        kind="slopsquat_suspect",
        dependency=ss.dependency,
        detail=detail,
        evidence={
            "score": ss.score,
            "reasons": list(ss.reasons),
            "suspected_root": suspected,
        },
        severity=ss.severity,              # type: ignore[arg-type]
        confidence=ss.confidence,
    )


def _artefact_to_finding(
    art: _artefacts.ArtefactFinding,
) -> SupplyChainFinding:
    return SupplyChainFinding(
        finding_id=(
            f"sca:supplychain:{art.kind}:"
            f"{art.dependency.ecosystem}:{art.path}"
        ),
        kind=art.kind,                     # type: ignore[arg-type]
        dependency=art.dependency,
        detail=art.detail,
        evidence={"path": str(art.path)},
        severity=art.severity,             # type: ignore[arg-type]
        confidence=art.confidence,
    )


def _python_import_to_finding(
    it: _python_imports.ImportTimeFinding,
) -> SupplyChainFinding:
    return SupplyChainFinding(
        finding_id=(
            f"sca:supplychain:python_import_time_execution:"
            f"{it.path}:{it.line}"
        ),
        kind="python_import_time_execution",
        dependency=it.dependency,
        detail=it.detail,
        evidence={"path": str(it.path), "line": it.line},
        severity=it.severity,                  # type: ignore[arg-type]
        confidence=it.confidence,
    )


def _exfil_to_finding(
    ex: _exfil.ExfilFinding,
) -> SupplyChainFinding:
    return SupplyChainFinding(
        finding_id=(
            f"sca:supplychain:known_exfil_destination:"
            f"{ex.path}:{ex.line}:{ex.category}"
        ),
        kind="known_exfil_destination",
        dependency=ex.dependency,
        detail=ex.detail,
        evidence={"path": str(ex.path), "line": ex.line,
                   "category": ex.category},
        severity=ex.severity,                  # type: ignore[arg-type]
        confidence=ex.confidence,
    )


def _gha_drift_to_finding(
    gha: _gha_drift.GhaDriftFinding,
) -> SupplyChainFinding:
    return SupplyChainFinding(
        finding_id=(
            f"sca:supplychain:gha_action_ref_drift:"
            f"{gha.path}:{gha.line}:{gha.action}"
        ),
        kind="gha_action_ref_drift",
        dependency=gha.dependency,
        detail=gha.detail,
        evidence={
            "path": str(gha.path), "line": gha.line,
            "action": gha.action, "ref": gha.ref, "ref_kind": gha.ref_kind,
        },
        severity=gha.severity,                 # type: ignore[arg-type]
        confidence=gha.confidence,
    )


def _git_drift_to_finding(
    gd: _git_drift.GitDriftFinding,
) -> SupplyChainFinding:
    return SupplyChainFinding(
        finding_id=(
            f"sca:supplychain:git_tag_drift:"
            f"{gd.dependency.ecosystem}:{gd.dependency.name}:"
            f"{gd.dependency.declared_in}"
        ),
        kind="git_tag_drift",
        dependency=gd.dependency,
        detail=gd.detail,
        evidence={"ref": gd.ref, "ref_kind": gd.ref_kind},
        severity=gd.severity,                  # type: ignore[arg-type]
        confidence=gd.confidence,
    )


def _typosquat_domain_to_finding(
    td: _typosquat_domain.TyposquatDomainFinding,
) -> SupplyChainFinding:
    return SupplyChainFinding(
        finding_id=(
            f"sca:supplychain:typosquat_domain:"
            f"{td.path}:{td.line}:{td.suspect_host}"
        ),
        kind="typosquat_domain",
        dependency=td.dependency,
        detail=td.detail,
        evidence={
            "path": str(td.path),
            "line": td.line,
            "suspect_host": td.suspect_host,
            "nearest_popular": td.nearest_popular,
            "distance": td.distance,
        },
        severity=td.severity,                  # type: ignore[arg-type]
        confidence=td.confidence,
    )


def _registry_meta_to_finding(
    rm: _registry_metadata.RegistryMetaFinding,
) -> SupplyChainFinding:
    return SupplyChainFinding(
        finding_id=(
            f"sca:supplychain:{rm.kind}:"
            f"{rm.dependency.ecosystem}:{rm.dependency.name}:"
            f"{rm.dependency.declared_in}"
        ),
        kind=rm.kind,                          # type: ignore[arg-type]
        dependency=rm.dependency,
        detail=rm.detail,
        evidence=dict(rm.evidence),
        severity=rm.severity,                  # type: ignore[arg-type]
        confidence=rm.confidence,
    )


def _truncate(s: str, limit: int = 200) -> str:
    s = s.strip()
    return s if len(s) <= limit else s[: limit - 1] + "…"


__all__ = ["evaluate"]
