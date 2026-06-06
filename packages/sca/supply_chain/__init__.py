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
    Confidence,
    Dependency,
    Manifest,
    SupplyChainFinding,
)
from . import artefacts as _artefacts
from . import binary_in_package as _binary_in_package
from . import exfil_destinations as _exfil
from . import gha_drift as _gha_drift
from . import gha_secret_flow as _gha_secret_flow
from . import gha_freshness as _gha_freshness
from . import gha_sunset as _gha_sunset
from . import git_drift as _git_drift
from . import cargo_build_scripts as _cargo_build
from . import commit_provenance as _commit_provenance
from . import composer_lifecycle_hooks as _composer_lifecycle_hooks
from . import install_hooks as _install_hooks
from . import orphan_commit_dep as _orphan_commit_dep
from . import python_imports as _python_imports
from . import python_lifecycle_hooks as _python_lifecycle_hooks
from . import rubygems_lifecycle_hooks as _rubygems_lifecycle_hooks
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

    for plh in _python_lifecycle_hooks.scan_manifests(
        manifests_list, deps_list,
    ):
        out.append(_python_lifecycle_to_finding(plh))

    for clh in _composer_lifecycle_hooks.scan_manifests(
        manifests_list, deps_list,
    ):
        out.append(_composer_lifecycle_to_finding(clh))

    for rlh in _rubygems_lifecycle_hooks.scan_target(
        target, manifests_list, deps_list,
    ):
        out.append(_rubygems_lifecycle_to_finding(rlh))

    for cpf in _commit_provenance.scan_target(
        target, manifests_list, deps_list,
    ):
        out.append(_commit_provenance_to_finding(cpf))

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

    for bip in _binary_in_package.scan_target(
        target, manifests_list, deps_list,
    ):
        out.append(_binary_in_package_to_finding(bip))

    for it in _python_imports.scan_target(
        target, manifests_list, cache=cache,
    ):
        out.append(_python_import_to_finding(it))

    for ex in _exfil.scan_target(target, manifests_list):
        out.append(_exfil_to_finding(ex))

    for gha in _gha_drift.scan_target(target, manifests_list):
        out.append(_gha_drift_to_finding(gha))

    for sf in _gha_secret_flow.scan_target(
        target, manifests_list, deps_list,
    ):
        out.append(_gha_secret_flow_to_finding(sf))

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

    # Generalised composite scoring across distinct detector families
    # (see ``composite.py`` for the family map + promotion rules).
    # Runs AFTER the slopsquat-specific escalation above so any
    # per-stack severity changes are already in place before the
    # family-level chokepoint sees them.
    from . import composite as _composite  # local to avoid cycles
    out = _composite.apply(out)

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
            # In-tree path references the hook body resolves to —
            # populated by ``_intree_resolve``.  Each entry includes
            # the path relative to the project root + the magic-byte
            # classification.  Composite scoring (Phase 1) pairs the
            # ``intree_has_binary`` signal with ``binary_in_package``
            # findings on the same dep to escalate to critical.
            "intree_targets": [
                {"path": str(t.path), "kind": t.kind}
                for t in hit.hit.intree_targets
            ],
            "intree_has_binary": any(
                t.is_executable_payload for t in hit.hit.intree_targets
            ),
            # Phase 5 conjunction flags — composite scoring uses these
            # to detect the worm/credential-stealer shape (HOOK family
            # base plus the C+G conjunction within a single hook).
            "reads_credentials": hit.hit.reads_credentials,
            "has_publish_action": hit.hit.has_publish_action,
        },
        severity=hit.severity,             # type: ignore[arg-type]
        confidence=hit.confidence,
    )


def _python_lifecycle_to_finding(
    plh: _python_lifecycle_hooks.PythonLifecycleFinding,
) -> SupplyChainFinding:
    """``setup.py`` execution is the Python equivalent of an install
    hook — emit under the ``install_hook_suspicious`` kind so
    composite scoring's HOOK family picks it up."""
    why = ", ".join(plh.hit.reasons) if plh.hit.reasons else "hook present"
    return SupplyChainFinding(
        finding_id=(
            f"sca:supplychain:install_hook_suspicious:"
            f"{plh.dependency.ecosystem}:{plh.dependency.name}:"
            f"setup.py:{plh.dependency.declared_in}"
        ),
        kind="install_hook_suspicious",
        dependency=plh.dependency,
        detail=(
            f"`setup.py` executes at install time; "
            f"reason: {why}; body: {_truncate(plh.hit.script_body)}"
        ),
        evidence={
            "script_key": plh.hit.script_key,
            "script_body": _truncate(plh.hit.script_body),
            "reasons": list(plh.hit.reasons),
            "reads_credentials": plh.hit.reads_credentials,
            "has_publish_action": plh.hit.has_publish_action,
            "ecosystem": "PyPI",
        },
        severity=plh.severity,                # type: ignore[arg-type]
        confidence=plh.confidence,
    )


def _composer_lifecycle_to_finding(
    clh: _composer_lifecycle_hooks.ComposerLifecycleFinding,
) -> SupplyChainFinding:
    why = ", ".join(clh.hit.reasons) if clh.hit.reasons else "hook present"
    return SupplyChainFinding(
        finding_id=(
            f"sca:supplychain:install_hook_suspicious:"
            f"{clh.dependency.ecosystem}:{clh.dependency.name}:"
            f"{clh.hit.script_key}:{clh.dependency.declared_in}"
        ),
        kind="install_hook_suspicious",
        dependency=clh.dependency,
        detail=(
            f"`scripts.{clh.hit.script_key}` runs at composer "
            f"install time; reason: {why}; body: "
            f"{_truncate(clh.hit.script_body)}"
        ),
        evidence={
            "script_key": clh.hit.script_key,
            "script_body": _truncate(clh.hit.script_body),
            "reasons": list(clh.hit.reasons),
            "reads_credentials": clh.hit.reads_credentials,
            "has_publish_action": clh.hit.has_publish_action,
            "ecosystem": "Composer",
        },
        severity=clh.severity,                # type: ignore[arg-type]
        confidence=clh.confidence,
    )


def _commit_provenance_to_finding(
    cpf: _commit_provenance.CommitProvenanceFinding,
) -> SupplyChainFinding:
    h = cpf.hit
    short_sha = h.commit_sha[:12]
    return SupplyChainFinding(
        finding_id=(
            f"sca:supplychain:commit_provenance_drift:{h.commit_sha}"
        ),
        kind="commit_provenance_drift",
        dependency=cpf.dependency,
        detail=(
            f"commit {short_sha} touching dependency manifest(s) "
            f"claims bot/automation identity "
            f"({h.author_name} <{h.author_email}>), is unsigned, "
            f"and has author/committer date skew of {h.skew_days} days "
            f"— forgery-shape conjunction worth review"
        ),
        evidence={
            "commit_sha": h.commit_sha,
            "sig_status": h.sig_status,
            "author_name": h.author_name,
            "author_email": h.author_email,
            "author_date": h.author_date_iso,
            "committer_date": h.committer_date_iso,
            "skew_days": h.skew_days,
            "subject": _truncate(h.subject, limit=200),
            "paths_touched": list(h.paths_touched),
        },
        severity=cpf.severity,                # type: ignore[arg-type]
        confidence=cpf.confidence,
    )


def _rubygems_lifecycle_to_finding(
    rlh: _rubygems_lifecycle_hooks.RubyGemsLifecycleFinding,
) -> SupplyChainFinding:
    why = ", ".join(rlh.hit.reasons) if rlh.hit.reasons else "hook present"
    return SupplyChainFinding(
        finding_id=(
            f"sca:supplychain:install_hook_suspicious:"
            f"{rlh.dependency.ecosystem}:{rlh.dependency.name}:"
            f"{rlh.hit.script_key}"
        ),
        kind="install_hook_suspicious",
        dependency=rlh.dependency,
        detail=(
            f"`{rlh.hit.script_key}` runs at gem install time "
            f"(native extension build); reason: {why}; body: "
            f"{_truncate(rlh.hit.script_body)}"
        ),
        evidence={
            "script_key": rlh.hit.script_key,
            "script_body": _truncate(rlh.hit.script_body),
            "reasons": list(rlh.hit.reasons),
            "reads_credentials": rlh.hit.reads_credentials,
            "has_publish_action": rlh.hit.has_publish_action,
            "ecosystem": "RubyGems",
        },
        severity=rlh.severity,                # type: ignore[arg-type]
        confidence=rlh.confidence,
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


def _gha_secret_flow_to_finding(
    sf: _gha_secret_flow.SecretFlowHit,
) -> SupplyChainFinding:
    return SupplyChainFinding(
        finding_id=(
            f"sca:supplychain:gha_secret_flow:"
            f"{sf.workflow_path.name}:{sf.job_id}:"
            f"{sf.step_index}:{sf.sink_kind}"
        ),
        kind="gha_secret_flow",
        dependency=sf.dependency,
        detail=sf.detail,
        evidence={
            "workflow_path": str(sf.workflow_path),
            "job_id": sf.job_id,
            "step_index": sf.step_index,
            "sink_kind": sf.sink_kind,
            "secret_names": list(sf.secret_names),
        },
        severity=sf.severity,                       # type: ignore[arg-type]
        confidence=Confidence(
            # ``tojson_secrets`` is the near-zero-FP anchor → high.
            # ``computed_access`` and ``run_block`` are
            # interpretation-sensitive → medium.  Others vary.
            "high" if sf.sink_kind == "tojson_secrets" else "medium",
            reason="static workflow-level taint shape",
        ),
    )


def _binary_in_package_to_finding(
    bip: _binary_in_package.BinaryHit,
) -> SupplyChainFinding:
    """Convert ``BinaryHit`` to ``SupplyChainFinding``.

    Severity defaults to ``medium`` standalone — the composite
    chokepoint promotes it to ``critical`` when ``install_hooks``
    fires on the same dep with ``intree_has_binary`` evidence
    (the Iron Worm A∧B archetype).

    Phase 8 standalone promotions:
      * A packed binary (UPX, Themida, VMProtect, ...) → high
        regardless of other signals — packers are rare on
        legitimate native modules.
      * A populated high-severity capability bucket
        (``exec``, ``network``, ``runtime_privilege``,
        ``kernel_trace``) → high — these are the rootkit /
        sandbox-escape / RCE / exfil vocabulary.
    """
    forensic = dict(bip.forensic_evidence)
    severity = "medium"
    promotion_reasons: List[str] = []
    if "packer" in forensic:
        severity = "high"
        promotion_reasons.append(
            f"binary is packed with {forensic['packer']}"
        )
    if forensic.get("high_severity_buckets"):
        severity = "high"
        promotion_reasons.append(
            "imports include high-severity capability bucket(s): "
            + ", ".join(forensic["high_severity_buckets"])
        )
    evidence = {
        "path": bip.relpath,
        "family": bip.family,
    }
    evidence.update(forensic)
    if promotion_reasons:
        evidence["forensic_promotion_reasons"] = promotion_reasons
    return SupplyChainFinding(
        finding_id=(
            f"sca:supplychain:binary_in_package:"
            f"{bip.dependency.ecosystem}:{bip.dependency.name}:"
            f"{bip.relpath}"
        ),
        kind="binary_in_package",
        dependency=bip.dependency,
        detail=(
            f"{bip.family.upper()} binary in published package tree at "
            f"`{bip.relpath}`; not in any opt-in legitimate location"
            + (f" — {'; '.join(promotion_reasons)}"
               if promotion_reasons else "")
        ),
        evidence=evidence,
        severity=severity,                  # type: ignore[arg-type]
        confidence=Confidence(
            "high",
            reason="magic-byte classified; outside opt-in allowlist",
        ),
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
