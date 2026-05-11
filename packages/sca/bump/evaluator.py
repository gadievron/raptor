"""Bump-time supply-chain evaluator.

Given a proposed ``(current_version, target_version)`` bump for one
dep, emits ``SupplyChainFinding`` rows for whichever bump-tier
detectors fire. The verdict ladder
(``review._compute_verdict``) consumes the result to gate the bump:

  * ``high``+ finding → Block
  * ``medium`` finding → escalate to Review
  * Two or more ``medium``+ findings → Block (compound red flags)

Detector roster (Phase 1.b ships only the first; the others gate
on per-ecosystem metadata extraction work):

  * ``recent_publish``      — target version published <N days ago
                              (rapid-release attack class)
  * ``maintainer_change``   — maintainer set differs between current
                              and target's publish windows
                              (account-takeover / handover class)
  * ``install_hook_delta``  — target adds install hooks the current
                              version didn't have (payload injection
                              class)

Per-ecosystem metadata access varies:

  * **npm**: per-version maintainers + dependencies + scripts via
    ``versions[v].maintainers / dependencies / scripts``. Best
    surface for all three detectors.
  * **PyPI**: per-version upload timestamps via
    ``releases[v][n].upload_time_iso_8601``; package-level
    maintainers only. Supports ``recent_publish`` precisely;
    ``maintainer_change`` is best-effort proxy at package level.
  * Other ecosystems: minimal per-version surface; for now the
    evaluator returns an empty list with a debug log."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

from ..models import Confidence, Dependency, PinStyle, SupplyChainFinding

logger = logging.getLogger(__name__)

# Default rapid-release window. A target version published less
# than this many days ago surfaces as ``recent_publish`` at medium
# severity. 30 days matches the operationally accepted window for
# "the package's been in the wild long enough that obvious bad
# behaviour would have been reported".
_RAPID_RELEASE_DAYS = 30


def evaluate_bump_supply_chain(
    *,
    ecosystem: str,
    name: str,
    current_version: str,
    target_version: str,
    pypi_client=None,
    npm_client=None,
    now: Optional[datetime] = None,
    rapid_release_days: int = _RAPID_RELEASE_DAYS,
) -> List[SupplyChainFinding]:
    """Return the bump-tier supply-chain findings for a proposed bump.

    Callers wire the per-ecosystem registry clients in (already
    cached / offline-aware / egress-allowlisted). Missing clients
    or unsupported ecosystems return an empty list — the bumper
    treats that as "no bump-tier signals available, fall through
    to vuln-only verdict".
    """
    now = now or datetime.now(timezone.utc)
    findings: List[SupplyChainFinding] = []

    target_publish = _target_publish_date(
        ecosystem=ecosystem, name=name, version=target_version,
        pypi_client=pypi_client, npm_client=npm_client,
    )
    if target_publish is not None:
        age = now - target_publish
        if age < timedelta(days=rapid_release_days):
            findings.append(_recent_publish_finding(
                ecosystem=ecosystem, name=name,
                target_version=target_version,
                target_publish=target_publish,
                age=age, threshold=rapid_release_days,
            ))
    else:
        logger.debug(
            "sca.bump: no publish date available for %s:%s@%s; "
            "skipping recent_publish detector",
            ecosystem, name, target_version,
        )

    # maintainer_change between current and target. Per-ecosystem
    # support:
    #
    #   * npm: ``versions[v].maintainers`` is per-version, so the
    #     comparison is precise.
    #   * PyPI: no per-version maintainer history in the public
    #     API (``info.maintainer`` is package-level current
    #     scalar). Best-effort would require an operator-side
    #     historical cache; deferred.
    #   * Other ecosystems: not yet wired.
    change = _maintainer_change(
        ecosystem=ecosystem, name=name,
        current_version=current_version,
        target_version=target_version,
        npm_client=npm_client,
    )
    if change is not None:
        findings.append(change)

    # install_hook_delta — target adds install-time scripts that
    # the current version didn't have. npm-only initially; PyPI
    # would require downloading the sdist and parsing setup.py
    # (deferred).
    hook_delta = _install_hook_delta(
        ecosystem=ecosystem, name=name,
        current_version=current_version,
        target_version=target_version,
        npm_client=npm_client,
    )
    if hook_delta is not None:
        findings.append(hook_delta)

    return findings


# ---------------------------------------------------------------------------
# Per-ecosystem publish-date extraction
# ---------------------------------------------------------------------------

def _target_publish_date(
    *,
    ecosystem: str,
    name: str,
    version: str,
    pypi_client,
    npm_client,
) -> Optional[datetime]:
    """Return the publish datetime for ``ecosystem:name@version``
    via the appropriate registry client, or ``None`` if the
    registry doesn't expose it or the lookup fails.
    """
    if ecosystem == "PyPI" and pypi_client is not None:
        return _pypi_version_publish(name, version, pypi_client)
    if ecosystem == "npm" and npm_client is not None:
        return _npm_version_publish(name, version, npm_client)
    # Other ecosystems land here. Per-version publish-date lookup
    # is doable for Cargo (crates.io API) / RubyGems / NuGet /
    # Maven Central (rest/v2) — future detector commits add them.
    return None


def _pypi_version_publish(
    name: str, version: str, client,
) -> Optional[datetime]:
    """Earliest upload_time across the version's distribution files."""
    meta = client.get_metadata(name)
    if not isinstance(meta, dict):
        return None
    releases = meta.get("releases") or {}
    files = releases.get(version)
    if not files:
        return None
    earliest: Optional[datetime] = None
    for entry in files:
        if not isinstance(entry, dict):
            continue
        ts = entry.get("upload_time_iso_8601") or entry.get("upload_time")
        if not isinstance(ts, str):
            continue
        parsed = _parse_iso(ts)
        if parsed is None:
            continue
        if earliest is None or parsed < earliest:
            earliest = parsed
    return earliest


def _npm_version_publish(
    name: str, version: str, client,
) -> Optional[datetime]:
    """``time[version]`` field of the npm packument."""
    meta = client.get_metadata(name)
    if not isinstance(meta, dict):
        return None
    times = meta.get("time") or {}
    ts = times.get(version)
    if not isinstance(ts, str):
        return None
    return _parse_iso(ts)


def _parse_iso(ts: str) -> Optional[datetime]:
    """ISO-8601 parser that tolerates trailing ``Z`` and missing
    fractional seconds (covers both PyPI and npm shapes)."""
    cleaned = ts.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(cleaned)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Per-ecosystem maintainer-change extraction
# ---------------------------------------------------------------------------

def _maintainer_change(
    *,
    ecosystem: str,
    name: str,
    current_version: str,
    target_version: str,
    npm_client,
) -> Optional[SupplyChainFinding]:
    """Compare maintainer sets at current and target versions.

    Returns a single ``maintainer_change`` finding when the sets
    differ (added maintainer = legitimate handover OR malicious
    takeover — operator decides). Returns ``None`` when the data
    is unavailable for the ecosystem, the metadata fetch failed,
    or the sets are identical.
    """
    if ecosystem != "npm" or npm_client is None:
        return None
    meta = npm_client.get_metadata(name)
    if not isinstance(meta, dict):
        return None
    versions = meta.get("versions") or {}
    cur_entry = versions.get(current_version)
    tgt_entry = versions.get(target_version)
    if not isinstance(cur_entry, dict) or not isinstance(tgt_entry, dict):
        return None

    cur_names = _maintainer_name_set(cur_entry.get("maintainers"))
    tgt_names = _maintainer_name_set(tgt_entry.get("maintainers"))
    if not cur_names or not tgt_names:
        # Either version has no recorded maintainers — can't
        # meaningfully compare. Silent skip.
        return None
    added = sorted(tgt_names - cur_names)
    removed = sorted(cur_names - tgt_names)
    if not added and not removed:
        return None

    return _maintainer_change_finding(
        ecosystem=ecosystem, name=name,
        current_version=current_version,
        target_version=target_version,
        added=added, removed=removed,
        current_maintainers=cur_names,
        target_maintainers=tgt_names,
    )


def _maintainer_name_set(raw) -> set:
    """Normalised name set from an npm packument's ``maintainers``
    list. Each entry is ``{"name": "...", "email": "..."}``; we
    key on the lowercased name (matches the scan-time
    ``_maintainer_change_check`` convention)."""
    if not isinstance(raw, list):
        return set()
    out: set = set()
    for m in raw:
        if isinstance(m, dict):
            n = m.get("name")
            if isinstance(n, str) and n.strip():
                out.add(n.strip().lower())
        elif isinstance(m, str):
            # Some npm tooling shorthand emits "name <email>" strings.
            out.add(m.split("<")[0].strip().lower())
    return out


# ---------------------------------------------------------------------------
# Per-ecosystem install-hook delta extraction
# ---------------------------------------------------------------------------

#: npm script hooks that run during ``npm install`` (including
#: transitive installs). These are the ones that matter for
#: supply-chain — when a user pulls in the package, these execute.
#: ``prepublish*`` / ``prepack`` / ``postpublish`` run on the
#: PUBLISHER's machine, not the installer's, so they aren't a
#: supply-chain vector against downstream consumers.
_INSTALL_TIME_HOOKS = ("preinstall", "install", "postinstall")


def _install_hook_delta(
    *,
    ecosystem: str,
    name: str,
    current_version: str,
    target_version: str,
    npm_client,
) -> Optional[SupplyChainFinding]:
    """Compare install-time scripts between current and target.

    Returns a single ``install_hook_suspicious`` finding when the
    target adds preinstall / install / postinstall hooks the
    current version didn't have. The shape detected is
    "the bump introduces install-time code execution that the
    current pin doesn't have" — the event-stream / colors.js
    payload-injection class.

    Returns ``None`` when the ecosystem isn't npm, the data is
    unavailable, or no new install-time hook was added.
    """
    if ecosystem != "npm" or npm_client is None:
        return None
    meta = npm_client.get_metadata(name)
    if not isinstance(meta, dict):
        return None
    versions = meta.get("versions") or {}
    cur_entry = versions.get(current_version)
    tgt_entry = versions.get(target_version)
    if not isinstance(cur_entry, dict) or not isinstance(tgt_entry, dict):
        return None

    cur_hooks = _install_hook_set(cur_entry.get("scripts"))
    tgt_hooks = _install_hook_set(tgt_entry.get("scripts"))
    added = sorted(tgt_hooks - cur_hooks)
    if not added:
        return None

    return _install_hook_finding(
        ecosystem=ecosystem, name=name,
        current_version=current_version,
        target_version=target_version,
        added_hooks=added,
        target_scripts=tgt_entry.get("scripts") or {},
    )


def _install_hook_set(scripts) -> set:
    """Return the subset of ``_INSTALL_TIME_HOOKS`` that have a
    non-empty entry in the scripts map. An empty-string script
    counts as "no hook" — npm treats those as no-ops."""
    if not isinstance(scripts, dict):
        return set()
    out: set = set()
    for hook in _INSTALL_TIME_HOOKS:
        body = scripts.get(hook)
        if isinstance(body, str) and body.strip():
            out.add(hook)
    return out


def _install_hook_finding(
    *,
    ecosystem: str,
    name: str,
    current_version: str,
    target_version: str,
    added_hooks: list,
    target_scripts: dict,
) -> SupplyChainFinding:
    """``install_hook_suspicious`` finding for a bump that
    introduces install-time scripts.

    Severity ``medium``: install hooks aren't malicious by
    default (legitimate packages use them for native builds),
    but adding them in a bump from an existing pin is a Review-
    tier signal. The verdict ladder compounds this to Block when
    paired with recent_publish or maintainer_change.

    Evidence carries the actual hook content (truncated) so PR
    reviewers can see what the new hook does without having to
    open the registry tab. Sanitised to escape ANSI / control
    chars before render.
    """
    placeholder_dep = Dependency(
        ecosystem=ecosystem,
        name=name,
        version=target_version,
        declared_in=Path("/<bump>"),
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl=f"pkg:{ecosystem.lower()}/{name}@{target_version}",
        parser_confidence=Confidence(
            "high",
            reason="bump-evaluator synthetic dep",
        ),
    )
    # Carry the hook bodies in evidence (truncated) so reviewers
    # see what the new script runs. Truncation cap kept tight
    # because PR-comment renderers will surface this verbatim.
    hook_bodies = {
        h: (target_scripts.get(h) or "")[:200]
        for h in added_hooks
    }
    detail = (
        f"target version {target_version} introduces install-time "
        f"hook(s) not present in {current_version}: "
        f"{', '.join(added_hooks)}"
    )
    return SupplyChainFinding(
        finding_id=(
            f"sca:bump:install_hook:{ecosystem}:{name}"
            f"@{current_version}->{target_version}"
        ),
        kind="install_hook_suspicious",
        dependency=placeholder_dep,
        detail=detail,
        evidence={
            "current_version": current_version,
            "target_version": target_version,
            "added_hooks": added_hooks,
            "hook_bodies": hook_bodies,
        },
        severity="medium",
        confidence=Confidence(
            "high",
            reason="per-version scripts from npm packument",
        ),
    )


# ---------------------------------------------------------------------------
# Finding constructors
# ---------------------------------------------------------------------------

def _recent_publish_finding(
    *,
    ecosystem: str,
    name: str,
    target_version: str,
    target_publish: datetime,
    age: timedelta,
    threshold: int,
) -> SupplyChainFinding:
    """Construct a ``recent_publish`` SupplyChainFinding for the target.

    Severity ``medium``: the rapid-release window is a Review-tier
    signal alone (operators may legitimately track unstable
    releases). It compounds to Block via the verdict ladder when
    paired with another medium+ bump-tier finding.

    The ``Dependency`` row carries the proposed target's
    coordinates so PR-comment rendering shows the right
    ``eco:name@version`` in the verdict table.
    """
    placeholder_dep = Dependency(
        ecosystem=ecosystem,
        name=name,
        version=target_version,
        declared_in=Path("/<bump>"),
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl=f"pkg:{ecosystem.lower()}/{name}@{target_version}",
        parser_confidence=Confidence(
            "high",
            reason="bump-evaluator synthetic dep",
        ),
    )
    days = max(0, age.days)
    return SupplyChainFinding(
        finding_id=(
            f"sca:bump:recent_publish:{ecosystem}:{name}@{target_version}"
        ),
        kind="recent_publish",
        dependency=placeholder_dep,
        detail=(
            f"target version {target_version} published "
            f"{target_publish.date().isoformat()} "
            f"({days} day(s) ago; rapid-release threshold "
            f"{threshold})"
        ),
        evidence={
            "target_version": target_version,
            "target_publish": target_publish.isoformat(),
            "age_days": days,
            "threshold_days": threshold,
        },
        severity="medium",
        confidence=Confidence(
            "high",
            reason="publish timestamp from registry",
        ),
    )


def _maintainer_change_finding(
    *,
    ecosystem: str,
    name: str,
    current_version: str,
    target_version: str,
    added,
    removed,
    current_maintainers: set,
    target_maintainers: set,
) -> SupplyChainFinding:
    """Construct a ``maintainer_change`` finding for a bump where
    the maintainer set at the target's publish time differs from
    the set at the current version's publish time.

    Severity ``medium``: legitimate handovers happen all the time
    (project transfers, maintainer retirement). Compound red flag
    when paired with recent_publish or install_hook_delta — the
    verdict ladder's "two mediums = Block" path catches the
    account-takeover shape.
    """
    placeholder_dep = Dependency(
        ecosystem=ecosystem,
        name=name,
        version=target_version,
        declared_in=Path("/<bump>"),
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl=f"pkg:{ecosystem.lower()}/{name}@{target_version}",
        parser_confidence=Confidence(
            "high",
            reason="bump-evaluator synthetic dep",
        ),
    )
    bits = []
    if added:
        bits.append(f"added: {', '.join(added)}")
    if removed:
        bits.append(f"removed: {', '.join(removed)}")
    detail = (
        f"maintainer set differs between {current_version} and "
        f"{target_version} — " + "; ".join(bits)
    )
    return SupplyChainFinding(
        finding_id=(
            f"sca:bump:maintainer_change:{ecosystem}:{name}"
            f"@{current_version}->{target_version}"
        ),
        kind="maintainer_change",
        dependency=placeholder_dep,
        detail=detail,
        evidence={
            "current_version": current_version,
            "target_version": target_version,
            "added": added,
            "removed": removed,
            "current_maintainers": sorted(current_maintainers),
            "target_maintainers": sorted(target_maintainers),
        },
        severity="medium",
        confidence=Confidence(
            "high",
            reason="per-version maintainers from npm packument",
        ),
    )
