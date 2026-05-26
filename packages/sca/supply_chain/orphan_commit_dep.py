"""npm ``optionalDependencies`` git-ref scanner — the Mini
Shai-Hulud secondary-delivery signal.

Background
~~~~~~~~~~

The May 2026 Mini Shai-Hulud incident weaponised 314 npm packages
under the compromised ``atool`` maintainer account. The PRIMARY
delivery was a ``preinstall`` hook (caught by ``install_hooks``).
The SECONDARY delivery — used as redundant payload reach in case
the preinstall hook failed — was an ``optionalDependencies`` entry
pointing to an orphan git commit in an UNRELATED repository::

    "optionalDependencies": {
        "@antv/setup": "github:antvis/G2#1916faa365f2788b6e19..."
    }

npm's resolver fetches the referenced commit via the GitHub API
and executes its package.json scripts. Three properties make this
strictly more dangerous than a normal git-ref dep:

1. **Orphan commits** are unreachable from any branch — they're
   invisible in the GitHub web UI but fetchable by SHA via the
   API. A casual reviewer scanning ``antvis/G2`` won't see the
   malicious commit anywhere.
2. **``optionalDependencies``** silently fails — npm reports the
   install as successful even when the optional dep errors,
   leaving the user with no signal that something happened.
3. **Cross-org references** — ``size-sensor`` (an atool package)
   referencing ``antvis/G2`` (a JetBrains visualization library)
   has no legitimate reason to exist. Real packages that depend on
   git refs almost always reference the same author's repo (a
   fork, a not-yet-published rewrite, etc.).

What this detector does
~~~~~~~~~~~~~~~~~~~~~~~

Pure heuristic — no network call. We parse the project's
``package.json`` and flag any git/github ref appearing in
``dependencies``, ``optionalDependencies``, ``devDependencies``,
or ``peerDependencies``. Severity escalates based on where the
ref lives + what it pins to:

- **high** — ``optionalDependencies`` carrying a git/github ref.
  The Shai-Hulud delivery shape. Legitimate uses are vanishingly
  rare; treat as actively-suspicious.
- **medium** — git/github ref in any other dep field. Common in
  internal monorepos / pre-publish prototypes; reduce severity
  but surface the row for SBOM / triage.

We DON'T attempt to verify SHA reachability via the GitHub API —
that's a future detector (network-bound, rate-limit-aware). The
heuristic-only check catches the Shai-Hulud pattern on shape
alone, which is sufficient for the CI-gate use case.

Limitations / future work
~~~~~~~~~~~~~~~~~~~~~~~~~

- Doesn't walk transitive deps in ``node_modules`` — we only see
  the project's own package.json. Transitive coverage is the same
  follow-up tracked across the supply_chain package.
- Doesn't query GitHub to confirm orphan-ness. A future tier would
  call ``GET /repos/{owner}/{repo}/compare/{default}...{sha}`` to
  detect SHAs unreachable from any branch (the "true orphan"
  signal). Today's heuristic surfaces ALL git-ref deps; the
  orphan-only filter would tighten precision at the cost of one
  network hop per ref.
- ``peerDependencies`` rarely carries git refs in practice but
  we scan it for symmetry — never want to be wrong-shaped.
"""

from __future__ import annotations

import json as _json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional

from ..models import Confidence, Dependency, Manifest, PinStyle

logger = logging.getLogger(__name__)


# Regex matches the shape ``github:user/repo#ref`` and the longer
# ``git+https://...github.com/user/repo.git#ref`` (and ssh / plain
# https variants). We don't enforce that the ref is a SHA — tag
# and branch refs are caught too, with a downstream severity
# adjustment.
_GITHUB_SHORT_RE = re.compile(
    r"^github:(?P<owner>[\w.\-]+)/(?P<repo>[\w.\-]+)"
    r"(?:#(?P<ref>[\w./\-]+))?$"
)
_GIT_URL_RE = re.compile(
    r"^git(?:\+(?:https?|ssh))?://"
    r"(?:[^@/]+@)?[\w.\-]+(?:/|:)"
    r"(?P<owner>[\w.\-]+)/(?P<repo>[\w.\-]+?)(?:\.git)?"
    r"(?:#(?P<ref>[\w./\-]+))?$"
)
# Plain ``user/repo`` shorthand (no scheme prefix) is npm-specific
# — interpreted as ``github:user/repo``. Bounded so we don't
# misread regular package names like ``@scope/name`` (which has a
# leading ``@``) or version specs.
_BARE_SHORTHAND_RE = re.compile(
    r"^(?P<owner>[\w][\w\-]+)/(?P<repo>[\w.\-]+)"
    r"(?:#(?P<ref>[\w./\-]+))?$"
)
# 40-char hex SHA — the most-suspicious ref shape (Shai-Hulud
# pinned to specific orphan SHAs). Tag/branch refs get a lower
# severity bump in `_classify_ref`.
_SHA40_RE = re.compile(r"^[a-f0-9]{40}$")

# Dep-field keys to scan, in priority order. The first three are
# install-time evaluated by npm; ``peerDependencies`` is hints-only
# at install time but the field is still a potential delivery
# channel if a downstream auto-installs peers.
_DEP_FIELDS = (
    "optionalDependencies",
    "dependencies",
    "devDependencies",
    "peerDependencies",
)


@dataclass(frozen=True)
class GitRefHit:
    """One git-ref dep entry."""

    field: str                   # which dep-key it appeared in
    dep_name: str                # the dep alias / name
    ref_spec: str                # raw value from package.json
    owner: str                   # parsed git host owner
    repo: str                    # parsed git host repo
    ref: Optional[str]           # SHA / tag / branch / None
    ref_kind: str                # "sha40" / "tag_or_branch" / "none"


@dataclass(frozen=True)
class OrphanCommitFinding:
    """Internal carrier — converted to ``SupplyChainFinding`` by
    the orchestrator. Same shape as ``InstallHookFinding`` /
    ``GitDriftFinding`` for orchestrator-side symmetry."""

    dependency: Dependency
    hit: GitRefHit
    severity: str
    confidence: Confidence


def scan_manifests(
    manifests: Iterable[Manifest],
    deps: Iterable[Dependency],
) -> List[OrphanCommitFinding]:
    """Walk every npm ``package.json`` for git/github refs in
    dependency fields. Returns one finding per (manifest × dep).
    """
    out: List[OrphanCommitFinding] = []
    deps_list = list(deps)
    for m in manifests:
        if m.path.name != "package.json" or m.is_lockfile:
            continue
        host = _host_dep(deps_list, m) or _placeholder_for_manifest(m)
        out.extend(_scan_one(m.path, host))
    return out


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _scan_one(path: Path, host: Dependency) -> List[OrphanCommitFinding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.debug(
            "sca.supply_chain.orphan_commit_dep: %s read failed: %s",
            path, e,
        )
        return []
    try:
        data = _json.loads(text)
    except _json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    out: List[OrphanCommitFinding] = []
    for field in _DEP_FIELDS:
        block = data.get(field)
        if not isinstance(block, dict):
            continue
        for dep_name, spec in block.items():
            if not isinstance(spec, str):
                continue
            hit = _classify_spec(field, dep_name, spec)
            if hit is None:
                continue
            severity, confidence = _severity_for(hit)
            out.append(OrphanCommitFinding(
                dependency=host, hit=hit,
                severity=severity, confidence=confidence,
            ))
    return out


def _classify_spec(
    field: str, dep_name: str, spec: str,
) -> Optional[GitRefHit]:
    """Recognise ``spec`` as a git/github ref. Returns ``None`` for
    plain semver / file: / npm: / workspace: specs."""
    spec_stripped = spec.strip()
    if not spec_stripped:
        return None
    # ``github:`` short form.
    m = _GITHUB_SHORT_RE.match(spec_stripped)
    if m is None:
        # ``git[+scheme]://`` URLs.
        m = _GIT_URL_RE.match(spec_stripped)
    if m is None and "/" in spec_stripped and not spec_stripped.startswith((
        "@", "npm:", "file:", "workspace:", "link:",
        "http:", "https:",
    )):
        # ``user/repo[#ref]`` shorthand. The leading-char guards
        # keep us from matching scoped-package specs (``@scope/...``)
        # or other non-git scheme specs.
        m2 = _BARE_SHORTHAND_RE.match(spec_stripped)
        # Require either a ``#ref`` segment OR that the spec
        # doesn't look like a normal package version — bare
        # ``a/b`` without ref is usually a typo or workspace alias
        # we shouldn't claim is git. Require ``#`` to commit to
        # this branch.
        if m2 is not None and "#" in spec_stripped:
            m = m2
    if m is None:
        return None
    owner = m.group("owner")
    repo = m.group("repo")
    ref = m.groupdict().get("ref")
    ref_kind = _classify_ref(ref)
    return GitRefHit(
        field=field, dep_name=dep_name, ref_spec=spec_stripped,
        owner=owner, repo=repo, ref=ref, ref_kind=ref_kind,
    )


def _classify_ref(ref: Optional[str]) -> str:
    if ref is None:
        return "none"
    if _SHA40_RE.match(ref):
        return "sha40"
    return "tag_or_branch"


def _severity_for(hit: GitRefHit) -> tuple[str, Confidence]:
    """Severity ladder:

    * ``high`` — ``optionalDependencies`` carrying any git-ref.
      Shai-Hulud delivery shape. Legitimate use is vanishingly
      rare; CI-gate-worthy.
    * ``medium`` — git-ref in ``dependencies`` / ``devDependencies``
      / ``peerDependencies`` pinned to a 40-char SHA. Less
      suspicious than optional-deps but worth surfacing.
    * ``low`` — git-ref in non-optional fields pinned to a tag /
      branch / unspecified. Common in internal monorepos +
      pre-publish prototypes; SBOM-style awareness.
    """
    if hit.field == "optionalDependencies":
        return (
            "high",
            Confidence(
                "high",
                reason=(
                    "git-ref dep in optionalDependencies — matches "
                    "Mini Shai-Hulud secondary-delivery shape"
                ),
            ),
        )
    if hit.ref_kind == "sha40":
        return (
            "medium",
            Confidence(
                "medium",
                reason="git-ref dep pinned to commit SHA",
            ),
        )
    return (
        "low",
        Confidence(
            "low",
            reason="git-ref dep in non-optional field",
        ),
    )


def _host_dep(
    deps: List[Dependency], manifest: Manifest,
) -> Optional[Dependency]:
    for d in deps:
        if d.declared_in == manifest.path:
            return d
    return None


def _placeholder_for_manifest(manifest: Manifest) -> Dependency:
    return Dependency(
        ecosystem=manifest.ecosystem,
        name="<package.json>",
        version=None,
        declared_in=manifest.path,
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.UNKNOWN,
        direct=True,
        purl="",
        parser_confidence=Confidence(
            "low",
            reason="placeholder for orphan-commit-dep finding host",
        ),
    )


__all__ = [
    "GitRefHit",
    "OrphanCommitFinding",
    "scan_manifests",
]
