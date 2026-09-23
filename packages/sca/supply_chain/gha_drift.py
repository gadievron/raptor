"""Detector for ``gha_action_ref_drift``.

GitHub Actions workflows reference third-party actions via
``uses: <owner>/<action>@<ref>`` lines. ``<ref>`` can be:

- a 40-char commit SHA (immutable; the action's bytes are pinned)
- a tag (mutable; the publisher can re-tag, ``v1`` and ``v1.2.3``
  alike)
- a branch (very mutable; new commits land continuously)

Tags and branches are *runtime-replaceable* by the action owner.
Real attacks have happened: an action gets compromised or a
maintainer's account is hijacked, the attacker re-publishes
``v3`` to point at malicious code, every workflow that
``uses: foo/action@v3`` runs the new code on next CI invocation.

GitHub's official guidance is to pin to a SHA. We flag any
non-SHA ref so the operator can decide whether the convenience
of a tag pin is worth the supply-chain risk.

Walks ``.github/workflows/*.yml`` and ``.github/workflows/*.yaml``.
Extraction is two-pass: a per-line regex for the plain ``uses:``
scalar shape (exact line numbers), unioned with a YAML document walk
(:mod:`packages.sca._gha_uses`) so block scalars, flow mappings,
quoted keys and anchor/alias indirection — which GitHub's own parser
runs identically — can't hide a mutable ref.  YAML parse failure
degrades to the regex pass alone.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from .. import _gha_uses
from ..models import Confidence, Dependency
from ..parsers import _safe_read
from ..parsers._base import build_purl
from ..parsers.inline_installs import classify_action_ref
from ._closest_manifest import rel_to_target as _rel
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

logger = logging.getLogger(__name__)


# `uses:` line shape (after YAML key trimming):
#   uses: owner/repo@ref
#   uses: owner/repo/sub-action@ref
#   uses: "owner/repo@ref"        (quoted — YAML-identical to bare)
#   uses: ./local-action          (no @ref — local action, ignore)
#   uses: docker://image:tag      (Docker action — different threat model)
# The spec may be wrapped in matching single or double quotes — YAML
# treats the quoted and bare scalars identically, so GitHub runs a
# quoted mutable ref exactly like a bare one; skipping quoted lines
# would leave them unchecked for pinning.
# The optional dash gates its own trailing whitespace — the naive
# ``\s*-?\s*`` pair was quadratic on an indent run (the same
# respelling the platform-matrix uses-line took).
_USES_RE = re.compile(
    r"""
    ^\s*(?:-\s*)?uses\s*:\s*
    (?P<quote>["']?)
    (?P<spec>[A-Za-z0-9_./+-]+@[A-Za-z0-9_./+-]+)
    (?P=quote)
    \s*(?:\#.*)?$
    """,
    re.VERBOSE,
)

_SHA_RE = re.compile(r"^[a-f0-9]{40}$")


@dataclass(frozen=True)
class GhaDriftFinding:
    dependency: Dependency
    detail: str
    path: Path
    line: int
    severity: str
    confidence: Confidence
    action: str
    ref: str
    ref_kind: str          # "sha" / "tag" / "branch_or_other"


def scan_target(target: Path) -> list[GhaDriftFinding]:
    """Walk ``.github/workflows/`` and flag mutable refs."""
    target = target.resolve()
    workflows_dir = target / ".github" / "workflows"
    if not workflows_dir.exists():
        return []
    out: list[GhaDriftFinding] = []
    for path in sorted(workflows_dir.iterdir()):
        if not path.is_file():
            continue
        if path.suffix.lower() not in {".yml", ".yaml"}:
            continue
        text = _safe_read.read_bounded(path, follow_symlinks=False)
        if text is None:
            # ``read_bounded`` already logged the underlying reason.
            continue
        out.extend(_scan_text(text, path, target))
    return out


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _scan_text(
    text: str,
    path: Path,
    target: Path,
) -> Iterable[GhaDriftFinding]:
    seen_specs: set[str] = set()
    for line_no, line in enumerate(text.splitlines(), start=1):
        m = _USES_RE.match(line)
        if not m:
            continue
        spec = m.group("spec")
        seen_specs.add(spec)
        finding = _spec_to_finding(spec, line_no, path, target)
        if finding is not None:
            yield finding
    # Second pass: YAML-walk the document so non-plain serializations
    # (block scalars, flow mappings, quoted keys, anchors/aliases) —
    # which GitHub runs identically — can't hide a mutable ref from
    # this detector.  The regex pass above keeps exact line numbers
    # for the plain shapes; only walk-discovered specs the regex
    # missed are emitted here (best-effort line).  A YAML parse
    # failure degrades to the regex-only behaviour.
    walked = _gha_uses.extract_uses_specs(text)
    if not walked:
        return
    for spec in dict.fromkeys(walked):
        if spec in seen_specs or "@" not in spec:
            continue
        finding = _spec_to_finding(
            spec, _gha_uses.best_effort_line(text, spec), path, target,
        )
        if finding is not None:
            yield finding


def _spec_to_finding(
    spec: str,
    line_no: int,
    path: Path,
    target: Path,
) -> GhaDriftFinding | None:
    """Classify one ``owner/repo@ref`` spec; None for skipped shapes
    (local actions, docker refs, SHA-pinned refs)."""
    # Docker / local-action specs go to a different uses: shape — we
    # already filtered those out by requiring `@` in the regex, but
    # docker://image:tag has `@` only on a digest pin.
    if spec.startswith(("./", "../", "docker://")):
        return None
    action, ref = spec.rsplit("@", 1)
    if not action or not ref:
        return None
    ref_kind = _classify_ref(ref)
    if ref_kind == "sha":
        return None
    severity = "medium" if ref_kind == "branch_or_other" else "low"
    reason = (
        "branch / non-tag ref — every CI run picks up whatever the "
        "head commit is at that moment"
        if ref_kind == "branch_or_other"
        else "tag ref — the action's owner can re-publish the same "
             "tag pointing at different code"
    )
    return GhaDriftFinding(
        dependency=_action_host_dep(action, ref, path),
        detail=(
            f"`{_rel(path, target)}:{line_no}` uses `{action}@{ref}` — "
            f"{reason}; pin to a 40-char commit SHA for "
            "supply-chain integrity"
        ),
        path=path,
        line=line_no,
        severity=severity,
        confidence=Confidence(
            "high",
            reason=f"action ref is a {ref_kind}, not a commit SHA",
        ),
        action=action,
        ref=ref,
        ref_kind=ref_kind,
    )


def _classify_ref(ref: str) -> str:
    """Categorise a ``uses: owner/repo@<ref>`` ref."""
    if _SHA_RE.match(ref.lower()):
        return "sha"
    # Tags typically look like `v1`, `v1.2`, `v1.2.3`, `release-1.0`.
    # Branches like `main`, `master`, `dev`, `feature/x`. Both are
    # mutable; the distinction tunes severity.
    if re.match(r"^v?\d", ref) and "/" not in ref:
        return "tag"
    return "branch_or_other"


def _action_host_dep(action: str, ref: str, workflow: Path) -> Dependency:
    """Anchor the finding to the ACTION dependency itself, mirroring
    the row the inline-installs workflow parser emits for the same
    ``uses:`` line (ecosystem / name / version key-equal).

    The finding's subject is the action — the report column names
    the thing whose ref drifts, and the composite chokepoint keys
    per-dep, so a sentinel / sunset / outdated finding on the SAME
    action composes with the drift signal (the GHA+SENTINEL hard
    pair). Anchoring at the project's closest manifest, as this
    detector used to, fragmented that conjunction: the pair could
    never co-fire on the canonical compromised-action shape.
    """
    pin_style, version = classify_action_ref(ref)
    return Dependency(
        ecosystem="GitHub Actions",
        name=action,
        version=version,
        declared_in=workflow,
        scope="build",
        is_lockfile=False,
        pin_style=pin_style,
        direct=True,
        purl=build_purl("githubactions", action, ref),
        parser_confidence=Confidence(
            "high",
            reason=f"GHA uses: {action}@{ref}",
        ),
        source_kind="gha_uses",
    )


__all__ = ["GhaDriftFinding", "scan_target"]
