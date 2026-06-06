"""Composer (PHP) ``composer.json`` lifecycle-hook scanner.

Composer's ``scripts`` block declares hooks that fire at well-defined
points in the dependency-management lifecycle.  The install-time
ones are the supply-chain attack surface:

  * ``pre-install-cmd``, ``post-install-cmd``
  * ``pre-update-cmd``, ``post-update-cmd``
  * ``pre-package-install``, ``post-package-install``
  * ``pre-package-update``, ``post-package-update``
  * ``pre-autoload-dump``, ``post-autoload-dump``

Each entry can be a string (single shell command), a list of
strings (multiple commands), or a PHP method reference
(``Vendor\\Class::method``).  We scan the shell-shaped forms; the
PHP-class form is out of scope (it requires loading the class to
analyse, which is a different regime).

Uses the shared :mod:`_hook_patterns` substrate so C/G + worm-shape
semantics match the npm and Python adapters exactly.
"""

from __future__ import annotations

import json as _json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional

from ..models import Confidence, Dependency, Manifest, PinStyle
from . import _hook_patterns

logger = logging.getLogger(__name__)


_LIFECYCLE_KEYS = (
    "pre-install-cmd", "post-install-cmd",
    "pre-update-cmd", "post-update-cmd",
    "pre-package-install", "post-package-install",
    "pre-package-update", "post-package-update",
    "pre-autoload-dump", "post-autoload-dump",
    "pre-status-cmd", "post-status-cmd",
)


@dataclass(frozen=True)
class ComposerLifecycleHit:
    script_key: str
    script_body: str
    reasons: List[str]
    reads_credentials: bool
    has_publish_action: bool


@dataclass(frozen=True)
class ComposerLifecycleFinding:
    dependency: Dependency
    hit: ComposerLifecycleHit
    severity: str
    confidence: Confidence


def scan_manifests(
    manifests: Iterable[Manifest],
    deps: Iterable[Dependency],
) -> List[ComposerLifecycleFinding]:
    out: List[ComposerLifecycleFinding] = []
    deps_list = list(deps)
    for m in manifests:
        if m.ecosystem != "Composer":
            continue
        if m.path.name != "composer.json" or m.is_lockfile:
            continue
        host = _host_dep(deps_list, m) or _placeholder_for_manifest(m)
        out.extend(_scan_one(m.path, host))
    return out


def _scan_one(
    path: Path, host: Dependency,
) -> List[ComposerLifecycleFinding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.debug(
            "sca.supply_chain.composer_lifecycle_hooks: %s read failed: %s",
            path, e,
        )
        return []
    try:
        data = _json.loads(text)
    except _json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    scripts = data.get("scripts")
    if not isinstance(scripts, dict):
        return []
    out: List[ComposerLifecycleFinding] = []
    for key in _LIFECYCLE_KEYS:
        entries = scripts.get(key)
        if entries is None:
            continue
        # Composer accepts string, list-of-strings, or method ref.
        # Each list entry is its own command — scan independently.
        if isinstance(entries, str):
            entries = [entries]
        elif not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, str):
                continue
            # PHP method refs (``Vendor\\Class::method``) — out of
            # scope for shell-pattern analysis.
            if "::" in entry and "/" not in entry and " " not in entry:
                continue
            analysis = _hook_patterns.analyse_body(entry)
            hit = ComposerLifecycleHit(
                script_key=key,
                script_body=entry.strip(),
                reasons=analysis.reasons,
                reads_credentials=analysis.reads_credentials,
                has_publish_action=analysis.has_publish_action,
            )
            worm_shape = (
                analysis.reads_credentials
                and analysis.has_publish_action
                and not _hook_patterns.is_publish_helper(host)
            )
            if analysis.reasons:
                out.append(ComposerLifecycleFinding(
                    dependency=host, hit=hit, severity="high",
                    confidence=Confidence(
                        "high",
                        reason=(
                            "composer.json script matches "
                            "known-dangerous pattern"
                        ),
                    ),
                ))
            elif worm_shape:
                out.append(ComposerLifecycleFinding(
                    dependency=host, hit=hit, severity="high",
                    confidence=Confidence(
                        "high",
                        reason=(
                            "composer.json script reads credentials "
                            "AND invokes a publish action "
                            "(self-replication shape)"
                        ),
                    ),
                ))
            # FP-tightening: composer scripts blocks are routine
            # (CI/test glue, code-style hooks, etc.).  No row on
            # mere presence — only pattern-hit and worm-shape earn
            # a finding.
    return out


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
        name="<composer.json>",
        version=None,
        declared_in=manifest.path,
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.UNKNOWN,
        direct=True,
        purl="",
        parser_confidence=Confidence(
            "low",
            reason="placeholder for composer-lifecycle-hook finding host",
        ),
    )


__all__ = [
    "ComposerLifecycleFinding",
    "ComposerLifecycleHit",
    "scan_manifests",
]
