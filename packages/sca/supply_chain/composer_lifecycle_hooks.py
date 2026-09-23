r"""Composer (PHP) ``composer.json`` lifecycle-hook scanner.

Composer's ``scripts`` block declares hooks that fire at well-defined
points in the dependency-management lifecycle.  The ones that fire
automatically from routine composer commands are the supply-chain
attack surface:

  * ``pre-install-cmd``, ``post-install-cmd``
  * ``pre-update-cmd``, ``post-update-cmd``
  * ``pre-package-install``, ``post-package-install``
  * ``pre-package-update``, ``post-package-update``
  * ``pre-autoload-dump``, ``post-autoload-dump``
  * ``pre-status-cmd``, ``post-status-cmd``

Each entry can be a string (single shell command), a list of
strings (multiple commands), or a PHP method reference
(``Vendor\Class::method``).  We scan the shell-shaped forms; the
PHP-class form is out of scope (it requires loading the class to
analyse, which is a different regime).

Uses the shared :mod:`_hook_patterns` substrate so C/G + worm-shape
semantics match the npm and Python adapters exactly.
"""

from __future__ import annotations

import json as _json
import logging
from dataclasses import dataclass

from ..models import Confidence, Dependency, Manifest
from ..parsers import _safe_read
from . import _hook_patterns, _own_host
from ..parsers._base import PARSE_ESCAPE_ERRORS
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

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
    reasons: list[str]
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
) -> list[ComposerLifecycleFinding]:
    out: list[ComposerLifecycleFinding] = []
    deps_list = list(deps)
    for m in manifests:
        # Discovery classifies composer.json as "Packagist" (the OSV
        # ecosystem name) — filtering on the registry-brand spelling
        # "Composer" matched NOTHING in production and left the whole
        # detector dead for every PHP target. The filename gate below
        # is the precise selector; the ecosystem gate is belt and
        # braces against same-named non-PHP files.
        if m.ecosystem != "Packagist":
            continue
        if m.path.name != "composer.json" or m.is_lockfile:
            continue
        host = _host_dep(deps_list, m)
        out.extend(_scan_one(m.path, host))
    return out


def _scan_one(
    path: Path, host: Dependency,
) -> list[ComposerLifecycleFinding]:
    text = _safe_read.read_bounded(path, follow_symlinks=False)
    if text is None:
        # ``read_bounded`` already logged the underlying reason.
        return []
    try:
        data = _json.loads(text)
    except (_json.JSONDecodeError, *PARSE_ESCAPE_ERRORS):  # hostile-input escape classes
        return []
    if not isinstance(data, dict):
        return []
    scripts = data.get("scripts")
    if not isinstance(scripts, dict):
        return []
    out: list[ComposerLifecycleFinding] = []
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
            worm_conjunction = (
                analysis.reads_credentials and analysis.has_publish_action
            )
            worm_shape = (
                worm_conjunction
                and not _hook_patterns.is_attested_publish_helper(host)
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
            elif worm_conjunction:
                # Worm conjunction fired but the host is an ATTESTED
                # publish helper — suppress the HIGH promotion, but
                # keep a low-severity row (parity with the npm
                # adapter's fall-through) so the HOOK family survives
                # for the composite chokepoint and the suppression
                # stays operator-visible.
                out.append(ComposerLifecycleFinding(
                    dependency=host, hit=hit, severity="low",
                    confidence=Confidence(
                        "medium",
                        reason=(
                            "composer.json script reads credentials "
                            "and invokes a publish action, but the "
                            "package is an attested publish helper — "
                            "worm-shape promotion suppressed"
                        ),
                    ),
                ))
            # FP-tightening: composer scripts blocks are routine
            # (CI/test glue, code-style hooks, etc.).  No row on
            # mere presence — only pattern-hit and worm-shape earn
            # a finding.
    return out


def _host_dep(
    deps: list[Dependency], manifest: Manifest,
) -> Dependency:
    """Anchor the finding on the package's OWN ``name`` from
    composer.json (placeholder when absent), via the shared resolver
    so every package-own detector produces an identical host key for
    this manifest."""
    del deps
    return _own_host.resolve_own_host(
        manifest,
        reason="placeholder for composer-lifecycle-hook finding host",
        placeholder_name="<composer.json>",
    )


__all__ = [
    "ComposerLifecycleFinding",
    "ComposerLifecycleHit",
    "scan_manifests",
]
