"""RubyGems ``extconf.rb`` / ``mkrf_conf.rb`` lifecycle-hook scanner.

When a gem declares native extensions in its ``.gemspec``
(``spec.extensions = ['ext/foo/extconf.rb']``), RubyGems EXECUTES
the extension script at install time on the user's machine.  This
is the Ruby equivalent of npm's ``postinstall`` script — the
Ruby supply-chain attack surface.

This adapter reuses the shared :mod:`_hook_patterns` substrate so
the credential-read (C), publish-action (G), worm-shape conjunction,
and dangerous-pattern lists are consistent across ecosystems.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from ..models import Confidence, Dependency, Manifest, PinStyle
from ..parsers import _safe_read
from . import _hook_patterns, _own_host
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

logger = logging.getLogger(__name__)


_EXTCONF_NAMES = ("extconf.rb", "mkrf_conf.rb")


@dataclass(frozen=True)
class RubyGemsLifecycleHit:
    script_key: str             # relative path of the extconf script
    script_body: str
    reasons: list[str]
    reads_credentials: bool
    has_publish_action: bool


@dataclass(frozen=True)
class RubyGemsLifecycleFinding:
    dependency: Dependency
    hit: RubyGemsLifecycleHit
    severity: str
    confidence: Confidence


def scan_target(
    target: Path,
    manifests: Sequence[Manifest] = (),
    deps: Sequence[Dependency] = (),
) -> list[RubyGemsLifecycleFinding]:
    """Walk ``target`` for ``extconf.rb`` / ``mkrf_conf.rb`` files
    (typically under ``ext/``) and scan each.

    Unlike npm and Composer where the lifecycle hook is declared
    inline in the manifest, RubyGems puts the body in a separate
    file referenced from the gemspec.  We don't parse ``.gemspec``
    here — we walk the project tree for the canonical names.
    Misses gems that use a non-canonical extension-script name; the
    convention is universal enough that this is rare.
    """
    target = target.resolve()
    if not target.is_dir():
        return []
    deps_list = list(deps)
    fallback_host = _host_dep_for_target(deps_list, manifests, target) \
        or _placeholder_for_target(target)
    # Multi-gem monorepo: anchor EACH script to the closest RubyGems
    # manifest dominating it (as binary_in_package does for binaries)
    # rather than pinning every extconf in the tree to the FIRST
    # manifest — that attributed gem B's extension script to gem A,
    # fragmented the composite HOOK/BINARY pair across the two gems'
    # hosts, and keyed the publish-helper suppression on the wrong
    # name.  Fall back to the historical first-manifest host when no
    # RubyGems manifest dominates the script.
    rubygems_manifests = [
        m for m in manifests
        if m.ecosystem == "RubyGems" and not m.is_lockfile
    ]
    out: list[RubyGemsLifecycleFinding] = []
    for script in _iter_extconf_scripts(target):
        host = (_dominating_host(script, rubygems_manifests)
                or fallback_host)
        out.extend(_scan_script(script, target, host))
    return out


def _dominating_host(
    script: Path, rubygems_manifests: list[Manifest],
) -> Dependency | None:
    """Host anchored at the deepest RubyGems manifest whose directory
    dominates ``script``; None when no manifest dominates."""
    from ._closest_manifest import closest_manifest
    m = closest_manifest(rubygems_manifests, script)
    if m is None:
        return None
    return _own_host.resolve_own_host(
        m,
        reason="placeholder for rubygems-lifecycle-hook finding host",
        placeholder_name="<extconf>",
    )


def _iter_extconf_scripts(target: Path) -> Iterable[Path]:
    # Walk via os.walk to honour discovery skip dirs lazily.
    from ..discovery import EXCLUDED_DIR_NAMES
    import os
    for dirpath, dirnames, filenames in os.walk(target):
        # Sorted so evidence order is filesystem-independent (parity
        # with reachability._walker's determinism rule).
        dirnames[:] = sorted(
            d for d in dirnames if d not in EXCLUDED_DIR_NAMES
        )
        for fn in sorted(filenames):
            if fn in _EXTCONF_NAMES:
                yield Path(dirpath) / fn


def _scan_script(
    script: Path, target: Path, host: Dependency,
) -> list[RubyGemsLifecycleFinding]:
    body = _safe_read.read_bounded(script, follow_symlinks=False)
    if body is None:
        # ``read_bounded`` already logged the underlying reason.
        return []
    analysis = _hook_patterns.analyse_body(body)
    try:
        rel = script.relative_to(target)
    except ValueError:
        rel = script
    hit = RubyGemsLifecycleHit(
        script_key=str(rel),
        script_body=body.strip(),
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
        return [RubyGemsLifecycleFinding(
            dependency=host, hit=hit, severity="high",
            confidence=Confidence(
                "high",
                reason="extconf.rb matches known-dangerous pattern",
            ),
        )]
    if worm_shape:
        return [RubyGemsLifecycleFinding(
            dependency=host, hit=hit, severity="high",
            confidence=Confidence(
                "high",
                reason=(
                    "extconf.rb reads credentials AND invokes a "
                    "publish action (self-replication shape)"
                ),
            ),
        )]
    if worm_conjunction:
        # Worm conjunction fired but the host is an ATTESTED publish
        # helper — suppress the HIGH promotion, but keep a
        # low-severity row (parity with the npm adapter's
        # fall-through) so the HOOK family survives for the composite
        # chokepoint and the suppression stays operator-visible.
        return [RubyGemsLifecycleFinding(
            dependency=host, hit=hit, severity="low",
            confidence=Confidence(
                "medium",
                reason=(
                    "extconf.rb reads credentials and invokes a "
                    "publish action, but the gem is an attested "
                    "publish helper — worm-shape promotion suppressed"
                ),
            ),
        )]
    # FP-tightening: ``extconf.rb`` legitimately calls ``system``
    # for autoconf-style platform probes; mere presence isn't
    # signal.  Only pattern-hit and worm-shape earn a finding.
    return []


def _host_dep_for_target(
    deps: list[Dependency],
    manifests: Sequence[Manifest],
    target: Path,
) -> Dependency | None:
    """Anchor extconf findings at the first RubyGems manifest under
    ``target``, carrying the gem's OWN name (gemspec) when it
    declares one.  The extconf script is the gem's own code —
    attributing it to whichever dep the parser emitted first named
    an innocent third party and keyed the publish-helper worm-shape
    suppression on the wrong name."""
    del deps
    for m in manifests:
        if m.ecosystem != "RubyGems" or m.is_lockfile:
            continue
        try:
            m.path.relative_to(target)
        except ValueError:
            continue
        return _own_host.resolve_own_host(
            m,
            reason="placeholder for rubygems-lifecycle-hook finding host",
            placeholder_name="<extconf>",
        )
    return None


def _placeholder_for_target(target: Path) -> Dependency:
    return Dependency(
        ecosystem="RubyGems",
        name="<extconf>",
        version=None,
        declared_in=target,
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.UNKNOWN,
        direct=True,
        purl="",
        parser_confidence=Confidence(
            "low",
            reason="placeholder for rubygems-lifecycle-hook finding host",
        ),
    )


__all__ = [
    "RubyGemsLifecycleFinding",
    "RubyGemsLifecycleHit",
    "scan_target",
]
