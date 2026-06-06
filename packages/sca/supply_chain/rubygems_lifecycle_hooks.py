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
from typing import Iterable, List, Optional, Sequence

from ..models import Confidence, Dependency, Manifest, PinStyle
from . import _hook_patterns

logger = logging.getLogger(__name__)


_EXTCONF_NAMES = ("extconf.rb", "mkrf_conf.rb")


@dataclass(frozen=True)
class RubyGemsLifecycleHit:
    script_key: str             # relative path of the extconf script
    script_body: str
    reasons: List[str]
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
) -> List[RubyGemsLifecycleFinding]:
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
    host = _host_dep_for_target(deps_list, manifests, target) \
        or _placeholder_for_target(target)
    out: List[RubyGemsLifecycleFinding] = []
    for script in _iter_extconf_scripts(target):
        out.extend(_scan_script(script, target, host))
    return out


def _iter_extconf_scripts(target: Path) -> Iterable[Path]:
    # Walk via os.walk to honour discovery skip dirs lazily.
    from ..discovery import EXCLUDED_DIR_NAMES
    import os
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIR_NAMES]
        for fn in filenames:
            if fn in _EXTCONF_NAMES:
                yield Path(dirpath) / fn


def _scan_script(
    script: Path, target: Path, host: Dependency,
) -> List[RubyGemsLifecycleFinding]:
    try:
        body = script.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.debug(
            "sca.supply_chain.rubygems_lifecycle_hooks: %s read failed: %s",
            script, e,
        )
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
    worm_shape = (
        analysis.reads_credentials
        and analysis.has_publish_action
        and not _hook_patterns.is_publish_helper(host)
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
    # FP-tightening: ``extconf.rb`` legitimately calls ``system``
    # for autoconf-style platform probes; mere presence isn't
    # signal.  Only pattern-hit and worm-shape earn a finding.
    return []


def _host_dep_for_target(
    deps: List[Dependency],
    manifests: Sequence[Manifest],
    target: Path,
) -> Optional[Dependency]:
    """Find the first RubyGems dep whose declared manifest is under
    ``target``.  Used to attribute extconf findings to the host
    gemspec/Gemfile."""
    for m in manifests:
        if m.ecosystem != "RubyGems":
            continue
        try:
            m.path.relative_to(target)
        except ValueError:
            continue
        for d in deps:
            if d.declared_in == m.path:
                return d
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
