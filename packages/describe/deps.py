"""Dependency-count snapshot for /describe.

Reuses ``packages/sca`` substrate: ``find_manifests`` walks the
target for known manifest files, ``parse_manifest`` extracts
:class:`Dependency` rows. We count direct deps per ecosystem
(skipping lockfiles, which would inflate the count with
transitive deps — operator wants "20 direct npm deps" not
"180 transitive").

Materially useful as a handoff signal: "180 npm + 12 pypi deps
detected → /sca is the natural next step before /agentic."

Best-effort throughout. /sca isn't available, manifest parsing
fails, target isn't a directory — all degrade silently to an
empty result so /describe doesn't crash on unusual targets.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict


# Cap on manifests we parse. /describe should be sub-second on
# normal repos; a monorepo with hundreds of package.json files
# would otherwise dominate the runtime. The cap is on parsing
# work, not on discovery — discovery is fast even at scale.
_MAX_MANIFESTS_TO_PARSE = 50


@dataclass(frozen=True)
class DependencyCounts:
    """Per-ecosystem direct-dep count + a truncation flag when
    we hit the parser cap."""
    by_ecosystem: Dict[str, int] = field(default_factory=dict)
    truncated: bool = False


def detect_dependency_counts(target_path: Path) -> DependencyCounts:
    """Walk the target for manifests, count direct deps per
    ecosystem (npm / pypi / cargo / gomod / …). Lockfiles
    excluded — they inflate the count with transitive deps.

    Silences /sca's ``sca.discovery`` / ``sca.parsers`` INFO
    logs for the duration — they'd otherwise leak the
    "found N manifest candidates" / "no parser for path"
    chatter into /describe's operator-facing block.
    """
    import logging

    try:
        from packages.sca.discovery import find_manifests
        from packages.sca.parsers import parse_manifest
    except Exception:  # noqa: BLE001
        return DependencyCounts()

    # Logger names follow __name__ in /sca's modules → fully
    # qualified as "packages.sca.discovery" / "packages.sca.parsers".
    discovery_logger = logging.getLogger("packages.sca.discovery")
    parsers_logger = logging.getLogger("packages.sca.parsers")
    prev_disc = discovery_logger.level
    prev_parse = parsers_logger.level
    discovery_logger.setLevel(logging.WARNING)
    parsers_logger.setLevel(logging.WARNING)
    try:
        manifests = find_manifests(target_path)
    except Exception:  # noqa: BLE001
        discovery_logger.setLevel(prev_disc)
        parsers_logger.setLevel(prev_parse)
        return DependencyCounts()

    # Drop lockfiles (transitive view); keep direct-manifest
    # files where the operator wrote their dep list.
    direct = [m for m in manifests if not m.is_lockfile]
    truncated = len(direct) > _MAX_MANIFESTS_TO_PARSE
    if truncated:
        direct = direct[:_MAX_MANIFESTS_TO_PARSE]

    counts: Dict[str, int] = {}
    try:
        for manifest in direct:
            try:
                deps = parse_manifest(manifest)
            except Exception:  # noqa: BLE001
                continue
            if not deps:
                continue
            eco = manifest.ecosystem or "unknown"
            counts[eco] = counts.get(eco, 0) + len(deps)
    finally:
        discovery_logger.setLevel(prev_disc)
        parsers_logger.setLevel(prev_parse)

    return DependencyCounts(by_ecosystem=counts, truncated=truncated)


__all__ = ["DependencyCounts", "detect_dependency_counts"]
