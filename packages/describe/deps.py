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
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


# Cap on manifests we parse. /describe should be sub-second on
# normal repos; a monorepo with hundreds of package.json files
# would otherwise dominate the runtime. The cap is on parsing
# work, not on discovery — discovery is fast even at scale.
_MAX_MANIFESTS_TO_PARSE = 50


@dataclass(frozen=True)
class DependencyCounts:
    """Per-ecosystem direct-dep count + a truncation flag when
    we hit the parser cap."""
    by_ecosystem: dict[str, int] = field(default_factory=dict)
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

    import threading

    # Logger names follow __name__ in /sca's modules → fully
    # qualified as "packages.sca.discovery" / "packages.sca.parsers".
    # Thread-scoped FILTER, not setLevel: a level clamp is
    # process-global state — a concurrent thread running /sca for its
    # own reasons had its INFO records silently dropped for the
    # duration of this helper's window.
    calling_thread = threading.get_ident()

    class _ThreadScopedMinWarning(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            if threading.get_ident() != calling_thread:
                return True
            return record.levelno >= logging.WARNING

    quiet = _ThreadScopedMinWarning()
    discovery_logger = logging.getLogger("packages.sca.discovery")
    parsers_logger = logging.getLogger("packages.sca.parsers")
    discovery_logger.addFilter(quiet)
    parsers_logger.addFilter(quiet)
    # ONE try/except/finally spanning everything after the filter
    # install: any gap between the install and the removal (e.g. the
    # lockfile filter tripping over sca ManifestInfo contract drift)
    # would both leave the sca loggers filtered AND propagate out of
    # this best-effort helper, turning /describe into a hard crash
    # instead of an empty deps field.
    counts: dict[str, int] = {}
    truncated = False
    try:
        manifests = find_manifests(target_path)

        # Drop lockfiles (transitive view); keep direct-manifest
        # files where the operator wrote their dep list.
        direct = [m for m in manifests if not m.is_lockfile]
        truncated = len(direct) > _MAX_MANIFESTS_TO_PARSE
        if truncated:
            direct = direct[:_MAX_MANIFESTS_TO_PARSE]

        for manifest in direct:
            try:
                deps = parse_manifest(manifest)
            except Exception:  # noqa: BLE001
                continue
            if not deps:
                continue
            eco = manifest.ecosystem or "unknown"
            counts[eco] = counts.get(eco, 0) + len(deps)
    except Exception:  # noqa: BLE001 — best-effort by contract
        return DependencyCounts()
    finally:
        discovery_logger.removeFilter(quiet)
        parsers_logger.removeFilter(quiet)

    return DependencyCounts(by_ecosystem=counts, truncated=truncated)


__all__ = ["DependencyCounts", "detect_dependency_counts"]
