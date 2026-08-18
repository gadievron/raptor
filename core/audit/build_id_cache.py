"""Build-ID-keyed binary analysis cache.

Caches binary analysis artifacts by ELF build-ID so a binary need not
be analysed twice across /understand, /audit, and /validate runs.
Build-ID change automatically invalidates (a rebuilt binary gets a new
build-ID and therefore a fresh, empty cache directory).

Production wiring:

  * The audit orchestrator loads this cache and passes it to
    ``binary_bridge.load_binary_bridge(build_id_cache=...)``, which
    merges cached ``layer0-findings`` into the bridge result.
  * The binary-oracle enrichment call sites (``libexec/raptor-audit``
    and ``core/inventory/builder``) populate ``oracle-verdicts`` via
    :func:`store_oracle_verdicts` after a binary is first classified.
  * Other artifacts in the layout are reserved for producers that
    compute them (e.g. /validate Stage E feasibility, external
    tooling); this module never fabricates artifacts.

ON-DISK LAYOUT — PUBLIC CONTRACT
================================

External consumers (other hosts / tools) read AND write this cache;
treat the directory structure and JSON schemas below as stable. Any
incompatible change MUST bump ``_FORMAT_VERSION`` (recorded both in a
``format.json`` marker at the cache root and in every artifact
envelope) so mixed-version consumers can detect it.

Directory structure::

    {cache_dir}/
        format.json             — {"format_version": 1}
        {build_id}/             — lowercase/uppercase hex only; anything
                                  else is rejected (path-escape guard)
            metadata.json       — ELF headers, security posture
            symbols.json        — imports, exports
            strings.json        — classified strings
            dwarf.json          — types, signatures (if present)
            layer0-findings.json — vulnerability patterns
            feasibility.json    — analyze_binary() output
            edges.json          — call-graph edges
            oracle-verdicts.json — per-function verdicts

Artifact envelope schema (every ``{artifact}.json``)::

    {
      "format_version": 1,          # layout version (absent = 1, legacy)
      "build_id": "<hex>",          # matches the directory name
      "artifact": "<name>",         # matches the file stem
      "source_command": "<str>",    # free-text producer tag
      "data": { ... }               # artifact payload (see below)
    }

Artifact payloads consumed by RAPTOR:

  * ``layer0-findings``: ``{"findings": [{"function": str,
    "target": str, "binary_path": str, ...}, ...]}`` — merged into the
    audit binary bridge as sink edges.
  * ``oracle-verdicts`` (written by :func:`store_oracle_verdicts`):
    ``{"binary_path": str, "tier": str, "verdicts": {name:
    {"classification": str, "address": int|null, "tier": str}}}``.

Partial caches are VALID: a consumer may have written only some
artifact files for a build-ID. Readers must (and :meth:`BuildIDCache.get`
does) treat a missing artifact file as a cache miss, never an error.
Unknown extra artifact files are ignored. Envelopes carrying a
``format_version`` greater than this module's ``_FORMAT_VERSION`` are
treated as cache misses (a newer producer wrote them).
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_CACHE_DIR = ".cache/binary"

# On-disk layout version — see the PUBLIC CONTRACT section of the
# module docstring. Bump on any incompatible layout/schema change.
_FORMAT_VERSION = 1
_FORMAT_MARKER = "format.json"


def _valid_build_id(build_id: str) -> bool:
    """Hex-only build IDs — anything else could escape cache_dir when
    joined into an on-disk path (e.g. ``../../``)."""
    return bool(re.match(r"^[0-9a-fA-F]+$", build_id or ""))


_KNOWN_ARTIFACTS = frozenset({
    "metadata",
    "symbols",
    "strings",
    "dwarf",
    "layer0-findings",
    "feasibility",
    "edges",
    "oracle-verdicts",
})


@dataclass
class BuildIDCache:
    """Persistent binary analysis cache keyed by build-ID."""

    cache_dir: Path
    _index: dict[str, dict[str, Path]] = field(default_factory=dict)

    def has(self, build_id: str, artifact: str) -> bool:
        if not _valid_build_id(build_id):
            return False
        path = self._artifact_path(build_id, artifact)
        return path.is_file()

    def get(self, build_id: str, artifact: str) -> dict[str, Any] | None:
        """Read a cached entry.

        Returns the on-disk envelope written by put() — the dict
        ``{"format_version", "build_id", "artifact", "source_command",
        "data"}`` — NOT the bare artifact payload. Consumers read
        ``entry["data"]``.

        Tolerant by design (the cache is shared with external
        consumers): a missing artifact file, unreadable JSON, or an
        envelope written under a NEWER format version all read as a
        cache miss (None), never an error.
        """
        if not _valid_build_id(build_id):
            return None
        path = self._artifact_path(build_id, artifact)
        if not path.is_file():
            return None
        try:
            entry = json.loads(path.read_text())
        except Exception:
            logger.debug("failed to read cache %s", path, exc_info=True)
            return None
        version = entry.get("format_version", 1) if isinstance(entry, dict) else None
        if not isinstance(version, int) or version > _FORMAT_VERSION:
            logger.debug(
                "build-id cache: %s has format_version %r > supported %d "
                "— treating as miss", path, version, _FORMAT_VERSION,
            )
            return None
        return entry

    def put(
        self,
        build_id: str,
        artifact: str,
        data: dict[str, Any],
        source_command: str = "",
    ) -> Path | None:
        """Write an artifact envelope; returns the path, or None when
        the build_id is rejected (non-hex — could otherwise traverse
        outside cache_dir via a crafted id)."""
        if not _valid_build_id(build_id):
            logger.warning(
                "build-ID cache: rejected invalid build_id %r (artifact %s)",
                build_id, artifact,
            )
            return None
        entry_dir = self.cache_dir / build_id
        entry_dir.mkdir(parents=True, exist_ok=True)
        self._ensure_format_marker()

        path = entry_dir / f"{artifact}.json"
        wrapped = {
            "format_version": _FORMAT_VERSION,
            "build_id": build_id,
            "artifact": artifact,
            "source_command": source_command,
            "data": data,
        }

        fd, tmp = tempfile.mkstemp(dir=str(entry_dir), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(wrapped, f, indent=2)
            os.replace(tmp, str(path))
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

        return path

    def _ensure_format_marker(self) -> None:
        """Write the layout-version marker at the cache root (once).

        Best-effort: another consumer may have written it already (any
        existing marker is left untouched — even a newer one, since
        the marker describes the WRITER'S layout and per-envelope
        version checks handle mixed-version reads).
        """
        marker = self.cache_dir / _FORMAT_MARKER
        if marker.exists():
            return
        try:
            fd, tmp = tempfile.mkstemp(dir=str(self.cache_dir), suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"format_version": _FORMAT_VERSION}, f)
            os.replace(tmp, str(marker))
        except OSError:
            logger.debug("could not write cache format marker", exc_info=True)

    def available_artifacts(self, build_id: str) -> list[str]:
        if not _valid_build_id(build_id):
            return []
        entry_dir = self.cache_dir / build_id
        if not entry_dir.is_dir():
            return []
        artifacts = []
        for path in entry_dir.iterdir():
            if path.suffix == ".json":
                artifacts.append(path.stem)
        return sorted(artifacts)

    def evict(self, build_id: str) -> int:
        if not _valid_build_id(build_id):
            return 0
        entry_dir = self.cache_dir / build_id
        if not entry_dir.is_dir():
            return 0
        count = 0
        for path in entry_dir.iterdir():
            try:
                path.unlink()
                count += 1
            except OSError:
                pass
        try:
            entry_dir.rmdir()
        except OSError:
            pass
        return count

    def summary(self) -> str:
        if not self.cache_dir.is_dir():
            return "Build-ID cache: empty"
        build_ids = [
            d.name for d in self.cache_dir.iterdir()
            if d.is_dir() and _valid_build_id(d.name)
        ]
        if not build_ids:
            return "Build-ID cache: empty"
        total_artifacts = sum(
            len(self.available_artifacts(bid)) for bid in build_ids
        )
        return (
            f"Build-ID cache: {len(build_ids)} binaries, "
            f"{total_artifacts} artifacts"
        )

    def _artifact_path(self, build_id: str, artifact: str) -> Path:
        return self.cache_dir / build_id / f"{artifact}.json"


def load_build_id_cache(
    cache_dir: Path | None = None,
) -> BuildIDCache:
    """Open the build-ID cache.

    Cache-dir resolution order:
      1. explicit *cache_dir* argument
      2. ``RAPTOR_BINARY_CACHE_DIR`` environment variable (set this to
         share the cache with an external consumer, e.g. a network
         mount written by another host/tool)
      3. the module default ``.cache/binary`` under the install root
         (``RaptorConfig.REPO_ROOT``, i.e. ``$RAPTOR_DIR``)
    """
    if cache_dir is None:
        env_dir = os.environ.get("RAPTOR_BINARY_CACHE_DIR")
        if env_dir:
            cache_dir = Path(env_dir)
        else:
            from core.config import RaptorConfig
            cache_dir = RaptorConfig.REPO_ROOT / _DEFAULT_CACHE_DIR
    return BuildIDCache(cache_dir=cache_dir)


def import_validate_evidence(
    cache: BuildIDCache,
    build_id: str,
) -> dict[str, Any] | None:
    """Import /validate Stage E feasibility results from the cache.

    Returns the cache envelope (see BuildIDCache.get — feasibility
    payload under ``["data"]``) if cached, None otherwise.
    """
    return cache.get(build_id, "feasibility")


def import_layer0_findings(
    cache: BuildIDCache,
    build_id: str,
) -> dict[str, Any] | None:
    """Import Layer 0 findings from the cache.

    Returns the cache envelope (findings payload under ``["data"]``)
    if cached, None otherwise.
    """
    return cache.get(build_id, "layer0-findings")


def store_oracle_verdicts(
    cache: BuildIDCache,
    inventory: dict[str, Any],
    source_command: str = "",
) -> int:
    """Populate ``oracle-verdicts`` from a binary-oracle-enriched inventory.

    Walks the per-item ``metadata.binary_oracle.binaries`` entries
    written by ``core.analysis.binary_oracle.enrich_inventory_with_
    binary_oracle`` and writes one ``oracle-verdicts`` artifact per
    build-ID (payload schema in the module docstring). Only artifacts
    the enrichment actually computed are written — nothing is
    fabricated. Binaries without a build-ID (or with a non-hex one)
    are skipped by put()'s validation.

    Returns the number of build-IDs written. Never raises on malformed
    inventory shapes — population is best-effort.
    """
    summary = inventory.get("binary_oracle")
    if not isinstance(summary, dict):
        return 0

    # build_id → {"binary_path", "tier", "verdicts": {name: {...}}}
    payloads: dict[str, dict[str, Any]] = {}
    for b in summary.get("binaries") or []:
        if not isinstance(b, dict):
            continue
        bid = b.get("build_id") or ""
        if not _valid_build_id(bid):
            continue
        payloads[bid] = {
            "binary_path": b.get("path", ""),
            "tier": b.get("tier", "unknown"),
            "verdicts": {},
        }

    for f in inventory.get("files") or []:
        for item in (f.get("items") or []) if isinstance(f, dict) else []:
            if not isinstance(item, dict):
                continue
            meta = item.get("metadata")
            bo = meta.get("binary_oracle") if isinstance(meta, dict) else None
            if not isinstance(bo, dict):
                continue
            name = item.get("name")
            if not isinstance(name, str) or not name:
                continue
            for entry in bo.get("binaries") or []:
                if not isinstance(entry, dict):
                    continue
                bid = entry.get("build_id") or ""
                payload = payloads.get(bid)
                if payload is None:
                    continue
                payload["verdicts"][name] = {
                    "classification": entry.get("classification", ""),
                    "address": entry.get("address"),
                    "tier": entry.get("tier", ""),
                }

    written = 0
    for bid, payload in payloads.items():
        if not payload["verdicts"]:
            continue
        if cache.put(bid, "oracle-verdicts", payload,
                     source_command=source_command) is not None:
            written += 1
    if written:
        logger.info(
            "build-id cache: stored oracle verdicts for %d binaries "
            "under %s", written, cache.cache_dir,
        )
    return written
