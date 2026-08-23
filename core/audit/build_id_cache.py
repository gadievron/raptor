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
      "binary_sha256": "<hex>",     # OPTIONAL: content hash of the
                                    # binary the artifact was computed
                                    # from (additive; absent = legacy)
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

from core.json import load_json_bounded

logger = logging.getLogger(__name__)

_DEFAULT_CACHE_DIR = ".cache/binary"

# On-disk layout version — see the PUBLIC CONTRACT section of the
# module docstring. Bump on any incompatible layout/schema change.
_FORMAT_VERSION = 1
_FORMAT_MARKER = "format.json"

# Byte ceiling for one cache envelope. The directory is shared and
# writable by external producers (see get()'s docstring), so a
# planted multi-GB envelope must be refused before the read, not
# buffered. Edge-index artifacts are the largest legitimate entries.
_MAX_ENVELOPE_BYTES = 64 * 1024 * 1024


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


def _valid_artifact(artifact: str) -> bool:
    """Only the documented artifact names may be read or written.

    Enforcing the allowlist in get/put (not just documenting it) keeps
    a crafted artifact name from traversing outside the entry dir when
    joined into ``{artifact}.json`` and keeps undocumented files in the
    shared, externally-writable cache from entering RAPTOR's evidence
    lanes.
    """
    return artifact in _KNOWN_ARTIFACTS


def _binary_sha256(binary_path: str | Path) -> str | None:
    """SHA-256 of the binary an artifact describes, or None."""
    try:
        from core.hash import sha256_file

        return sha256_file(Path(binary_path))
    except Exception:  # noqa: BLE001 — unhashable binary = no binding
        return None


@dataclass
class BuildIDCache:
    """Persistent binary analysis cache keyed by build-ID."""

    cache_dir: Path
    _index: dict[str, dict[str, Path]] = field(default_factory=dict)

    def has(self, build_id: str, artifact: str) -> bool:
        if not _valid_build_id(build_id) or not _valid_artifact(artifact):
            return False
        path = self._artifact_path(build_id, artifact)
        return path.is_file()

    def get(
        self,
        build_id: str,
        artifact: str,
        *,
        expected_binary_sha256: str | None = None,
    ) -> dict[str, Any] | None:
        """Read a cached entry.

        Returns the on-disk envelope written by put() — the dict
        ``{"format_version", "build_id", "artifact", "source_command",
        "data"}`` — NOT the bare artifact payload. Consumers read
        ``entry["data"]``.

        Tolerant by design (the cache is shared with external
        consumers): a missing artifact file, unreadable JSON, or an
        envelope written under a NEWER format version all read as a
        cache miss (None), never an error. Artifact names outside the
        documented allowlist are always a miss.

        ``expected_binary_sha256`` binds the read to binary content:
        when the caller knows the hash of the binary it is asking
        about AND the envelope records the producer-side hash
        (``binary_sha256``), a mismatch is a miss — a forged build-id
        cannot substitute artifacts computed for a different binary.
        Envelopes without the field (legacy / external producers)
        remain readable at build-id scope only — and build-id scope
        is NOT a trust boundary: the cache directory is shared and
        writable by design for external producers, so anything
        running at the operator's uid can mint a hash-less envelope
        under a chosen build-id and have it read back here as
        evidence. RAPTOR's own import helpers therefore hash-verify
        and refuse hash-less envelopes; callers that accept
        build-id-scope reads accept that exposure. Closing it needs
        a format-version bump making ``binary_sha256`` mandatory,
        deferred until it can be coordinated with external producers
        of this documented contract.
        """
        if not _valid_build_id(build_id) or not _valid_artifact(artifact):
            return None
        path = self._artifact_path(build_id, artifact)
        if not path.is_file():
            return None
        try:
            # Bounded helper (capped read + growth re-check), not
            # plain load_json: the cache dir is writable by external
            # producers, so the stat-then-uncapped-read window would
            # let a racing writer balloon the read past the gate.
            entry = load_json_bounded(path, max_bytes=_MAX_ENVELOPE_BYTES)
        except (OSError, ValueError):
            logger.debug("failed to read cache %s", path, exc_info=True)
            return None
        version = entry.get("format_version", 1) if isinstance(entry, dict) else None
        if not isinstance(version, int) or version > _FORMAT_VERSION:
            logger.debug(
                "build-id cache: %s has format_version %r > supported %d "
                "— treating as miss", path, version, _FORMAT_VERSION,
            )
            return None
        recorded_sha = entry.get("binary_sha256") or ""
        if expected_binary_sha256 and recorded_sha \
                and recorded_sha != expected_binary_sha256:
            logger.warning(
                "build-id cache: %s records binary_sha256 %s but the "
                "current binary hashes to %s — content mismatch under "
                "the same build-id; treating as miss",
                path, recorded_sha[:16], expected_binary_sha256[:16],
            )
            return None
        return entry

    def put(
        self,
        build_id: str,
        artifact: str,
        data: dict[str, Any],
        source_command: str = "",
        binary_sha256: str = "",
    ) -> Path | None:
        """Write an artifact envelope; returns the path, or None when
        the build_id is rejected (non-hex — could otherwise traverse
        outside cache_dir via a crafted id) or the artifact name is
        outside the documented allowlist (same traversal shape, plus
        undocumented files must not enter the shared layout).

        ``binary_sha256`` (optional, additive envelope field) records
        the content hash of the binary the artifact was computed from
        so readers can bind cache hits to binary content, not just the
        linker-choosable build-id."""
        if not _valid_build_id(build_id):
            logger.warning(
                "build-ID cache: rejected invalid build_id %r (artifact %s)",
                build_id, artifact,
            )
            return None
        if not _valid_artifact(artifact):
            logger.warning(
                "build-ID cache: rejected unknown artifact %r "
                "(build_id %s); allowed: %s",
                artifact, build_id, sorted(_KNOWN_ARTIFACTS),
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
        if binary_sha256:
            wrapped["binary_sha256"] = binary_sha256

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
        artifacts = [path.stem for path in entry_dir.iterdir() if path.suffix == ".json"]
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


def _hash_bound_import(
    cache: BuildIDCache,
    build_id: str,
    artifact: str,
    binary_path: str | Path | None,
) -> dict[str, Any] | None:
    """Content-hash-verified cache read for the import helpers.

    The shared cache is externally writable and build-ids are
    linker-choosable, so these helpers REQUIRE the envelope to be
    bound to the current binary's content: the caller must name the
    on-disk binary, it must hash, and the envelope must record a
    matching ``binary_sha256``. Anything less — no binary named,
    unhashable binary, envelope without a recorded hash, hash
    mismatch — returns None (fail closed). Future wiring therefore
    cannot skip the verification.
    """
    if not binary_path:
        logger.warning(
            "build-id cache import refused for %s/%s: no binary path "
            "supplied — cannot bind the envelope to binary content",
            build_id, artifact,
        )
        return None
    expected_sha = _binary_sha256(binary_path)
    if not expected_sha:
        logger.warning(
            "build-id cache import refused for %s/%s: binary %s cannot "
            "be hashed — refusing build-id-scoped read",
            build_id, artifact, binary_path,
        )
        return None
    envelope = cache.get(
        build_id, artifact, expected_binary_sha256=expected_sha,
    )
    if envelope is None:
        return None
    if (envelope.get("binary_sha256") or "") != expected_sha:
        # get() tolerates hash-less legacy envelopes at build-id
        # scope; the import helpers do not — an unstamped envelope in
        # an externally-writable cache is unverifiable.
        logger.warning(
            "build-id cache import refused for %s/%s: envelope does "
            "not record a matching binary_sha256",
            build_id, artifact,
        )
        return None
    return envelope


def import_validate_evidence(
    cache: BuildIDCache,
    build_id: str,
    binary_path: str | Path | None = None,
) -> dict[str, Any] | None:
    """Import /validate Stage E feasibility results from the cache.

    Returns the cache envelope (see BuildIDCache.get — feasibility
    payload under ``["data"]``) only when it is content-hash-bound to
    the on-disk binary at *binary_path* (see ``_hash_bound_import``);
    None otherwise.
    """
    return _hash_bound_import(cache, build_id, "feasibility", binary_path)


def import_layer0_findings(
    cache: BuildIDCache,
    build_id: str,
    binary_path: str | Path | None = None,
) -> dict[str, Any] | None:
    """Import Layer 0 findings from the cache.

    Returns the cache envelope (findings payload under ``["data"]``)
    only when it is content-hash-bound to the on-disk binary at
    *binary_path* (see ``_hash_bound_import``); None otherwise.
    """
    return _hash_bound_import(
        cache, build_id, "layer0-findings", binary_path,
    )


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
            # Authority marker travels with the cached verdicts so a
            # future reader can never resurrect suppression authority
            # a guessed env-build never had (absent key = full grade,
            # matching the per-item gates).
            "suppression_grade": b.get("suppression_grade", True),
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
        # Content binding: stamp the analysed binary's hash into the
        # envelope so later readers can reject a forged build-id
        # carrying artifacts for a different binary.
        sha = ""
        if payload.get("binary_path"):
            sha = _binary_sha256(payload["binary_path"]) or ""
        if cache.put(bid, "oracle-verdicts", payload,
                     source_command=source_command,
                     binary_sha256=sha) is not None:
            written += 1
    if written:
        logger.info(
            "build-id cache: stored oracle verdicts for %d binaries "
            "under %s", written, cache.cache_dir,
        )
    return written
