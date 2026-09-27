"""Ghidra eBPF lifter capability record + consult API.

The Ghidra eBPF processor module is community-contributed and its
ISA v2/v3/v4 decode fidelity (jmp32, sdiv/smod, movsx, bswap, gotol,
atomics beyond xadd) is NOT assumed — it is measured by the probe in
:mod:`packages.ghidra.ebpf_probe` (generated-at-probe-time objects,
llvm-objdump ground truth) and persisted here as a machine-readable
capability record keyed by the Ghidra install + processor-module
identity, so a Ghidra upgrade or module edit invalidates the record
automatically.

**Contract for the eBPF lifter lane (blocking gate).** Any consumer
that lets Ghidra-decoded eBPF content (disassembly, decompilation,
xrefs) influence analysis MUST call :func:`ebpf_lifter_capability`
first and honour the tier:

* ``TIER_TRUSTED`` — the probe passed for THIS install: lifter-lane
  output may ride at its normal evidence tier.
* ``TIER_DOWNGRADED`` — the probe failed, has not run, or cannot be
  attributed to this install (unknown never grants trust): Ghidra
  eBPF decode output is hint-tier steering evidence only and must
  never ride into verdicts.

There is no third tier and no override flag: the only way to earn
``TIER_TRUSTED`` is a passing probe record for the current install
fingerprint (``packages/ghidra/scripts/ebpf-lifter-probe`` runs the
probe and writes the record).

**Stamp staleness — reader contract.** The bridge stamps
``metadata["ebpf_lifter_capability"]`` into ``re-database.json`` at
WRITE time; that artifact is long-lived shared state, so a
``trusted`` stamp earned under one Ghidra install can survive a
Ghidra upgrade inside the cached artifact. A stamp read back from a
cached database is therefore descriptive provenance only — it is NOT
valid without fingerprint revalidation. Any verdict-tier consumer
MUST call :func:`ebpf_lifter_capability` fresh at decision time
rather than trusting a cached stamp.

The consult API never raises — an unreadable install, a hostile or
corrupt record file, or a missing toolchain all degrade to
``TIER_DOWNGRADED`` with a reason string.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

#: Capability tiers. Deliberately a two-value enum: "unknown" is not
#: a tier — an unknown capability MUST behave exactly like a failed
#: probe (fail-closed), so it maps to ``TIER_DOWNGRADED`` with a
#: reason instead of getting a third value consumers could treat as
#: "probably fine".
TIER_TRUSTED = "trusted"
TIER_DOWNGRADED = "downgraded"

#: Record schema version. Bump on any incompatible record-shape
#: change; a mismatched schema is treated as no-record (downgrade),
#: never best-effort parsed.
CAPABILITY_SCHEMA = 1

#: The record ``kind`` discriminator (guards against an unrelated
#: JSON file landing at the record path).
CAPABILITY_KIND = "ghidra-ebpf-lifter-capability"

#: Ceiling on files hashed into the install fingerprint. Lower and a
#: legitimate processor module (eBPF ships ~20 files; the largest
#: Ghidra processor modules stay under a few hundred) could exceed it
#: and become unfingerprintable (permanent downgrade); higher and a
#: hostile/corrupt install tree could stall startup hashing thousands
#: of planted files.
MAX_MODULE_FILES = 512

#: Per-file ceiling for fingerprint hashing. Lower and a legitimate
#: compiled ``.sla``/``lib`` artifact (single-digit MiB today) could
#: push the module over and make it unfingerprintable; higher and a
#: planted multi-GiB file turns every consult into a long hash stall.
MAX_MODULE_FILE_BYTES = 64 * 1024 * 1024

#: Ceiling for reading a persisted capability record. Lower and a
#: legitimate record (a few KiB for the full feature matrix) could be
#: refused; higher and a corrupt/hostile file at the record path gets
#: buffered wholesale before validation.
RECORD_MAX_BYTES = 1024 * 1024

#: Matched with ``fullmatch`` — ``$`` would tolerate one trailing
#: newline, letting a not-quite-hex value reach path composition.
_HEX_RE = re.compile(r"[0-9a-f]{16,128}")


@dataclass(frozen=True)
class EbpfLifterCapability:
    """Result of a capability consult. ``tier`` is authoritative."""

    tier: str
    reason: str
    fingerprint: Optional[str] = None
    record_path: Optional[str] = None
    failed_features: tuple[str, ...] = field(default_factory=tuple)

    @property
    def trusted(self) -> bool:
        return self.tier == TIER_TRUSTED

    def as_metadata(self) -> dict[str, Any]:
        """Compact dict for stamping into artifact metadata.

        Record-derived text is escaped at intake in
        :func:`evaluate_record`; escaping again here is belt-and-braces
        (idempotent on already-escaped text) so no stamp consumer can
        receive control bytes even if a future producer path forgets.
        """
        from core.security.log_sanitisation import escape_nonprintable
        meta: dict[str, Any] = {
            "tier": self.tier,
            "reason": escape_nonprintable(self.reason),
        }
        if self.fingerprint:
            meta["install_fingerprint"] = self.fingerprint
        if self.failed_features:
            meta["failed_features"] = [
                escape_nonprintable(name) for name in self.failed_features
            ]
        return meta


def _downgraded(
    reason: str,
    *,
    fingerprint: Optional[str] = None,
    record_path: Optional[str] = None,
    failed: tuple[str, ...] = (),
) -> EbpfLifterCapability:
    return EbpfLifterCapability(
        tier=TIER_DOWNGRADED,
        reason=reason,
        fingerprint=fingerprint,
        record_path=record_path,
        failed_features=failed,
    )


def ghidra_install_root() -> Optional[Path]:
    """Resolve the Ghidra install root, or None.

    Primary: ``analyzeHeadless`` on PATH resolved through symlinks —
    the wrapper lives in ``<install>/support/`` (same resolution the
    sandbox read-grant logic in :mod:`packages.ghidra.headless`
    uses). Fallback: a valid ``GHIDRA_INSTALL_DIR`` (must contain
    ``support/analyzeHeadless``, mirroring headless's validation).
    Never hardcodes an install location.
    """
    binary = shutil.which("analyzeHeadless")
    if binary:
        try:
            real = Path(binary).resolve()
        except OSError:
            real = None
        if real is not None and real.parent.name == "support":
            return real.parent.parent
    install_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if install_dir:
        candidate = Path(install_dir)
        if (candidate.is_absolute()
                and (candidate / "support" / "analyzeHeadless").is_file()):
            try:
                return candidate.resolve()
            except OSError:
                return None
    return None


def ebpf_module_dir(
    install_root: Optional[Path] = None,
) -> Optional[Path]:
    """The install's eBPF processor-module directory, or None."""
    root = install_root if install_root is not None else \
        ghidra_install_root()
    if root is None:
        return None
    module = root / "Ghidra" / "Processors" / "eBPF"
    return module if module.is_dir() else None


def _application_version(install_root: Path) -> str:
    """``application.version`` from the install's properties file.

    Returns ``""`` when unreadable — the fingerprint still covers the
    module file contents, so a version-less install is fingerprintable
    (just less descriptive).
    """
    props = install_root / "Ghidra" / "application.properties"
    try:
        # The properties file is small (~1 KiB); the cap only guards
        # against a corrupt/hostile install tree.
        if props.stat().st_size > RECORD_MAX_BYTES:
            return ""
        for line in props.read_text(
                encoding="utf-8", errors="replace").splitlines():
            if line.startswith("application.version="):
                return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return ""


def install_fingerprint(
    install_root: Optional[Path] = None,
) -> Optional[str]:
    """Fingerprint of the Ghidra install + eBPF processor module.

    SHA-256 over the application version plus every module file's
    (relative path, content hash), sorted — so upgrading Ghidra,
    swapping the eBPF module, or editing a SLEIGH spec all change the
    fingerprint and orphan any previously earned capability record.

    Returns None when there is no install, no eBPF module, or the
    module tree exceeds the hashing ceilings (unfingerprintable ⇒
    capability unknown ⇒ downgrade — never a partial hash that could
    collide across differing installs).
    """
    root = install_root if install_root is not None else \
        ghidra_install_root()
    if root is None:
        return None
    module = ebpf_module_dir(root)
    if module is None:
        return None
    try:
        files = sorted(
            p for p in module.rglob("*") if p.is_file()
        )
    except OSError:
        return None
    if len(files) > MAX_MODULE_FILES:
        logger.warning(
            "eBPF module dir has %d files (> %d) — refusing to "
            "fingerprint", len(files), MAX_MODULE_FILES,
        )
        return None
    outer = hashlib.sha256()
    outer.update(
        ("ghidra=" + _application_version(root) + "\n").encode("utf-8"))
    for path in files:
        try:
            if path.stat().st_size > MAX_MODULE_FILE_BYTES:
                logger.warning(
                    "eBPF module file %s exceeds the %d-byte hashing "
                    "ceiling — refusing to fingerprint",
                    path.name, MAX_MODULE_FILE_BYTES,
                )
                return None
            digest = hashlib.sha256()
            with path.open("rb") as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    digest.update(chunk)
        except OSError:
            return None
        rel = path.relative_to(module).as_posix()
        outer.update(
            (rel + "\t" + digest.hexdigest() + "\n").encode("utf-8"))
    return outer.hexdigest()


def capability_dir() -> Path:
    """Directory holding persisted capability records.

    Under ``RaptorConfig.BASE_OUT_DIR`` (the same RAPTOR-owned output
    convention the binary-oracle edge cache uses) — never inside the
    Ghidra install (often read-only, and a record there would survive
    an in-place module swap only by accident, not by design).
    """
    from core.config import RaptorConfig
    return Path(RaptorConfig.BASE_OUT_DIR) / "ghidra-capability"


def record_path(fingerprint: str) -> Optional[Path]:
    """Record path for *fingerprint*, or None for a malformed one.

    The fingerprint embeds in a filename; validate it is a plain hex
    run at use-site (belt-and-braces against any future producer
    change) so no other value can steer path composition.
    """
    if not isinstance(fingerprint, str) \
            or not _HEX_RE.fullmatch(fingerprint):
        return None
    return capability_dir() / f"ebpf-lifter-{fingerprint[:16]}.json"


def save_capability_record(record: dict[str, Any]) -> Path:
    """Persist a probe-produced capability record (atomic write).

    The record must carry the ``install_fingerprint`` it was earned
    against; refusing anything else keeps a probe run from silently
    blessing a different install.
    """
    fingerprint = record.get("install_fingerprint")
    path = record_path(fingerprint) if isinstance(fingerprint, str) \
        else None
    if path is None:
        raise ValueError(
            "capability record has no valid install_fingerprint — "
            "refusing to persist"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    from core.json import save_json
    save_json(path, record)
    return path


def load_capability_record(
    fingerprint: str,
) -> tuple[Optional[dict[str, Any]], Optional[Path]]:
    """Load the record for *fingerprint*: ``(record, path)``.

    ``record`` is None when missing, oversized, malformed, or not a
    capability record for this exact fingerprint. Never raises.
    """
    path = record_path(fingerprint)
    if path is None or not path.is_file():
        return None, path
    from core.json import load_json
    data = load_json(path, max_bytes=RECORD_MAX_BYTES)
    if not isinstance(data, dict):
        return None, path
    if data.get("schema") != CAPABILITY_SCHEMA:
        return None, path
    if data.get("kind") != CAPABILITY_KIND:
        return None, path
    if data.get("install_fingerprint") != fingerprint:
        return None, path
    return data, path


def evaluate_record(
    record: dict[str, Any],
    fingerprint: str,
    path: Optional[Path],
) -> EbpfLifterCapability:
    """Tier a loaded record. ``TIER_TRUSTED`` only on a full pass.

    Trust requires: a non-empty feature matrix, every feature's
    ``pass`` true, AND the record's own aggregate ``pass`` true (the
    aggregate alone is not sufficient — a truncated feature matrix
    with a stale aggregate must not grant trust; the per-feature scan
    alone is not sufficient either — the aggregate is the probe's own
    attestation that the matrix it wrote was complete).
    """
    features = record.get("features")
    if not isinstance(features, dict) or not features:
        return _downgraded(
            "capability record has no feature matrix",
            fingerprint=fingerprint,
            record_path=str(path) if path else None,
        )
    # Feature names come from the on-disk record — escape them at
    # intake so the composed reason, the failed_features metadata, and
    # every downstream log line carry only printable text (the
    # core.security.log_sanitisation contract).
    from core.security.log_sanitisation import escape_nonprintable
    failed = tuple(sorted(
        escape_nonprintable(str(name))
        for name, entry in features.items()
        if not (isinstance(entry, dict) and entry.get("pass") is True)
    ))
    if failed or record.get("pass") is not True:
        reasons = ", ".join(failed) if failed else "aggregate pass=false"
        return _downgraded(
            f"probe gate failed for: {reasons}",
            fingerprint=fingerprint,
            record_path=str(path) if path else None,
            failed=failed,
        )
    return EbpfLifterCapability(
        tier=TIER_TRUSTED,
        reason="probe gate passed for this Ghidra install",
        fingerprint=fingerprint,
        record_path=str(path) if path else None,
    )


def ebpf_lifter_capability() -> EbpfLifterCapability:
    """Consult the Ghidra eBPF lifter capability for THIS install.

    ``TIER_TRUSTED`` requires a persisted probe record, earned by
    ``packages/ghidra/scripts/ebpf-lifter-probe``, whose install
    fingerprint matches the currently discovered Ghidra install and
    whose feature matrix fully passed. Everything else — Ghidra
    absent, eBPF module absent, unfingerprintable install, no record,
    stale record (fingerprint mismatch), corrupt record, failed
    features — is ``TIER_DOWNGRADED`` with a reason. Never raises.
    """
    try:
        fingerprint = install_fingerprint()
    except Exception:  # noqa: BLE001 — consult must never raise
        logger.warning("eBPF capability fingerprint failed",
                       exc_info=True)
        fingerprint = None
    if fingerprint is None:
        return _downgraded(
            "Ghidra install or eBPF processor module not found (or "
            "not fingerprintable) — capability unknown"
        )
    try:
        record, path = load_capability_record(fingerprint)
    except Exception:  # noqa: BLE001 — consult must never raise
        logger.warning("eBPF capability record load failed",
                       exc_info=True)
        record, path = None, None
    if record is None:
        return _downgraded(
            "no probe record for this Ghidra install — run "
            "packages/ghidra/scripts/ebpf-lifter-probe to measure it",
            fingerprint=fingerprint,
            record_path=str(path) if path else None,
        )
    try:
        return evaluate_record(record, fingerprint, path)
    except Exception:  # noqa: BLE001 — consult must never raise
        logger.warning("eBPF capability record evaluation failed",
                       exc_info=True)
        return _downgraded(
            "capability record unreadable",
            fingerprint=fingerprint,
            record_path=str(path) if path else None,
        )
