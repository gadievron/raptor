"""Engagement artifact ledger — mechanical inventory of a target set.

One recursive enumeration of an operator-given install directory into
ARTIFACT ROWS: executables and shared objects (ELF facts via
:func:`core.binary.elf.extract_elf_facts`), kernel modules (the
``elf-kmod`` target-kind vocabulary from
``packages.fuzzing.target_detector``), archives (expanded through the
EXISTING hardened extractor :func:`core.archive.extract.extract_to_dir`
— children enter as rows with provenance links), data corpora
(family-clustered on the ``corpus_profile`` name-template vocabulary),
eBPF blobs (an ``EM_BPF`` classification row ONLY — analysis is a
later capability), and unreadable oddities (declared-degraded
``unknown`` rows). The ledger is CLOSED over the operator-given
directory: nothing outside ``target_root`` is ever enumerated.

Doctrine (pinned by ``.github/tests/test_engagement_ledger_doctrine.py``):

- **No LLM anywhere near classification.** Every row fact is a
  deterministic byte-level extraction, and every exposure feature
  names its mechanical extractor in an ``extractor`` field. This
  module must never import an LLM/dispatch seam.
- **Second-life provenance (M1).** Every row carries
  ``derived_from_target`` naming exactly which of its fields hold
  target-derived bytes; any render path escapes those fields per the
  ``core.security.log_sanitisation`` contract; store writes go through
  ``save_json`` (atomic) under :func:`core.atomic_fs.fs_lock.artifact_lock`.
  Nothing target-derived is ever a raw key in an operator-facing
  surface (family keys are fixed-vocabulary by construction; artifact
  ids are hex digests / identity anchors).
- **Identity collision detection (M2).** A build-id (or any producer-
  authored identity) is attacker-forgeable. Collisions are grouped by
  ``(kind, anchor)`` — the artifact-id key itself, so two DIFFERENT
  forged values sharing a 16-hex anchor prefix cannot alias to one
  artifact id / checklist slot — and ``sha256`` identities are
  included (a 64-bit anchor birthday is grindable). Every member of a
  colliding group with differing content demotes to content-hash
  identity WIDENED to the full digest (alias-proof by construction)
  and is flagged ``elevated_interest``; a member whose content hash
  could not be read is stripped of the colliding identity and re-keyed
  from its path (``unverified-<hex>``) — never left wearing a forged
  identity. All of it is recorded in the document's ``collisions``
  list. The same content-proof gates status write-back inheritance:
  a rebuild carries a row's previous engagement status only when the
  previous row's ``identity.sha256`` matches the current bytes — a
  replaced artifact wearing a persisted identity never inherits
  ``verdicted``.
- **Bounded expansion (S14).** Per-archive child caps + a recursion
  depth cap; an over-cap archive keeps its extracted children, gains
  one ``archive-remainder`` row for the unexpanded tail, and the
  document records an explicit "archive truncated at N of M" residual
  naming WHICH cap fired — never a silent partial. Members the
  hardened extractor drops (traversal-named, oversized, encrypted,
  unwritable) are counted per reason into an
  ``archive_members_dropped`` residual; hostile-name drops flag the
  archive row ``elevated_interest``.

Storage, all under the run/project OUTPUT directory (never the target):

- ``ledger.json`` — the document (schema below), atomically replaced
  under its sibling flock on every write.
- ``checklists/<artifact-id>.json`` — per-artifact coverage-
  denominator slots. This is the seam that retires the single
  project-checklist-slot race: each artifact's checklist (in the
  :mod:`core.inventory.binary_builder` schema, ``binary:<stem>`` file
  keys unchanged) gets its own slot keyed by the artifact's content
  identity, so concurrent audits of sibling binaries can no longer
  cross-inherit one shared slot. This module lands the WRITER and a
  reader API; migrating audit prep onto the reader is the composition
  series' job.
- ``ledger-extract/<artifact-id>/`` — bounded archive extraction
  trees (hardened extractor output only: regular files, no symlinks).

Document shape (``schema_version`` 1)::

    {
      "schema_version": 1, "generated_at": iso, "target_root": str,
      "caps": {...effective caps...},
      "counts": {"rows": n, "by_class": {...}},
      "rows": [ {row}, ... ],
      "reverse_needed": [ {"name","providers","consumers"}, ... ],
      "collisions": [ {"identity_kind","anchor","artifact_ids"}, ... ],
      "residuals": [ {"kind","message",...}, ... ],
    }

Row shape::

    {
      "artifact_id": "<identity_kind>-<anchor>" | "corpus-family-<hex>"
                     | "unverified-<hex>" (collision, hash unreadable),
      "class": target-kind vocab | "elf-ebpf" | "archive" |
               "archive-remainder" | "corpus-family" | "unknown",
      "format_tier": see FORMAT_TIER_BY_CLASS,
      "path": relative path (target-derived),
      "size_bytes": int,
      "identity": {"kind","value","anchor","sha256"} | None,
      "links": {"needed": [...], "soname": str|None} (ELF only),
      "exposure": [ {"feature","value","extractor"}, ... ],
      "family": {...} (corpus-family / archive-remainder only),
      "provenance": {"origin": "target_walk"|"archive_member", ...},
      "archive_format": str, "expanded": bool (archive rows only),
      "elevated_interest": bool, "elevated_interest_reason": str,
      "status": {"state","updated_at",...} (stage write-back slot),
      "caps_hit": [...], "derived_from_target": [field names],
    }

``reverse_needed`` entries carry ``derived_from_target: ["name"]`` —
the linked ``name`` is raw DT_NEEDED/soname bytes and must be escaped
at render exactly like row fields.

Policy slots (the depth-policy governor's durable state — the ledger
owns the SCHEMA, the governor owns the SEMANTICS):

- per-row ``policy`` — tier assignment record (tier / bucket / basis
  / signals / promotion provenance), written through
  :func:`set_artifact_policy`.
- per-row ``reservation`` — the budget governor's per-segment
  pessimistic charge (reserved / reconciled state, consecutive-death
  counter), written through the same seam.
- document-level ``policy`` — engagement-scoped policy state
  (envelope, feasibility verdict, park record, escalations), merged
  through :func:`update_engagement_policy`.
- document-level ``policy_amendments`` — the append-only degradation
  audit trail (S15), via :func:`append_policy_amendment`. A resume
  reads the AMENDED slots, never a recomputed launch policy.

Every policy write validates against a closed key set and token
charsets — policy state is steering-grade, so a value that is not
provably a minted id / fixed-vocabulary token / bounded number is
refused at the write, never stored. Rebuilds carry row policy slots
under the same content-hash proof as status (a replaced artifact
never keeps its tier or its reservation) and carry the document-level
policy block wholesale (engagement state, not artifact state).
"""

from __future__ import annotations

import logging
import os
import re
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from core.binary.identity import (
    KIND_SHA256,
    ContentIdentity,
    content_identity,
    identity_anchor,
)
from core.atomic_fs.fs_lock import artifact_lock
from core.hash import sha256_file, sha256_string
from core.json import load_json, save_json
from core.security.log_sanitisation import sanitise_for_terminal

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1
LEDGER_FILENAME = "ledger.json"
CHECKLIST_DIR_NAME = "checklists"
EXTRACT_DIR_NAME = "ledger-extract"

# EM_BPF (ELF e_machine 247): classified as its own row class here —
# ``core.binary.elf._MACHINE_ARCH`` has no BPF entry today, and the
# eBPF analysis chain is a later capability. The row exists so the
# blob is never silently folded into "unknown data".
_EM_BPF = 247

# ── Row classes ──────────────────────────────────────────────────────
# Binary classes reuse the ``packages.fuzzing.target_detector`` kind
# vocabulary verbatim (elf-linux / elf-kmod / macho / pe-exe / pe-dll /
# pe-sys / te / java-class ...). Ledger-only additions:
CLASS_ELF_EBPF = "elf-ebpf"
CLASS_ARCHIVE = "archive"
CLASS_ARCHIVE_REMAINDER = "archive-remainder"
CLASS_CORPUS_FAMILY = "corpus-family"
CLASS_UNKNOWN = "unknown"

#: detector kinds the ledger records as binary rows (identity + facts).
_BINARY_KINDS = frozenset({
    "elf-linux", "elf-kmod", "macho",
    "pe-exe", "pe-dll", "pe-sys", "te", "java-class",
})

# ── Format-capability tiers (the design's tier table) ────────────────
# ``full``            — the whole per-class analysis chain exists (ELF).
# ``near_full``       — chain minus the entry catalogs' full depth (.ko).
# ``core``            — identity + core substrate landed, named
#                       periphery adapters pending (PE / Mach-O).
# ``classify_only``   — classified and declined for analysis (TE
#                       firmware precedent; EM_BPF until its annex).
# ``container``       — expandable holder, children carry the analysis.
# ``data``            — corpus family; the profiler lane applies.
# ``declared_degraded`` — honest floor for everything else.
TIER_FULL = "full"
TIER_NEAR_FULL = "near_full"
TIER_CORE = "core"
TIER_CLASSIFY_ONLY = "classify_only"
TIER_CONTAINER = "container"
TIER_DATA = "data"
TIER_DECLARED_DEGRADED = "declared_degraded"

FORMAT_TIER_BY_CLASS: dict[str, str] = {
    "elf-linux": TIER_FULL,
    "elf-kmod": TIER_NEAR_FULL,
    "macho": TIER_CORE,
    "pe-exe": TIER_CORE,
    "pe-dll": TIER_CORE,
    "pe-sys": TIER_CORE,
    "te": TIER_CLASSIFY_ONLY,
    CLASS_ELF_EBPF: TIER_CLASSIFY_ONLY,
    CLASS_ARCHIVE: TIER_CONTAINER,
    CLASS_CORPUS_FAMILY: TIER_DATA,
    CLASS_ARCHIVE_REMAINDER: TIER_DECLARED_DEGRADED,
    CLASS_UNKNOWN: TIER_DECLARED_DEGRADED,
}

# ── Status write-back vocabulary ─────────────────────────────────────
STATUS_STATES = frozenset({
    "inventoried",   # initial — the build stamps it
    "queued", "in_progress", "analysed", "verdicted", "parked", "failed",
})
_STATUS_DETAIL_MAX = 512
# C2's depth slot rides uninterpreted but charset-validated (it is a
# policy label, never target bytes).
_DEPTH_RE = re.compile(r"^[A-Za-z0-9_.:-]{0,32}$")
_ARTIFACT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,96}$")

# ── Policy-slot validation (schema is C1-owned; semantics live in
#    core.engagement.governor) ────────────────────────────────────────
# Token charset for policy values that must be provably non-target
# bytes: feature names, extractor module paths, basis labels. Wider
# than _DEPTH_RE (extractor paths carry dots and brackets) but still
# rejects every escape/control byte and whitespace.
_POLICY_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.\[\]:,-]{1,120}$")
#: Closed per-row policy key set. Unknown keys are refused so schema
#: growth is always a deliberate ledger diff, never a caller drift.
_POLICY_KEYS = frozenset({
    "tier", "bucket", "basis", "floor", "assigned_at",
    "low_exposure_verified", "signals", "promoted_by",
})
_RESERVATION_KEYS = frozenset({
    "segment", "reserved_usd", "actual_usd", "state", "deaths",
    "updated_at", "estimate_source", "shape",
})
_RESERVATION_STATES = frozenset({"reserved", "reconciled"})
# List bounds. Signals: one entry per mechanical exposure feature — a
# row carries at most a handful; 16 matches MAX_EXPOSURE_NAMES'
# posture. Promoted-by: consumers of one library at T3; 32 covers a
# hub library while bounding a hostile-doc replay flood.
_MAX_POLICY_SIGNALS = 16
_MAX_PROMOTED_BY = 32
# Amendment bounds, both directions: too low and a legitimate long
# engagement's degradation trail truncates (each degrade rung + park
# is one record); too high and a compromised stage can bloat the
# document past its own readers. 512 records x 4 KiB = 2 MiB worst
# case — an over-cap append is REFUSED with a one-time residual, so
# the on-disk trail is never silently rewritten.
_MAX_POLICY_AMENDMENTS = 512
_MAX_AMENDMENT_BYTES = 4096
# Engagement policy block: envelope + feasibility + park + a bounded
# escalation list. 64 KiB is orders above the real block while
# keeping a hostile merge from turning ledger.json into a flood.
_MAX_ENGAGEMENT_POLICY_BYTES = 64 * 1024
# API-appended residuals (parks, governor events) share the document
# residual list with build-time entries; the append seam refuses past
# this bound so a looping caller cannot balloon the document.
_MAX_APPENDED_RESIDUALS = 4096
# Money bounds mirror the resume spend-evidence doctrine: figures are
# operator/config/estimator-derived (never target bytes), but the
# document lives inside sandbox write grants — clamp keeps the budget
# math finite either way.
_MAX_POLICY_USD = 1e7
_MAX_SEGMENT = 1_000_000
_MAX_DEATHS = 1_000

# ── Caps (S14 + walk bounds) — each documented both directions ──────
# Walk bound: an install dir is operator-chosen but its CONTENT is
# hostile; without a file bound a crafted tree (or a mistaken "/" )
# turns one build into an unbounded stat storm. Real installs sit
# orders below; breach is a recorded residual, never silent.
MAX_WALK_FILES = 100_000
# Individual-row bound: binary/archive/unknown rows are per-file;
# data files cluster to families so they never count here. Higher
# just sells memory to a crafted tree of a million tiny ELFs; lower
# would truncate real firmware trees (hundreds of binaries).
MAX_LEDGER_ROWS = 4_096
# Family-row bound mirrors the profiler's MAX_FAMILIES posture: the
# counts always carry the true totals, examples are bounded.
MAX_FAMILY_ROWS = 512
MAX_FAMILY_EXAMPLES = 8
# Exposure list bounds: names inside feature values are bounded so a
# hostile import table cannot balloon the row.
MAX_EXPOSURE_NAMES = 16
# Reverse-index bound: DT_NEEDED per row is already capped upstream
# (core.binary.elf _MAX_NEEDED_ENTRIES); this bounds the aggregate.
MAX_REVERSE_ENTRIES = 4_096
# Status-table render bound: the table is an operator terminal
# surface — a 4096-row install must not flood it; elided rows stay
# reachable one at a time via ``ledger show``.
MAX_STATUS_TABLE_ROWS = 200

_NAME_RENDER_MAX = 120
_HEAD_BYTES = 64

#: Extractor drop reasons that are finding-grade hostility on the
#: archive itself (crafted member names / bomb shapes), vs. benign
#: degradation (oversized, encrypted, unwritable). Vocabulary:
#: ``core.zip.safe_member.UnsafeMemberReason`` values plus the write-
#: boundary reasons ``core.archive.extract`` counts.
_HOSTILE_MEMBER_DROP_REASONS = frozenset({
    "path_traversal", "absolute_path", "backslash_path",
    "symlink_unsafe", "special_file", "compression_bomb",
    "out_of_tree",
})

#: DecompressionLimitExceeded.cap → (doc caps_hit key, operator cap name).
_ARCHIVE_CAP_LABELS = {
    "total_bytes": ("archive_total_bytes", "max_archive_total_bytes"),
    "entry_count": ("archive_children", "max_archive_children"),
}


@dataclass(frozen=True)
class LedgerCaps:
    """Effective bounds for one build — S14's archive caps plus the
    expansion switch. Defaults refuse bombs while never truncating the
    motivating real installs; every value is recorded in the document
    so a truncation is reproducible.

    * ``max_archive_children`` — extracted members per archive. Lower
      truncates real plugin bundles; higher hands a crafted zip a
      per-archive row flood.
    * ``max_archive_total_bytes`` — summed extracted bytes per
      archive. The motivating 2 GiB kernel-source archive must be
      TRUNCATED HONESTLY by default, not extracted into the project
      dir; operators raise it deliberately per run.
    * ``max_archive_member_bytes`` — single-member bound (bomb
      defence, mirrors the extractor's own default posture).
    * ``max_archive_depth`` — nested-archive recursion bound. 1 =
      expand archives found in the target walk, classify-only for
      archives found INSIDE archives; 0 with ``expand_archives``
      False disables expansion entirely.
    """

    max_archive_children: int = 256
    max_archive_total_bytes: int = 64 * 1024 * 1024
    max_archive_member_bytes: int = 32 * 1024 * 1024
    max_archive_depth: int = 1
    expand_archives: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_archive_children": self.max_archive_children,
            "max_archive_total_bytes": self.max_archive_total_bytes,
            "max_archive_member_bytes": self.max_archive_member_bytes,
            "max_archive_depth": self.max_archive_depth,
            "expand_archives": self.expand_archives,
            "max_walk_files": MAX_WALK_FILES,
            "max_ledger_rows": MAX_LEDGER_ROWS,
            "max_family_rows": MAX_FAMILY_ROWS,
        }


# ── Paths ────────────────────────────────────────────────────────────

def ledger_path(output_dir: Path | str) -> Path:
    return Path(output_dir) / LEDGER_FILENAME


def checklist_slot_path(output_dir: Path | str, artifact_id: str) -> Path:
    """Per-artifact coverage-denominator slot.

    ``artifact_id`` is charset-gated (minted ids are identity anchors
    / digests — lowercase hex plus the kind prefix), so a target-
    derived string can never become a file name here.
    """
    if not _ARTIFACT_ID_RE.fullmatch(artifact_id):
        raise ValueError(f"invalid artifact id: {artifact_id!r}")
    return Path(output_dir) / CHECKLIST_DIR_NAME / f"{artifact_id}.json"


def _extract_root(output_dir: Path, artifact_id: str) -> Path:
    if not _ARTIFACT_ID_RE.fullmatch(artifact_id):
        raise ValueError(f"invalid artifact id: {artifact_id!r}")
    return Path(output_dir) / EXTRACT_DIR_NAME / artifact_id


# ── Small helpers ────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _esc(value: str) -> str:
    return sanitise_for_terminal(value, max_len=_NAME_RENDER_MAX)


def _read_head(path: Path) -> bytes | None:
    try:
        with path.open("rb") as fh:
            return fh.read(_HEAD_BYTES)
    except OSError:
        return None


def _elf_machine(head: bytes) -> int | None:
    """``e_machine`` from an ELF header prefix, honouring ``EI_DATA``
    byte order — two bytes read straight off the spec, only so the
    ledger can put ``EM_BPF`` blobs in their own declared row class."""
    if len(head) < 20 or head[:4] != b"\x7fELF":
        return None
    byteorder: Literal["little", "big"] = (
        "big" if head[5] == 2 else "little"
    )
    return int.from_bytes(head[18:20], byteorder)


def _sha256_or_none(path: Path) -> str | None:
    try:
        return sha256_file(path)
    except OSError:
        return None


def _exec_bit(path: Path) -> bool:
    try:
        return bool(path.stat().st_mode & 0o111)
    except OSError:
        return False


def _identity_block(
    path: Path, sha: str | None,
) -> tuple[dict[str, Any] | None, str | None]:
    """``(identity dict, artifact_id)`` via the sealed identity front
    door — never a raw build-id read of our own."""
    ident: ContentIdentity | None
    try:
        ident = content_identity(path)
    except Exception:  # noqa: BLE001 — hostile input must cost one row, not the build
        logger.debug("ledger: identity probe failed for %s", path,
                     exc_info=True)
        ident = None
    if ident is None:
        if sha is None:
            return None, None
        anchor = identity_anchor(KIND_SHA256, sha)
        if anchor is None:  # pragma: no cover - sha256 hex always anchors
            return None, None
        ident = ContentIdentity(KIND_SHA256, sha, anchor)
    block = {
        "kind": ident.kind,
        "value": ident.value,
        "anchor": ident.anchor_hex,
        "sha256": sha,
    }
    return block, f"{ident.kind}-{ident.anchor_hex}"


# ── Target-derived field marking (M1) ────────────────────────────────
# The candidate universe: every row field whose VALUE holds bytes that
# originated in the target. The writer stamps each row with the subset
# actually present, so renderers/exporters know exactly what to escape.
TARGET_DERIVED_FIELD_UNIVERSE: tuple[str, ...] = (
    "path",
    "identity.value",
    "identity.anchor",
    "identity.sha256",
    "links.needed",
    "links.soname",
    "exposure[].value",
    "family.key",
    "family.examples_escaped",
    "provenance.member_path",
)


def _stamp_derived(row: dict[str, Any]) -> None:
    present: list[str] = []
    if row.get("path"):
        present.append("path")
    ident = row.get("identity") or {}
    for leg in ("value", "anchor", "sha256"):
        if ident.get(leg):
            present.append(f"identity.{leg}")
    links = row.get("links") or {}
    if links.get("needed"):
        present.append("links.needed")
    if links.get("soname"):
        present.append("links.soname")
    if any(f.get("value") for f in row.get("exposure") or []):
        present.append("exposure[].value")
    family = row.get("family") or {}
    if family.get("key"):
        present.append("family.key")
    if family.get("examples_escaped"):
        present.append("family.examples_escaped")
    prov = row.get("provenance") or {}
    if prov.get("member_path"):
        present.append("provenance.member_path")
    row["derived_from_target"] = present


# ── Exposure features (mechanical only — each cites its extractor) ──

def _elf_exposure(
    path: Path, sha: str | None, facts: Any, meta: Any, kind: str,
) -> list[dict[str, Any]]:
    """MECHANICAL exposure features for one ELF row.

    Doctrine: no LLM, no heuristic scoring — every entry is a
    deterministic extraction and names its extractor. Consumers (the
    depth-policy governor) treat these as facts to combine, never as
    verdicts.
    """
    features: list[dict[str, Any]] = []
    features.append({
        "feature": "executable_mode",
        "value": _exec_bit(path),
        "extractor": "os.stat",
    })
    if facts is not None:
        features.append({
            "feature": "interpreter",
            "value": bool(facts.has_interpreter),
            "extractor": "core.binary.elf.extract_elf_facts",
        })
        features.append({
            "feature": "export_surface",
            "value": {
                "export_count": len(facts.exports),
                "func_export_count": sum(
                    1 for t in facts.export_types.values() if t == "FUNC"
                ),
            },
            "extractor": "core.binary.elf.extract_elf_facts",
        })
        features.append({
            "feature": "dynamic_linkage",
            "value": {"needed_count": len(facts.needed),
                      "has_soname": bool(facts.soname)},
            "extractor": "core.binary.elf.extract_elf_facts",
        })
    imports = sorted(getattr(meta, "imports", None) or [])
    if imports and sha:
        # Lazy call-site import — the house core→packages bridge (see
        # core.binary.identity's docstring for the precedent).
        from packages.binary_analysis.input_channels import (
            recover_static_channels,
        )
        channels, _evidence = recover_static_channels(sha, imports)
        if channels:
            features.append({
                "feature": "input_channels",
                "value": sorted(c.kind for c in channels),
                "extractor": ("packages.binary_analysis.input_channels"
                              ".recover_static_channels"),
            })
        from packages.binary_analysis.surface_classification import (
            classify_security_api,
        )
        sink_names: list[str] = []
        for name in imports:
            cls = classify_security_api(name)
            if cls is not None and cls.is_sink:
                sink_names.append(name)
        if sink_names:
            features.append({
                "feature": "sink_imports",
                "value": {
                    "count": len(sink_names),
                    "names": [_esc(n) for n in
                              sink_names[:MAX_EXPOSURE_NAMES]],
                },
                "extractor": ("packages.binary_analysis"
                              ".surface_classification"
                              ".classify_security_api"),
            })
    if kind == "elf-kmod":
        from packages.binary_analysis.ingress import driver_entry_catalogs
        catalog = driver_entry_catalogs()["linux"]
        names = set(imports)
        if facts is not None:
            names.update(facts.exports)
        matches = sorted(
            name for name in names
            if any(name.endswith(sym) for sym in catalog)
        )
        if matches:
            features.append({
                "feature": "driver_entry_symbols",
                "value": [_esc(n) for n in
                          matches[:MAX_EXPOSURE_NAMES]],
                "extractor": ("packages.binary_analysis.ingress"
                              ".driver_entry_catalogs"),
            })
    return features


# ── Enumeration ──────────────────────────────────────────────────────

class _Builder:
    """One build pass. Not a public API — :func:`build_ledger` is."""

    def __init__(self, target_root: Path, output_dir: Path,
                 caps: LedgerCaps) -> None:
        self.target_root = target_root
        self.output_dir = output_dir
        self.caps = caps
        self.rows: list[dict[str, Any]] = []
        self.residuals: list[dict[str, Any]] = []
        self.caps_hit: set[str] = set()
        self._walked = 0
        self._family_members: dict[str, list[tuple[str, int]]] = {}
        self._family_bytes: dict[str, int] = {}
        self._family_origins: dict[str, set[str]] = {}
        self._collisions: list[dict[str, Any]] = []
        self._symlinks_skipped = 0

    # -- walk -------------------------------------------------------

    def run(self) -> dict[str, Any]:
        for path in self._iter_files(self.target_root):
            rel = self._rel(path, self.target_root)
            self._classify_and_add(
                path, rel,
                provenance={"origin": "target_walk"},
                depth=0,
            )
        self._flush_families()
        self._detect_collisions()
        if self._symlinks_skipped:
            # Counted, never exemplified: symlink names are attacker-
            # chosen and the walk refuses to follow them by doctrine.
            self.residuals.append({
                "kind": "symlinks_skipped",
                "message": (f"{self._symlinks_skipped} symlink(s) "
                            "skipped (never followed)"),
            })
        reverse = self._reverse_needed()
        by_class: dict[str, int] = {}
        for row in self.rows:
            by_class[row["class"]] = by_class.get(row["class"], 0) + 1
        doc: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "generated_at": _now(),
            "target_root": str(self.target_root),
            "caps": self.caps.to_dict(),
            "caps_hit": sorted(self.caps_hit),
            "counts": {"rows": len(self.rows), "by_class": by_class},
            "rows": self.rows,
            "reverse_needed": reverse,
            "collisions": self._collisions,
            "residuals": self.residuals,
        }
        return doc

    def _iter_files(self, root: Path) -> list[Path]:
        """Deterministic, symlink-refusing, bounded walk. The project
        output dir is skipped when it nests under the target (the
        ledger must never enumerate its own artifacts)."""
        out_resolved = self.output_dir.resolve()
        files: list[Path] = []
        stack = [root]
        while stack:
            current = stack.pop()
            try:
                with os.scandir(current) as scan:
                    entries = sorted(scan, key=lambda e: e.name)
            except OSError:
                self.residuals.append({
                    "kind": "unreadable_dir",
                    "message": _esc(str(current)),
                })
                continue
            for entry in entries:
                try:
                    if entry.is_symlink():
                        self._symlinks_skipped += 1
                        continue
                    epath = Path(entry.path)
                    if entry.is_dir(follow_symlinks=False):
                        if epath.resolve() == out_resolved:
                            continue
                        stack.append(epath)
                        continue
                    if not entry.is_file(follow_symlinks=False):
                        self.residuals.append({
                            "kind": "non_regular_file",
                            "message": _esc(entry.name),
                        })
                        continue
                except OSError:
                    continue
                self._walked += 1
                if self._walked > MAX_WALK_FILES:
                    self.caps_hit.add("max_walk_files")
                    self.residuals.append({
                        "kind": "walk_truncated",
                        "message": (f"target walk truncated at "
                                    f"{MAX_WALK_FILES} files"),
                    })
                    return files
                files.append(epath)
        return files

    @staticmethod
    def _rel(path: Path, root: Path) -> str:
        try:
            return str(path.relative_to(root))
        except ValueError:
            return str(path)

    # -- classification ----------------------------------------------

    def _classify_and_add(
        self, path: Path, rel: str, *,
        provenance: dict[str, Any], depth: int,
    ) -> None:
        head = _read_head(path)
        try:
            size = path.stat().st_size
        except OSError:
            size = -1
        if head is None or size < 0:
            self._add_unknown(path, rel, provenance)
            return

        machine = _elf_machine(head)
        if machine == _EM_BPF:
            self._add_ebpf(path, rel, size, provenance)
            return

        kind = self._detect_kind(path, head)
        if kind in _BINARY_KINDS:
            self._add_binary(path, rel, size, kind, provenance)
            return

        fmt = self._archive_format(path)
        if fmt is not None:
            self._add_archive(path, rel, size, fmt, provenance,
                              depth=depth)
            return

        self._cluster_data_file(
            path.name, rel, size, head,
            origin=str(provenance.get("origin") or "target_walk"))

    @staticmethod
    def _detect_kind(path: Path, head: bytes) -> str:
        """Target-kind vocabulary via the existing detector — consulted
        only for the magic classes the ledger records as binary rows,
        so the detector's directory/source heuristics never engage."""
        is_binary_magic = (
            head[:4] == b"\x7fELF"
            or head[:2] == b"MZ"
            or head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                            b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
                            b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
                            b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca")
        )
        if not is_binary_magic:
            return ""
        from packages.fuzzing.target_detector import detect
        try:
            return detect(path).kind
        except Exception:  # noqa: BLE001 — a detector crash on hostile bytes costs one row
            logger.debug("ledger: target detect failed for %s", path,
                         exc_info=True)
            return ""

    @staticmethod
    def _archive_format(path: Path) -> str | None:
        from core.archive.detect import detect_format
        return detect_format(path)

    # -- row builders -------------------------------------------------

    def _row_budget_ok(self) -> bool:
        if len(self.rows) >= MAX_LEDGER_ROWS:
            if "max_ledger_rows" not in self.caps_hit:
                self.caps_hit.add("max_ledger_rows")
                self.residuals.append({
                    "kind": "rows_truncated",
                    "message": (f"per-file rows truncated at "
                                f"{MAX_LEDGER_ROWS}"),
                })
            return False
        return True

    def _base_row(
        self, rel: str, cls: str, size: int,
        provenance: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "artifact_id": "",
            "class": cls,
            "format_tier": FORMAT_TIER_BY_CLASS.get(
                cls, TIER_DECLARED_DEGRADED),
            "path": rel,
            "size_bytes": size,
            "identity": None,
            "links": None,
            "exposure": [],
            "family": None,
            "provenance": provenance,
            "elevated_interest": False,
            "elevated_interest_reason": "",
            "status": {"state": "inventoried", "updated_at": _now()},
            "caps_hit": [],
        }

    def _finish_row(self, row: dict[str, Any]) -> None:
        _stamp_derived(row)
        self.rows.append(row)

    def _add_unknown(self, path: Path, rel: str,
                     provenance: dict[str, Any]) -> None:
        if not self._row_budget_ok():
            return
        row = self._base_row(rel, CLASS_UNKNOWN, -1, provenance)
        row["artifact_id"] = f"unknown-{sha256_string(rel)[:16]}"
        row["caps_hit"] = ["unreadable"]
        self._finish_row(row)

    def _add_ebpf(self, path: Path, rel: str, size: int,
                  provenance: dict[str, Any]) -> None:
        """EM_BPF classification row ONLY — no facts / exposure pass
        runs here; the eBPF chain is a later capability and the tier
        says so."""
        if not self._row_budget_ok():
            return
        sha = _sha256_or_none(path)
        identity, artifact_id = _identity_block(path, sha)
        if identity is None or artifact_id is None:
            self._add_unknown(path, rel, provenance)
            return
        row = self._base_row(rel, CLASS_ELF_EBPF, size, provenance)
        row["identity"] = identity
        row["artifact_id"] = artifact_id
        self._finish_row(row)

    def _add_binary(self, path: Path, rel: str, size: int, kind: str,
                    provenance: dict[str, Any]) -> None:
        if not self._row_budget_ok():
            return
        sha = _sha256_or_none(path)
        identity, artifact_id = _identity_block(path, sha)
        if identity is None or artifact_id is None:
            self._add_unknown(path, rel, provenance)
            return
        row = self._base_row(rel, kind, size, provenance)
        row["identity"] = identity
        row["artifact_id"] = artifact_id
        if kind.startswith("elf-"):
            from core.binary.elf import extract_elf_facts, parse_elf
            facts = extract_elf_facts(path)
            meta = parse_elf(path)
            if facts is not None:
                row["links"] = {
                    "needed": list(facts.needed),
                    "soname": facts.soname,
                }
                row["caps_hit"] = list(facts.caps_hit)
            row["exposure"] = _elf_exposure(path, sha, facts, meta, kind)
        else:
            row["exposure"] = [{
                "feature": "executable_mode",
                "value": _exec_bit(path),
                "extractor": "os.stat",
            }]
        self._finish_row(row)

    # -- archives (S14) ------------------------------------------------

    def _add_archive(
        self, path: Path, rel: str, size: int, fmt: str,
        provenance: dict[str, Any], *, depth: int,
    ) -> None:
        if not self._row_budget_ok():
            return
        sha = _sha256_or_none(path)
        identity, artifact_id = _identity_block(path, sha)
        if identity is None or artifact_id is None:
            self._add_unknown(path, rel, provenance)
            return
        row = self._base_row(rel, CLASS_ARCHIVE, size, provenance)
        row["identity"] = identity
        row["artifact_id"] = artifact_id
        row["archive_format"] = fmt

        if not self.caps.expand_archives:
            row["expanded"] = False
            self._finish_row(row)
            return
        if depth >= self.caps.max_archive_depth:
            row["expanded"] = False
            row["caps_hit"] = ["archive_depth_capped"]
            self.caps_hit.add("archive_depth")
            self.residuals.append({
                "kind": "archive_depth_capped",
                "artifact_id": artifact_id,
                "message": (f"nested archive at depth {depth} not "
                            f"expanded (cap "
                            f"{self.caps.max_archive_depth})"),
            })
            self._finish_row(row)
            return

        truncated = False
        cap_kind = ""
        failed = ""
        summary: dict[str, Any] | None = None
        dest = _extract_root(self.output_dir, artifact_id)
        shutil.rmtree(dest, ignore_errors=True)
        from core.archive.errors import (
            ArchiveError,
            DecompressionLimitExceeded,
            UnsupportedArchive,
        )
        from core.archive.extract import extract_to_dir
        try:
            summary = extract_to_dir(
                path, dest,
                max_total_bytes=self.caps.max_archive_total_bytes,
                max_files=self.caps.max_archive_children,
                max_member_bytes=self.caps.max_archive_member_bytes,
            )
        except DecompressionLimitExceeded as exc:
            truncated = True
            cap_kind = getattr(exc, "cap", "") or ""
        except (UnsupportedArchive, ArchiveError) as exc:
            failed = str(exc)
        row["expanded"] = not failed
        if failed:
            row["caps_hit"] = ["archive_extract_failed"]
            self.residuals.append({
                "kind": "archive_extract_failed",
                "artifact_id": artifact_id,
                "message": _esc(failed),
            })
            self._finish_row(row)
            return
        # Silent-drop defence: the extractor's summary counts members
        # it refused at the safety filter / write boundary. Surface
        # every drop as a counted, per-reason residual — a member that
        # vanishes between the archive and the ledger is exactly the
        # place a hostile payload hides. Hostile-name drops (reason
        # vocabulary is extractor-authored constants, never target
        # bytes) additionally flag the archive row itself.
        dropped = int((summary or {}).get("dropped") or 0)
        if dropped:
            reasons: dict[str, int] = dict(
                (summary or {}).get("dropped_reasons") or {})
            hostile = sorted(
                set(reasons) & _HOSTILE_MEMBER_DROP_REASONS)
            row["caps_hit"] = list(row.get("caps_hit") or []) + [
                "archive_members_dropped"]
            if hostile:
                row["elevated_interest"] = True
                row["elevated_interest_reason"] = (
                    "hostile_archive_members:" + ",".join(hostile))
            breakdown = ", ".join(
                f"{reason}: {n}" for reason, n in sorted(reasons.items()))
            self.residuals.append({
                "kind": "archive_members_dropped",
                "artifact_id": artifact_id,
                "dropped": dropped,
                "reasons": reasons,
                "message": (
                    f"{dropped} archive member(s) dropped by the "
                    f"extractor ({breakdown or 'reason unknown'})"),
            })
        self._finish_row(row)

        extracted = 0
        for child in self._iter_files(dest):
            extracted += 1
            member_rel = self._rel(child, dest)
            self._classify_and_add(
                child, member_rel,
                provenance={
                    "origin": "archive_member",
                    "parent": artifact_id,
                    "member_path": member_rel,
                },
                depth=depth + 1,
            )
        if truncated:
            doc_key, cap_label = _ARCHIVE_CAP_LABELS.get(
                cap_kind, ("archive_limit", "archive caps"))
            self.caps_hit.add(doc_key)
            total = self._archive_member_total(path, fmt)
            total_str = str(total) if total is not None else "unknown"
            self.residuals.append({
                "kind": "archive_truncated",
                "artifact_id": artifact_id,
                "extracted": extracted,
                "total": total,
                "cap": cap_label,
                "message": (f"archive truncated at {extracted} of "
                            f"{total_str} members (cap: {cap_label})"),
            })
            # The over-cap tail is family-clustered to ONE expandable
            # row: re-running the build with raised caps expands it.
            # The remainder row spends row budget like every other
            # row path — at the budget edge the residual above still
            # records the truncation.
            if not self._row_budget_ok():
                return
            remainder = self._base_row(
                rel, CLASS_ARCHIVE_REMAINDER, -1,
                {"origin": "archive_member", "parent": artifact_id},
            )
            remainder["artifact_id"] = f"{artifact_id}-remainder"
            remainder["family"] = {
                "key": f"archive-remainder|{fmt}",
                "member_count": (total - extracted
                                 if total is not None else None),
                "examples_escaped": [],
            }
            self._finish_row(remainder)

    @staticmethod
    def _archive_member_total(path: Path, fmt: str) -> int | None:
        """True member count where a container states it cheaply (zip
        EOCD via the existing manifest probe); ``None`` — rendered
        "unknown" — for stream formats that carry no total."""
        if fmt != "zip":
            return None
        from packages.binary_analysis.manifest import (
            zip_central_directory_bounds,
        )
        bounds = zip_central_directory_bounds(path)
        return bounds[0] if bounds is not None else None

    # -- corpus families ------------------------------------------------

    def _cluster_data_file(self, name: str, rel: str, size: int,
                           head: bytes, *, origin: str) -> None:
        from packages.binary_analysis.corpus_profile import family_key
        key = family_key(name, head)
        self._family_members.setdefault(key, [])
        members = self._family_members[key]
        members.append((rel, size))
        self._family_bytes[key] = self._family_bytes.get(key, 0) + max(size, 0)
        self._family_origins.setdefault(key, set()).add(origin)

    def _flush_families(self) -> None:
        ordered = sorted(
            self._family_members.items(),
            key=lambda kv: (-len(kv[1]), kv[0]),
        )
        for key, members in ordered[:MAX_FAMILY_ROWS]:
            origins = sorted(self._family_origins.get(key, ()))
            row = self._base_row(
                "", CLASS_CORPUS_FAMILY, self._family_bytes.get(key, 0),
                {"origin": origins[0] if len(origins) == 1 else "mixed",
                 "origins": origins},
            )
            row["artifact_id"] = (
                f"corpus-family-{sha256_string(key)[:16]}"
            )
            row["family"] = {
                "key": key,
                "member_count": len(members),
                "examples_escaped": [
                    _esc(rel) for rel, _size in
                    sorted(members)[:MAX_FAMILY_EXAMPLES]
                ],
                "vocabulary": ("packages.binary_analysis"
                               ".corpus_profile.family_key"),
            }
            self._finish_row(row)
        overflow = len(ordered) - MAX_FAMILY_ROWS
        if overflow > 0:
            self.caps_hit.add("max_family_rows")
            self.residuals.append({
                "kind": "families_truncated",
                "message": (f"{overflow} corpus families beyond the "
                            f"{MAX_FAMILY_ROWS}-row cap"),
            })

    # -- identity collisions (M2) ---------------------------------------

    def _detect_collisions(self) -> None:
        # Group by (kind, ANCHOR) — the artifact-id key itself — not
        # the full identity value: two DIFFERENT forged build-ids
        # sharing a 16-hex prefix would otherwise alias to one
        # artifact id / checklist slot / status row with no demotion
        # and no record. sha256 identities are included: the 64-bit
        # anchor is birthday-grindable (~2^32 work) and deserves the
        # same detection.
        groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for row in self.rows:
            ident = row.get("identity")
            if not ident or not ident.get("kind") or not ident.get("anchor"):
                continue
            groups.setdefault(
                (ident["kind"], ident["anchor"]), []).append(row)
        for (kind, anchor), rows in sorted(groups.items()):
            shas = {r["identity"].get("sha256") for r in rows}
            if len(rows) < 2 or len(shas) < 2:
                continue
            # Forged/colliding identity anchor with differing content:
            # demote EVERY member to content-hash identity, widened to
            # the FULL digest — a collision group is exactly where the
            # 16-hex anchor proved forgeable/grindable, so the demoted
            # ids must be alias-proof, not just re-prefixed. Rows with
            # the same content (duplicate file at two paths) correctly
            # share the demoted id.
            demoted_ids: list[str] = []
            unverified_ids: list[str] = []
            for row in rows:
                sha = row["identity"].get("sha256")
                row["elevated_interest"] = True
                if sha is None:
                    # Content hash unreadable: this row cannot prove
                    # which side of the collision it is. It must NOT
                    # keep the colliding identity — strip it and
                    # re-key from the row's path so it can never
                    # alias a sibling's checklist slot.
                    parent = str(
                        (row.get("provenance") or {}).get("parent") or "")
                    row["identity"] = None
                    row["artifact_id"] = (
                        "unverified-"
                        + sha256_string(
                            f"{parent}/{row.get('path')}")[:16])
                    row["elevated_interest_reason"] = (
                        f"identity_collision_unverifiable:{kind}")
                    _stamp_derived(row)
                    unverified_ids.append(row["artifact_id"])
                    continue
                row["identity"] = {
                    "kind": KIND_SHA256, "value": sha,
                    "anchor": sha, "sha256": sha,
                }
                row["artifact_id"] = f"{KIND_SHA256}-{sha}"
                row["elevated_interest_reason"] = (
                    f"identity_collision:{kind}"
                )
                _stamp_derived(row)
                demoted_ids.append(row["artifact_id"])
            self._collisions.append({
                "identity_kind": kind,
                "anchor": anchor,
                "artifact_ids": sorted(demoted_ids),
                "unverified_artifact_ids": sorted(unverified_ids),
            })

    # -- reverse DT_NEEDED index (the new leg beside the forward one) --

    def _reverse_needed(self) -> list[dict[str, Any]]:
        providers: dict[str, set[str]] = {}
        consumers: dict[str, set[str]] = {}
        for row in self.rows:
            links = row.get("links") or {}
            soname = links.get("soname")
            if soname:
                providers.setdefault(soname, set()).add(
                    row["artifact_id"])
            base = Path(row.get("path") or "").name
            if base and row["class"].startswith("elf-"):
                providers.setdefault(base, set()).add(
                    row["artifact_id"])
            for needed in links.get("needed") or []:
                consumers.setdefault(needed, set()).add(
                    row["artifact_id"])
        entries: list[dict[str, Any]] = []
        for name in sorted(consumers):
            entries.append({
                "name": name,
                "providers": sorted(providers.get(name, ())),
                "consumers": sorted(consumers[name]),
                # M1 at the document level too: ``name`` is a raw
                # DT_NEEDED/soname string from target bytes — future
                # consumers must escape it like any row field.
                # (providers/consumers hold minted artifact ids.)
                "derived_from_target": ["name"],
            })
            if len(entries) >= MAX_REVERSE_ENTRIES:
                self.caps_hit.add("max_reverse_entries")
                self.residuals.append({
                    "kind": "reverse_index_truncated",
                    "message": (f"reverse DT_NEEDED index truncated at "
                                f"{MAX_REVERSE_ENTRIES} names"),
                })
                break
        return entries


# ── Public API ───────────────────────────────────────────────────────

def build_ledger(
    target_root: Path | str,
    output_dir: Path | str,
    *,
    caps: LedgerCaps | None = None,
) -> dict[str, Any]:
    """Enumerate ``target_root`` into the ledger document and write it
    (atomically, under the sibling flock) to
    ``<output_dir>/ledger.json``. Returns the document.

    Existing per-artifact status write-back (``status`` slots set by a
    previous engagement pass) is PRESERVED across rebuilds for rows
    whose artifact id survives — a re-enumeration must not silently
    reset engagement progress — but ONLY when the previous row's
    ``identity.sha256`` matches the current bytes. A replaced artifact
    wearing a persisted identity (a trojaned rebuild carrying the same
    build-id) must not inherit ``verdicted``/``analysed``: the carry is
    refused, the row is flagged ``elevated_interest``, and a
    ``status_carry_refused`` residual records it. Rows with no content
    hash by construction (corpus families, archive remainders,
    ``unknown``) carry on id alone — their ids already derive from the
    family key / path and they hold no per-binary verdict to trojan.
    """
    root = Path(target_root)
    out = Path(output_dir)
    if not root.is_dir():
        raise ValueError(f"target root is not a directory: {root}")
    out.mkdir(parents=True, exist_ok=True)
    doc = _Builder(root.resolve(), out, caps or LedgerCaps()).run()
    lp = ledger_path(out)
    with artifact_lock(lp, subject="engagement ledger"):
        previous = load_json(lp)
        if isinstance(previous, dict):
            # Engagement-scoped policy state (document-level block +
            # amendment trail) carries WHOLESALE: it is policy history
            # about the engagement, not a claim about any artifact's
            # bytes, and a rebuild that silently dropped it would
            # violate S15 (resume must load amended policy).
            prev_block = previous.get("policy")
            if isinstance(prev_block, dict):
                doc["policy"] = prev_block
            prev_trail = previous.get("policy_amendments")
            if isinstance(prev_trail, list):
                doc["policy_amendments"] = prev_trail
            carried: dict[
                str,
                tuple[dict[str, Any] | None, dict[str, Any] | None,
                      dict[str, Any] | None, str | None],
            ] = {}
            for row in previous.get("rows") or []:
                # Shape-guard BEFORE any attribute access: a corrupted
                # prior ledger (non-dict row) must cost the carry, not
                # crash the rebuild.
                if not isinstance(row, dict):
                    continue
                status = row.get("status") or {}
                keep_status: dict[str, Any] | None = (
                    status
                    if status.get("state") not in (None, "inventoried")
                    else None)
                policy = row.get("policy")
                keep_policy = policy if isinstance(policy, dict) else None
                reservation = row.get("reservation")
                keep_res = (reservation
                            if isinstance(reservation, dict) else None)
                if (keep_status is None and keep_policy is None
                        and keep_res is None):
                    continue
                prev_ident = row.get("identity")
                prev_sha = (prev_ident.get("sha256")
                            if isinstance(prev_ident, dict) else None)
                carried[str(row.get("artifact_id"))] = (
                    keep_status, keep_policy, keep_res, prev_sha)
            for row in doc["rows"]:
                kept = carried.get(row["artifact_id"])
                if not kept:
                    continue
                status, policy, reservation, prev_sha = kept
                cur_sha = (row.get("identity") or {}).get("sha256")
                if ((prev_sha is not None and prev_sha == cur_sha)
                        or (prev_sha is None and cur_sha is None)):
                    # Content proof held: status AND policy slots
                    # carry together — a tier assignment / reservation
                    # is a claim about these exact bytes just like a
                    # verdict is.
                    if status is not None:
                        row["status"] = status
                    if policy is not None:
                        row["policy"] = policy
                    if reservation is not None:
                        row["reservation"] = reservation
                else:
                    row["elevated_interest"] = True
                    row["elevated_interest_reason"] = (
                        "status_carry_refused:content_changed")
                    doc["residuals"].append({
                        "kind": "status_carry_refused",
                        "artifact_id": row["artifact_id"],
                        "message": (
                            "content hash missing or changed under a "
                            "persisted identity — engagement status "
                            "and policy slots reset to inventoried"),
                    })
        save_json(lp, doc)
    return doc


def load_ledger(output_dir: Path | str) -> dict[str, Any] | None:
    """The ledger document, or ``None`` when absent/unreadable."""
    doc = load_json(ledger_path(output_dir))
    return doc if isinstance(doc, dict) else None


def set_artifact_status(
    output_dir: Path | str,
    artifact_id: str,
    state: str,
    *,
    detail: str = "",
    depth: str = "",
) -> bool:
    """Stage write-back: update the status slot of every row carrying
    ``artifact_id``. Read-modify-write under the ledger's flock.

    ``state`` must come from :data:`STATUS_STATES`; ``depth`` is the
    (charset-gated) policy-tier slot a later governor writes; ``detail``
    is machine-authored free text, length-capped at store time and
    escaped at render like everything else.
    """
    if state not in STATUS_STATES:
        raise ValueError(f"invalid status state: {state!r}")
    if not _ARTIFACT_ID_RE.fullmatch(artifact_id):
        raise ValueError(f"invalid artifact id: {artifact_id!r}")
    if not _DEPTH_RE.fullmatch(depth):
        raise ValueError(f"invalid depth label: {depth!r}")
    lp = ledger_path(output_dir)
    with artifact_lock(lp, subject="engagement ledger"):
        doc = load_json(lp)
        if not isinstance(doc, dict):
            return False
        hit = False
        for row in doc.get("rows") or []:
            if row.get("artifact_id") != artifact_id:
                continue
            status: dict[str, Any] = {
                "state": state,
                "updated_at": _now(),
            }
            if detail:
                status["detail"] = detail[:_STATUS_DETAIL_MAX]
            if depth:
                status["depth"] = depth
            row["status"] = status
            hit = True
        if hit:
            save_json(lp, doc)
    return hit


# ── Policy slots (schema here; semantics in the governor) ───────────

def is_artifact_id(value: str) -> bool:
    """True when ``value`` is shaped like a minted artifact id — the
    same charset gate every path/key seam in this module applies."""
    return bool(_ARTIFACT_ID_RE.fullmatch(value))


def _require_token(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _POLICY_TOKEN_RE.fullmatch(value):
        raise ValueError(f"invalid policy token for {field}: {value!r}")
    return value


def _require_usd(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"invalid USD figure for {field}: {value!r}")
    v = float(value)
    if v != v or v in (float("inf"), float("-inf")):
        raise ValueError(f"non-finite USD figure for {field}")
    if not 0.0 <= v <= _MAX_POLICY_USD:
        raise ValueError(f"USD figure out of bounds for {field}: {v}")
    return round(v, 6)


def _validate_policy(policy: dict[str, Any]) -> dict[str, Any]:
    unknown = set(policy) - _POLICY_KEYS
    if unknown:
        raise ValueError(f"unknown policy key(s): {sorted(unknown)}")
    out: dict[str, Any] = {}
    for key in ("tier", "bucket", "basis", "floor"):
        if key in policy:
            value = policy[key]
            if not isinstance(value, str) or not _DEPTH_RE.fullmatch(value):
                raise ValueError(f"invalid policy label for {key}: {value!r}")
            out[key] = value
    if "assigned_at" in policy:
        out["assigned_at"] = _require_token(
            policy["assigned_at"], "assigned_at")
    if "low_exposure_verified" in policy:
        flag = policy["low_exposure_verified"]
        if flag is not None and not isinstance(flag, bool):
            raise ValueError("low_exposure_verified must be bool or None")
        out["low_exposure_verified"] = flag
    signals = policy.get("signals")
    if signals is not None:
        if (not isinstance(signals, list)
                or len(signals) > _MAX_POLICY_SIGNALS):
            raise ValueError("policy signals must be a bounded list")
        kept: list[dict[str, str]] = []
        for sig in signals:
            if not isinstance(sig, dict) or set(sig) - {"feature",
                                                        "extractor"}:
                raise ValueError(f"invalid policy signal: {sig!r}")
            kept.append({
                "feature": _require_token(sig.get("feature"),
                                          "signal feature"),
                "extractor": _require_token(sig.get("extractor"),
                                            "signal extractor"),
            })
        out["signals"] = kept
    promoted = policy.get("promoted_by")
    if promoted is not None:
        if not isinstance(promoted, list) or len(promoted) > _MAX_PROMOTED_BY:
            raise ValueError("promoted_by must be a bounded list")
        ids: list[str] = []
        for pid in promoted:
            if not isinstance(pid, str) or not is_artifact_id(pid):
                raise ValueError(f"invalid promoted_by id: {pid!r}")
            ids.append(pid)
        out["promoted_by"] = ids
    return out


def _validate_reservation(reservation: dict[str, Any]) -> dict[str, Any]:
    unknown = set(reservation) - _RESERVATION_KEYS
    if unknown:
        raise ValueError(f"unknown reservation key(s): {sorted(unknown)}")
    out: dict[str, Any] = {}
    if "segment" in reservation:
        seg = reservation["segment"]
        if (isinstance(seg, bool) or not isinstance(seg, int)
                or not 0 <= seg <= _MAX_SEGMENT):
            raise ValueError(f"invalid reservation segment: {seg!r}")
        out["segment"] = seg
    for key in ("reserved_usd", "actual_usd"):
        if key in reservation and reservation[key] is not None:
            out[key] = _require_usd(reservation[key], key)
    if "state" in reservation:
        state = reservation["state"]
        if state not in _RESERVATION_STATES:
            raise ValueError(f"invalid reservation state: {state!r}")
        out["state"] = state
    if "deaths" in reservation:
        deaths = reservation["deaths"]
        if (isinstance(deaths, bool) or not isinstance(deaths, int)
                or not 0 <= deaths <= _MAX_DEATHS):
            raise ValueError(f"invalid reservation deaths: {deaths!r}")
        out["deaths"] = deaths
    for key in ("updated_at", "estimate_source", "shape"):
        if key in reservation:
            out[key] = _require_token(reservation[key], key)
    return out


def set_artifact_policy(
    output_dir: Path | str,
    artifact_id: str,
    *,
    policy: dict[str, Any] | None = None,
    reservation: dict[str, Any] | None = None,
) -> bool:
    """Write the row-level ``policy`` / ``reservation`` slot(s) of
    every row carrying ``artifact_id``. Read-modify-write under the
    ledger's flock; each supplied slot REPLACES that slot whole (the
    governor always writes complete records, so a partial merge could
    only resurrect stale fields).

    Validation is fail-closed: unknown keys, non-token strings,
    unbounded lists and non-finite/out-of-range numbers raise
    ``ValueError`` before the document is touched.
    """
    if not is_artifact_id(artifact_id):
        raise ValueError(f"invalid artifact id: {artifact_id!r}")
    checked_policy = _validate_policy(policy) if policy is not None else None
    checked_res = (_validate_reservation(reservation)
                   if reservation is not None else None)
    if checked_policy is None and checked_res is None:
        raise ValueError("nothing to write: pass policy and/or reservation")
    lp = ledger_path(output_dir)
    with artifact_lock(lp, subject="engagement ledger"):
        doc = load_json(lp)
        if not isinstance(doc, dict):
            return False
        hit = False
        for row in doc.get("rows") or []:
            if row.get("artifact_id") != artifact_id:
                continue
            if checked_policy is not None:
                row["policy"] = dict(checked_policy)
            if checked_res is not None:
                row["reservation"] = dict(checked_res)
            hit = True
        if hit:
            save_json(lp, doc)
    return hit


def set_artifact_policies(
    output_dir: Path | str,
    policies: dict[str, dict[str, Any]],
) -> int:
    """Bulk form of :func:`set_artifact_policy` for the launch-time
    assignment pass: every slot validates BEFORE the document is
    touched, then all rows update under one flock cycle (per-artifact
    writes would re-read and re-write the whole document N times).
    Returns the number of rows updated.
    """
    checked: dict[str, dict[str, Any]] = {}
    for artifact_id, policy in policies.items():
        if not is_artifact_id(artifact_id):
            raise ValueError(f"invalid artifact id: {artifact_id!r}")
        checked[artifact_id] = _validate_policy(policy)
    if not checked:
        return 0
    lp = ledger_path(output_dir)
    hits = 0
    with artifact_lock(lp, subject="engagement ledger"):
        doc = load_json(lp)
        if not isinstance(doc, dict):
            return 0
        for row in doc.get("rows") or []:
            slot = checked.get(str(row.get("artifact_id")))
            if slot is None:
                continue
            row["policy"] = dict(slot)
            hits += 1
        if hits:
            save_json(lp, doc)
    return hits


def append_policy_amendment(
    output_dir: Path | str,
    amendment: dict[str, Any],
) -> int:
    """Append one S15 amendment record to the document's append-only
    ``policy_amendments`` trail. Returns the assigned sequence number,
    or ``-1`` when the trail is at capacity (a one-time
    ``policy_amendments_truncated`` residual records the refusal —
    callers must treat ``-1`` as an escalation, never a success).

    ``amendment`` must carry a token ``kind``; the whole record is
    byte-bounded so the trail cannot bloat the document. ``seq`` and
    ``at`` are stamped here.
    """
    from core.json.utils import dumps_artifact
    if not isinstance(amendment, dict):
        raise ValueError("amendment must be a dict")
    _require_token(amendment.get("kind"), "amendment kind")
    record = dict(amendment)
    if len(dumps_artifact(record).encode("utf-8")) > _MAX_AMENDMENT_BYTES:
        raise ValueError("amendment record over the byte bound")
    lp = ledger_path(output_dir)
    with artifact_lock(lp, subject="engagement ledger"):
        doc = load_json(lp)
        if not isinstance(doc, dict):
            return -1
        trail = doc.get("policy_amendments")
        if not isinstance(trail, list):
            trail = []
            doc["policy_amendments"] = trail
        if len(trail) >= _MAX_POLICY_AMENDMENTS:
            residuals = doc.setdefault("residuals", [])
            if not any(r.get("kind") == "policy_amendments_truncated"
                       for r in residuals if isinstance(r, dict)):
                residuals.append({
                    "kind": "policy_amendments_truncated",
                    "message": (f"amendment trail at capacity "
                                f"({_MAX_POLICY_AMENDMENTS}); further "
                                "amendments refused"),
                })
                save_json(lp, doc)
            return -1
        record["seq"] = len(trail) + 1
        record["at"] = _now()
        trail.append(record)
        save_json(lp, doc)
        return int(record["seq"])


def load_policy_amendments(output_dir: Path | str) -> list[dict[str, Any]]:
    """The append-only amendment trail (empty when absent)."""
    doc = load_ledger(output_dir)
    trail = (doc or {}).get("policy_amendments")
    return [a for a in trail if isinstance(a, dict)] \
        if isinstance(trail, list) else []


def update_engagement_policy(
    output_dir: Path | str,
    updates: dict[str, Any],
) -> bool:
    """Shallow-merge ``updates`` into the document-level ``policy``
    block (engagement-scoped state: envelope, feasibility verdict,
    park record, escalations). Keys are token-gated; the merged block
    is byte-bounded — an over-budget merge raises ``ValueError`` with
    the document untouched, so the on-disk block always stays small
    enough to read.
    """
    from core.json.utils import dumps_artifact
    if not isinstance(updates, dict) or not updates:
        raise ValueError("updates must be a non-empty dict")
    for key in updates:
        _require_token(key, "engagement policy key")
    lp = ledger_path(output_dir)
    with artifact_lock(lp, subject="engagement ledger"):
        doc = load_json(lp)
        if not isinstance(doc, dict):
            return False
        block = doc.get("policy")
        merged = dict(block) if isinstance(block, dict) else {}
        merged.update(updates)
        size = len(dumps_artifact(merged).encode("utf-8"))
        if size > _MAX_ENGAGEMENT_POLICY_BYTES:
            raise ValueError(
                f"engagement policy block would be {size} bytes "
                f"(over the {_MAX_ENGAGEMENT_POLICY_BYTES} bound)")
        doc["policy"] = merged
        save_json(lp, doc)
    return True


def load_engagement_policy(output_dir: Path | str) -> dict[str, Any]:
    """The document-level policy block (empty when absent)."""
    doc = load_ledger(output_dir)
    block = (doc or {}).get("policy")
    return dict(block) if isinstance(block, dict) else {}


def append_residual(
    output_dir: Path | str,
    kind: str,
    message: str,
    *,
    artifact_id: str | None = None,
) -> bool:
    """Append one residual record to the document (the seam parks and
    governor events use — a park is a ledger STATUS plus a residual,
    durable by doctrine). ``kind`` is token-gated; ``message`` is
    machine-authored text, length-capped at store time and escaped at
    render like every residual. Refuses past the appended-residual
    bound so a looping caller cannot balloon the document.
    """
    _require_token(kind, "residual kind")
    if artifact_id is not None and not is_artifact_id(artifact_id):
        raise ValueError(f"invalid artifact id: {artifact_id!r}")
    lp = ledger_path(output_dir)
    with artifact_lock(lp, subject="engagement ledger"):
        doc = load_json(lp)
        if not isinstance(doc, dict):
            return False
        residuals = doc.setdefault("residuals", [])
        if len(residuals) >= _MAX_APPENDED_RESIDUALS:
            return False
        record: dict[str, Any] = {
            "kind": kind,
            "message": str(message)[:_STATUS_DETAIL_MAX],
        }
        if artifact_id is not None:
            record["artifact_id"] = artifact_id
        residuals.append(record)
        save_json(lp, doc)
    return True


# ── Per-artifact coverage-denominator slots ─────────────────────────

def write_artifact_checklist(
    output_dir: Path | str,
    artifact_id: str,
    checklist: dict[str, Any],
) -> Path:
    """Write one artifact's checklist (the
    :func:`core.inventory.binary_builder.build_binary_checklist`
    schema, ``binary:<stem>`` file keys unchanged) into its OWN slot.

    The slot is stamped with the artifact id so a consumer joining by
    stem can verify it holds the artifact it thinks it does — stems
    collide, content identities do not (extra top-level keys are
    tolerated by every checklist consumer).
    """
    slot = checklist_slot_path(output_dir, artifact_id)
    payload = dict(checklist)
    payload["artifact_id"] = artifact_id
    with artifact_lock(slot, subject="artifact checklist"):
        save_json(slot, payload)
    return slot


def read_artifact_checklist(
    output_dir: Path | str,
    artifact_id: str,
) -> dict[str, Any] | None:
    """One artifact's checklist slot, or ``None`` when absent."""
    slot = checklist_slot_path(output_dir, artifact_id)
    doc = load_json(slot)
    return doc if isinstance(doc, dict) else None


def list_artifact_checklists(output_dir: Path | str) -> list[str]:
    """Artifact ids that currently have a checklist slot."""
    base = Path(output_dir) / CHECKLIST_DIR_NAME
    if not base.is_dir():
        return []
    out: list[str] = []
    for entry in sorted(base.glob("*.json")):
        if _ARTIFACT_ID_RE.fullmatch(entry.stem):
            out.append(entry.stem)
    return out


# ── Rendering (escape-at-render for every target-derived field) ─────

def render_status_lines(
    doc: dict[str, Any], output_dir: Path | str,
) -> list[str]:
    """Operator status table: one bounded, escaped line per row plus
    counts and residuals. Coverage denominators come from the
    per-artifact checklist slots when present."""
    lines: list[str] = []
    counts = doc.get("counts") or {}
    lines.append(
        f"Ledger: {counts.get('rows', 0)} rows "
        f"(target {_esc(str(doc.get('target_root', '')))})"
    )
    by_class = counts.get("by_class") or {}
    for cls in sorted(by_class):
        lines.append(f"  {cls:<20s} {by_class[cls]:>5d}")
    lines.append("")
    header = (f"  {'artifact':<26s} {'class':<14s} {'tier':<18s} "
              f"{'state':<12s} {'items':>6s}  path")
    lines.append(header)
    rows = doc.get("rows") or []
    shown_rows = rows[:MAX_STATUS_TABLE_ROWS]
    for row in shown_rows:
        artifact_id = str(row.get("artifact_id") or "?")
        checklist = read_artifact_checklist(output_dir, artifact_id) \
            if _ARTIFACT_ID_RE.fullmatch(artifact_id) else None
        items = (str(checklist.get("total_items"))
                 if isinstance(checklist, dict)
                 and checklist.get("total_items") is not None else "-")
        state = str((row.get("status") or {}).get("state") or "?")
        flag = " ⚠" if row.get("elevated_interest") else ""
        shown = row.get("path") or (row.get("family") or {}).get("key", "")
        lines.append(
            f"  {artifact_id[:26]:<26s} {str(row.get('class'))[:14]:<14s} "
            f"{str(row.get('format_tier'))[:18]:<18s} {state[:12]:<12s} "
            f"{items:>6s}  {_esc(str(shown))}{flag}"
        )
    if len(rows) > len(shown_rows):
        lines.append(
            f"  ... {len(rows) - len(shown_rows)} more row(s) elided "
            f"(table cap {MAX_STATUS_TABLE_ROWS}; "
            "use `ledger show <artifact>` for any row)"
        )
    for residual in doc.get("residuals") or []:
        lines.append(
            f"  residual [{_esc(str(residual.get('kind')))}]: "
            f"{_esc(str(residual.get('message', '')))}"
        )
    for collision in doc.get("collisions") or []:
        lines.append(
            "  collision: forged/colliding "
            f"{collision.get('identity_kind')} identity — demoted "
            f"{len(collision.get('artifact_ids') or [])} artifact(s) "
            "to content-hash identity (elevated interest)"
        )
    return lines


def render_artifact_lines(row: dict[str, Any]) -> list[str]:
    """Full single-row view — every target-derived field escaped."""
    lines = [
        f"Artifact: {_esc(str(row.get('artifact_id')))}",
        f"  class: {row.get('class')}  tier: {row.get('format_tier')}",
        f"  path: {_esc(str(row.get('path') or ''))}",
        f"  size: {row.get('size_bytes')}",
    ]
    ident = row.get("identity") or {}
    if ident:
        lines.append(
            f"  identity: {_esc(str(ident.get('kind')))} "
            f"{_esc(str(ident.get('value') or ''))}"
        )
    if row.get("elevated_interest"):
        lines.append(
            f"  elevated interest: "
            f"{_esc(str(row.get('elevated_interest_reason')))}"
        )
    links = row.get("links") or {}
    if links.get("soname"):
        lines.append(f"  soname: {_esc(str(links['soname']))}")
    for needed in links.get("needed") or []:
        lines.append(f"  needs: {_esc(str(needed))}")
    for feature in row.get("exposure") or []:
        value = feature.get("value")
        shown = (_esc(str(value)) if not isinstance(value, (bool, int))
                 else str(value))
        lines.append(
            f"  exposure {feature.get('feature')}: {shown} "
            f"[{feature.get('extractor')}]"
        )
    family = row.get("family") or {}
    if family:
        lines.append(
            f"  family: {_esc(str(family.get('key')))} "
            f"({family.get('member_count')} member(s))"
        )
        for example in family.get("examples_escaped") or []:
            lines.append(f"    e.g. {example}")
    prov = row.get("provenance") or {}
    if prov.get("origin") == "archive_member":
        lines.append(
            f"  from archive: {prov.get('parent')} "
            f"member {_esc(str(prov.get('member_path') or ''))}"
        )
    status = row.get("status") or {}
    lines.append(
        f"  status: {status.get('state')} "
        f"({status.get('updated_at', '?')})"
    )
    if status.get("depth"):
        lines.append(f"  depth: {status['depth']}")
    if row.get("caps_hit"):
        lines.append(
            "  caps hit: "
            + ", ".join(_esc(str(c)) for c in row["caps_hit"])
        )
    lines.append(
        "  target-derived fields: "
        + (", ".join(row.get("derived_from_target") or []) or "none")
    )
    return lines


__all__ = [
    "CHECKLIST_DIR_NAME",
    "EXTRACT_DIR_NAME",
    "FORMAT_TIER_BY_CLASS",
    "LEDGER_FILENAME",
    "SCHEMA_VERSION",
    "STATUS_STATES",
    "TARGET_DERIVED_FIELD_UNIVERSE",
    "LedgerCaps",
    "append_policy_amendment",
    "append_residual",
    "build_ledger",
    "checklist_slot_path",
    "is_artifact_id",
    "ledger_path",
    "list_artifact_checklists",
    "load_engagement_policy",
    "load_ledger",
    "load_policy_amendments",
    "read_artifact_checklist",
    "render_artifact_lines",
    "render_status_lines",
    "set_artifact_policies",
    "set_artifact_policy",
    "set_artifact_status",
    "update_engagement_policy",
    "write_artifact_checklist",
]
