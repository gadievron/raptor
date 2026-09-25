"""Kind-aware content identity — the single front door.

Every consumer that needs "which module is this file" routes here:
:func:`content_identity` sniffs the format from magic bytes FIRST,
then extracts the strongest per-format identity available:

  ==============  ====================================================
  kind            value
  ==============  ====================================================
  elf_build_id    the GNU ``.note.gnu.build-id`` hex (the existing
                  sandboxed extractor — never re-implemented here)
  macho_uuid      the LC_UUID payload hex of the analysed slice
  pe_guid_age     the canonical RSDS GUID+age serialization
                  (:func:`core.binary.pe.canonical_pe_identity`)
  sha256          whole-file content hash — every other format, every
                  extraction failure, and every degenerate identity
  ==============  ====================================================

Anchor derivation is per-kind (:func:`identity_anchor`) and is the
one rule every join key in the repo shares; see that function for the
pe_guid_age hashing rationale.  Unreadable files return ``None``;
readable files ALWAYS identify (worst case ``sha256``) — the front
door never raises on hostile input.

Fat Mach-O identity is per-ANALYSED-slice: with a ``slice_selection``
the selected slice's LC_UUID is the identity; a fat file WITHOUT a
selection falls back to the whole-file sha256 so re-lipo'd containers
never alias.  Only a thin Mach-O or an explicitly selected slice
earns ``macho_uuid``.

Trust scope, stated plainly: build-ids, LC_UUIDs, and RSDS records
are producer-authored bytes — a hostile module can CHOOSE its
identity value.  The front door widens which formats can do so (PE
and Mach-O previously always got a content hash); it does not change
the trust class.  Deliberate collision stays out of scope for the
anchor and is handled by provenance gates on the producers, plus the
identity-kind join witness (:func:`core.binary.addrmap.record_join_anomalies`).

Import direction: this module lives in ``core/`` and reaches the
Mach-O walk in ``packages.binary_analysis.macho`` through a lazy
call-site import — the house bridging pattern
(:mod:`core.binary.addrmap` already bridges to
``packages.binary_analysis._artifact_lock`` and
``packages.ghidra.model`` the same way).  The walk is never
duplicated here.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, NamedTuple

# addrmap owns the anchor grammar (length + plausibility screen);
# the front door shares its exact constants so a value that anchors
# here always parses there.
from core.binary.addrmap import _ANCHOR_HEX_LEN, _HEX_RUN_RE

logger = logging.getLogger(__name__)

KIND_ELF_BUILD_ID = "elf_build_id"
KIND_MACHO_UUID = "macho_uuid"
KIND_PE_GUID_AGE = "pe_guid_age"
KIND_SHA256 = "sha256"

# Every kind the anchor rule table knows. A record carrying a kind
# outside this set anchors as NOTHING (fail-closed) — a future kind
# must extend :func:`identity_anchor` before its anchors join.
IDENTITY_KINDS = frozenset({
    KIND_ELF_BUILD_ID, KIND_MACHO_UUID, KIND_PE_GUID_AGE, KIND_SHA256,
})

# Prefix-anchored kinds: anchor = value[:16] (a plausible sub-16-hex
# value anchors at its full length). sha256/build-id/UUID truncation
# keeps full prefix entropy, so the at-most-16-hex prefix is the
# unchanged historical rule.
_PREFIX_KINDS = frozenset({KIND_ELF_BUILD_ID, KIND_MACHO_UUID, KIND_SHA256})

# Degenerate identity values: valid hex runs a producer can emit
# without meaning anything (zeroed LC_UUID from stripped/re-signed
# tooling, zeroed RSDS GUID). Anchoring them would alias every such
# module onto one identity, so they fall through to sha256.
_ALL_ZERO_32 = "0" * 32

_MZ_MAGIC = b"MZ"


class ContentIdentity(NamedTuple):
    """One module identity: ``(kind, value, anchor_hex)``.

    ``value`` is the full canonical identity (lowercase hex);
    ``anchor_hex`` is the join-key form from :func:`identity_anchor`.
    """

    kind: str
    value: str
    anchor_hex: str


def identity_anchor(kind: str | None, value: str | None) -> str | None:
    """Per-kind anchor for an identity value — THE single derivation.

    * ``elf_build_id`` / ``macho_uuid`` / ``sha256`` — the value
      truncated to AT MOST 16 lowercase hex (unchanged historical
      semantics; requires a plausible 8-128 hex run, else ``None``).
      A plausible value shorter than 16 hex (an 8-15 hex build-id)
      anchors at its full length — exactly what ``module_anchor``
      always produced; anchor lengths are collision-distinct, so a
      short anchor can never alias a truncated long one.
    * ``pe_guid_age`` — ``sha256(canonical_value)[:16]``, NOT a value
      prefix.  A prefix anchor would be GUID-only (the age falls past
      16 hex) and MSVC incremental relinks keep the GUID while
      bumping the age — different builds would share an anchor and
      misjoin rel-vaddr evidence.  Hashing folds the age in at zero
      namespace cost; the manifest records the full value for
      external correlation.
    * kind absent (``None`` / ``""``) — legacy records predate the
      kind field and were always build-id-or-sha prefix anchors:
      the prefix rule applies (elf-or-unknown, never an error).
    * any other kind — ``None`` (fail-closed; a record minted by a
      newer schema must not anchor under a rule written for a
      different kind — callers fall to their sha256 leg).
    """
    if not isinstance(value, str):
        return None
    lowered = value.strip().lower()
    if not _HEX_RUN_RE.fullmatch(lowered):
        return None
    if not kind or kind in _PREFIX_KINDS:
        return lowered[:_ANCHOR_HEX_LEN]
    if kind == KIND_PE_GUID_AGE:
        from core.hash import sha256_string
        return sha256_string(lowered)[:_ANCHOR_HEX_LEN]
    return None


def content_identity(
    path: Path | str,
    *,
    slice_selection: Any = None,
) -> ContentIdentity | None:
    """Identify the module at ``path``: format sniff, then per-format
    extraction, then the sha256 fallback.

    ``slice_selection`` names the analysed Mach-O slice (an object
    with integer ``offset``/``size`` attributes, e.g. the manifest's
    ``MachOSlice``, or an ``(offset, size)`` tuple); it is ignored
    for non-Mach-O files.

    Returns ``None`` only when the file cannot be read at all —
    every readable file identifies, worst case as its content hash.
    Never raises on hostile input (truncated, mis-magiced, or
    pathological files degrade to ``sha256``).
    """
    p = Path(path)
    try:
        with p.open("rb") as fh:
            head = fh.read(4)
    except OSError:
        return None

    ident: ContentIdentity | None = None
    if head == _elf_magic():
        ident = _elf_identity(p)
    elif head[:2] == _MZ_MAGIC:
        ident = _pe_identity(p)
    elif _is_macho_magic(head):
        ident = _macho_identity(p, head, slice_selection)
    if ident is not None:
        return ident
    return _sha256_identity(p)


# ---------------------------------------------------------------------------
# Per-format arms
# ---------------------------------------------------------------------------

def _elf_magic() -> bytes:
    from core.binary.elf import _ELF_MAGIC
    return _ELF_MAGIC


def _elf_identity(p: Path) -> ContentIdentity | None:
    """ELF arm: the existing sandboxed build-id extractor, verbatim.

    ``core.binary.elf._read_build_id`` is the one notes reader
    repo-wide (sandboxed readelf with the SandboxSetupError refusal
    contract) — the front door adds only the fallthrough policy.
    """
    try:
        from core.binary.elf import _read_build_id
        value, gap = _read_build_id(p)
    except Exception:  # noqa: BLE001 — the build-id is an optimisation; sha256 is the fallback identity
        logger.debug("identity: build-id probe failed for %s",
                     p, exc_info=True)
        return None
    if gap is not None:
        # Sandbox refusal means readelf never executed — degrading to
        # the content hash (no subprocess) weakens no containment,
        # but the operator should see the identity got weaker.
        # Behaviour flip vs the retired chains, stated durably: the
        # old CFG/edge key derivations CRASHED whole runs here; on a
        # sandbox-refused host, previously-warm caches keyed by the
        # sha identity now remain servable and the refusal no longer
        # aborts the caller (cold extraction still refuses loudly
        # upstream; containment unchanged).
        logger.warning(
            "content_identity: sandboxed build-id probe refused (%s) "
            "— falling back to the content hash", gap,
        )
        return None
    anchor = identity_anchor(KIND_ELF_BUILD_ID, value)
    if value is None or anchor is None:
        return None
    return ContentIdentity(KIND_ELF_BUILD_ID, value.strip().lower(), anchor)


def _pe_identity(p: Path) -> ContentIdentity | None:
    """PE arm: the RSDS debug identity via the existing extractor.

    All-zero GUIDs are degenerate (see module constants) and fall
    through; so does any image without a parseable RSDS record.
    """
    from core.binary.pe import extract_pe_facts
    facts = extract_pe_facts(p)  # never raises past itself
    if facts is None or not facts.debug_identity:
        return None
    if facts.debug_guid == _ALL_ZERO_32:
        return None
    value = facts.debug_identity.strip().lower()
    anchor = identity_anchor(KIND_PE_GUID_AGE, value)
    if anchor is None:
        return None
    return ContentIdentity(KIND_PE_GUID_AGE, value, anchor)


def _selection_bounds(selection: Any) -> tuple[int, int] | None:
    """(offset, size) from a slice-selection shape, else ``None``."""
    if selection is None:
        return None
    offset = getattr(selection, "offset", None)
    size = getattr(selection, "size", None)
    if offset is None and size is None and (
        isinstance(selection, (tuple, list)) and len(selection) == 2
    ):
        offset, size = selection
    if isinstance(offset, bool) or isinstance(size, bool):
        return None
    if isinstance(offset, int) and isinstance(size, int):
        return offset, size
    return None


def _macho_identity(
    p: Path, head: bytes, selection: Any,
) -> ContentIdentity | None:
    """Mach-O arm: LC_UUID of the analysed slice.

    Identity is per-ANALYSED-slice: an explicit selection names the
    slice; a THIN file is its own single slice; a FAT file without a
    selection has no analysed slice and falls through to the
    whole-file sha256 (re-lipo'd containers must never alias).
    All-zero LC_UUIDs are degenerate and fall through.
    """
    # Lazy call-site import — the house core→packages bridge (see
    # module docstring); the LC walk itself is never duplicated.
    from packages.binary_analysis.macho import (
        THIN_MACHO_MAGICS,
        extract_macho_facts,
        extract_macho_slice_facts,
    )
    uuid: str | None = None
    bounds = _selection_bounds(selection)
    if bounds is not None:
        slice_facts = extract_macho_slice_facts(
            p, offset=bounds[0], size=bounds[1],
        )
        uuid = slice_facts.uuid if slice_facts is not None else None
    elif head in THIN_MACHO_MAGICS:
        facts = extract_macho_facts(p)
        if facts is not None and not facts.is_fat and len(facts.slices) == 1:
            uuid = facts.slices[0].uuid
    else:
        # Fat container without a selection: no analysed slice, no
        # slice identity.
        return None
    if not uuid or uuid == _ALL_ZERO_32:
        return None
    value = uuid.strip().lower()
    anchor = identity_anchor(KIND_MACHO_UUID, value)
    if anchor is None:
        return None
    return ContentIdentity(KIND_MACHO_UUID, value, anchor)


def _sha256_identity(p: Path) -> ContentIdentity | None:
    try:
        from core.hash import sha256_file
        value = sha256_file(p)
    except OSError:
        return None
    anchor = identity_anchor(KIND_SHA256, value)
    if anchor is None:  # pragma: no cover - sha256 hex always anchors
        return None
    return ContentIdentity(KIND_SHA256, value, anchor)


# ---------------------------------------------------------------------------
# Manifest-shaped consumers
# ---------------------------------------------------------------------------

def manifest_anchor(manifest_or_dict: Any) -> str | None:
    """Kind-aware module anchor from a manifest's identity legs.

    Reads ``build_id`` + ``identity_kind`` (attribute or key), falling
    back to the ``binary_sha256`` leg when the identity value cannot
    anchor — exactly the preference ``module_anchor`` always applied,
    made kind-aware.  Old records (``build_id`` set, kind absent) are
    elf-or-unknown: the prefix rule, never an error.  Unknown kinds
    refuse the identity leg (see :func:`identity_anchor`) and anchor
    on the sha leg instead.
    """
    if isinstance(manifest_or_dict, dict):
        kind = manifest_or_dict.get("identity_kind")
        value = manifest_or_dict.get("build_id")
        sha = manifest_or_dict.get("binary_sha256")
    else:
        kind = getattr(manifest_or_dict, "identity_kind", None)
        value = getattr(manifest_or_dict, "build_id", None)
        sha = getattr(manifest_or_dict, "binary_sha256", None)
    anchor = identity_anchor(
        kind if isinstance(kind, str) else None,
        value if isinstance(value, str) else None,
    )
    if anchor is not None:
        return anchor
    return identity_anchor(KIND_SHA256, sha if isinstance(sha, str) else None)


def _is_macho_magic(head: bytes) -> bool:
    from packages.binary_analysis.macho import (
        FAT_MACHO_MAGICS,
        THIN_MACHO_MAGICS,
    )
    return head in THIN_MACHO_MAGICS or head in FAT_MACHO_MAGICS


__all__ = [
    "IDENTITY_KINDS",
    "KIND_ELF_BUILD_ID",
    "KIND_MACHO_UUID",
    "KIND_PE_GUID_AGE",
    "KIND_SHA256",
    "ContentIdentity",
    "content_identity",
    "identity_anchor",
    "manifest_anchor",
]
