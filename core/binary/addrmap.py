"""Normalized function identity (fid) across binary-analysis producers.

Every RE engine reports the same function at a different absolute
address (engines rebase PIE images differently: one loads at 0, one
at 0x100000), so addresses cannot join artifacts across tools, runs,
or stores. A ``fid`` normalises the identity::

    fid = <content-anchor>:<rel-vaddr>

where the content anchor identifies the MODULE (its GNU build-id,
else a SHA-256 content-hash prefix — the
:func:`packages.binary_analysis.function_cfg` cache-key family) and
the rel-vaddr is the function entry minus the module's RECORDED
image base.

Policy (fail-closed throughout):

* A producer that records no image base emits NO fid — consumers
  fall back to name matching. A guessed base mints wrong identities
  that silently join evidence to the wrong function.
* Cross-space translation prefers recorded bases on both sides;
  when exactly one side lacks a base it falls back to the empirical
  modal-delta estimator that already exists
  (:meth:`packages.ghidra.model.REDatabase._estimate_base_delta`) —
  one mechanism family, this module is its documented front door;
  otherwise there is no translation.
* Joins resolve exact fid first, then a bounded nearest-entry
  tolerance (flagged ``fid_fuzzy``), then a name fallback; misses
  are RECORDED (``fid-misses.json``) — a silently dropped
  seed/finding is the failure mode this module exists to prevent.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Hex length of the content anchor. Both directions: the full
# build-id / sha256 (40-64 hex) would make accidental collisions
# impossible but turns every report line and join key into noise;
# 8 hex (the compact sketch form) carries a 32-bit birthday risk
# once projects hold many modules plus per-version anchors. 16 hex
# = 64 bits keeps accidental collision negligible at any realistic
# module count. Length defends only against ACCIDENT: build-id
# bytes are attacker-chosen (a hostile module can copy another's
# build-id verbatim), so deliberate collision is out of scope for
# the anchor and is handled by provenance gates on the producers.
_ANCHOR_HEX_LEN = 16

# Nearest-entry tolerance for fuzzy fid joins, in bytes; the
# comparison is EXCLUSIVE (distance < window). Tools disagree on
# function entries on stripped/optimised binaries (thunk vs body,
# cold-split fragments, mis-detected starts). Both directions: a
# wider window rescues more entry-point disagreements but starts
# joining ADJACENT tiny functions; narrower misses real
# disagreements. PLT stubs sit 16 bytes apart, so an exclusive
# 16-byte window joins strictly inside one stub slot and can never
# reach the next slot's entry. Two candidates inside the window
# are AMBIGUOUS and refuse (mirrors the name path's duplicate
# refusal) — the miss log records them.
FID_FUZZY_WINDOW_BYTES = 16

_HEX_RUN_RE = re.compile(r"^[0-9a-f]{8,128}$")
_FID_RE = re.compile(r"^([0-9a-f]{8,64}):0x([0-9a-f]{1,16})$")
_OPERATION_RE = re.compile(r"^[a-z0-9_.-]{1,64}$")

MISSES_FILENAME = "fid-misses.json"

# Sentinel distinguishing "attribute absent" (shapes without the
# recorded marker, e.g. REDatabase/BinaryManifest) from a present
# falsy marker (degraded run — refuse).
_NO_MARKER = object()

# fid-misses.json growth caps. Both directions: uncapped, a hostile
# module with tens of thousands of near-miss functions turns the
# miss log into a disk-growth primitive; capped too tightly the log
# stops being an audit trail for exactly the runs that need it.
# 500 misses records every realistic join's residue; 200 operations
# covers a long multi-phase run while bounding the file. Keys are
# clipped and escaped exactly like values (a caller-shaped dict can
# smuggle hostile bytes in either position) and capped per entry.
# Byte-budget consistency (the reset-avoidance invariant): worst
# case one operation serialises to
# 500 x 8 x (64 + 200 + ~10 JSON overhead) ~= 1.1 MiB, so the 4 MiB
# keep-newest budget always retains at least the newest operation,
# and 4 MiB < the 8 MiB read bound — the load path can never see a
# file it refuses (which would silently reset the log).
_MAX_MISSES_PER_OPERATION = 500
_MAX_OPERATIONS = 200
_MAX_MISS_TEXT_CHARS = 200
_MAX_MISS_KEY_CHARS = 64
_MAX_KEYS_PER_MISS = 8
_MAX_MISSES_FILE_BYTES = 4 * 1024 * 1024
_MISSES_READ_BOUND_BYTES = 8 * 1024 * 1024


# ---------------------------------------------------------------------------
# Content anchor
# ---------------------------------------------------------------------------

def module_anchor(
    *,
    build_id: str | None = None,
    binary_sha256: str | None = None,
) -> str | None:
    """Anchor prefix from already-known identifiers (no file I/O).

    Prefers the build-id, else the SHA-256 — the same preference the
    function-CFG cache key family uses. Returns ``None`` when
    neither value is a plausible hex run (fail-closed: junk from a
    planted artifact must not mint identities).
    """
    for candidate in (build_id, binary_sha256):
        if isinstance(candidate, str):
            lowered = candidate.strip().lower()
            if _HEX_RUN_RE.fullmatch(lowered):
                return lowered[:_ANCHOR_HEX_LEN]
    return None


def content_anchor(
    binary_path: str | Path | None,
    *,
    binary_sha256: str | None = None,
) -> str | None:
    """Derive the module anchor for ``binary_path``.

    Build-id via the existing extractor
    (:func:`core.analysis.binary_oracle.read_build_id`, sandboxed
    binutils), else the streamed content hash, else a caller-supplied
    known digest, else ``None``.
    """
    build_id: str | None = None
    sha: str | None = None
    if binary_path is not None:
        path = Path(binary_path)
        # is_file() gate: read_build_id spawns a sandboxed readelf,
        # and the sandbox refuses (BaseException, by design) rather
        # than degrade when asked to pin a nonexistent target — an
        # absent binary is an anchor miss here, not a sandbox event.
        if path.is_file():
            from core.sandbox.errors import SandboxSetupError
            try:
                from core.analysis.binary_oracle import read_build_id
                build_id = read_build_id(path)
            except SandboxSetupError as exc:
                # Named explicitly (the sandbox errors are
                # BaseException so blanket handlers cannot silently
                # swallow them): the anchor probe is enrichment, and
                # the sha256 fallback below needs no subprocess — a
                # sandbox-refusing host degrades loudly to the
                # content-hash anchor instead of aborting the run.
                logger.warning(
                    "content_anchor: sandboxed build-id probe refused "
                    "(%s) — falling back to the content hash", exc,
                )
                build_id = None
            except Exception:  # noqa: BLE001 — build-id is an optimisation; the content hash is the fallback identity
                build_id = None
            if build_id is None:
                try:
                    from core.hash import sha256_file
                    sha = sha256_file(path)
                except OSError:
                    sha = None
    return module_anchor(
        build_id=build_id,
        binary_sha256=sha or binary_sha256,
    )


# ---------------------------------------------------------------------------
# Image base
# ---------------------------------------------------------------------------

def _parse_base(value: Any) -> int | None:
    """Coerce a recorded image-base value to an int.

    Producers disagree on the wire type: the Ghidra export and the
    live r2 context carry ints, the serialised context map carries a
    hex string (``"0x100000"``), absent/None/empty means NOT
    recorded. 0 is a legitimately recorded base (relocatable
    objects), so only genuine absence maps to ``None``.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(text, 16) if text.lower().startswith("0x") else int(text)
        except ValueError:
            return None
    return None


def image_base(manifest_or_db: Any) -> int | None:
    """Recorded image base of a producer artifact, or ``None``.

    Accepts the shapes the binary lane actually produces:

    * ``BinaryManifest`` / ``BinaryContextMap``-like objects — the
      ``image_base`` attribute;
    * ``REDatabase``-like objects — ``metadata["image_base"]``
      (key absent ⇒ the producer recorded no base, e.g. the
      objdump fallback importer);
    * serialised dicts of either — ``image_base`` key, else
      ``metadata.image_base``.

    ``None`` means "no base recorded" and every fid-minting caller
    must treat it as a refusal, never substitute 0.

    Shapes that carry an explicit ``image_base_recorded`` marker
    (the live context object and its serialised map) are honoured
    FIRST: a present-and-falsy marker means the ``image_base``
    value is a dataclass/serialiser default, not a fact — reading
    past it would mint base-0 identities for exactly the degraded
    runs the marker exists to flag.
    """
    if manifest_or_db is None:
        return None
    if isinstance(manifest_or_db, dict):
        if (
            "image_base_recorded" in manifest_or_db
            and not manifest_or_db["image_base_recorded"]
        ):
            return None
        if "image_base" in manifest_or_db:
            return _parse_base(manifest_or_db.get("image_base"))
        metadata = manifest_or_db.get("metadata")
        if isinstance(metadata, dict) and "image_base" in metadata:
            return _parse_base(metadata.get("image_base"))
        return None
    metadata = getattr(manifest_or_db, "metadata", None)
    if isinstance(metadata, dict) and "image_base" in metadata:
        return _parse_base(metadata.get("image_base"))
    if hasattr(manifest_or_db, "image_base"):
        marker = getattr(manifest_or_db, "image_base_recorded", _NO_MARKER)
        if marker is not _NO_MARKER and not marker:
            return None
        return _parse_base(manifest_or_db.image_base)
    return None


# ---------------------------------------------------------------------------
# fid mint / parse
# ---------------------------------------------------------------------------

def make_fid(anchor: str | None, address: Any, base: int | None) -> str | None:
    """Mint ``<anchor>:0x<rel-vaddr>``; ``None`` on any missing leg.

    A negative rel-vaddr means the recorded base does not describe
    this address's space (wrong-binary metadata, or a planted base)
    — refuse rather than mint a wrong identity. The anchor is
    shape-checked so a junk anchor from a planted artifact cannot
    mint fids that every reader's strict parser then rejects.
    """
    if base is None:
        return None
    # Normalise through module_anchor so a caller holding the FULL
    # build-id/sha256 mints the same truncated anchor every other
    # producer mints — full-length anchors would never join.
    normalised = module_anchor(build_id=anchor if isinstance(anchor, str) else None)
    if normalised is None:
        return None
    anchor = normalised
    if isinstance(address, bool) or not isinstance(address, int):
        return None
    rel = address - base
    if rel < 0:
        return None
    return f"{anchor}:0x{rel:x}"


def to_fid(
    addr: Any,
    manifest_or_db: Any = None,
    *,
    anchor: str | None = None,
    base: int | None = None,
) -> str | None:
    """fid for ``addr`` in a producer's address space.

    The anchor and base default from ``manifest_or_db`` (recorded
    values only — see :func:`image_base`); explicit keyword values
    win, letting hot loops resolve them once.
    """
    if base is None:
        base = image_base(manifest_or_db)
    if anchor is None and manifest_or_db is not None:
        if isinstance(manifest_or_db, dict):
            anchor = module_anchor(
                build_id=manifest_or_db.get("build_id"),
                binary_sha256=manifest_or_db.get("binary_sha256"),
            )
        else:
            anchor = module_anchor(
                build_id=getattr(manifest_or_db, "build_id", None),
                binary_sha256=getattr(manifest_or_db, "binary_sha256", None),
            )
    return make_fid(anchor, addr, base)


def from_fid(fid: Any) -> tuple[str, int] | None:
    """``(anchor, rel_vaddr)`` for a well-formed fid, else ``None``.

    Strict shape check — fids ride through JSON artifacts a hostile
    run directory can pre-stage, so junk parses to ``None`` rather
    than a partial identity.
    """
    if not isinstance(fid, str):
        return None
    match = _FID_RE.fullmatch(fid.strip().lower())
    if not match:
        return None
    return match.group(1), int(match.group(2), 16)


def normalise_fid(value: Any) -> str | None:
    """Round-trip a serialised fid through the strict parser.

    For ``from_dict`` seams: a fid field in an on-disk artifact is
    only as trustworthy as its shape — anything malformed collapses
    to ``None`` (absent), never rides raw into consumers.
    """
    parsed = from_fid(value)
    if parsed is None:
        return None
    anchor, rel = parsed
    return f"{anchor}:0x{rel:x}"


def passthrough_fid(record: Any) -> dict[str, str]:
    """Additive ``{"fid": ...}`` fragment forwarding a RECORD's fid.

    For consumers that copy function records out of disk-loadable
    artifacts (context maps in a run dir a hostile process could
    pre-stage): the fid rides through the strict parser, so junk
    collapses to absent instead of propagating verbatim.
    """
    if not isinstance(record, dict):
        return {}
    fid = normalise_fid(record.get("fid"))
    return {"fid": fid} if fid else {}


def stamp_redb_fids(db: Any, *, anchor: str | None = None) -> int:
    """Mint fids onto an RE database's function records in place.

    Producer seam for the import parsers: requires a RECORDED image
    base on the database (fail-closed — the objdump fallback importer
    records none and stays fid-free) and a derivable module anchor
    (caller-supplied, else probed from ``db.binary_path``). Existing
    fids are kept (round-tripped databases re-stamp idempotently).
    Returns the number of records stamped.
    """
    base = image_base(db)
    if base is None:
        return 0
    if anchor is None:
        anchor = content_anchor(getattr(db, "binary_path", None))
    if not anchor:
        return 0
    stamped = 0
    for func in _functions(db):
        if getattr(func, "fid", None):
            continue
        fid = make_fid(anchor, getattr(func, "address", None), base)
        if fid is not None:
            func.fid = fid
            stamped += 1
    return stamped


# ---------------------------------------------------------------------------
# Cross-space translation
# ---------------------------------------------------------------------------

def _functions(db: Any) -> list[Any]:
    functions = getattr(db, "functions", None)
    return functions if isinstance(functions, list) else []


def _named_overlap_count(a: Any, b: Any) -> int:
    """Count same-named non-auto functions shared by two databases.

    Mirrors the eligibility precondition of the modal-delta
    estimator (non-auto names only); the vote arithmetic itself
    stays in :meth:`REDatabase._estimate_base_delta`.
    """
    names_a = {
        f.name for f in _functions(a)
        if getattr(f, "name", "") and not getattr(f, "is_auto_named", False)
    }
    if not names_a:
        return 0
    return sum(
        1 for f in _functions(b)
        if getattr(f, "name", "") in names_a
        and not getattr(f, "is_auto_named", False)
    )


def _resolve_address(name_or_addr: Any, src: Any) -> int | None:
    """int address passthrough; a name resolves against ``src``'s
    function list (unique, non-auto names only — a tool-synthetic
    ``FUN_...``/``fcn....`` name is base-dependent and never a
    cross-space identity)."""
    if isinstance(name_or_addr, bool):
        return None
    if isinstance(name_or_addr, int):
        return name_or_addr
    if not isinstance(name_or_addr, str) or not name_or_addr:
        return None
    matches = [
        f for f in _functions(src)
        if getattr(f, "name", None) == name_or_addr
        and not getattr(f, "is_auto_named", False)
    ]
    if len(matches) != 1:
        return None
    address = matches[0].address
    if isinstance(address, bool) or not isinstance(address, int):
        return None
    return address


def translate(name_or_addr: int | str, src: Any, dst: Any) -> int | None:
    """Translate an address (or unique symbol name) from ``src``'s
    address space into ``dst``'s.

    Precedence:

    1. Both sides carry a RECORDED image base → pure arithmetic.
    2. Exactly one side lacks a base AND the two databases share
       named symbols → the existing empirical estimator
       (``REDatabase._estimate_base_delta``, modal same-name delta
       with its own vote floor) supplies the delta.
    3. Otherwise ``None`` — no translation, fail-closed. A guessed
       delta joins evidence to the wrong function.
    """
    addr = _resolve_address(name_or_addr, src)
    if addr is None:
        return None
    base_src = image_base(src)
    base_dst = image_base(dst)
    if base_src is not None and base_dst is not None:
        return addr - base_src + base_dst
    if (base_src is None) == (base_dst is None):
        return None
    estimator = getattr(dst, "_estimate_base_delta", None)
    if not callable(estimator):
        return None
    if _named_overlap_count(src, dst) < 2:
        return None
    delta = estimator(src)
    if delta == 0:
        # The estimator's contract folds "no consistent evidence"
        # into 0. Accept a zero delta only when it is witnessed by
        # actual same-name address agreement — otherwise 0 is a
        # guess wearing a number.
        agreeing = 0
        dst_addrs = {
            f.name: f.address for f in _functions(dst)
            if getattr(f, "name", "")
            and not getattr(f, "is_auto_named", False)
        }
        for f in _functions(src):
            if getattr(f, "is_auto_named", False):
                continue
            other = dst_addrs.get(getattr(f, "name", ""))
            if other is not None and other == getattr(f, "address", None):
                agreeing += 1
        if agreeing < 2:
            return None
    return addr + delta


# ---------------------------------------------------------------------------
# Join with miss policy
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FidMatch:
    """One resolved join. ``method`` grades the match: ``exact``
    (fid equality), ``fid_fuzzy`` (nearest entry within
    :data:`FID_FUZZY_WINDOW_BYTES`, ``distance`` bytes off), or
    ``name`` (name fallback — no fid on one side)."""

    payload: Any
    method: str
    distance: int = 0


def _looks_tool_synthetic(name: str) -> bool:
    """Placeholder-name check via the single existing definition.

    Lazy import: this module is core-level and
    ``packages.ghidra.model`` is stdlib-only, so the import is safe;
    if it is unavailable the name fallback refuses (fail-closed)
    rather than matching base-dependent placeholder names.
    """
    try:
        from packages.ghidra.model import looks_tool_synthetic
    except ImportError:  # pragma: no cover - packages tree absent
        return True
    return looks_tool_synthetic(name)


class FidIndex:
    """Join-side index over one producer's function records.

    Resolution order per the miss policy: exact fid → bounded
    nearest-entry fuzzy (flagged) → unique non-placeholder name.
    """

    def __init__(self) -> None:
        self._exact: dict[str, Any] = {}
        self._by_anchor: dict[str, list[tuple[int, Any]]] = {}
        self._by_name: dict[str, Any] = {}
        self._ambiguous_names: set[str] = set()

    def add(
        self,
        payload: Any,
        *,
        fid: Any = None,
        name: str | None = None,
    ) -> None:
        parsed = from_fid(fid)
        if parsed is not None:
            anchor, rel = parsed
            self._exact.setdefault(f"{anchor}:0x{rel:x}", payload)
            self._by_anchor.setdefault(anchor, []).append((rel, payload))
        if isinstance(name, str) and name and not _looks_tool_synthetic(name):
            if name in self._by_name:
                self._ambiguous_names.add(name)
            else:
                self._by_name[name] = payload

    def resolve(
        self,
        *,
        fid: Any = None,
        name: str | None = None,
    ) -> FidMatch | None:
        parsed = from_fid(fid)
        if parsed is not None:
            anchor, rel = parsed
            exact = self._exact.get(f"{anchor}:0x{rel:x}")
            if exact is not None:
                return FidMatch(payload=exact, method="exact")
            in_window: list[tuple[int, Any]] = [
                (abs(candidate_rel - rel), payload)
                for candidate_rel, payload in self._by_anchor.get(anchor, ())
                if abs(candidate_rel - rel) < FID_FUZZY_WINDOW_BYTES
            ]
            # >=2 candidates in-window is AMBIGUOUS: picking the
            # nearest silently joins evidence to whichever adjacent
            # tiny function the tools' entry disagreement landed on.
            # Refuse, exactly like the name path refuses duplicate
            # names — the caller's miss recording keeps it visible.
            if len(in_window) == 1:
                distance, payload = in_window[0]
                return FidMatch(
                    payload=payload, method="fid_fuzzy", distance=distance,
                )
        if (
            isinstance(name, str)
            and name
            and name not in self._ambiguous_names
            and not _looks_tool_synthetic(name)
        ):
            payload = self._by_name.get(name)
            if payload is not None:
                return FidMatch(payload=payload, method="name")
        return None


# ---------------------------------------------------------------------------
# Miss recording
# ---------------------------------------------------------------------------

def _clip_miss_text(value: Any) -> str:
    """Escape-at-capture for miss-record strings: function names and
    fids in a miss record originate in a hostile binary and the file
    is a jq-to-terminal surface."""
    from core.security.log_sanitisation import escape_nonprintable
    return escape_nonprintable(str(value))[:_MAX_MISS_TEXT_CHARS]


def record_fid_misses(
    out_dir: str | Path,
    operation: str,
    misses: list[dict[str, Any]],
) -> Path | None:
    """Append one join operation's misses to ``fid-misses.json``.

    Read-modify-write under the run-artifact lock (the binary run
    dir's existing serialisation seam) so concurrent joiners never
    silently drop each other's records. Empty miss lists write
    nothing. Never raises: a miss log must not fail the join that
    produced it — but failures are logged loudly, because a lost
    miss record is itself the silent-drop failure mode.
    """
    if not misses:
        return None
    out_path = Path(out_dir)
    target = out_path / MISSES_FILENAME
    if not _OPERATION_RE.fullmatch(operation or ""):
        operation = "unknown"
    entries = []
    for item in misses[:_MAX_MISSES_PER_OPERATION]:
        if not isinstance(item, dict):
            continue
        entry: dict[str, str] = {}
        for key, value in item.items():
            if not isinstance(key, str):
                continue
            if len(entry) >= _MAX_KEYS_PER_MISS:
                break
            # Keys get the same escape+clip as values: both
            # positions are caller-shaped and can carry hostile
            # binary bytes into a jq-to-terminal artifact.
            entry[_clip_miss_text(key)[:_MAX_MISS_KEY_CHARS]] = (
                _clip_miss_text(value)
            )
        entries.append(entry)
    record = {
        "operation": operation,
        "count": len(misses),
        "recorded": len(entries),
        "misses": entries,
    }
    try:
        import contextlib
        lock_ctx: Any
        try:
            from packages.binary_analysis._artifact_lock import (
                run_artifacts_lock,
            )
            lock_ctx = run_artifacts_lock(out_path)
        except ImportError:  # pragma: no cover - packages tree absent
            lock_ctx = contextlib.nullcontext()
        with lock_ctx:
            document: dict[str, Any] = {"schema_version": 1, "operations": []}
            if target.is_file():
                try:
                    from core.json.bounded import load_json_bounded
                    existing = load_json_bounded(
                        target, max_bytes=_MISSES_READ_BOUND_BYTES,
                    )
                    if isinstance(existing, dict) and isinstance(
                        existing.get("operations"), list,
                    ):
                        document = existing
                except (OSError, ValueError):
                    logger.warning(
                        "fid-misses: existing %s unreadable — starting a "
                        "fresh document", target,
                    )
            operations = document.get("operations")
            if not isinstance(operations, list):
                operations = []
            operations.append(record)
            # Keep the newest operations (the current run's joins are
            # the ones an operator is debugging) under BOTH caps: the
            # count cap and the byte budget, newest-first — see the
            # budget-consistency arithmetic at the constants. Without
            # the byte trim, worst-case growth crossed the read bound
            # and the next append silently reset the whole log.
            import json as _json
            kept: list[Any] = []
            budget = _MAX_MISSES_FILE_BYTES
            for op in reversed(operations[-_MAX_OPERATIONS:]):
                size = len(_json.dumps(op))
                if kept and size > budget:
                    break
                kept.append(op)
                budget -= size
            kept.reverse()
            document["operations"] = kept
            document["schema_version"] = 1
            from core.json import save_json
            save_json(target, document)
    except OSError:
        logger.warning(
            "fid-misses: could not record %d miss(es) for %s in %s",
            len(misses), operation, out_path, exc_info=True,
        )
        return None
    return target


__all__ = [
    "FID_FUZZY_WINDOW_BYTES",
    "MISSES_FILENAME",
    "FidIndex",
    "FidMatch",
    "content_anchor",
    "from_fid",
    "image_base",
    "make_fid",
    "module_anchor",
    "normalise_fid",
    "passthrough_fid",
    "record_fid_misses",
    "stamp_redb_fids",
    "to_fid",
    "translate",
]
