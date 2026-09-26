"""Turn SMT sat witnesses into AFL++ seed inputs and dictionary tokens.

Two pipelines persist solver witnesses that today only the exploit LLM
reads:

* /agentic Tier 4 — ``autonomous_analysis_report.json`` →
  ``results[].smt_witness`` with ``model`` (``{name: int}``),
  ``anon_var_map`` (``_anon_N`` → original call subexpression, e.g.
  ``strlen(argv[1])``), and the weakest-precondition fields.
* /validate Stage B — ``attack-paths.json`` → per-path ``smt_model``
  (``{name: int}``) written by the mechanical SMT sweep.

A witness assigns integers to *source-level variables* — it is not a
wire-format input, so this module only synthesizes artifacts with a
mechanical mapping:

* **length rule** — a variable whose (decoded) name has length/count/
  size semantics becomes a seed file of exactly that many bytes
  (clamped to ``SEED_LEN_CAP``, clamping recorded, never silent).
* **magic-value rule** — every integer value becomes an AFL dictionary
  token (little-endian, minimal fixed width) plus a small standalone
  seed file holding the raw encoding. Dictionaries are the honest
  general-purpose channel for magic values: AFL splices tokens at
  arbitrary offsets, which is exactly the uncertainty we have.

There is no template-splice rule: the existing corpus machinery
(``seed_corpus.py``) records name/kind/hash per seed but no field
offsets, so a value-at-offset splice has no mechanical basis today.

Every artifact carries a manifest entry naming the producing finding /
attack path, the variable, and the witness value, so a crash found
from one is traceable back to the finding that predicted it.

Plant containment: every filesystem touch this flow makes under the
run dir goes through a predictable name the previous campaign's
sandboxed target could occupy, and this module runs in the
UNSANDBOXED parent. Containment sits at the flow entry —
:func:`ensure_real_seed_dir` vets the seed-dir name itself before any
write (a plant there redirects or kills EVERY artifact at once) — and
per name behind it: seeds are O_EXCL/O_NOFOLLOW exclusive creates,
the dictionary writes and the manifest write refuse a plant loudly
and skip. On every plant shape the posture is the same: warn (escaped,
bounded rendering), skip the touch, leave the plant in place —
removing a target-planted object is a destructive step this flow
never takes — and never crash the /fuzz run.
"""

from __future__ import annotations

import logging
import os
import re
import stat
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.atomic_fs import write_new_bytes, write_text_atomically
from core.json import load_json, save_json
from core.run.safe_io import safe_run_mkdir
from core.security.log_sanitisation import sanitise_for_terminal
from core.source import read_text_capped

# Analysis-report / attack-path artifacts are RAPTOR-written run
# output — the audit-artifact budget class.
_MAX_ARTIFACT_BYTES = 64 * 1024 * 1024

logger = logging.getLogger(__name__)

# A seed of exactly-witnessed length: cap so a witness like
# len=2**63-1 cannot fill the disk. Clamps are recorded per-seed.
SEED_LEN_CAP = 1024 * 1024

# Bounds against a hostile or degenerate producer file. All are
# recorded in the manifest when hit — no silent truncation.
MAX_WITNESSES = 200
MAX_SEEDS = 512
MAX_DICT_ENTRIES = 1024

# Read bound for the two dictionary files ``merge_witness_dict``
# consumes out of the reused run dir. Downward pressure: both names
# are predictable and the dir was writable by the previous campaign's
# sandboxed target, so an unbounded read of a planted file is a
# parent-process memory lever — past the cap the merge refuses.
# Upward pressure: AFL-style dictionaries are one short token per
# line (MAX_DICT_ENTRIES witness tokens render well under 256 KiB),
# and audit-mined operator dictionaries stay orders of magnitude
# under 4 MiB — a legitimate dict must never hit the refusal.
MAX_DICT_FILE_CHARS = 4 * 1024 * 1024

SEED_DIR_NAME = "smt-seeds"
MANIFEST_NAME = "smt-seeds-manifest.json"

# Matches identifier tokens with length/count/size semantics, either
# as the whole name or as an underscore-delimited component
# (buf_len, nmemb, data_size, ...).
_LENGTH_TOKEN_RE = re.compile(
    r"(?:^|_)(len|length|size|sz|count|cnt|num|nmemb|nbytes|bytes)(?:_|$)",
    re.IGNORECASE,
)

# Decoded anon labels that denote a length-of-input quantity.
_LENGTH_CALL_RE = re.compile(r"^\s*(strlen|strnlen|wcslen|sizeof)\s*\(")

# Deterministic filler for length-rule seeds.
_FILL_BYTE = b"A"


@dataclass
class WitnessRecord:
    """One witness model plus provenance."""

    source_file: str
    origin_id: str  # finding_id or attack-path id
    model: dict[str, int]
    anon_var_map: dict[str, str] = field(default_factory=dict)


def _decoded_name(var: str, anon_var_map: dict[str, str]) -> str:
    return anon_var_map.get(var, var)


def _is_length_like(label: str) -> bool:
    if _LENGTH_CALL_RE.match(label):
        return True
    # Strip a call-expression wrapper down to its identifier head for
    # token matching (e.g. ``buf_len`` inside ``(size_t)buf_len``).
    ident = re.sub(r"[^A-Za-z0-9_]", "_", label)
    return bool(_LENGTH_TOKEN_RE.search(ident))


def _coerce_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def _le_encoding(value: int) -> bytes | None:
    """Little-endian encoding at the minimal fixed width (4 or 8 bytes).

    Negative values are two's-complement at the same width. Values
    outside a 64-bit range have no defined wire form here.
    """
    for fmt, lo, hi in (("<i", -(2**31), 2**31 - 1), ("<q", -(2**63), 2**63 - 1)):
        if lo <= value <= hi:
            return struct.pack(fmt, value)
    for fmt, hi in (("<I", 2**32 - 1), ("<Q", 2**64 - 1)):
        if 0 <= value <= hi:
            return struct.pack(fmt, value)
    return None


def _dict_escape(data: bytes) -> str:
    out = []
    for b in data:
        if 32 <= b <= 126 and b not in (0x22, 0x5C):  # printable, not " or \
            out.append(chr(b))
        else:
            out.append(f"\\x{b:02x}")
    return "".join(out)


def _sanitize_token_name(label: str) -> str:
    name = re.sub(r"[^A-Za-z0-9_]", "_", label).strip("_") or "var"
    return name[:64]


def _write_seed_exclusive(seed_path: Path, data: bytes) -> str | None:
    """Exclusive, symlink-refusing seed write. Returns a skip reason
    for the manifest on refusal, None on success.

    O_CREAT|O_EXCL|O_NOFOLLOW via the shared helper: the seed dir is
    inside the (reused, target-writable) run dir, so anything already
    occupying a deterministic seed name — including a dangling
    symlink, which passes ``exists() == False`` — fails closed with a
    manifest record instead of being followed or overwritten.
    """
    try:
        write_new_bytes(seed_path, data)
    except FileExistsError:
        return "seed filename collision"
    except OSError as exc:
        return f"seed write refused: {type(exc).__name__}"
    return None


def ensure_real_seed_dir(seed_dir: str | Path) -> str | None:
    """Entry containment for the seed dir: create it, or accept only a
    pre-existing REAL directory. Returns a refusal reason on any plant
    shape, ``None`` when the directory is safe to use.

    The seed dir sits at a predictable name (``SEED_DIR_NAME``) inside
    the reused run dir the previous campaign's sandboxed target could
    write, and every artifact of the ``--from-smt-witness`` flow —
    built-in corpus seeds, witness seeds, ``smt-witness.dict``, the
    manifest — is written through this name by the unsandboxed parent,
    which then reads the campaign corpus back through it. The old
    ``mkdir(parents=True, exist_ok=True)`` was the wrong gate twice
    over:

    * a planted regular FILE or DANGLING SYMLINK raised
      ``FileExistsError`` (``exist_ok`` tolerates only a real
      directory) — uncaught through the bare /fuzz CLI handler, the
      whole run died before any campaign;
    * a planted SYMLINK to an attacker-chosen DIRECTORY passed
      silently (CPython's ``exist_ok`` re-check is ``is_dir()``, which
      FOLLOWS symlinks), so the parent wrote all seeds, the
      dictionary, and the manifest into the attacker's directory —
      ``save_json``'s ``os.replace`` CLOBBERING anything there named
      like the manifest — and the campaign corpus was read back
      through the attacker's directory.

    Delegates to :func:`core.run.safe_io.safe_run_mkdir` — the same
    O_NOFOLLOW-honest create-or-verify the run dir itself gets one
    level up: absent → created ``0o700`` (fchmod through an
    ``O_DIRECTORY | O_NOFOLLOW`` handle, never by name); pre-existing
    real directory owned by the current user and not world-writable →
    accepted; ANY other occupant of the name (regular file, dangling
    symlink, symlink to a directory, FIFO, foreign or world-writable
    dir) → refused. Callers refuse loudly and skip every write AND
    read under the name — ``read_text_capped`` hardens only the final
    component, so a symlinked seed dir would still redirect the
    dictionary read-back through its parent — and leave the plant in
    place.
    """
    seed_dir = Path(seed_dir)
    try:
        seed_dir.parent.mkdir(parents=True, exist_ok=True)
        safe_run_mkdir(seed_dir)
    except OSError as exc:
        # UnsafeRunDirError is a PermissionError → OSError; a failed
        # parent mkdir (planted file on the parent path) lands here
        # too. The reason feeds the manifest and the log site.
        return f"{type(exc).__name__}: {exc}"
    return None


def collect_witnesses(source_dir: Path) -> tuple[list[WitnessRecord], list[dict]]:
    """Scan a run output dir for witness records from both producers.

    Returns (records, skipped) — skipped entries carry a reason so the
    caller's summary never hides a drop.
    """
    source_dir = Path(source_dir)
    records: list[WitnessRecord] = []
    skipped: list[dict] = []

    report = source_dir / "autonomous_analysis_report.json"
    if report.is_file():
        try:
            data = load_json(
                report, strict=True, max_bytes=_MAX_ARTIFACT_BYTES,
            )
            if not isinstance(data, dict):
                # List-shaped (or otherwise non-object) report: the
                # .get() walk below would raise — record the drop like
                # any other unreadable file.
                msg = f"non-object JSON ({type(data).__name__})"
                raise ValueError(msg)
            for result in data.get("results") or []:
                if not isinstance(result, dict):
                    continue
                witness = result.get("smt_witness") or {}
                model = witness.get("model") or {}
                if not model:
                    continue
                records.append(WitnessRecord(
                    source_file=report.name,
                    origin_id=str(result.get("finding_id") or "unknown"),
                    model=dict(model),
                    anon_var_map=dict(witness.get("anon_var_map") or {}),
                ))
        except (ValueError, OSError) as exc:
            skipped.append({"file": report.name, "reason": f"unreadable: {exc}"})

    paths_file = source_dir / "attack-paths.json"
    if paths_file.is_file():
        try:
            data = load_json(
                paths_file, strict=True, max_bytes=_MAX_ARTIFACT_BYTES,
            )
            for path in data if isinstance(data, list) else []:
                if not isinstance(path, dict):
                    continue
                model = path.get("smt_model") or {}
                if not model:
                    continue
                records.append(WitnessRecord(
                    source_file=paths_file.name,
                    origin_id=str(path.get("id") or "unknown"),
                    model=dict(model),
                ))
        except (ValueError, OSError) as exc:
            skipped.append({"file": paths_file.name, "reason": f"unreadable: {exc}"})

    if not records and not skipped and not report.is_file() and not paths_file.is_file():
        skipped.append({
            "file": str(source_dir),
            "reason": "no autonomous_analysis_report.json or attack-paths.json found",
        })

    if len(records) > MAX_WITNESSES:
        skipped.append({
            "file": str(source_dir),
            "reason": f"witness cap: kept first {MAX_WITNESSES} of {len(records)}",
        })
        records = records[:MAX_WITNESSES]

    return records, skipped


def synthesize_seeds(
    records: list[WitnessRecord],
    out_dir: Path,
    *,
    skipped: list[dict] | None = None,
) -> dict:
    """Write seed files, a dictionary, and a manifest under ``out_dir``.

    Returns the manifest dict. ``skipped`` entries from collection are
    carried into the manifest so the audit trail is complete.

    Plant containment (the run dir is reused and was writable by the
    previous campaign's sandboxed target):

    * ``out_dir`` itself is vetted by :func:`ensure_real_seed_dir`
      before ANY write. On refusal (file / dangling symlink /
      symlink-to-directory / any non-real-dir occupant of the name)
      NOTHING is written — the returned manifest carries the reason
      under ``seed_dir_refused`` plus a ``skipped`` record, and the
      plant is left in place.
    * A directory planted at the MANIFEST name inside a real seed dir
      is refused loudly and the manifest file is skipped —
      ``os.replace`` cannot swap a directory and this writer never
      removes a target-planted tree. Seeds and the dictionary are
      unaffected by that shape, and the returned in-memory manifest
      still drives the run (the earlier claim that seeds AND the
      manifest always survive a plant was wrong for exactly this
      shape: the ``IsADirectoryError`` used to crash the whole run).
    """
    out_dir = Path(out_dir)
    refusal = ensure_real_seed_dir(out_dir)
    if refusal is not None:
        logger.warning(
            "refusing SMT witness synthesis: %s is not usable as the "
            "seed dir (%s) — a planted object in the reused run dir? "
            "left in place; nothing written",
            sanitise_for_terminal(str(out_dir)),
            sanitise_for_terminal(refusal, max_len=200))
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "witnesses": len(records),
            "seed_count": 0,
            "dict_entries": 0,
            "dict_file": None,
            "caps_hit": [],
            "seeds": [],
            "skipped": [
                *(skipped or []),
                {"file": str(out_dir),
                 "reason": f"seed dir refused: {refusal}"},
            ],
            "seed_dir_refused": refusal,
        }

    seeds: list[dict] = []
    dict_entries: dict[str, str] = {}  # token name -> escaped value
    all_skipped: list[dict] = list(skipped or [])
    caps_hit: list[str] = []

    for idx, rec in enumerate(records):
        for var, raw in sorted(rec.model.items()):
            value = _coerce_int(raw)
            provenance = {
                "source_file": rec.source_file,
                "origin_id": rec.origin_id,
                "variable": var,
                "value": raw,
            }
            if value is None:
                all_skipped.append({**provenance, "reason": "non-integer value"})
                continue

            label = _decoded_name(var, rec.anon_var_map)
            token_base = _sanitize_token_name(label)

            # Length rule: a seed of exactly the witnessed length.
            if _is_length_like(label) and value > 0:
                if len(seeds) >= MAX_SEEDS:
                    caps_hit.append("seeds")
                else:
                    clamped = value > SEED_LEN_CAP
                    length = min(value, SEED_LEN_CAP)
                    name = f"smt_{idx:03d}_{token_base}_len{value}"[:120]
                    seed_path = out_dir / name
                    # Exclusive create, not exists()-then-write: a
                    # pre-existing file must never be silently
                    # overwritten and then listed in the manifest —
                    # and a planted DANGLING symlink passes
                    # exists() == False, making the plain write_bytes
                    # create the attacker-chosen target. Anything
                    # occupying the name refuses with a skip record.
                    skip_reason = _write_seed_exclusive(
                        seed_path, _FILL_BYTE * length)
                    if skip_reason is not None:
                        all_skipped.append({
                            **provenance,
                            "reason": skip_reason,
                            "seed": name,
                        })
                    else:
                        seeds.append({
                            **provenance,
                            "seed": name,
                            "rule": "length",
                            "bytes": length,
                            "clamped": clamped,
                        })
            elif _is_length_like(label) and value <= 0:
                all_skipped.append({
                    **provenance,
                    "reason": "length-like variable with non-positive value",
                })

            # Magic-value rule: dictionary token + tiny raw seed.
            encoded = _le_encoding(value)
            if encoded is None:
                all_skipped.append({
                    **provenance, "reason": "value outside 64-bit range",
                })
                continue
            if len(dict_entries) < MAX_DICT_ENTRIES:
                dict_entries[f"smt_{token_base}_{value & 0xFFFFFFFFFFFFFFFF:x}"] = (
                    _dict_escape(encoded)
                )
            else:
                caps_hit.append("dict")
            if len(seeds) >= MAX_SEEDS:
                caps_hit.append("seeds")
            else:
                name = f"smt_{idx:03d}_{token_base}_raw"[:120]
                seed_path = out_dir / name
                # Exclusive create (see the length rule above): every
                # dropped artifact is recorded — the manifest promises
                # no silent truncation — and a planted dangling
                # symlink can never route the write elsewhere.
                skip_reason = _write_seed_exclusive(seed_path, encoded)
                if skip_reason is None:
                    seeds.append({
                        **provenance,
                        "seed": name,
                        "rule": "magic-value",
                        "bytes": len(encoded),
                        "clamped": False,
                    })
                else:
                    all_skipped.append({
                        **provenance,
                        "reason": skip_reason,
                        "seed": name,
                    })

    dict_path = None
    if dict_entries:
        dict_path = out_dir / "smt-witness.dict"
        lines = [f'{name}="{value}"' for name, value in sorted(dict_entries.items())]
        # Atomic write: the run dir is reused and target-writable —
        # os.replace over a planted symlink replaces the symlink
        # itself, never follows it. Same write containment as the
        # merge in merge_witness_dict: os.replace cannot swap a
        # planted DIRECTORY (and removing a target-planted tree is a
        # destructive step never taken here) — warn once and ship the
        # manifest without a dictionary file rather than crash the
        # /fuzz run.
        try:
            write_text_atomically(dict_path, "\n".join(lines) + "\n")
        except OSError as exc:
            logger.warning(
                "witness dictionary not written (%s: %s) — a planted "
                "object at %s? left in place; seeds are unaffected and "
                "the manifest write is guarded on its own",
                type(exc).__name__,
                sanitise_for_terminal(str(exc), max_len=200),
                sanitise_for_terminal(str(dict_path)))
            dict_path = None

    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "witnesses": len(records),
        "seed_count": len(seeds),
        "dict_entries": len(dict_entries),
        "dict_file": dict_path.name if dict_path else None,
        "caps_hit": sorted(set(caps_hit)),
        "seeds": seeds,
        "skipped": all_skipped,
        "seed_dir_refused": None,
    }
    # Same containment as the dictionary write above, for the same
    # reason: the manifest name is exactly as predictable, and
    # save_json's os.replace cannot swap a planted DIRECTORY
    # (IsADirectoryError used to propagate up through the bare /fuzz
    # CLI handler and kill the run before any campaign). Warn and
    # skip; the in-memory manifest still drives the run.
    try:
        save_json(out_dir / MANIFEST_NAME, manifest, sort_keys=True)
    except OSError as exc:
        logger.warning(
            "witness manifest not written (%s: %s) — a planted object "
            "at %s? left in place; seeds and dictionary are unaffected "
            "and the in-memory manifest still drives the run",
            type(exc).__name__,
            sanitise_for_terminal(str(exc), max_len=200),
            sanitise_for_terminal(str(out_dir / MANIFEST_NAME)))
    return manifest


def merge_witness_dict(seed_dir: Path, run_out_dir: Path) -> Path | None:
    """Merge witness dictionary tokens into the run's ``fuzz.dict``.

    ``/fuzz`` auto-discovers ``<out_dir>/fuzz.dict`` when the operator
    did not pass ``--dict`` (see ``audit_dict``), so appending here
    needs no new runner plumbing. Existing lines (e.g. audit-mined
    tokens) are preserved; duplicates are dropped.

    Both files sit at predictable names inside the reused run dir the
    previous campaign's sandboxed target could write, and this runs in
    the unsandboxed parent — so the reads are hardened
    (``read_text_capped``: O_NOFOLLOW + fstat-S_ISREG, bounded).
    ``Path.read_text`` followed a planted symlink here, copying
    operator-readable file content into the merged ``fuzz.dict`` the
    NEXT campaign's sandboxed target can read; an unbounded read of a
    planted multi-GB file was a parent memory lever. A planted
    non-regular ``fuzz.dict`` is refused loudly (its content is never
    read) and handled per shape: a symlink or FIFO is REPLACED by the
    atomic write (``os.replace`` swaps the plant's inode itself), a
    DIRECTORY skips the merge — ``os.replace`` cannot swap a
    directory, and removing a target-planted tree from the
    unsandboxed parent is a destructive step this merge never takes.
    A hostile witness dict or an over-``MAX_DICT_FILE_CHARS`` file on
    either side refuses the whole merge loudly. Any write failure is
    contained here (warn + skip), never propagated to the CLI.
    """
    witness_dict = Path(seed_dir) / "smt-witness.dict"
    witness_got = read_text_capped(witness_dict, MAX_DICT_FILE_CHARS)
    if witness_got is None:
        if os.path.lexists(witness_dict):
            logger.warning(
                "refusing witness-dict merge: %s is not a readable "
                "regular file (planted symlink/FIFO in the reused "
                "run dir?)", witness_dict)
        return None
    witness_text, witness_truncated = witness_got
    if witness_truncated:
        logger.warning(
            "refusing witness-dict merge: %s exceeds the %d-char "
            "dictionary bound", witness_dict, MAX_DICT_FILE_CHARS)
        return None

    target = Path(run_out_dir) / "fuzz.dict"
    existing: list[str] = []
    target_got = read_text_capped(target, MAX_DICT_FILE_CHARS)
    if target_got is not None:
        target_text, target_truncated = target_got
        if target_truncated:
            logger.warning(
                "refusing witness-dict merge: %s exceeds the %d-char "
                "dictionary bound — left untouched", target,
                MAX_DICT_FILE_CHARS)
            return None
        existing = target_text.splitlines()
    elif os.path.lexists(target):
        # Present but not a readable regular file: a planted symlink
        # (dangling ones pass exists()==False), FIFO, or directory.
        # Never read through any of them; the shapes then diverge at
        # the write. A DIRECTORY is refused outright: os.replace
        # cannot swap one (the atomic write raised IsADirectoryError
        # up through the /fuzz CLI), and removing a target-planted
        # tree from the unsandboxed parent is a destructive step this
        # merge never takes (same contract as open_exclusive_artifact
        # replace=True: a directory at the name still raises).
        try:
            plant_is_dir = stat.S_ISDIR(os.lstat(target).st_mode)
        except OSError:
            plant_is_dir = False  # vanished/unreadable: let the
            # hardened write below decide loudly.
        if plant_is_dir:
            logger.warning(
                "refusing witness-dict merge: %s is a directory "
                "(planted in the reused run dir?) — merge skipped, "
                "directory left in place",
                sanitise_for_terminal(str(target)))
            return None
        # Symlink/FIFO: merge from empty; the atomic write below
        # replaces the plant itself, never what it points at.
        logger.warning(
            "%s is not a readable regular file (planted symlink/FIFO "
            "in the reused run dir?) — its content is NOT merged; "
            "the witness dict replaces it", target)
    seen = set(existing)
    added = [
        line for line in witness_text.splitlines()
        if line and line not in seen
    ]
    if not added:
        return target if target.is_file() else None
    # Atomic read-merge-write commit (same rationale as the witness
    # dict write above — the plain write_text followed planted
    # symlinks in the reused run dir). Contained: a plant re-appearing
    # in the check→write window (or any other write failure) must
    # cost only the merge, never the fuzz run — the caller
    # (synthesize_from_run_dir → the bare /fuzz CLI handler) has no
    # handler of its own. The atomic writer already unlinked its
    # tempfile on the failure path.
    try:
        write_text_atomically(target, "\n".join([*existing, *added]) + "\n")
    except OSError as exc:
        logger.warning(
            "witness-dict merge not written (%s: %s) — merge skipped; "
            "the dictionary at %s is a planted or hostile object?",
            type(exc).__name__,
            sanitise_for_terminal(str(exc), max_len=200),
            sanitise_for_terminal(str(target)))
        return None
    return target


def synthesize_from_run_dir(source_dir: Path, run_out_dir: Path) -> dict:
    """End-to-end: scan ``source_dir``, write seeds under the run dir.

    Returns the manifest augmented with ``seed_dir`` and
    ``merged_dict`` keys. Logs the one-line operator summary.

    When the seed-dir name itself is planted (``seed_dir_refused`` set
    by :func:`synthesize_seeds`), the dictionary merge is skipped too:
    nothing was written, and reading ``smt-witness.dict`` back would
    traverse the planted name — ``read_text_capped`` refuses a symlink
    only at the FINAL component, so a symlinked seed dir would still
    route the read through the attacker-chosen directory.
    """
    records, skipped = collect_witnesses(Path(source_dir))
    seed_dir = Path(run_out_dir) / SEED_DIR_NAME
    manifest = synthesize_seeds(records, seed_dir, skipped=skipped)
    if manifest.get("seed_dir_refused"):
        merged = None
    else:
        merged = merge_witness_dict(seed_dir, run_out_dir)
    manifest["seed_dir"] = str(seed_dir)
    manifest["merged_dict"] = str(merged) if merged else None
    logger.info(
        "smt-witness seeds: %d witnesses -> %d seeds, %d dict entries, "
        "%d skipped%s (from %s)",
        manifest["witnesses"], manifest["seed_count"],
        manifest["dict_entries"], len(manifest["skipped"]),
        f", caps hit: {','.join(manifest['caps_hit'])}" if manifest["caps_hit"] else "",
        source_dir,
    )
    return manifest
