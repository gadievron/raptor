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
"""

from __future__ import annotations

import json
import logging
import re
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# A seed of exactly-witnessed length: cap so a witness like
# len=2**63-1 cannot fill the disk. Clamps are recorded per-seed.
SEED_LEN_CAP = 1024 * 1024

# Bounds against a hostile or degenerate producer file. All are
# recorded in the manifest when hit — no silent truncation.
MAX_WITNESSES = 200
MAX_SEEDS = 512
MAX_DICT_ENTRIES = 1024

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
            data = json.loads(report.read_text(encoding="utf-8"))
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
        except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
            skipped.append({"file": report.name, "reason": f"unreadable: {exc}"})

    paths_file = source_dir / "attack-paths.json"
    if paths_file.is_file():
        try:
            data = json.loads(paths_file.read_text(encoding="utf-8"))
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
        except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
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
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

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
                    (out_dir / name).write_bytes(_FILL_BYTE * length)
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
                if not seed_path.exists():
                    seed_path.write_bytes(encoded)
                    seeds.append({
                        **provenance,
                        "seed": name,
                        "rule": "magic-value",
                        "bytes": len(encoded),
                        "clamped": False,
                    })

    dict_path = None
    if dict_entries:
        dict_path = out_dir / "smt-witness.dict"
        lines = [f'{name}="{value}"' for name, value in sorted(dict_entries.items())]
        dict_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "witnesses": len(records),
        "seed_count": len(seeds),
        "dict_entries": len(dict_entries),
        "dict_file": dict_path.name if dict_path else None,
        "caps_hit": sorted(set(caps_hit)),
        "seeds": seeds,
        "skipped": all_skipped,
    }
    (out_dir / MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    return manifest


def merge_witness_dict(seed_dir: Path, run_out_dir: Path) -> Path | None:
    """Merge witness dictionary tokens into the run's ``fuzz.dict``.

    ``/fuzz`` auto-discovers ``<out_dir>/fuzz.dict`` when the operator
    did not pass ``--dict`` (see ``audit_dict``), so appending here
    needs no new runner plumbing. Existing lines (e.g. audit-mined
    tokens) are preserved; duplicates are dropped.
    """
    witness_dict = Path(seed_dir) / "smt-witness.dict"
    if not witness_dict.is_file():
        return None
    target = Path(run_out_dir) / "fuzz.dict"
    existing: list[str] = []
    if target.is_file():
        existing = target.read_text(encoding="utf-8").splitlines()
    seen = set(existing)
    added = [
        line for line in witness_dict.read_text(encoding="utf-8").splitlines()
        if line and line not in seen
    ]
    if not added:
        return target if target.is_file() else None
    target.write_text("\n".join([*existing, *added]) + "\n", encoding="utf-8")
    return target


def synthesize_from_run_dir(source_dir: Path, run_out_dir: Path) -> dict:
    """End-to-end: scan ``source_dir``, write seeds under the run dir.

    Returns the manifest augmented with ``seed_dir`` and
    ``merged_dict`` keys. Logs the one-line operator summary.
    """
    records, skipped = collect_witnesses(Path(source_dir))
    seed_dir = Path(run_out_dir) / SEED_DIR_NAME
    manifest = synthesize_seeds(records, seed_dir, skipped=skipped)
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
