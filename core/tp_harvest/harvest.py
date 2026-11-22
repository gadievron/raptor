"""The harvest chokepoint: walk one run, emit records/candidates/pointers.

Standalone and post-run by design (``raptor-tp-harvest <run-dir>``),
not a pipeline stage: the flywheel consumes verdicts after a run has
finished, its promotion steps are human-gated per finding, and
re-running must be cheap. Idempotence is keyed on finding identity
(the ``finding_signature`` harvest_id): a re-run over unchanged
findings is a no-op, and everything emitted or skipped is written to
``tp-harvest/harvest-manifest.json`` with an enumerated reason —
never silent.
"""

from __future__ import annotations

import dataclasses
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.json import load_json, save_json
from core.json.jsonl import load_jsonl
from core.logging import get_logger
from core.paths import confine
from core.project.findings_utils import FindingsLoadDisclosure, finding_file, load_findings_from_dir
from core.run import load_run_metadata
from core.tp_harvest import candidates as candidates_mod
from core.tp_harvest import labels as labels_mod
from core.tp_harvest.records import (
    SKIP_ALREADY_HARVESTED,
    SKIP_DUPLICATE_IN_RUN,
    SKIP_FINDING_MALFORMED,
    SKIP_PATH_ESCAPES_TARGET,
    HarvestRecord,
    build_record,
    classify_finding,
    harvest_identity,
)
from core.witness.provenance import (
    sanitise_findings_evidence,
    stamp_harvest_entry,
    verify_harvest_entry,
)

logger = get_logger()

HARVEST_DIRNAME = "tp-harvest"
MANIFEST_FILENAME = "harvest-manifest.json"
RECORDS_DIRNAME = "records"
CANDIDATES_DIRNAME = "candidates"

MANIFEST_SCHEMA_VERSION = 1
_MAX_MANIFEST_BYTES = 8 * 1024 * 1024
_MAX_RECORD_BYTES = 8 * 1024 * 1024
_MAX_BACKLOG_BYTES = 8 * 1024 * 1024

# Bound on the tp-harvest/ structure walk. The gate must SEE every
# entry to vet it; a planted tree bigger than any legitimate harvest
# output refuses fail-closed instead of walking unbounded.
_MAX_HARVEST_TREE_ENTRIES = 20_000


class HostileRunDirError(RuntimeError):
    """The run dir's tp-harvest/ tree fails the structure gate."""


def refuse_symlinked_harvest_dir(run_dir: Path) -> None:
    """Refuse a ``tp-harvest/`` tree carrying ANY symlink.

    The harvest writes into attacker-influencible territory: an
    imported/hostile run dir can pre-plant symlinks where the harvest
    will write (a candidate file aimed at ``engine/semgrep/rules/``
    turns never-auto-enable into auto-enable; a backlog symlink turns
    the append into arbitrary-file append). Per-write O_NOFOLLOW /
    atomic-rename discipline covers the FINAL path component; this
    gate covers the directories themselves (``tp-harvest`` or
    ``candidates/`` symlinked wholesale re-roots every "safe" write).
    Legitimate harvest output never contains symlinks, so any symlink
    is refused loudly — fail-closed, never skipped silently.
    """
    root = Path(run_dir) / HARVEST_DIRNAME
    if root.is_symlink():
        raise HostileRunDirError(
            f"{root} is a symlink — refusing to harvest into a "
            "re-rooted tp-harvest tree")
    if not root.is_dir():
        return
    seen = 0
    for entry in root.rglob("*"):
        seen += 1
        if seen > _MAX_HARVEST_TREE_ENTRIES:
            raise HostileRunDirError(
                f"{root} holds more than {_MAX_HARVEST_TREE_ENTRIES} "
                "entries — not a harvest output; refusing")
        if entry.is_symlink():
            raise HostileRunDirError(
                f"symlink inside the harvest tree: {entry} — refusing "
                "(pre-planted links re-route harvest writes)")


def harvest_dir(run_dir: Path) -> Path:
    return run_dir / HARVEST_DIRNAME


def manifest_path(run_dir: Path) -> Path:
    return harvest_dir(run_dir) / MANIFEST_FILENAME


def record_path(run_dir: Path, harvest_id: str) -> Path:
    return harvest_dir(run_dir) / RECORDS_DIRNAME / f"{harvest_id}.json"


def backlog_path(run_dir: Path) -> Path:
    return harvest_dir(run_dir) / labels_mod.BACKLOG_FILENAME


def load_manifest(run_dir: Path) -> dict[str, Any]:
    """The harvest manifest, or a fresh skeleton when absent."""
    raw = load_json(manifest_path(run_dir), max_bytes=_MAX_MANIFEST_BYTES)
    if isinstance(raw, dict) and isinstance(raw.get("entries"), dict):
        return raw
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "run_dir": str(run_dir),
        "entries": {},
    }


def load_record(run_dir: Path, harvest_id: str) -> HarvestRecord | None:
    """A previously emitted record, or None.

    Authenticated: the record file alone is run-dir-resident bytes an
    imported or pre-planted run dir can ship wholesale, so a record is
    served only when the manifest entry for *harvest_id* carries this
    install's emission stamp for this run AND the entry's
    ``record_sha256`` still matches the on-disk bytes. Forged trees
    (and post-emission edits) read as absent — the consumer that
    matters most is label emission, which must never pin a corpus
    label to a record the harvest never projected. Pre-authentication
    harvests heal on re-run: the stampless entry stops
    short-circuiting, so the record is re-projected and re-stamped.
    """
    entry = load_manifest(run_dir)["entries"].get(harvest_id)
    if not (isinstance(entry, dict)
            and verify_harvest_entry(entry, harvest_id, run_dir)):
        return None
    path = record_path(run_dir, harvest_id)
    if str(entry.get("record_sha256") or "") != _record_sha256(path):
        return None
    raw = load_json(path, max_bytes=_MAX_RECORD_BYTES)
    if not isinstance(raw, dict):
        return None
    names = {f.name for f in dataclasses.fields(HarvestRecord)}
    try:
        return HarvestRecord(**{k: v for k, v in raw.items() if k in names})
    except TypeError:
        return None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def harvest_run(
    run_dir: Path,
    *,
    with_candidates: bool = True,
) -> dict[str, Any]:
    """Harvest one run directory. Returns a summary dict.

    Summary keys: ``run_dir``, ``target_path``, ``command``,
    ``findings_total``, ``harvested`` (new harvest_ids this pass),
    ``skipped`` (reason -> count), ``notes`` (operator-facing
    caveats), ``manifest`` (path). The manifest on disk carries the
    durable per-finding audit trail.
    """
    run_dir = Path(run_dir)
    notes: list[str] = []

    # Structure gate FIRST — before any read of or write into
    # tp-harvest/. Raises HostileRunDirError on a planted symlink.
    refuse_symlinked_harvest_dir(run_dir)

    meta = load_run_metadata(run_dir)
    target_path = ""
    command = ""
    if isinstance(meta, dict):
        target_path = str(meta.get("target_path") or "")
        command = str(meta.get("command") or "")
    else:
        notes.append(
            "no .raptor-run.json — span hashes and target-tree seeds "
            "unavailable")

    disclosure = FindingsLoadDisclosure()
    findings = load_findings_from_dir(run_dir, disclosure=disclosure)
    # Evidence-provenance clamp BEFORE classification: finding rows
    # are run-dir-resident (imported run dirs ship their own), and
    # classify_finding is a pure projection of the recorded verdict —
    # so every mechanical claim (witness verdicts, feasibility
    # records, confirmed/exploitable statuses on any channel) must
    # carry this install's stamp or demote to confirmed_unverified,
    # which classifies as a named skip. Without the clamp a
    # hand-edited findings.json walks a forged Confirmed straight
    # onto the disclosure backlog and into rule candidates.
    demotions = sanitise_findings_evidence({"findings": findings}, run_dir)
    if any(demotions.values()):
        detail = ", ".join(
            f"{name}: {count}"
            for name, count in sorted(demotions.items()) if count
        )
        notes.append(
            "unverified evidence claims demoted before classification "
            f"({detail}) — rows lacked this install's provenance stamp")
    if not findings and disclosure.discarded_rows:
        notes.append("no valid findings remain — malformed rows were skipped")
    elif not findings:
        notes.append("no findings artifact (or empty) — nothing to harvest")

    outcomes: list[Any] = []
    if findings:
        try:
            from core.labeled_attempts.view import collect_outcomes
            outcomes = collect_outcomes(run_dir)
        except Exception:  # noqa: BLE001 — evidence enrichment is best-effort
            notes.append("verified-outcome backend unavailable — records "
                         "carry no outcome pointers")

    manifest = load_manifest(run_dir)
    entries: dict[str, Any] = manifest["entries"]
    now = _now()

    harvested: list[str] = []
    skipped: dict[str, int] = {}
    if disclosure.discarded_rows:
        skipped[SKIP_FINDING_MALFORMED] = disclosure.discarded_rows
    seen_this_pass: set[str] = set()

    # Backlog hids already on disk — pointer appends are keyed so a
    # re-emission (deleted record, crashed pass) never duplicates a
    # pointer.
    backlog_hids = {
        row.get("harvest_id")
        for row in load_jsonl(backlog_path(run_dir),
                              max_total_bytes=_MAX_BACKLOG_BYTES)
        if isinstance(row, dict)
    }

    def _skip(reason: str) -> None:
        skipped[reason] = skipped.get(reason, 0) + 1

    for finding in findings:
        try:
            entry_hid = _harvest_one(
                finding, run_dir=run_dir, target_path=target_path,
                command=command, outcomes=outcomes, now=now,
                entries=entries, seen_this_pass=seen_this_pass,
                backlog_hids=backlog_hids, notes=notes,
                with_candidates=with_candidates, skip=_skip,
            )
        except Exception as exc:  # noqa: BLE001 — one hostile/malformed
            # row must not abort the pass and strand emitted records;
            # the row skips BY NAME and the harvest continues.
            logger.warning(
                "tp-harvest: finding row defeated projection (%s: %s) "
                "— skipped as %s",
                type(exc).__name__, exc, SKIP_FINDING_MALFORMED,
            )
            _skip(SKIP_FINDING_MALFORMED)
            continue
        if entry_hid is not None:
            harvested.append(entry_hid)

    manifest["last_run"] = {
        "at": now,
        "harvested": len(harvested),
        "skipped": skipped,
    }
    save_json(manifest_path(run_dir), manifest, sort_keys=True)

    return {
        "run_dir": str(run_dir),
        "target_path": target_path,
        "command": command,
        "findings_total": disclosure.total_rows,
        "harvested": harvested,
        "skipped": skipped,
        "notes": notes,
        "manifest": str(manifest_path(run_dir)),
    }


def _status_of(finding: dict[str, Any]) -> str:
    from core.tp_harvest.records import effective_status

    return effective_status(finding)


def _record_sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""


def _harvest_one(
    finding: Any,
    *,
    run_dir: Path,
    target_path: str,
    command: str,
    outcomes: list[Any],
    now: str,
    entries: dict[str, Any],
    seen_this_pass: set[str],
    backlog_hids: set[Any],
    notes: list[str],
    with_candidates: bool,
    skip: Any,
) -> str | None:
    """Process one finding row. Returns its hid when newly harvested."""
    if not isinstance(finding, dict):
        skip(SKIP_FINDING_MALFORMED)
        return None
    hid = harvest_identity(finding)
    if hid in seen_this_pass:
        skip(SKIP_DUPLICATE_IN_RUN)
        return None
    seen_this_pass.add(hid)

    prior = entries.get(hid)
    if (isinstance(prior, dict) and prior.get("action") == "harvested"
            and record_path(run_dir, hid).is_file()
            and not verify_harvest_entry(prior, hid, run_dir)):
        # The entry claims a prior emission this install never stamped
        # for this run — a pre-planted/imported tp-harvest tree (the
        # record_sha256 beside it is attacker-computable, so the
        # tamper check below cannot stand alone), or a harvest from
        # before entries were stamped. Either way it carries no
        # short-circuit authority: fall through and re-project from
        # the live finding row, which rewrites (and stamps) the entry
        # via whichever arm classification takes.
        notes.append(
            f"manifest entry {hid} lacks this install's emission "
            "stamp — ignored and re-projected from the finding row")
        prior = None
    if (isinstance(prior, dict) and prior.get("action") == "harvested"
            and record_path(run_dir, hid).is_file()):
        # Idempotence: keyed on finding identity — already emitted.
        prior["last_seen_at"] = now
        stored = prior.get("record_sha256")
        if stored and stored != _record_sha256(record_path(run_dir, hid)):
            # Tamper marker: the on-disk record no longer matches what
            # the harvest emitted. Kept (the operator adjudicates),
            # but marked and surfaced — never silent.
            prior["record_tampered"] = True
            notes.append(
                f"record {hid} differs from its emission hash — "
                "tampered or hand-edited; marked in the manifest")
        skip(SKIP_ALREADY_HARVESTED)
        return None

    ok, reason = classify_finding(finding)
    if ok and target_path and confine(target_path, finding_file(finding)) is None:
        # The finding's path escapes the target tree — every read the
        # harvest would do with it (seed line, span hash) is refused,
        # so the finding skips by name rather than emitting an
        # unpinnable record.
        ok, reason = False, SKIP_PATH_ESCAPES_TARGET
    if not ok:
        # Previously-skipped entries are re-classified every pass:
        # findings.json can gain verdicts between harvests.
        entries[hid] = {
            "finding_id": str(finding.get("id")
                              or finding.get("finding_id") or ""),
            "status": _status_of(finding),
            "action": "skipped",
            "skip_reason": reason,
            "first_seen_at": (prior or {}).get("first_seen_at", now),
            "last_seen_at": now,
        }
        skip(reason)
        return None

    record = build_record(
        finding, run_dir=run_dir, target_path=target_path,
        command=command, outcomes=outcomes, harvested_at=now,
    )
    rec_path = record_path(run_dir, hid)
    save_json(rec_path, record.to_dict(), sort_keys=True)

    candidate_rel: str | None = None
    candidate_skip = ""
    if with_candidates:
        cand_path, candidate_skip = candidates_mod.emit_candidate(
            record, harvest_dir(run_dir) / CANDIDATES_DIRNAME)
        if cand_path is not None:
            candidate_rel = str(cand_path.relative_to(run_dir))

    # Default not-labelable: route to the disclosure backlog (keyed —
    # a hid already on the backlog is not appended again). The
    # operator flips provenance per finding via the CLI's --label.
    if hid not in backlog_hids:
        labels_mod.append_backlog_pointer(backlog_path(run_dir), record)
        backlog_hids.add(hid)

    entry: dict[str, Any] = {
        "finding_id": record.finding_id,
        "status": record.status,
        "action": "harvested",
        "record": str(rec_path.relative_to(run_dir)),
        "record_sha256": _record_sha256(rec_path),
        "candidate": candidate_rel,
        "candidate_skip_reason": candidate_skip,
        "backlog": True,
        "label": None,
        "oracle_verified": record.oracle_verified,
        "first_harvested_at": now,
        "last_seen_at": now,
    }
    # Emission provenance: binds this install + run + hid + the record
    # bytes, so a pre-planted manifest/record pair can neither
    # short-circuit a later pass nor be served by load_record.
    stamp_harvest_entry(entry, hid, run_dir)
    entries[hid] = entry
    return hid


def record_label_emitted(run_dir: Path, harvest_id: str,
                         label_path: Path) -> None:
    """Stamp a label emission into the manifest's audit trail."""
    manifest = load_manifest(run_dir)
    entry = manifest["entries"].get(harvest_id)
    if isinstance(entry, dict):
        entry["label"] = str(label_path)
        entry["label_emitted_at"] = _now()
    save_json(manifest_path(run_dir), manifest, sort_keys=True)
