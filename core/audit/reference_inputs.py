"""Portable identities of delivered reference text, never verification evidence.

Only pipeline resolver objects supply entry contents. These identities narrow
reuse when the conditional rule text changes; they do not establish target
language mode, applicability, completeness of a reference pack, or a proof.
No journal value selects a path, module or loader.
"""

from __future__ import annotations

import hashlib
import json
import re

from core.language_reference import ReferenceAnswer, ReferenceEntry

MAX_ENTRIES = 32
MAX_SNAPSHOT_BYTES = 16 * 1024
_MAX_DELIVERIES = 64
_MAX_SNAPSHOTS = 64
_MAX_PACK_ENTRIES = 256
_ROLE = "review-reference-inputs"
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_Entry = tuple[str, int, str, str]
_KEYS = {"id", "version", "pack_version", "sha256"}


def _pack_label(value: object) -> bool:
    return (isinstance(value, str) and bool(value) and len(value) <= 128
            and all(32 <= ord(char) < 127 for char in value))


def _entry(value: object) -> _Entry | None:
    if not isinstance(value, dict) or set(value) != _KEYS:
        return None
    entry_id, version = value.get("id"), value.get("version")
    pack, digest = value.get("pack_version"), value.get("sha256")
    if (not isinstance(entry_id, str) or _ID.fullmatch(entry_id) is None
            or type(version) is not int or not 0 < version < 2**31
            or not isinstance(pack, str) or not _pack_label(pack)
            or not isinstance(digest, str) or _SHA256.fullmatch(digest) is None):
        return None
    return entry_id, version, pack, digest


def _render_identity(entry: ReferenceEntry, pack: str) -> _Entry | None:
    if not isinstance(entry, ReferenceEntry):
        return None
    try:
        text = entry.render_core()
        if not isinstance(text, str) or len(text) > MAX_SNAPSHOT_BYTES:
            return None
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    except (TypeError, ValueError, UnicodeError):
        return None
    return _entry({"id": entry.entry_id, "version": entry.version,
                   "pack_version": pack, "sha256": digest})


def _canonical(snapshot: dict) -> bytes:
    return json.dumps(snapshot, ensure_ascii=True, separators=(",", ":"),
                      sort_keys=True).encode("utf-8")


def _snapshot(entries: set[_Entry], complete: bool) -> dict:
    rows: list[dict] = []
    result = {"version": 1, "role": _ROLE, "complete": complete, "entries": rows}
    identities: dict[str, _Entry] = {}
    for entry_id, version, pack, digest in sorted(entries):
        identity = (entry_id, version, pack, digest)
        previous = identities.get(entry_id)
        if previous is not None and previous != identity:
            result["complete"] = False
        identities[entry_id] = identity
        if len(rows) >= MAX_ENTRIES:
            result["complete"] = False
            continue
        rows.append({"id": entry_id, "version": version,
                     "pack_version": pack, "sha256": digest})
        # Reserve the longer false spelling before declaring the record full.
        if len(_canonical({**result, "complete": False})) > MAX_SNAPSHOT_BYTES:
            rows.pop()
            result["complete"] = False
    return result


def _decode(value: object) -> tuple[set[_Entry], bool]:
    if not isinstance(value, dict):
        return set(), False
    complete = (set(value) == {"version", "role", "complete", "entries"}
                and type(value.get("version")) is int and value.get("version") == 1
                and value.get("role") == _ROLE and value.get("complete") is True)
    rows = value.get("entries")
    if not isinstance(rows, list):
        return set(), False
    entries: set[_Entry] = set()
    if len(rows) > MAX_ENTRIES:
        complete = False
    for row in rows[:MAX_ENTRIES]:
        identity = _entry(row)
        if identity is None:
            complete = False
        else:
            entries.add(identity)
    bounded = _snapshot(entries, complete)
    return ({(row["id"], row["version"], row["pack_version"], row["sha256"])
             for row in bounded["entries"]}, bounded["complete"])


def reference_inputs_from_delivery(
    delivery: object, answers: tuple[ReferenceAnswer, ...],
) -> dict | None:
    """Bind actual fitting to its owned answers, including prerequisites.

    An explicit empty/omitted delivery creates no dependency. Missing metadata
    for supplied answers is different: it produces an incomplete record.
    """
    if delivery is None and not answers:
        return None
    if not isinstance(answers, tuple) or not isinstance(delivery, list):
        return _snapshot(set(), False)
    complete = len(answers) <= _MAX_DELIVERIES and len(delivery) <= _MAX_DELIVERIES
    owned: dict[str, ReferenceAnswer] = {}
    for answer in answers[:_MAX_DELIVERIES]:
        if (not isinstance(answer, ReferenceAnswer) or not isinstance(answer.request_id, str)
                or not answer.request_id or len(answer.request_id) > 128
                or not isinstance(answer.entries, tuple) or len(answer.entries) > MAX_ENTRIES):
            complete = False
            continue
        previous = owned.get(answer.request_id)
        if previous is not None and previous != answer:
            complete = False
        owned[answer.request_id] = answer
    entries: set[_Entry] = set()
    delivered = False
    seen: set[str] = set()
    fitting: dict[str, bool] = {}
    for row in delivery[:_MAX_DELIVERIES]:
        if not isinstance(row, dict) or type(row.get("delivered")) is not bool:
            complete = False
            continue
        request_id = row.get("request_id")
        owned_answer = owned.get(request_id) if isinstance(request_id, str) else None
        if owned_answer is None:
            complete = False
            continue
        seen.add(owned_answer.request_id)
        previous_fitting = fitting.get(owned_answer.request_id)
        if previous_fitting is not None and previous_fitting != row["delivered"]:
            complete = False
        fitting[owned_answer.request_id] = row["delivered"]
        if row["delivered"] is not True:
            continue
        delivered = True
        expected = [{"id": entry.entry_id, "version": entry.version}
                    for entry in owned_answer.entries if isinstance(entry, ReferenceEntry)]
        supplied = row.get("entries")
        if (not owned_answer.entries or len(expected) != len(owned_answer.entries)
                or not isinstance(supplied, list) or len(supplied) > MAX_ENTRIES
                or any(not isinstance(item, dict) or set(item) != {"id", "version"}
                       or type(item.get("version")) is not int for item in supplied)
                or row.get("pack_version") != owned_answer.pack_version
                or supplied != expected):
            complete = False
            continue
        for entry in owned_answer.entries:
            identity = _render_identity(entry, owned_answer.pack_version)
            if identity is None:
                complete = False
            else:
                entries.add(identity)
    complete = complete and set(owned) <= seen
    if not delivered and complete:
        return None
    return _snapshot(entries, complete)


def merge_reference_inputs(*snapshots: object) -> dict | None:
    """Union exact delivered identities without repairing unknown history."""
    entries: set[_Entry] = set()
    complete = len(snapshots) <= _MAX_SNAPSHOTS
    present = False
    for snapshot in snapshots[:_MAX_SNAPSHOTS]:
        if snapshot is None:
            continue
        present = True
        decoded, known = _decode(snapshot)
        entries.update(decoded)
        complete = complete and known
    return _snapshot(entries, complete) if present or not complete else None


def reference_inputs_digest(snapshot: object) -> str | None:
    """Name a complete nonempty reference set without certifying its rules."""
    entries, complete = _decode(snapshot)
    if not complete or not entries:
        return None
    return hashlib.sha256(_canonical(_snapshot(entries, True))).hexdigest()


def reference_inputs_current(snapshot: object) -> bool:
    """Compare only against the current local pipeline pack, never row code."""
    if snapshot is None:
        return True
    entries, complete = _decode(snapshot)
    if not complete or not entries:
        return False
    from core.language_reference import c_integer

    # The current resolver uses this default pack label; labels alone are not
    # content identities. Both rendered contents and entry versions must match.
    pack = ReferenceAnswer("", "unsupported").pack_version
    current: dict[str, _Entry] = {}
    if not isinstance(c_integer.ENTRIES, tuple) or len(c_integer.ENTRIES) > _MAX_PACK_ENTRIES:
        return False
    prerequisites: dict[str, tuple[str, ...]] = {}
    for entry in c_integer.ENTRIES:
        identity = _render_identity(entry, pack)
        if identity is None or identity[0] in current:
            return False
        required = entry.prerequisites
        if (not isinstance(required, tuple) or len(required) > MAX_ENTRIES
                or any(not isinstance(item, str) or _ID.fullmatch(item) is None for item in required)):
            return False
        current[identity[0]] = identity
        prerequisites[identity[0]] = required
    delivered_ids = {entry[0] for entry in entries}
    # A newly required entry must have actually travelled in the old packet.
    # Its own identity and prerequisites are checked by the same finite set.
    return all(current.get(entry[0]) == entry
               and all(required in delivered_ids for required in prerequisites[entry[0]])
               for entry in entries)


def review_context_digest(source_inputs: object, reference_inputs: object = None) -> str | None:
    """Preserve legacy source digests; bind both sets when references exist."""
    from .review_context_inputs import context_inputs_digest

    source_digest = context_inputs_digest(source_inputs)
    if reference_inputs is None:
        return source_digest
    reference_digest = reference_inputs_digest(reference_inputs)
    if source_digest is None or reference_digest is None:
        return None
    return hashlib.sha256(_canonical({"version": 1, "role": "review-input-digests",
                                      "source": source_digest, "reference": reference_digest})).hexdigest()


def reference_answer_already_delivered(answer: ReferenceAnswer, snapshot: object) -> bool:
    """Compare desired reading with actual supplied entries, not question IDs.

    This grants no new delivery credit or target-fact authority. An omitted,
    unknown or changed entry cannot suppress useful subsequent lookup work.
    """
    if (not isinstance(answer, ReferenceAnswer) or not answer.entries
            or len(answer.entries) > MAX_ENTRIES or not reference_inputs_current(snapshot)):
        return False
    entries, complete = _decode(snapshot)
    return complete and all(_render_identity(entry, answer.pack_version) in entries for entry in answer.entries)
