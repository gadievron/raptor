"""Source-hash + audit-log helpers for the /audit review loop.

Post-migration surface: ``record_review`` and the ``coverage-audit.json``
writer path were removed as part of the annotation → journal migration
(see ``design/coverage-annotation-redesign-amendment-2026-07-28.md``).
The review journal is the sole authority for LLM review state; the
coverage store imports LLM review existence from the journal, not from
this module.

What remains here:

- :func:`_compute_hash` — source-content hash for staleness detection.
  Called by :func:`core.audit.collector.append_journal_for_outcome`.
- :func:`load_audit_log` / :func:`append_audit_log` — the
  ``.audit-log.jsonl`` event log. Carries non-review events
  (context-load / tool-dispatch / batch-flush) PLUS per-review
  telemetry: Collector.submit still appends one
  ``action="orchestrator_review"`` record per review (status,
  hypothesis, evidence_tool, cost) which strategy_stats aggregates
  for cross-run strategy win rates. The review journal (from
  2026-07-28 onwards) remains the sole AUTHORITY for verdicts —
  these log records are telemetry, not review state.
- :func:`_resolve_annotations_dir` — project-level annotations dir
  resolution, used by consumers that write / read human annotations.
"""

from __future__ import annotations

import logging
import os
import re
import stat as _stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

AUDIT_LOG_FILENAME = ".audit-log.jsonl"

#: PER-SHARD read budgets for the audit event log (see
#: load_audit_log). Historically these were whole-log budgets and the
#: comment above them claimed "a legitimate log is a few MB on the
#: largest runs" — falsified in production: a multi-segment run's
#: trail crossed the 64 MiB budget on a mid-sized target, and
#: the loader's refuse-whole arm silently fed [] to every consumer
#: (resume suppression, fail-open deferral, telemetry) for the rest
#: of the run. The writer now rolls to numbered sibling shards below
#: this budget (see _AUDIT_LOG_SHARD_ROLL_BYTES) and the loader reads
#: the contiguous shard set, so the budget is a per-file hostile-input
#: bound again, not a ceiling on legitimate trail growth. Trade-off,
#: both directions: LOWER multiplies shard count (per-shard open/scan
#: overhead) for the same trail; HIGHER grows the single-allocation
#: worst case a planted file can force on every loader.
_AUDIT_LOG_MAX_BYTES = 64 * 1024 * 1024
#: Real rows are a few hundred bytes to a few KiB (review telemetry
#: with hypothesis text); 1 MiB keeps ~3 orders of magnitude of
#: headroom while bounding what one hostile line can make the reader
#: buffer.
_AUDIT_LOG_MAX_LINE_BYTES = 1024 * 1024

#: Retained-row COUNT bound per shard. The byte budget alone does not
#: bound reader memory: parsed-object overhead is per row, so a flood
#: of minimal rows under the byte budget could retain millions of
#: objects. Trade-off, both directions: too low and a legitimately
#: dense shard reads partial (disclosed, over-review direction); too
#: high and the tiny-row flood OOMs the reader. A production
#: multi-segment trail measured ~2 KiB/row — a full 64 MiB shard is
#: ~34k such rows, so 500k is >10x headroom over the densest
#: plausible legitimate shard.
_AUDIT_LOG_MAX_ROWS_PER_SHARD = 500_000

#: Roll threshold for the ACTIVE shard (same 3/4 ratio as the review
#: journal's shards). Trade-off, both directions: LOWER means more
#: shard files for the same trail; HIGHER pushes a full shard toward
#: the per-shard read budget, whose overflow arm degrades that shard
#: to a newest-tail read. 3/4 leaves a full margin for appends that
#: race the roll decision.
_AUDIT_LOG_SHARD_ROLL_BYTES = (_AUDIT_LOG_MAX_BYTES * 3) // 4

#: Shard-count bound. Trade-off, both directions: LOWER stops rolling
#: on a legitimate mega-run (its final shard then grows past the read
#: budget and degrades to a disclosed newest-tail read — bounded
#: remedy: ``raptor-audit audit-log rotate``); HIGHER scales a
#: hostile plant fan-out and the loader's worst-case aggregate work
#: linearly. 64 shards ≈ 3 GiB of trail — about double the largest
#: trail projected for the biggest targets (a production
#: multi-segment run measured ~1.4x ONE read budget on a target
#: roughly 1/16 that size).
_AUDIT_LOG_MAX_SHARDS = 64

_AUDIT_LOG_SHARD_RE = re.compile(r"^\.audit-log\.(\d{3,})\.jsonl$")


def _resolve_annotations_dir(out_dir: Path) -> Path:
    """Resolve annotations directory to project level when possible.

    Project runs have out_dir = project_dir/<run_name>/, so
    out_dir.parent is the project directory. Annotations at the project
    level survive /project clean (which deletes run dirs).

    Detection: a run dir contains .raptor-run.json (written by
    raptor-run-lifecycle start). If present, the parent is the
    project directory.
    """
    # The run pin decides the project level — pre-fix bare
    # out_dir.parent lost the operator's human-grade annotation inputs
    # (Reflexion veto, FP primers) for --out runs, and standalone runs
    # shared a pseudo project dir. Pin-less legacy dirs keep the
    # marker+parent probe.
    try:
        from core.run.pin import pin_project_dir, resolve_run_pin
        pin = resolve_run_pin(out_dir)
        if pin.authoritative:
            project_dir = pin_project_dir(out_dir)
            if project_dir is not None and project_dir != out_dir:
                return project_dir / "annotations"
            return out_dir / "annotations"
    except ImportError:
        pass  # pin subsystem absent — legacy probe below
    except Exception as exc:  # noqa: BLE001 — legacy probe below, loudly
        # Annotations carry operator-authority notes (Reflexion veto,
        # FP primers): a failed pin resolution silently rerouting
        # reads/writes to the legacy location would drop them without
        # a trace, so the downgrade must be operator-visible. The
        # exception message is duck-typed input — escape and bound it;
        # the full traceback stays at DEBUG.
        from core.security.log_sanitisation import sanitise_for_terminal
        logger.warning(
            "annotations-dir pin resolution failed for %s — falling "
            "back to the run-marker probe; project-level annotations "
            "may not be found: %s",
            out_dir,
            sanitise_for_terminal(f"{type(exc).__name__}: {exc}"),
        )
        logger.debug(
            "annotations-dir pin resolution detail", exc_info=True,
        )
    run_marker = out_dir / ".raptor-run.json"
    if run_marker.exists():
        project_dir = out_dir.parent
        if project_dir and project_dir != out_dir:
            return project_dir / "annotations"
    return out_dir / "annotations"


def _audit_log_shard_name(n: int) -> str:
    """On-disk name of shard *n* (1-based; shard 1 is the historical
    single file, so single-shard trails stay byte-identical)."""
    if n == 1:
        return AUDIT_LOG_FILENAME
    return f".audit-log.{n:03d}.jsonl"


def audit_log_paths(out_dir: Path) -> list[Path]:
    """The audit log's contiguous shard set, in append order.

    Mirrors ``core.coverage.journal.journal_shard_paths``: always
    starts with ``.audit-log.jsonl`` (whether or not it exists yet)
    and extends through consecutively numbered siblings. Contiguity-
    by-construction: a planted high-numbered file does not extend the
    set (the loader discloses non-contiguous leftovers separately).
    """
    out_dir = Path(out_dir)
    paths = [out_dir / AUDIT_LOG_FILENAME]
    n = 2
    while n <= _AUDIT_LOG_MAX_SHARDS:
        p = out_dir / _audit_log_shard_name(n)
        try:
            if not p.exists():
                break
        except OSError:
            break
        paths.append(p)
        n += 1
    return paths


def _audit_log_orphan_names(out_dir: Path, known: int) -> list[str]:
    """Numbered shard files BEYOND the contiguous set — evidence that
    an interior shard was deleted (rows silently invisible), so the
    load must disclose incompleteness rather than pretend the
    survivors are the whole trail."""
    names: list[str] = []
    try:
        candidates = sorted(p.name for p in Path(out_dir).iterdir())
    except OSError:
        return names
    for name in candidates:
        m = _AUDIT_LOG_SHARD_RE.match(name)
        if not m:
            continue
        n = int(m.group(1))
        # A name that is not the canonical spelling of its number
        # (wider zero-padding — ``.audit-log.0002.jsonl`` — or the
        # numbered spelling of shard 1) is never generated by the
        # writer and never read by ``audit_log_paths``, whatever its
        # number parses to; it is always a leftover/plant, disclosed
        # rather than silently shadowed by the canonical shard.
        if name != _audit_log_shard_name(n) or n > known:
            names.append(name)
    return names[:8]


def audit_log_append_path(out_dir: Path) -> Path:
    """The shard the next append lands in: the last contiguous shard,
    or — once it crosses the roll threshold — the next number.

    Cross-process note (same contract as the journal's
    ``_append_shard_path``): two appenders can both observe the
    threshold crossing and both open the SAME next shard (O_CREAT
    without O_EXCL) — they simply share it, each row staying
    line-atomic via the writer's single O_APPEND write. A shard can
    exceed the threshold by the appends that raced the roll; the
    threshold's margin below the read budget absorbs that.
    """
    paths = audit_log_paths(out_dir)
    last = paths[-1]
    try:
        size = last.stat().st_size
    except OSError:
        size = 0
    if size < _AUDIT_LOG_SHARD_ROLL_BYTES:
        return last
    if len(paths) >= _AUDIT_LOG_MAX_SHARDS:
        logger.warning(
            "audit log: shard bound (%d) reached in %s — appending to "
            "the final shard past its roll threshold; run "
            "`raptor-audit audit-log rotate %s` after the run stops",
            _AUDIT_LOG_MAX_SHARDS, out_dir, out_dir,
        )
        return last
    return Path(out_dir) / _audit_log_shard_name(len(paths) + 1)


@dataclass(frozen=True)
class AuditLogDisclosure:
    """What the loader could NOT give its caller, made visible.

    ``complete`` is True only when every on-disk trail byte was
    parsed. Consumers that suppress work based on row PRESENCE (the
    resume workqueue filter) should warn on an incomplete load: the
    missing rows fail toward re-review (safe, expensive), never
    toward a wrong verdict.
    """

    complete: bool = True
    total_bytes: int = 0
    shards: int = 0
    #: Shard names read as a bounded newest tail (over the per-shard
    #: read budget — the pre-rotation legacy single-file shape).
    tail_read_shards: tuple[str, ...] = ()
    #: Shard names whose retained-row count bound bound the read.
    row_capped_shards: tuple[str, ...] = ()
    #: Numbered shard files beyond the contiguous set (interior
    #: shard deleted, or a plant).
    orphan_shards: tuple[str, ...] = field(default=())
    #: Contiguous-set shards whose bytes were not parsed. Two loss
    #: classes: ABSENT while a LATER shard was read (the first shard
    #: deleted out from under a rolled trail — the writer always
    #: creates it before rolling — or a shard vanishing mid-load),
    #: and PRESENT-BUT-UNREADABLE (a symlink or unopenable file at a
    #: shard name — the O_NOFOLLOW read discipline refuses it), which
    #: always counts. Either way the survivors must not masquerade as
    #: the whole trail.
    missing_shards: tuple[str, ...] = ()

    @property
    def reason(self) -> str:
        """Human summary of why the load is incomplete ('' when
        complete)."""
        if self.complete:
            return ""
        bits: list[str] = []
        if self.tail_read_shards:
            bits.append(
                "over-budget shard(s) read as bounded newest tail: "
                + ", ".join(self.tail_read_shards))
        if self.row_capped_shards:
            bits.append(
                "row-count bound hit in: "
                + ", ".join(self.row_capped_shards))
        if self.orphan_shards:
            bits.append(
                "non-contiguous shard file(s) not read: "
                + ", ".join(self.orphan_shards))
        if self.missing_shards:
            bits.append(
                "unreadable or deleted shard(s) in the contiguous "
                "set: " + ", ".join(self.missing_shards))
        return "; ".join(bits)


def load_audit_log_disclosed(
    out_dir: Path,
) -> tuple[list[dict[str, Any]], AuditLogDisclosure]:
    """Load the audit event log's contiguous shard set, disclosing
    anything the budgets kept out.

    NEVER silently returns ``[]`` for an over-budget trail: a shard
    past the per-shard read budget (the pre-rotation legacy shape —
    one production multi-segment trail crossed the budget and every
    consumer read [] for the rest of the run) degrades to a bounded
    NEWEST-tail read of that shard, loudly, with the loss recorded in
    the returned :class:`AuditLogDisclosure`. Rows keep append order
    across shards, so last-row-per-key consumers see the true last
    row either way.
    """
    from core.json import load_jsonl
    rows: list[dict[str, Any]] = []
    total_bytes = 0
    tail_read: list[str] = []
    row_capped: list[str] = []
    paths = audit_log_paths(out_dir)
    shards_read = 0
    absent: list[str] = []
    unreadable: list[str] = []
    for p in paths:
        try:
            st = os.lstat(p)
        except OSError:
            absent.append(p.name)
            continue
        # Present-but-unreadable is a different loss class from
        # absent: an entry EXISTS at a contiguous shard name and its
        # bytes were not parsed, so the load can never be complete —
        # whereas an absent shard 1 with nothing after it is just an
        # empty trail. lstat + O_NOFOLLOW mirror the read discipline
        # of core.json.load_jsonl, which loads a symlinked or
        # unopenable trail as [] (best-effort, debug-level) — without
        # this probe those shards would vanish from the disclosure.
        if not _stat.S_ISREG(st.st_mode):
            unreadable.append(p.name)
            continue
        try:
            probe_fd = os.open(
                str(p), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            unreadable.append(p.name)
            continue
        try:
            size = os.fstat(probe_fd).st_size
        finally:
            os.close(probe_fd)
        shards_read += 1
        total_bytes += size
        if size > _AUDIT_LOG_MAX_BYTES:
            tail_read.append(p.name)
        # Per-shard budgets: the trail is sandbox-writable run-dir
        # input that carries suppression authority — same intake rule
        # as the journal's per-shard caps. oversize_tail: an
        # over-budget shard degrades to its newest tail instead of
        # [] (nothing suppresses for the unread span — over-review).
        shard_rows = load_jsonl(
            p,
            max_total_bytes=_AUDIT_LOG_MAX_BYTES,
            max_line_bytes=_AUDIT_LOG_MAX_LINE_BYTES,
            oversize_tail=True,
            max_records=_AUDIT_LOG_MAX_ROWS_PER_SHARD,
        )
        if len(shard_rows) >= _AUDIT_LOG_MAX_ROWS_PER_SHARD:
            # At-bound is indistinguishable from over-bound from out
            # here; flagging the exact-full shard too errs toward
            # disclosure (over-review direction).
            row_capped.append(p.name)
        rows.extend(shard_rows)
    orphans = _audit_log_orphan_names(out_dir, len(paths))
    # An ABSENT shard counts as loss only when some LATER shard was
    # read: the empty dir (no trail yet) reads shard 1 as absent too,
    # and that must stay a complete-empty load. shard 1 absent with
    # shard 2 present means the trail's head was deleted. A
    # present-but-UNREADABLE shard always counts.
    lost = set(unreadable) | (set(absent) if shards_read else set())
    missing = tuple(p.name for p in paths if p.name in lost)
    disclosure = AuditLogDisclosure(
        complete=not (tail_read or row_capped or orphans or missing),
        total_bytes=total_bytes,
        shards=shards_read,
        tail_read_shards=tuple(tail_read),
        row_capped_shards=tuple(row_capped),
        orphan_shards=tuple(orphans),
        missing_shards=missing,
    )
    if not disclosure.complete:
        logger.warning(
            "audit log at %s loaded INCOMPLETE (%s) — consumers see "
            "the newest rows only; affected functions/sites re-review. "
            "Remedy: `raptor-audit audit-log rotate %s` (run must be "
            "stopped)",
            out_dir, disclosure.reason, out_dir,
        )
    return rows, disclosure


def load_audit_log(out_dir: Path) -> list[dict[str, Any]]:
    """Load the audit event log (one JSON record per line).

    Carries operational events — ``action=context``,
    ``action=tool_dispatch``, ``action=batch_flush``,
    ``action=record_migrated`` stub (one-shot per run for grep
    discoverability) — plus one ``action=orchestrator_review``
    telemetry record per review (written by Collector, consumed by
    strategy_stats). Authoritative review VERDICTS live in
    ``review-journal.jsonl`` in the same directory (since 2026-07-28).

    The trail is sharded like the review journal: the writer rolls
    ``.audit-log.jsonl`` to numbered siblings (``.audit-log.002.jsonl``,
    …) below the per-shard read budget, and this loader returns the
    contiguous shard set in append order. An over-budget shard (the
    pre-rotation legacy single-file shape) degrades to a bounded
    newest-tail read with a loud warning — never a silent ``[]``.
    Callers that must SEE the degradation use
    :func:`load_audit_log_disclosed`.

    Row contract: rows written by this install carry the per-purpose,
    run-bound ``integrity`` stamp (see :func:`stamp_audit_log_row`)
    and are returned WITH it — consumers read fields and must
    tolerate the stamp like any additive key. Authority-bearing
    consumers (resume suppression, fail-open deferral, the re-log
    join, cmd_record's gates, the G3 feed) route through
    :func:`load_verified_audit_log` instead, where the stamp decides;
    this tolerant loader serves the telemetry tier only. The consumer
    census test pins which readers sit on which side.
    """
    rows, _disclosure = load_audit_log_disclosed(out_dir)
    return rows


def load_verified_audit_log(out_dir: Path) -> list[dict[str, Any]]:
    """Rows of the audit event log whose run-bound integrity token
    verifies — the loader for AUTHORITY-bearing consumers.

    The log lives in the target-writable run dir; any consumer whose
    read SUPPRESSES work or relaxes a gate (resume dedup, fail_open
    census-site deferral, the end-of-run re-log join, cmd_record's
    mechanical gates) must judge only rows this install minted for
    THIS run directory, or a planted row steers the decision
    (``core.coverage.journal_mac``, audit-log domain, run-bound).
    Unstamped (pre-MAC legacy or forged), tampered, and cross-run-
    replayed rows are dropped here and thereby fail toward
    NOT-suppressing — the same tolerant-reader compromise as the
    journal's unstamped tier. Telemetry consumers (strategy stats,
    critique, gate-engagement summaries) keep reading
    :func:`load_audit_log` directly: dropped rows keep their
    telemetry value, they just never carry authority. The consumer
    census test pins which readers sit on which side.
    """
    from core.coverage import journal_mac
    binding = journal_mac.audit_log_run_binding(out_dir)
    verified: list[dict[str, Any]] = []
    dropped = 0
    rows, disclosure = load_audit_log_disclosed(out_dir)
    if not disclosure.complete:
        # Fail-closed stays per-row (unverifiable rows drop below);
        # incompleteness only SHRINKS the set — every absent row
        # fails toward NOT suppressing / NOT relaxing, so a partial
        # trail cannot grant anything. But authority consumers must
        # hear about it: their decisions now rest on the newest tail
        # of the trail only.
        logger.warning(
            "audit log: authority-bearing read at %s is operating on "
            "an INCOMPLETE trail (%s) — absent rows grant nothing "
            "(affected work re-reviews); rotate the trail to restore "
            "the full record", out_dir, disclosure.reason,
        )
    for row in rows:
        if not isinstance(row, dict):
            dropped += 1
            continue
        if journal_mac.verify_audit_log_row(
            row, row.get(journal_mac.TOKEN_KEY), binding,
        ):
            verified.append(row)
        else:
            dropped += 1
    if dropped:
        logger.warning(
            "audit log: %d row(s) without a verifying integrity token "
            "excluded from an authority-bearing read (telemetry "
            "consumers still see them; affected functions/sites "
            "re-review)", dropped,
        )
    return verified


def stamp_audit_log_row(
    entry: dict[str, Any], out_dir: Path,
) -> dict[str, Any]:
    """The entry with its integrity token minted (a copy).

    The log lives in the target-writable run dir, and one row class
    (``action=record`` / ``orchestrator_review``) grants resume
    review-SUPPRESSION authority — the same forged-clean-row lever
    the journal MAC closed, so the same per-purpose key mechanism
    stamps this lane (``core.coverage.journal_mac``, audit-log
    domain), run-bound to *out_dir* so a row copied from a sibling
    run's log never verifies here. No usable key = persist unstamped:
    the row keeps its telemetry value and simply never suppresses.
    """
    from core.coverage import journal_mac
    stamped = {
        k: v for k, v in entry.items() if k != journal_mac.TOKEN_KEY
    }
    token = journal_mac.mint_audit_log_row(
        stamped, journal_mac.audit_log_run_binding(out_dir))
    if token:
        stamped[journal_mac.TOKEN_KEY] = token
    return stamped


def append_audit_log(out_dir: Path, entry: dict[str, Any]) -> None:
    """Append an entry to the audit event log.

    Routed through ``core.json.append_jsonl`` so the trail gets the
    same O_APPEND line-atomicity and O_NOFOLLOW symlink refusal as
    every other JSONL trail writer, and stamped with the audit-log
    integrity token (see :func:`stamp_audit_log_row`) — the row
    lands on disk with the ``integrity`` key appended and otherwise
    byte-identical to *entry* (compact separators).

    The append target is shard-resolved (:func:`audit_log_append_path`):
    once the active shard crosses the roll threshold, appends move to
    the next numbered sibling, keeping every shard under the reader's
    per-shard budget. The integrity stamp is per-row and run-bound —
    it does not bind the row to a file name — so rows verify
    unchanged whichever shard they land in.
    """
    import json

    from core.json import append_jsonl
    stamped = stamp_audit_log_row(entry, out_dir)
    # Write/read parity for the per-line budget: the reader skips a
    # line over _AUDIT_LOG_MAX_LINE_BYTES as malformed, so a row that
    # big is invisible to every consumer from the moment it lands.
    # The trail is append-only — the row is still written (silently
    # dropping audit data would be worse) — but the writer flags it
    # at creation time, where the offending call site is
    # identifiable, instead of leaving the loss to surface as a
    # reader-side skip long after.
    line_bytes = len(json.dumps(
        stamped, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")) + 1
    if line_bytes > _AUDIT_LOG_MAX_LINE_BYTES:
        logger.warning(
            "audit log append at %s: row is %d bytes — over the "
            "reader's per-line budget (%d bytes), so every reader "
            "will skip it. Trim the row's payload at the call site.",
            out_dir, line_bytes, _AUDIT_LOG_MAX_LINE_BYTES,
        )
    append_jsonl(audit_log_append_path(out_dir), stamped,
                 compact=True)


def _compute_hash(
    target_path: Path,
    file_path: str,
    line_start: int,
    line_end: int | None,
) -> str | None:
    """Compute source hash for staleness detection.

    Returns None if the source file is missing or hashing failed —
    callers treat a missing hash as ``source_hash=""`` on journal
    entries, which effectively disables staleness checks for that
    function (safe over-review, not silent miss).
    """
    full_path = target_path / file_path
    if not full_path.exists():
        return None

    try:
        from core.annotations.storage import compute_function_hash

        from .context import fallback_span_end

        # A missing line_end means the review covered the fallback
        # read window (core.audit.context._read_source), so the hash
        # must cover the SAME window: hashing only the header line
        # left every body edit below it invisible to staleness and
        # reuse gating (changed code silently reused as reviewed).
        end = fallback_span_end(line_start, line_end)
        return compute_function_hash(full_path, line_start, end)
    except Exception:  # noqa: BLE001 — best-effort: missing hash only widens review
        logger.debug("hash computation failed for %s:%d", file_path, line_start)
        return None

def binary_item_hash(file_entry: dict, item: dict) -> str | None:
    """Staleness anchor for a binary checklist item.

    Binds the review to the BINARY's content (the file entry's
    sha256, stamped at checklist build) and the function's
    address/size — a rebuilt binary or a moved/resized function
    invalidates the review instead of silently suppressing it.
    Self-describing ``bin:`` prefix so the journal fold can route it.
    """
    sha = file_entry.get("sha256") or ""
    addr = item.get("address")
    if addr is None:
        addr = (item.get("metadata") or {}).get("address")
    if not sha or addr is None:
        return None
    size = item.get("size") or (item.get("metadata") or {}).get("size") or 0
    # Checklists round-trip through JSON and other producers may spell
    # addresses as hex strings — coerce so both forms hash identically;
    # unparsable values return None (missing hash only widens review)
    # instead of raising out of the caller's checklist walk.
    addr = _as_int(addr)
    size = _as_int(size)
    if addr is None or size is None:
        return None
    return f"bin:{sha[:12]}:{addr:x}:{size:x}"


def _as_int(value: Any) -> int | None:
    """``value`` as an int; accepts hex/octal/binary string spellings
    (``int(x, 0)``). None when unparsable."""
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


def binary_source_hash(
    out_dir: Path, file_path: str, function_name: str,
) -> str | None:
    """Write-time twin of :func:`binary_item_hash` — resolves the
    item from the run's checklist."""
    try:
        from pathlib import Path as _Path

        from core.audit.gaps import load_checklist
        cl = load_checklist(_Path(out_dir))
        for fe in (cl or {}).get("files", []):
            if fe.get("path") != file_path:
                continue
            items = fe.get("items", fe.get("functions", [])) or []
            for item in items:
                if item.get("name") == function_name:
                    return binary_item_hash(fe, item)
    except Exception:  # noqa: BLE001 — missing hash only widens review
        logger.debug(
            "binary source hash failed for %s:%s",
            file_path, function_name, exc_info=True,
        )
    return None
