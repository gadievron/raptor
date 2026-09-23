"""Review journal — append-only JSONL record of every LLM review decision.

Each entry captures the full context available at review time: verdict,
strategies, domain model state, hypotheses tested, and prose reasoning.
This enables context-aware staleness detection (re-review when domain
knowledge grows) and crash-safe resume (read journal, skip reviewed).

Per-run: ``review-journal.jsonl`` in the output directory.
Project-level: ``review-journal-index.json`` — compacted view, one entry
per ``(file, function)`` pair, most recent wins.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import threading
import types
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Union, get_args, get_origin, get_type_hints

from core.json import load_json, loads

try:
    import fcntl
    _HAS_FCNTL = True
except ImportError:
    _HAS_FCNTL = False

logger = logging.getLogger(__name__)

JOURNAL_FILENAME = "review-journal.jsonl"
INDEX_FILENAME = "review-journal-index.json"
INDEX_SCHEMA_VERSION = 1

# Byte budget for loading the journal / index. Both can arrive via a
# /project archive import, so the st_size gate (before any read)
# keeps an oversize file from being buffered. Real journals are one
# ~1 KiB line per reviewed function — even huge audits stay far under
# this.
_MAX_JOURNAL_BYTES = 256 * 1024 * 1024

# domain-model.json is a small RAPTOR-written study artifact.
_MAX_DOMAIN_MODEL_BYTES = 64 * 1024 * 1024

# Per-load cap on detailed row-quarantine warnings. A hostile journal
# is millions of refused rows; one warning per row is its own flood
# (the refusals themselves stay counted and summarised). High enough
# that every genuine truncated-write/corruption incident (a handful of
# rows) keeps full detail; low enough that an at-cap degenerate file
# cannot emit millions of log lines. Downgrading (not dropping) the
# excess keeps the detail reachable at debug level.
_ROW_WARN_LIMIT = 20

VALID_VERDICTS = frozenset({
    "clean", "suspicious", "finding", "error", "dormant",
    # Gate-resolution bucket: tool-blind, needs concrete verification.
    # Journaled when the end-of-run resolution passes re-journal final
    # statuses (entries were committed mid-loop, pre-resolution).
    "dark",
})


# ── file:function key encoding ───────────────────────────────────────
#
# In-memory keys join the file path and function name with ':'. The
# raw join is not injective: file "a.c:evil" + function "f" collides
# with file "a.c" + function "evil:f". Producers and consumers must
# therefore percent-encode the FILE component before joining.
#
# The encoding is deliberately minimal — only ':' and '%' (the escape
# character itself) are encoded, so every path without those two
# characters keeps its historical key byte-for-byte. A full
# ``urllib.parse.quote`` would also rewrite spaces and non-ASCII
# paths, silently desyncing the many raw ``f"{file}:{name}"`` joins
# elsewhere in the tree that this chokepoint must stay consistent
# with.
#
# On-disk compatibility: journal entries persist ``file`` and
# ``function`` as separate JSON fields — keys are always recomputed
# from those fields at read time, never parsed from disk. The
# project index's dict keys (``index_key``) are opaque identity
# handles: old-format keys keep loading (entries reconstruct from
# fields), and a re-merge of a colon-bearing file simply adds a row
# under the new key, which ``load_index`` collapses to
# latest-by-timestamp.

def encode_key_file(file: str) -> str:
    """Percent-encode ':' and '%' in a key's file component."""
    if ":" not in file and "%" not in file:
        return file
    return file.replace("%", "%25").replace(":", "%3A")


def make_function_key(file: str, function: str) -> str:
    """Injective ``file:function`` key (file component encoded)."""
    return f"{encode_key_file(file)}:{function}"


def split_function_key(key: str) -> tuple[str, str]:
    """Split a key back into (file, function).

    Splits on the LAST ':' — the historical convention — so
    old-format (unencoded) keys still parse, then decodes the file
    component. Decode order matters: '%3A' first (encoded ':' — a
    literal '%' is always followed by '25' after encoding), then
    '%25'.
    """
    file, _, function = key.rpartition(":")
    return file.replace("%3A", ":").replace("%25", "%"), function


# Journal entry schema version.
#
# Version 1 (current):
#   - Original field set defined by the amendment
#   - Additive changes (new optional fields) preserve version=1
#   - Breaking changes (removed fields, changed types, reinterpreted
#     values) bump to version=2
#   - Legacy entries without a ``schema_version`` field are treated
#     as version=1 (they predate the field but are structurally
#     compatible with it)
#
# Readers reject unknown versions loudly — do not silently skip.
SCHEMA_VERSION = 1


@dataclass
class ReviewJournalEntry:
    """One LLM review decision with full context."""

    ts: str
    run_id: str
    file: str
    function: str
    verdict: str
    source_hash: str
    # Receiver-qualified name (``Class.method``) when the inventory
    # metadata carries one. Optional presentation/join identity —
    # ``function`` stays the bare name every key derives from, so
    # same-named methods stay auditable in reports.
    function_qualified: str | None = None
    line_start: int = 0
    line_end: int | None = None
    cwe: str | None = None
    confidence: float | None = None
    strategy_id: str | None = None
    strategies: list[str] = field(default_factory=list)
    domain_model_hash: str | None = None
    domain_concepts_available: list[str] = field(default_factory=list)
    invariants_available: list[str] = field(default_factory=list)
    hypotheses: list[dict[str, str]] = field(default_factory=list)
    body: str = ""
    reading_list_items: list[str] = field(default_factory=list)
    # Receipts of study answers whose re-review produced this verdict
    # (question, tier, file, line, sha256, verified) — makes a bad
    # study answer's blast radius traceable from the journal.
    study_receipts: list[dict] = field(default_factory=list)
    model: str | None = None
    # Tools whose OUTPUT the verdict carries (the confirming receipt
    # stamp) — never the dispatched union. Downstream verdict-weight
    # consumers (Reflexion referee, survival telemetry, verdict reuse,
    # corpus attribution) read this field; a dispatched-but-silent tool
    # is not evidence (see core.audit.promotion_alarm).
    evidence_tools: list[str] = field(default_factory=list)
    # Tools that RAN for this review regardless of what they concluded
    # (refuted/inconclusive/confirmed). Provenance/coverage signal
    # only — kept separate so evidence_tools stays outcome-bearing
    # (the old union let dispatched-but-unconfirming runs read
    # as confirming receipts in the durable journal).
    tools_dispatched: list[str] = field(default_factory=list)
    # Chain step types that did NOT look for this function: the
    # tool-chain early exit after a promotion-grade receipt, channel
    # health/coverage gates, codeql database-membership misses,
    # definitional (unqueryable-name) skips, and substrate skips
    # (target language outside the tier's model). Kept separate
    # from tools_dispatched (the channel did not look — it must not
    # read as coverage or as a silently-refuting run) and from
    # tools that errored. Additive; absent on rows without a skip.
    tools_skipped: list[str] | None = None
    token_budget: int | None = None
    cost_usd: float | None = None
    duration_s: float | None = None
    prior_review: str | None = None
    lesson: str | None = None
    validate_verdict: str | None = None
    validate_reason: str | None = None
    verdict_rationale: str | None = None
    counter_hypothesis: str | None = None
    # ``source_drifted``: Reflexion correction entries set this true
    # when the source has changed since the prior review — surfaces
    # the drift instead of hiding it behind an inherited
    # ``source_hash``.
    source_drifted: bool | None = None
    # ``context_reduced``: verdict produced by the reduced-context
    # timeout retry (heaviest context blocks stripped). Recorded so
    # cross-run verdict reuse can refuse to import a lower-confidence
    # verdict as durable coverage.
    context_reduced: bool | None = None
    # ``reused`` / ``reused_from_run``: this entry was imported from a
    # prior run's verdict (source hash unchanged) rather than produced
    # by a live review. ``reused_from_run`` always names the ORIGINAL
    # producing run, so chains of reuse keep pointing at the run that
    # actually did the review.
    reused: bool | None = None
    reused_from_run: str | None = None
    # ``producer``: which tool produced this entry — ``audit`` or
    # ``agentic``. Enables reliable ``import_journal`` tool-label
    # mapping without inferring from ``run_id`` string patterns.
    producer: str | None = None
    # ``error_class``: machine-readable failure class on
    # ``verdict == "error"`` rows (``environment`` for systemic
    # environmental failures vs the per-function classes). Error rows
    # never fold into coverage or verdict reuse regardless; the class
    # lets readers separate "the environment failed" from "this
    # review failed" without parsing the body. Additive; absent on
    # non-error and pre-field rows.
    error_class: str | None = None
    # ``edge_callee``: set ONLY on tier-1 edge-contract review entries
    # ("callee_file:callee", file component percent-encoded). The
    # entry's ``file``/``function`` stay the CALLER so every existing
    # consumer keys off the caller; ``key``/``index_key`` gain an
    # edge suffix so an edge review never collides with — or worse,
    # evicts / suppresses — the caller's own function review. For
    # edge entries ``source_hash`` is the two-span form:
    # caller-span hash + callee-span hash concatenated (drift in
    # EITHER endpoint resurfaces the edge).
    edge_callee: str | None = None
    # ``edge_verdicts``: tier-2 folded edge-contract verdicts recorded
    # on the CALLER's normal function entry:
    # ``[{callee, call_line, verdict}]``. Additive; absent when the
    # review carried no edge-contract section.
    edge_verdicts: list[dict] | None = None
    # ``provisional``: this finding-grade row was appended by the
    # mid-loop promotion cadence, BEFORE the post-loop resolution
    # passes (refutation gates, binary-oracle demotion, the
    # counter-escalation floor) had their chance to retract it. The
    # end-of-run finalization appends a corrective row without the
    # mark when the promotion survives; a row still carrying it means
    # the run was interrupted before finalization. Cross-run verdict
    # reuse refuses provisional rows — the verdict is not settled.
    # Additive; absent on non-provisional rows.
    provisional: bool | None = None
    # ``integrity``: HMAC provenance token over the row's canonical
    # JSON (this field excluded), stamped by append_entry. The gap
    # fold verifies before granting verdict-reuse authority; see
    # core.coverage.journal_mac. Additive; absent on pre-MAC rows.
    integrity: str | None = None
    schema_version: int = SCHEMA_VERSION

    @property
    def key(self) -> str:
        base = make_function_key(self.file, self.function)
        if self.edge_callee:
            # Distinct resume/fold identity: an edge review must never
            # mark the caller function itself as reviewed.
            return f"{base}->{self.edge_callee}"
        return base

    @property
    def index_key(self) -> str:
        """Index key: (file, function, model, strategy_hash, producer).

        Amendment §1 D1 widens the compaction key from
        ``(file, function)`` to preserve multi-model + multi-strategy
        history — otherwise Phase-5 context-aware staleness has no
        signal to work with.

        The producer segment preserves multi-PRODUCER history: an
        /agentic finding-analysis and an /audit review of the same
        function can share model + strategy_hash (default model, empty
        strategies), and without the segment whichever merged later
        EVICTED the other from the index — the audit verdict was gone,
        not merely shadowed. Old-format keys keep loading (entries
        reconstruct from fields; a re-merge adds a row under the new
        key and ``load_index`` collapses by timestamp).
        """
        strategy_hash = _canonical_strategy_hash(self.strategies)
        model = self.model or ""
        base = (
            f"{encode_key_file(self.file)}:{self.function}"
            f":{model}:{strategy_hash}:{entry_producer(self)}"
        )
        if self.edge_callee:
            # Edge entries index separately per callee — sharing the
            # caller's index key would evict the caller's function
            # verdict from the compacted index (same eviction class
            # the producer segment exists to prevent).
            base = f"{base}:{self.edge_callee}"
        # Span suffix ('@' cannot appear in the colon-joined segments'
        # separator role): same-named items at different spans (macro
        # redefinitions, C++ overloads) are distinct review subjects —
        # without the suffix they evict each other at merge time, so a
        # NEW run's cross-run reuse only ever sees one of N reviewed
        # sites and re-buys the rest (companion of the same-run
        # per-site fold fix). Legacy span-less keys are re-homed
        # losslessly at merge time (entries always carried line_start
        # in their FIELDS; only the key lacked it).
        return f"{base}@{self.line_start or 0}"

    def to_dict(self) -> dict[str, Any]:
        d = {k: v for k, v in asdict(self).items() if v is not None}
        # ``schema_version`` is required; keep even when default.
        d["schema_version"] = self.schema_version
        return d


def is_mechanical_echo(entry: Any) -> bool:
    """True for post-loop mechanical echo rows.

    Pattern-scan findings are journalled after the review loop for
    cross-layer visibility — one ``[mechanical]`` row per finding,
    zero cost, no rationale, ``post-loop-mechanical`` strategy tag.
    They are NOT LLM reviews: naive verdict counts that include them
    inflate by one suspicious row per pattern-scan finding. Accepts a
    :class:`ReviewJournalEntry` or a raw journal dict — the single
    counting rule for every summary consumer.
    """
    if isinstance(entry, dict):
        strategies = entry.get("strategies")
        body = entry.get("body")
    else:
        strategies = getattr(entry, "strategies", None)
        body = getattr(entry, "body", None)
    return (
        "post-loop-mechanical" in (strategies or [])
        or (body or "").startswith("[mechanical]")
    )


def _canonical_strategy_hash(strategies: list[str]) -> str:
    """Sha1 of comma-joined sorted strategy names, first 12 chars.

    Deterministic across list-order permutations. Empty list → the
    sentinel ``"empty"``. See amendment §1 D1 rationale.
    """
    if not strategies:
        return "empty"
    import hashlib
    canon = ",".join(sorted(s for s in strategies if s))
    if not canon:
        return "empty"
    return hashlib.sha1(canon.encode()).hexdigest()[:12]


def now_iso() -> str:
    """UTC ISO-8601 timestamp with microsecond precision.

    Microseconds (six digits) guarantee that sequential appends —
    e.g. Reflexion's seed + correction pair, or a batched collector
    flushing many outcomes in tight succession — sort strictly
    monotonically. Prior second-only precision (%Y-%m-%dT%H:%M:%SZ)
    caused ``latest_entries`` and ``merge_into_index`` to see ties,
    which forced a choice between correctness (last-write-wins on
    tie) and idempotency (equal-ts merge counts as no-op). The
    strict-monotone stamp makes both cases align on `>` semantics.
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# ── Write ────────────────────────────────────────────────────────────

#: Serialises appends from THIS process's threads. POSIX only makes
#: O_APPEND writes atomic up to PIPE_BUF; audit entries (full review
#: bodies, hypotheses, study receipts) routinely exceed that, and the
#: parallel executor appends from several worker threads through
#: separate fds — interleaved partial writes corrupted lines.
_append_lock = threading.Lock()

#: Hardened open flags, mirroring ``core.json.jsonl.append_jsonl``:
#: O_NOFOLLOW refuses a symlink planted at the journal path inside a
#: writable run dir (fails with ELOOP); O_CLOEXEC keeps the fd out of
#: spawned children (tool subprocesses must not inherit a journal fd).
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
#: O_NONBLOCK on the WRITE side: an O_WRONLY open of a planted
#: reader-less FIFO blocks forever (O_NOFOLLOW does not help);
#: with the flag it fails fast (ENXIO), and a FIFO that has a
#: reader is caught by the fstat(S_ISREG) check on the opened fd.
#: Regular files ignore the flag entirely.
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


def _fd_is_regular(fd: int) -> bool:
    import stat as _stat
    return _stat.S_ISREG(os.fstat(fd).st_mode)

#: Bounded retries for the (rare) short-write path in
#: :func:`append_entry`. Each retry re-writes the WHOLE line after
#: rolling back the partial bytes, so a persistent failure (ENOSPC)
#: surfaces as a raised OSError with the journal still line-intact.
_APPEND_MAX_ATTEMPTS = 3


def append_entry(out_dir: Path, entry: ReviewJournalEntry) -> None:
    """Locked, torn-write-safe single-line append to review-journal.jsonl.

    The whole encoded line is issued as ONE ``os.write`` under a
    per-process lock plus an advisory ``flock`` (cross-fd /
    cross-process safety — a resumed segment or a sweep can append
    concurrently from another process). A single write() syscall on a
    regular file is not interruptible mid-copy the way a Python-level
    write LOOP is: the pre-fix loop could be abandoned between partial
    writes (worker killed, exception), leaving a truncated line that
    the NEXT append glued onto — one corrupt line AND one lost entry.

    Torn-write handling (house precedent: ``core.json`` save/append
    hardening): if the single write comes back short (ENOSPC, quota),
    the partial bytes are rolled back with ``ftruncate`` to the
    pre-write size — legal because ``flock`` is still held, so our
    partial line is provably the tail of the file — and the whole
    line is retried, bounded by ``_APPEND_MAX_ATTEMPTS``. Exhaustion
    raises ``OSError`` with the journal left line-intact.

    Raises ``OSError`` — notably ELOOP when the journal path is a
    symlink (O_NOFOLLOW). No per-entry fsync — the caller can
    ``flush_journal()`` at batch end.
    """
    journal_path = out_dir / JOURNAL_FILENAME
    out_dir.mkdir(parents=True, exist_ok=True)
    # Provenance stamp (core.coverage.journal_mac): the fold trusts
    # rows for review suppression and $0 verdict reuse, so each row
    # carries a MAC over its own canonical content. Stamped on the
    # entry object too, so a caller that keeps it sees the same row
    # a reader would load. No usable key → the row persists unstamped
    # and demotes to the hash-gated legacy tier on read.
    from core.coverage import journal_mac
    row = entry.to_dict()
    row.pop(journal_mac.TOKEN_KEY, None)
    token = journal_mac.mint_row(row)
    if token:
        entry.integrity = token
        row[journal_mac.TOKEN_KEY] = token
    # allow_nan=False: the reader (load_journal via core.json.loads)
    # skips NaN/Infinity lines as malformed on both backends — a
    # non-finite float in any field would silently drop this MAC'd
    # row on the next read. Fail loudly at write time instead (same
    # parity rule as save_json / append_jsonl).
    data = (
        json.dumps(row, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode("utf-8")
    with _append_lock:
        fd = os.open(
            str(journal_path),
            os.O_WRONLY | os.O_APPEND | os.O_CREAT
            | _O_NOFOLLOW | _O_CLOEXEC | _O_NONBLOCK,
            0o644,
        )
        try:
            if not _fd_is_regular(fd):
                # A planted FIFO (with a reader — the reader-less case
                # already failed the open with ENXIO thanks to
                # O_NONBLOCK) or device node: writing the journal into
                # it silently discards MAC-stamped rows and every
                # journal writer queues behind this one on
                # _append_lock. Same disposition as the symlink plant
                # (O_NOFOLLOW → ELOOP): raise, journal untouched.
                msg = (
                    f"journal path {journal_path} is not a regular "
                    "file — refusing to append"
                )
                raise OSError(msg)
            if _HAS_FCNTL:
                fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                for attempt in range(1, _APPEND_MAX_ATTEMPTS + 1):
                    size_before = os.fstat(fd).st_size
                    written = os.write(fd, data)
                    if written == len(data):
                        break
                    # Short write: roll the partial line back so the
                    # journal never carries a torn tail. Safe under
                    # the held flock — no cooperating writer can have
                    # appended after our partial bytes.
                    with contextlib.suppress(OSError):
                        os.ftruncate(fd, size_before)
                    logger.warning(
                        "journal append short write (%d of %d bytes, "
                        "attempt %d/%d) — rolled back",
                        written, len(data), attempt, _APPEND_MAX_ATTEMPTS,
                    )
                    if attempt == _APPEND_MAX_ATTEMPTS:
                        msg = (
                            f"journal append failed after "
                            f"{_APPEND_MAX_ATTEMPTS} short-write attempts "
                            f"({written} of {len(data)} bytes)"
                        )
                        raise OSError(msg)
            finally:
                if _HAS_FCNTL:
                    fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def flush_journal(out_dir: Path) -> None:
    """fsync the journal file — call at batch/run boundaries.

    Same fd discipline as the appender: the pre-fix bare ``O_RDONLY``
    open followed a planted symlink (fsync of a FOREIGN file) and
    blocked forever on a writer-less FIFO (a read-side open of a FIFO
    waits for a writer). Best-effort: a refused/missing journal is
    silently skipped, like the old ``is_file()`` probe's negative.
    """
    from core.source import open_regular
    fh = open_regular(out_dir / JOURNAL_FILENAME, "rb")
    if fh is None:
        return
    with fh:
        os.fsync(fh.fileno())


# ── Read ─────────────────────────────────────────────────────────────

def load_entries(out_dir: Path) -> list[ReviewJournalEntry]:
    """Load all valid entries from review-journal.jsonl.

    Skips corrupt trailing line (truncated write) with a warning.
    Interior corrupt lines are also skipped with warnings.
    """
    journal_path = out_dir / JOURNAL_FILENAME
    # fd-discipline open (core.source.open_regular): the journal sits
    # in the sandbox-writable run dir, and the previous
    # is_symlink()/is_file() probes raced a swap — a symlink swapped
    # in between check and open read a FOREIGN journal into this
    # run's merge, and a planted FIFO blocked the open forever.
    # O_NOFOLLOW + O_NONBLOCK + fstat(S_ISREG) on the OPENED fd close
    # both windows.
    from core.source import open_regular
    fh = open_regular(journal_path, "rb")
    if fh is None:
        return []

    # Size gate on the OPENED fd, before the read buffers anything.
    try:
        size = os.fstat(fh.fileno()).st_size
    except OSError:
        fh.close()
        return []
    if size > _MAX_JOURNAL_BYTES:
        fh.close()
        logger.warning(
            "journal: %s is %d bytes (over the %d byte cap); "
            "refusing to load", journal_path, size, _MAX_JOURNAL_BYTES,
        )
        return []

    entries: list[ReviewJournalEntry] = []
    # Read raw BYTES and hand each line to the parser individually. A
    # whole-file ``read_text()`` decoded BEFORE any per-line quarantine
    # could run, so one undecodable byte (anything with the run-dir
    # write grant can append ``b"\x80"``) crashed every journal
    # consumer at once; per-row parsing contains a bad encoding to the
    # row that carries it (both JSON backends decode per input).
    #
    # STREAM the lines instead of materialising a whole-file
    # ``splitlines()``: a degenerate journal of 2-3 byte rows costs one
    # small bytes object PER LINE when split eagerly (~20x the file
    # size in peak RSS — an at-cap journal of tiny rows OOM-killed the
    # reader that exists to contain hostile bytes). Iterating the file
    # keeps one line alive at a time, so the byte cap bounds the
    # reader's own memory, not just the file. Pinned by the RSS-bounded
    # test in core/coverage/tests/test_journal_containment.py.
    corrupt = 0
    row_warnings = 0
    budget = _MAX_JOURNAL_BYTES

    def _row_warning(msg: str, *args: object) -> None:
        # Rate-limit per-row warnings: a hostile journal is millions of
        # refused rows, and one warning per row is its own flood. The
        # first _ROW_WARN_LIMIT keep full detail; the rest downgrade to
        # debug, and the trailing summary always reports totals.
        nonlocal row_warnings
        row_warnings += 1
        if row_warnings <= _ROW_WARN_LIMIT:
            logger.warning(msg, *args)
            if row_warnings == _ROW_WARN_LIMIT:
                logger.warning(
                    "journal: further per-row warnings for %s "
                    "downgraded to debug", journal_path,
                )
        else:
            logger.debug(msg, *args)

    try:
        with fh:
            i = -1
            while True:
                # Bounded readline: the fstat gate above races a
                # writer that grows the file after the check, so the
                # cap is re-enforced on the bytes actually read — and
                # at LINE granularity too: a plain ``for line in fh``
                # materialised one multi-GiB line whole before the
                # budget check fired, so the cap held only between
                # lines. readline(budget + 1) bounds the worst case
                # to one capped chunk.
                line = fh.readline(budget + 1)
                if not line:
                    break
                i += 1
                budget -= len(line)
                if budget < 0:
                    logger.warning(
                        "journal: %s grew past the %d byte cap "
                        "mid-read; stopping (%d entries loaded)",
                        journal_path, _MAX_JOURNAL_BYTES, len(entries),
                    )
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = loads(line)
                except Exception:  # noqa: BLE001 — row containment boundary
                    # ANY parse failure quarantines THIS row only — malformed
                    # JSON (ValueError), undecodable bytes (UnicodeDecodeError),
                    # nesting bombs (RecursionError on the stdlib arm; orjson
                    # rejects depth with ValueError). Enumerating exception
                    # types here is exactly how each previous planted-row
                    # generation crashed every consumer: the journal lives in
                    # the sandbox-writable run dir, so the boundary must be
                    # total. Pinned by the generative containment test
                    # (core/coverage/tests/test_intake_containment.py).
                    corrupt += 1
                    logger.debug(
                        "journal: skipping corrupt line %d in %s",
                        i + 1, journal_path,
                    )
                    continue
                if not isinstance(raw, dict):
                    # Valid JSON is not necessarily a dict: ``null``, a
                    # list, a string, or a bare number parses fine but
                    # would raise AttributeError inside _entry_from_dict
                    # — past any except tuple keyed on the dict schema.
                    # Quarantine the row BEFORE handing it over:
                    # anything that is not a validated dict is
                    # contained here.
                    _row_warning(
                        "journal: skipping non-dict entry on line %d: %s",
                        i + 1, type(raw).__name__,
                    )
                    continue
                try:
                    entries.append(_entry_from_dict(raw))
                except Exception as exc:  # noqa: BLE001 — row containment boundary
                    # The journal lives inside the run dir — SANDBOX-
                    # WRITABLE — so ONE planted row must quarantine
                    # (skip + warn), never persistently crash every
                    # journal consumer (audit resume, reports,
                    # completion merge). The catch is deliberately
                    # total: the previous tuple (TypeError/KeyError/
                    # ValueError) was a shape enumeration, and each
                    # newly reachable exception class (serializer
                    # RecursionError on a deep field, future validator
                    # arms) re-opened the crash. Same oracle as the
                    # parse arm above.
                    _row_warning(
                        "journal: skipping malformed entry on line %d: %s",
                        i + 1, exc,
                    )
    except OSError as exc:
        # Open failure, or a read failure mid-iteration (EIO): keep
        # whatever already loaded (degrade, never propagate) and warn.
        logger.warning(
            "journal: failed to read %s: %s", journal_path, exc,
        )
    if corrupt:
        logger.warning(
            "journal: skipped %d corrupt line(s) in %s "
            "(%d entries loaded)",
            corrupt, journal_path, len(entries),
        )
    return entries


# ── row field-type validation ────────────────────────────────────────
#
# The journal (and the index its rows merge into) lives inside the
# sandbox-writable run dir, so EVERY field of a row is attacker-
# writable — not just the row's outer shape. Schema-version and
# line-span vetting alone left the other fields' types unchecked: a
# planted ``"file": 5`` crashed ``encode_key_file`` inside every
# ``reviewed_set()`` call, and an int ``ts`` crashed the ordering
# compares in ``latest_entries`` and ``merge_into_index`` — one
# 60-byte line persistently wedged every journal consumer (audit
# resume, reports, verdict reuse, completion merge). The expected
# types are derived MECHANICALLY from the dataclass annotations, not
# from an enumerated field list, so a field added to
# :class:`ReviewJournalEntry` is validated from birth; the closure
# test enumerates ``dataclasses.fields()`` against the validator.

#: Fields whose values are CLAMPED to safe defaults instead of
#: quarantining the row (see the span vetting in _entry_from_dict —
#: a forged span is contained while the rest of the row's evidence
#: is kept).
_CLAMPED_FIELDS = frozenset({"line_start", "line_end"})

_FIELD_TYPES: dict[str, Any] | None = None


def _field_types() -> dict[str, Any]:
    """Resolved ``{field: annotation}`` map for the entry dataclass."""
    global _FIELD_TYPES
    if _FIELD_TYPES is None:
        _FIELD_TYPES = get_type_hints(ReviewJournalEntry)
    return _FIELD_TYPES


def _value_matches(value: Any, expected: Any) -> bool:
    """True when a parsed-JSON *value* conforms to annotation *expected*.

    Depth rule: lists are validated through their ELEMENTS, but
    validation stops at dict-ness — JSON object keys are always str,
    and the dict values inside journal rows (hypothesis fields, study
    receipts, edge verdicts) are LLM-derived free-form that consumers
    guard and format individually; validating them strictly would
    retroactively quarantine legitimate historical rows. ``bool`` is
    rejected where int/float is expected (``isinstance(True, int)``
    holds in Python); int is accepted where float is expected (JSON
    has a single number type).
    """
    origin = get_origin(expected)
    if origin in (Union, types.UnionType):
        return any(_value_matches(value, arg) for arg in get_args(expected))
    if expected is type(None):
        return value is None
    if origin is list or expected is list:
        if not isinstance(value, list):
            return False
        args = get_args(expected)
        return not args or all(_value_matches(v, args[0]) for v in value)
    if origin is dict or expected is dict:
        return isinstance(value, dict)
    if expected is bool:
        return isinstance(value, bool)
    if expected is int:
        return isinstance(value, int) and not isinstance(value, bool)
    if expected is float:
        return (
            isinstance(value, (int, float)) and not isinstance(value, bool)
        )
    if expected is str:
        return isinstance(value, str)
    # Unknown annotation: fail closed — quarantining the row beats
    # handing an unvalidated value to consumers. The closure test
    # surfaces a missing validator arm at development time.
    return False


def _validate_field_types(raw: dict[str, Any]) -> None:
    """Raise ``ValueError`` for any known field with a wrong-typed value.

    Unknown keys are ignored (tolerant reader — additive fields from a
    same-schema-version future writer must not quarantine); absent
    fields take the dataclass defaults.
    """
    for name, expected in _field_types().items():
        if name in _CLAMPED_FIELDS or name == "schema_version":
            # Spans are clamped by _entry_from_dict (forged-span
            # containment keeps the row); schema_version is vetted
            # before this runs.
            continue
        if name not in raw:
            continue
        if not _value_matches(raw[name], expected):
            msg = (
                f"field {name!r} has type {type(raw[name]).__name__}, "
                f"expected {expected}"
            )
            raise ValueError(msg)


def _validate_serializable(raw: dict[str, Any]) -> None:
    """Raise ``ValueError`` when *raw* cannot round-trip the journal's
    own serializer.

    Type validation alone leaves the CONTENT unchecked: a lone
    surrogate inside a ``str`` field (deliverable as a pure-ASCII
    ``\\ud800`` escape) and a float that overflowed to ``inf`` at
    parse (``1e400`` — ``parse_constant`` only fires on the literal
    ``NaN``/``Infinity`` tokens) both pass the type arms and then
    detonate at the WRITE boundary — ``save_json`` inside the merge
    flock (``UnicodeEncodeError`` at the utf-8 encode /
    ``ValueError`` from ``allow_nan=False``) — so one planted row
    persistently crashed every run-completion merge on stdlib-json
    environments (orjson rejects both shapes at parse, but orjson is
    an optional dependency). The invariant is json.dumps-ability
    under the writers' exact strictness pins (``allow_nan=False``,
    raw-UTF-8 encodable), NOT an enumerated hostile-value list —
    anything the journal's own writers would refuse to serialize is
    refused at row acceptance, closing the class.
    """
    try:
        json.dumps(raw, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        # UnicodeEncodeError ⊂ ValueError. RecursionError: a structure
        # deep enough to blow the ENCODER's recursion (parse and dump
        # limits differ with stack depth at the call site) is just as
        # unserializable — normalise it to the same refusal so callers'
        # ValueError arms (row quarantine, IndexUnreadable) see it.
        msg = f"row does not round-trip the journal serializer: {exc}"
        raise ValueError(msg) from exc


def _entry_from_dict(raw: dict[str, Any]) -> ReviewJournalEntry:
    """Construct an entry from a parsed JSON dict, tolerating missing optional fields.

    Schema-version compat: absent ``schema_version`` field defaults to
    1 (legacy entries predate the field). Unknown versions raise a
    loud ``ValueError`` — do not silently reinterpret unknown data.
    Every known field's TYPE is then validated against the dataclass
    annotation (:func:`_validate_field_types`), and the row's CONTENT
    must round-trip the journal's own serializer
    (:func:`_validate_serializable`) — either violation raises
    ``ValueError`` into the callers' quarantine arms.
    """
    version = raw.get("schema_version", 1)
    # Exact-int check: ``True == 1`` and ``1.0 == 1`` both slip a bare
    # equality compare, storing/re-emitting a wrong-typed version
    # marker as-is — pin the field to a genuine int.
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or version != SCHEMA_VERSION
    ):
        msg = (
            f"unknown journal entry schema_version={version!r}; "
            f"this reader supports {SCHEMA_VERSION} only"
        )
        raise ValueError(msg)
    _validate_field_types(raw)
    _validate_serializable(raw)
    # Line spans are vetted at parse: journal files live inside run
    # dirs (sandbox write grants), and a forged multi-million-line
    # span detonates in the coverage store's interval-to-set
    # conversion (hundreds of MB per row) at every snapshot/render.
    _MAX_LINE = 2_000_000
    _ls = raw.get("line_start", 0)
    _le = raw.get("line_end")
    if not isinstance(_ls, int) or isinstance(_ls, bool) \
            or not (0 <= _ls <= _MAX_LINE):
        _ls = 0
    if _le is not None and (not isinstance(_le, int)
                            or isinstance(_le, bool)
                            or not (0 <= _le <= _MAX_LINE)):
        _le = None
    if _le is not None and _ls and _le < _ls:
        _le = None
    if _le is not None and _ls and (_le - _ls) > 50_000:
        _le = _ls + 50_000  # no real function is 50k lines
    return ReviewJournalEntry(
        ts=raw["ts"],
        run_id=raw["run_id"],
        file=raw["file"],
        function=raw["function"],
        function_qualified=raw.get("function_qualified"),
        verdict=raw["verdict"],
        source_hash=raw.get("source_hash", ""),
        line_start=_ls,
        line_end=_le,
        cwe=raw.get("cwe"),
        confidence=raw.get("confidence"),
        strategy_id=raw.get("strategy_id"),
        strategies=raw.get("strategies", []),
        domain_model_hash=raw.get("domain_model_hash"),
        domain_concepts_available=raw.get("domain_concepts_available", []),
        invariants_available=raw.get("invariants_available", []),
        hypotheses=raw.get("hypotheses", []),
        body=raw.get("body", ""),
        reading_list_items=raw.get("reading_list_items", []),
        study_receipts=raw.get("study_receipts", []),
        model=raw.get("model"),
        evidence_tools=raw.get("evidence_tools", []),
        tools_dispatched=raw.get("tools_dispatched", []),
        tools_skipped=raw.get("tools_skipped"),
        token_budget=raw.get("token_budget"),
        cost_usd=raw.get("cost_usd"),
        duration_s=raw.get("duration_s"),
        prior_review=raw.get("prior_review"),
        lesson=raw.get("lesson"),
        validate_verdict=raw.get("validate_verdict"),
        validate_reason=raw.get("validate_reason"),
        verdict_rationale=raw.get("verdict_rationale"),
        counter_hypothesis=raw.get("counter_hypothesis"),
        source_drifted=raw.get("source_drifted"),
        context_reduced=raw.get("context_reduced"),
        reused=raw.get("reused"),
        reused_from_run=raw.get("reused_from_run"),
        producer=raw.get("producer"),
        error_class=raw.get("error_class"),
        edge_callee=raw.get("edge_callee"),
        edge_verdicts=raw.get("edge_verdicts"),
        provisional=raw.get("provisional"),
        integrity=raw.get("integrity"),
        schema_version=version,
    )


def reviewed_set(out_dir: Path) -> set[str]:
    """Return ``{file:function}`` keys for fast resume lookup.

    Error verdicts are excluded — they represent transient failures
    (budget exceeded, API error, truncation) and must be retried on
    the next run, not suppressed as "already reviewed". ``dark``
    verdicts are excluded for the same direction: dark is by
    definition an UNRESOLVED state (the gate-resolution bucket,
    journaled mid-loop and resolved by the post-loop dark pass) — an
    interrupt in that window persists dark entries, and letting them
    suppress re-review left the function at "needs concrete
    verification" across every later segment.

    Edge rows are KEPT here (unlike
    :func:`entry_earns_function_coverage`): their keys carry the edge
    suffix, so they suppress re-review of the EDGE subject itself and
    can never satisfy a lookup for the caller's function key.
    """
    return {
        e.key for e in load_entries(out_dir)
        if e.verdict not in ("error", "dark")
    }


def entry_earns_function_coverage(entry: ReviewJournalEntry) -> bool:
    """True when a journal entry earns FUNCTION-level coverage credit.

    The single screening rule for every lane that projects journal
    rows into durable coverage marks — the store's journal import and
    the ``coverage-journal.json`` record builder. Excluded:

    * ``error`` rows — transient failures; the function was never
      actually reviewed and must be retried, not marked covered;
    * ``dark`` rows — the unresolved gate-resolution bucket; a
      durable coverage mark has no re-adjudication route, so an
      interrupted run's dark rows must stay visible as unreviewed;
    * edge-contract rows (``edge_callee`` set) — only the CALL EDGE
      was examined, and ``ReviewJournalEntry.key`` documents the
      invariant: an edge review must never mark the caller function
      itself as reviewed.

    Same direction as :func:`reviewed_set`; the two differ only on
    edge rows (see its docstring).
    """
    return (
        entry.verdict not in ("error", "dark")
        and not entry.edge_callee
    )


# ── Producer kind ────────────────────────────────────────────────────
#
# Two producers write journal entries, and they record different KINDS
# of review. /audit entries are function-grade: the whole function was
# examined under its inferred strategies, so the entry satisfies "this
# function was reviewed" and may suppress gaps or be reused as a $0
# verdict. /agentic entries are finding-grade: they record the analysis
# of ONE scanner finding located in the function — real examination
# evidence (they still count as tool coverage and as prior claims), but
# never a function review. A function whose single XSS finding was
# analysed has not been reviewed for memory, concurrency, or auth.

PRODUCER_AUDIT = "audit"
PRODUCER_AGENTIC = "agentic"
#: /validate-derived entries (the feedback loop journaling a validated
#: finding in a function no audit ever reviewed). Like /agentic
#: entries these are finding-grade: a deep-dive of ONE finding is not
#: a function review. Never inferred from run_id — only stamped
#: explicitly by the feedback writer.
PRODUCER_VALIDATE = "validate"

#: Producers whose entries record per-FINDING work, not function
#: reviews. Everything else (audit, unknown-but-legacy) is
#: function-grade.
_FINDING_GRADE_PRODUCERS = frozenset({PRODUCER_AGENTIC, PRODUCER_VALIDATE})

#: run_id prefixes that identify /agentic-side producers for legacy
#: entries written before the ``producer`` field was stamped. Matches
#: the historical heuristic in ``core.coverage.importer``.
_AGENTIC_RUN_PREFIXES = ("agentic", "scan")


def entry_producer(entry: ReviewJournalEntry) -> str:
    """Resolve which tool produced a journal entry.

    Prefers the explicit ``producer`` field; legacy entries without it
    fall back to the run-id prefix convention (any run_id starting with
    ``agentic`` or ``scan`` labels as agentic; everything else defaults
    to ``audit``, the historical ``checked_by`` convention).
    """
    if entry.producer:
        return entry.producer
    run_id = entry.run_id or ""
    if run_id.startswith(_AGENTIC_RUN_PREFIXES):
        return PRODUCER_AGENTIC
    return PRODUCER_AUDIT


def is_function_grade(entry: ReviewJournalEntry) -> bool:
    """True when the entry records a function-grade review.

    Finding-grade entries (/agentic analyses, /validate-derived
    corrections for functions no audit reviewed) return False — they
    must not suppress audit gaps or be imported as reused verdicts.
    See the producer-kind note above.
    """
    return entry_producer(entry) not in _FINDING_GRADE_PRODUCERS


def latest_function_grade_index(
    project_dir: Path,
) -> dict[str, ReviewJournalEntry]:
    """Collapse the project index to latest-per-``(file, function)``
    among FUNCTION-GRADE entries only.

    :func:`load_index`'s plain collapse keeps the newest entry of any
    kind, so a fresh /agentic finding-analysis would shadow an older
    /audit verdict for the same function — the gap fold would then
    either wrongly suppress on a finding-grade entry or wrongly
    resurface a properly audited function. Kind-aware consumers (the
    audit gap fold) use this collapse instead.

    Collapse identity is per-SITE — ``(file, function, line_start)``,
    keyed ``file:function@line`` — not per-``(file, function)``:
    same-named items at different spans (macro redefinitions, C++
    overloads) are distinct review subjects, and the coarse collapse
    starved all but one of their verdicts, so cross-run reuse re-bought
    the N-1 siblings on every new run (companion of the same-run
    per-site fold). Computed from entry FIELDS, so legacy span-less
    index rows collapse correctly too.
    """
    return latest_function_grade_collapse(load_index_full(project_dir).values())


def latest_function_grade_collapse(
    entries: Iterable[ReviewJournalEntry],
) -> dict[str, ReviewJournalEntry]:
    """Per-site latest-function-grade collapse over pre-loaded
    *entries* — the core of :func:`latest_function_grade_index`,
    split out so callers that already hold the full index (the gap
    fold loads it once for both the collapse and the strategy
    backfill) don't parse a multi-MB index file twice."""
    result: dict[str, ReviewJournalEntry] = {}
    for entry in entries:
        if not is_function_grade(entry):
            continue
        site_key = f"{entry.key}@{entry.line_start or 0}"
        existing = result.get(site_key)
        if existing is None or entry.ts > existing.ts:
            result[site_key] = entry
    return result


def latest_entries(out_dir: Path) -> dict[str, ReviewJournalEntry]:
    """Return the most recent entry per ``file:function`` key.

    Uses strict ``>`` on ``entry.ts`` (a microsecond-precision UTC
    ISO string emitted by :func:`now_iso`). Two entries can only
    tie if written within the same microsecond, which never happens
    for sequential Python appends — so first-in-file wins on the
    theoretically-possible tie, matching :func:`merge_into_index`
    and preserving idempotent-merge semantics.
    """
    best: dict[str, ReviewJournalEntry] = {}
    for entry in load_entries(out_dir):
        existing = best.get(entry.key)
        if existing is None or entry.ts > existing.ts:
            best[entry.key] = entry
    return best


# ── Project-level index ──────────────────────────────────────────────

def _flock(path: Path):
    """Advisory flock on a .lock sidecar.

    O_NOFOLLOW + degrade-with-warning mirrors the store's
    ``coverage_store_lock``: a planted symlink at the sidecar path
    would otherwise make this process create and flock an
    attacker-chosen path. A refused open degrades to the no-lock path
    (same as non-POSIX) rather than crashing the merge.
    """
    if not _HAS_FCNTL:
        yield
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    # O_NONBLOCK: an O_WRONLY open of a planted reader-less FIFO
    # blocked the merge forever; with the flag it fails fast (ENXIO,
    # → the warn-and-degrade arm below) and a FIFO that has a reader
    # is refused by the regularity check on the opened fd.
    flags = (
        os.O_WRONLY | os.O_CREAT
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | _O_NONBLOCK
    )
    try:
        fd = os.open(str(lock_path), flags, 0o600)
    except OSError as exc:
        logger.warning(
            "journal index lock %s: refusing to open (%s); proceeding "
            "WITHOUT cross-process lock — investigate a planted "
            "symlink or FIFO at that path", lock_path, exc)
        yield
        return
    try:
        regular = _fd_is_regular(fd)
    except OSError:
        regular = False
    if not regular:
        os.close(fd)
        logger.warning(
            "journal index lock %s is not a regular file; proceeding "
            "WITHOUT cross-process lock — investigate a planted "
            "FIFO/device at that path", lock_path)
        yield
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)

# contextmanager must wrap the generator
_flock = contextlib.contextmanager(_flock)


def _row_ts(row: Any) -> str:
    """Best-effort ``ts`` of a raw index row for latest-wins compares.

    Index rows are attacker-writable (archive import): a non-dict row
    or a non-str ``ts`` reads as the empty string — sorting BELOW
    every real microsecond ISO stamp, so garbage never outranks a
    genuine entry and never crashes the ``>`` compare inside the
    merge flock.
    """
    if not isinstance(row, dict):
        return ""
    ts = row.get("ts", "")
    return ts if isinstance(ts, str) else ""


def rehome_legacy_keys(index: dict[str, Any]) -> int:
    """Re-home rows whose on-disk key predates the current
    ``index_key`` format (span suffix, producer segment, and any
    earlier key-format generation). Mutates *index* in place and
    returns the number of rows moved.

    The row CONTENT is untouched — fields are the source of truth and
    keys are opaque handles — so the move is lossless; latest-ts wins
    when the new home is already occupied, which merges stale legacy
    duplicates away. Rows that cannot be parsed stay in place under
    their old key (never drop history the reader refuses). The single
    implementation for every index writer (run-completion merge,
    compaction) — the walk was previously duplicated verbatim and the
    copies had already begun to drift.
    """
    rehomed = 0
    for old_key in list(index.keys()):
        row = index[old_key]
        if not isinstance(row, dict):
            # A non-dict value has no .get and would crash the re-home
            # inside the writer's flock.
            continue  # unreadable row: leave in place, never drop
        try:
            entry = _entry_from_dict(row)
        except Exception:  # noqa: BLE001 — row containment boundary
            # Total per-row quarantine, same rationale as load_entries:
            # index rows arrive via archive import and per-run merges,
            # so any exception class a planted row can raise must
            # contain to that row.
            continue  # unreadable row: leave in place, never drop
        new_key = entry.index_key
        if new_key == old_key:
            continue
        existing = index.get(new_key)
        if existing is None or entry.ts > _row_ts(existing):
            index[new_key] = row
        del index[old_key]
        rehomed += 1
    return rehomed


def merge_into_index(project_dir: Path, run_dir: Path) -> int:
    """Merge run journal entries into the project-level index.

    Storage key: ``(file, function, model, strategy_hash)`` via
    ``entry.index_key`` (amendment §1 D1). This preserves multi-
    model + multi-strategy history: a function reviewed by opus AND
    gemini gets two rows in the index, and Phase-5 context-aware
    staleness has real signal to work with instead of the
    latest-per-function collapse the pre-D1 code produced.

    Ties on ``ts`` resolve to strict-monotone microsecond stamps
    (see :func:`now_iso`); re-running a merge on the same run dir
    is a genuine no-op.

    Returns the number of entries merged (new or updated).
    """
    run_entries = load_entries(run_dir)
    if not run_entries:
        return 0
    # Per-run merge cap: journals live inside sandbox write grants,
    # and per-journal size caps alone let a hostile run push the
    # INDEX past its own read budget across several subdir journals —
    # after which (pre-guard) the next load read it as empty and the
    # next merge destroyed all accumulated history.
    _MAX_MERGE_ENTRIES = 20_000
    if len(run_entries) > _MAX_MERGE_ENTRIES:
        logger.warning(
            "journal: run %s carries %d entries — merging only the "
            "newest %d", run_dir, len(run_entries), _MAX_MERGE_ENTRIES)
        run_entries = sorted(run_entries,
                             key=lambda e: e.ts)[-_MAX_MERGE_ENTRIES:]

    index_path = project_dir / INDEX_FILENAME

    with _flock(index_path):
        try:
            index = _load_index(index_path, for_write=True)
        except IndexUnreadable as e:
            logger.error("journal: %s — run %s NOT merged", e, run_dir)
            return 0
        merged = 0

        rehomed = rehome_legacy_keys(index)
        if rehomed:
            logger.info(
                "journal index: re-homed %d legacy-format key(s)", rehomed,
            )

        for entry in run_entries:
            key = entry.index_key
            existing = index.get(key)
            if existing is None or entry.ts > _row_ts(existing):
                index[key] = entry.to_dict()
                merged += 1

        if merged or rehomed:
            try:
                _write_index(index_path, index)
            except IndexWriteOverBudget as e:
                # Same loud-refusal convention as IndexUnreadable: the
                # index on disk stays readable AND writable (compaction
                # included), and the run journal keeps every row — a
                # refused merge loses nothing durable.
                logger.error(
                    "journal: %s — run %s NOT merged (the run journal "
                    "keeps its rows)", e, run_dir)
                return 0

    return merged


def merge_run_into_index(project_dir: Path, run_dir: Path) -> int:
    """Merge a RUN's journals into the project index — root and
    one-level tool subdirs.

    Producers write journals where they run: /audit at the run root,
    /agentic's analysis agent under ``autonomous/``. The same
    one-level-subdir convention as ``core.coverage.record.
    load_records`` (which globs ``coverage-*.json`` in tool subdirs).
    Before this, run-completion merged only the root journal, so
    /agentic per-finding entries never reached the project index —
    cross-run consumers (prior finding-grade claims, the coverage
    importer's index path) silently saw nothing.

    Returns total entries merged.
    """
    run_dir = Path(run_dir)
    merged = merge_into_index(project_dir, run_dir)
    try:
        # No symlinked dirs: the walk otherwise followed a planted
        # link OUT of the run dir and merged a foreign journal into
        # this project's index. Subdir count capped (merge-time DoS).
        subdirs = sorted(d for d in run_dir.iterdir()
                         if d.is_dir() and not d.is_symlink())[:64]
    except OSError:
        return merged
    for sub in subdirs:
        if (sub / JOURNAL_FILENAME).is_file():
            merged += merge_into_index(project_dir, sub)
    return merged


def load_index(project_dir: Path) -> dict[str, ReviewJournalEntry]:
    """Load the project-level journal index, collapsed to
    latest-per-``(file, function)``.

    The on-disk storage is keyed by ``index_key`` (widened for
    multi-model / multi-strategy history — see
    :func:`merge_into_index`). Most consumers want the collapsed
    view ("what's the most recent verdict for F"), so this
    function returns a dict keyed by ``file:function``. Consumers
    that need the full history use :func:`load_index_full`.
    """
    result: dict[str, ReviewJournalEntry] = {}
    for entry in load_index_full(project_dir).values():
        existing = result.get(entry.key)
        if existing is None or entry.ts > existing.ts:
            result[entry.key] = entry
    return result


def load_index_full(project_dir: Path) -> dict[str, ReviewJournalEntry]:
    """Load the full project-level journal index — every entry
    keyed by ``index_key``
    (``file:function:model:strategy_hash:producer``).

    Preserves the multi-model + multi-strategy history the amendment
    §1 D1 storage layout captures. Used by consumers that need
    context-aware queries (e.g. Phase-5 staleness gate: was F
    reviewed under strategies containing 'aliasing'?).
    """
    index_path = project_dir / INDEX_FILENAME
    raw = _load_index(index_path)
    result: dict[str, ReviewJournalEntry] = {}
    for key, entry_dict in raw.items():
        if not isinstance(entry_dict, dict):
            # A non-dict entry VALUE passes the container gates but
            # has no .get — quarantine per row, like the journal
            # reader's non-dict line gate.
            logger.warning(
                "journal index: skipping %s: not an object (%s)",
                key, type(entry_dict).__name__)
            continue
        try:
            result[key] = _entry_from_dict(entry_dict)
        except Exception as exc:  # noqa: BLE001 — row containment boundary
            # Total per-row quarantine (same boundary as load_entries):
            # one planted index row must never crash the consumers of
            # the full-history view.
            logger.warning("journal index: skipping %s: %s", key, exc)
    return result


class IndexUnreadable(RuntimeError):
    """The index exists but cannot be read (oversize/corrupt) — a
    WRITER must fail loudly rather than rewrite a fresh index over
    it: 'starting fresh' at write time silently destroyed every
    accumulated verdict (including MAC-stamped finding rows) when an
    attacker inflated the index past its cap via per-run merges."""


def _load_index(path: Path, for_write: bool = False
                ) -> dict[str, dict[str, Any]]:
    """Load raw index dict from disk (bounded — st_size gate before
    read). Readers degrade to empty; writers (``for_write=True``)
    raise :class:`IndexUnreadable` when a file EXISTS but cannot be
    read, so a merge never replaces unknown history."""
    from core.json.utils import load_json

    if not path.is_file():
        return {}
    try:
        data = load_json(path, strict=True, max_bytes=_MAX_JOURNAL_BYTES)
    except Exception as e:  # noqa: BLE001 — intake containment boundary
        # Total by design: the strict parse raises OSError/ValueError
        # for the common corruptions but also RecursionError for a
        # nesting-bomb index (stdlib backend) — and the index arrives
        # via /project archive import, so any exception class a
        # planted file can raise must resolve to the same two
        # dispositions: readers degrade to empty, writers refuse via
        # IndexUnreadable (never rewrite history that failed to read).
        if for_write:
            raise IndexUnreadable(
                f"journal index at {path} is unreadable ({e}) — "
                "refusing to overwrite it") from e
        logger.warning("journal: unreadable index at %s — read as "
                       "empty (writers refuse)", path)
        return {}
    if not isinstance(data, dict):
        if for_write:
            raise IndexUnreadable(
                f"journal index at {path} is not an object — "
                "refusing to overwrite it")
        return {}
    entries = data.get("entries", {})
    if not isinstance(entries, dict):
        # Same threat model as the top-level gate: the index is
        # reachable via a /project archive import, and a list/null
        # "entries" value passed the dict gate above only to crash
        # every consumer's .items()/.get — the writer path crashed
        # INSIDE the merge flock, so every run-completion merge failed
        # with a raw traceback instead of the designed loud refusal.
        if for_write:
            raise IndexUnreadable(
                f"journal index at {path} has a non-object 'entries' "
                "value — refusing to overwrite it")
        logger.warning(
            "journal: index at %s has a non-object 'entries' value — "
            "read as empty (writers refuse)", path)
        return {}
    if for_write:
        # Write-boundary round-trip proof: never-drop preserves rows
        # that fail row validation IN the entries dict, and the writer
        # serializes the WHOLE dict — so a planted row whose CONTENT
        # the serializer refuses (lone-surrogate str, non-finite
        # float; both parse on stdlib json) crashed save_json inside
        # the merge flock on EVERY retry. Refuse loudly instead, file
        # untouched — parity with orjson environments, where the same
        # planted index already refuses at parse via the unreadable
        # arm above. Readers need no proof: rows quarantine
        # individually through _entry_from_dict.
        try:
            _validate_serializable(entries)
        except ValueError as e:
            raise IndexUnreadable(
                f"journal index at {path} carries content its own "
                "writer cannot re-serialize — refusing to rewrite "
                f"it ({e.__cause__})") from e
    return entries


class IndexWriteOverBudget(RuntimeError):
    """The serialized index would exceed the read budget — the write
    refuses so the ON-DISK index always stays readable. Writing past
    the cap manufactured a permanently frozen index: every later read
    degraded to empty (accumulated history invisible) and every
    writer — including compaction, the in-band remedy — refused via
    :class:`IndexUnreadable`. The per-run merge-entry cap bounds row
    COUNT, not bytes (indent-2 re-serialization inflates list-heavy
    rows several-fold), so the byte bound must sit at the write."""


def _write_index(path: Path, entries: dict[str, dict[str, Any]]) -> None:
    """Atomic write of the index file, bounded by the read budget.

    Raises :class:`IndexWriteOverBudget` (file untouched) when the
    serialized document would exceed ``_MAX_JOURNAL_BYTES`` — an index
    the writer cannot re-read is destroyed history, so it must never
    reach disk. Serialization matches :func:`core.json.save_json`
    (same encoder arms, newline, atomic tempfile + rename).
    """
    from core.atomic_fs import write_text_atomically
    from core.json.utils import dumps_artifact

    index_data = {
        "schema_version": INDEX_SCHEMA_VERSION,
        "updated_at": now_iso(),
        "entries": entries,
    }
    content = dumps_artifact(index_data) + "\n"
    size = len(content.encode("utf-8"))
    if size > _MAX_JOURNAL_BYTES:
        raise IndexWriteOverBudget(
            f"journal index at {path} would serialize to {size} bytes "
            f"(over the {_MAX_JOURNAL_BYTES} byte read budget) — "
            "refusing to write an index its own reader must refuse"
        )
    write_text_atomically(path, content, tmp_prefix=".~savejson-")


# ── Domain model hash ───────────────────────────────────────────────

def _domain_model_parent(out_dir: Path) -> Path | None:
    """The project-level dir whose domain-model.json this run may import.

    Resolved through the RUN PIN: a pinned run yields its project's
    output dir, a standalone run (authoritative pin-to-none) yields
    None — a bare ``out_dir.parent`` probe would let a standalone run
    sitting next to any unrelated domain-model.json import another
    target's semantic concepts. Pin-less legacy dirs keep the parent
    probe (reads only, pre-series shape).
    """
    try:
        from core.run.pin import pin_project_dir, resolve_run_pin
        pin = resolve_run_pin(out_dir)
        if pin.authoritative:
            return pin_project_dir(out_dir)
        return out_dir.parent
    except Exception:  # noqa: BLE001 — legacy probe
        return out_dir.parent


def _find_domain_model_file(out_dir: Path) -> Path | None:
    """Locate domain-model.json in standard locations.

    The project-canonical candidates come from the RUN PIN's project
    dir (:func:`_domain_model_parent`) — the pre-fix bare
    ``out_dir.parent`` probe let a standalone run sitting next to any
    unrelated domain-model.json import another target's semantic
    concepts into the staleness gate and strategy relevance.
    """
    candidates = [out_dir / "domain-model.json"]
    parent = _domain_model_parent(out_dir)
    if parent is not None:
        candidates.append(parent / "concepts" / "domain-model.json")
        candidates.append(parent / "domain-model.json")
    for c in candidates:
        if c.is_file():
            return c
    return None


def compute_domain_model_hash(out_dir: Path) -> str | None:
    """Compute SHA-256 prefix of domain-model.json for staleness comparison.

    Byte-budgeted (``_MAX_DOMAIN_MODEL_BYTES``, matching
    :func:`load_domain_model`): the file sits in run/project dirs
    another principal can write, and this was the one domain-model
    reader with NO size gate — a sparse multi-GiB plant OOM'd the
    hashing process. An over-budget file reads as "no model"
    (truncated bytes must not mint a hash that would then compare
    stale/fresh against nothing).
    """
    import hashlib

    from core.source import read_bytes_capped

    path = _find_domain_model_file(out_dir)
    if path is None:
        return None
    read = read_bytes_capped(path, _MAX_DOMAIN_MODEL_BYTES)
    if read is None:
        return None
    content, truncated = read
    if truncated:
        logger.warning(
            "domain-model at %s exceeds %d bytes; ignoring for "
            "staleness hashing", path, _MAX_DOMAIN_MODEL_BYTES)
        return None
    return hashlib.sha256(content).hexdigest()[:8]


def load_domain_model(
    out_dir: Path,
    *,
    run_only: bool = False,
) -> dict[str, Any] | None:
    """Load parsed domain-model.json for concept-level relevance checks.

    ``run_only=True`` restricts the search to ``out_dir`` itself — the
    model this run's own study pass wrote — skipping the project-level
    candidates a prior run may have left behind (cold-profile corpus
    runs must not import accumulated knowledge).
    """
    if run_only:
        path = out_dir / "domain-model.json"
        if not path.is_file():
            return None
    else:
        path = _find_domain_model_file(out_dir)
    if path is None:
        return None
    return load_json(path, max_bytes=_MAX_DOMAIN_MODEL_BYTES)


def domain_model_context(out_dir: Path) -> dict[str, Any] | None:
    """Current-domain-model view for the context-staleness gate.

    Returns ``{"hash", "canonical", "concepts": {id: [strategies]},
    "invariant_concept": {inv_id: concept_id}}``, or ``None`` when no
    domain model exists (or the file is unreadable — no comparison
    basis either way).

    Resolution order is amendment §3: project-canonical first
    (``<project>/concepts/``, then legacy ``<project>/``), per-run
    file last with ``canonical=False``. A per-run hash has no
    cross-run comparison semantics — the gate must not treat hash
    equality against it as freshness (safe over-review).

    Project-canonical candidates resolve through the run pin
    (:func:`_domain_model_parent`, same probe as
    :func:`_find_domain_model_file`): a standalone run next to a
    foreign target's domain-model.json must not adopt it as its
    canonical model.
    """
    import hashlib
    candidates: list[tuple[Path, bool]] = []
    parent = _domain_model_parent(out_dir)
    if parent is not None:
        candidates.append((parent / "concepts" / "domain-model.json", True))
        candidates.append((parent / "domain-model.json", True))
    candidates.append((out_dir / "domain-model.json", False))
    from core.source import read_bytes_capped
    for path, canonical in candidates:
        if not path.is_file():
            continue
        # Byte-budgeted like every other domain-model reader: the
        # candidates live in writable run/project dirs; an oversize
        # plant means "no comparison basis", never an OOM.
        read = read_bytes_capped(path, _MAX_DOMAIN_MODEL_BYTES)
        if read is None:
            return None
        content, truncated = read
        if truncated:
            logger.warning(
                "domain-model at %s exceeds %d bytes; no staleness "
                "comparison basis", path, _MAX_DOMAIN_MODEL_BYTES)
            return None
        try:
            # Parse the same bytes the staleness hash below covers;
            # core.json.loads accepts bytes directly.
            raw = loads(content)
        except Exception:  # noqa: BLE001 — intake containment boundary
            # domain-model.json sits in the same writable dirs as the
            # journal; a nesting bomb (RecursionError, stdlib backend)
            # or any other planted shape means "no comparison basis" —
            # the same disposition as unreadable/malformed.
            return None
        if not isinstance(raw, dict):
            return None
        concepts: dict[str, list[str]] = {}
        for c in raw.get("concepts") or []:
            if isinstance(c, dict) and c.get("id"):
                concepts[c["id"]] = [
                    s for s in (c.get("related_strategies") or [])
                    if isinstance(s, str)
                ]
        invariant_concept: dict[str, str] = {}
        for inv in raw.get("invariants") or []:
            if isinstance(inv, dict) and inv.get("id"):
                invariant_concept[inv["id"]] = inv.get("concept") or ""
        return {
            "hash": hashlib.sha256(content).hexdigest()[:8],
            "canonical": canonical,
            "concepts": concepts,
            "invariant_concept": invariant_concept,
        }
    return None
