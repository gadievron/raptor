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
import tempfile
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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
            | _O_NOFOLLOW | _O_CLOEXEC,
            0o644,
        )
        try:
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
    """fsync the journal file — call at batch/run boundaries."""
    journal_path = out_dir / JOURNAL_FILENAME
    if not journal_path.is_file():
        return
    fd = os.open(str(journal_path), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


# ── Read ─────────────────────────────────────────────────────────────

def load_entries(out_dir: Path) -> list[ReviewJournalEntry]:
    """Load all valid entries from review-journal.jsonl.

    Skips corrupt trailing line (truncated write) with a warning.
    Interior corrupt lines are also skipped with warnings.
    """
    journal_path = out_dir / JOURNAL_FILENAME
    if not journal_path.is_file():
        return []

    # Size gate before the read buffers the whole journal.
    try:
        size = journal_path.stat().st_size
    except OSError:
        return []
    if size > _MAX_JOURNAL_BYTES:
        logger.warning(
            "journal: %s is %d bytes (over the %d byte cap); "
            "refusing to load", journal_path, size, _MAX_JOURNAL_BYTES,
        )
        return []

    entries: list[ReviewJournalEntry] = []
    lines = journal_path.read_text(encoding="utf-8").splitlines()

    corrupt = 0
    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue
        try:
            raw = loads(line)
        except ValueError:
            corrupt += 1
            if i == len(lines) - 1:
                logger.debug(
                    "journal: skipping corrupt trailing line in %s", journal_path,
                )
            else:
                logger.debug(
                    "journal: skipping corrupt line %d in %s", i + 1, journal_path,
                )
            continue
        try:
            entries.append(_entry_from_dict(raw))
        except (TypeError, KeyError) as exc:
            logger.warning(
                "journal: skipping malformed entry on line %d: %s", i + 1, exc,
            )
    if corrupt:
        logger.warning(
            "journal: skipped %d corrupt line(s) in %s "
            "(%d entries loaded)",
            corrupt, journal_path, len(entries),
        )
    return entries


def _entry_from_dict(raw: dict[str, Any]) -> ReviewJournalEntry:
    """Construct an entry from a parsed JSON dict, tolerating missing optional fields.

    Schema-version compat: absent ``schema_version`` field defaults to
    1 (legacy entries predate the field). Unknown versions raise a
    loud ``ValueError`` — do not silently reinterpret unknown data.
    """
    version = raw.get("schema_version", 1)
    if version != SCHEMA_VERSION:
        msg = (
            f"unknown journal entry schema_version={version}; "
            f"this reader supports {SCHEMA_VERSION} only"
        )
        raise ValueError(msg)
    return ReviewJournalEntry(
        ts=raw["ts"],
        run_id=raw["run_id"],
        file=raw["file"],
        function=raw["function"],
        function_qualified=raw.get("function_qualified"),
        verdict=raw["verdict"],
        source_hash=raw.get("source_hash", ""),
        line_start=raw.get("line_start", 0),
        line_end=raw.get("line_end"),
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
        edge_callee=raw.get("edge_callee"),
        edge_verdicts=raw.get("edge_verdicts"),
        integrity=raw.get("integrity"),
        schema_version=version,
    )


def reviewed_set(out_dir: Path) -> set[str]:
    """Return ``{file:function}`` keys for fast resume lookup.

    Error verdicts are excluded — they represent transient failures
    (budget exceeded, API error, truncation) and must be retried on
    the next run, not suppressed as "already reviewed".
    """
    return {e.key for e in load_entries(out_dir) if e.verdict != "error"}


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
    result: dict[str, ReviewJournalEntry] = {}
    for entry in load_index_full(project_dir).values():
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
    """Advisory flock on a .lock sidecar."""
    if not _HAS_FCNTL:
        yield
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT, 0o600)
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

    index_path = project_dir / INDEX_FILENAME

    with _flock(index_path):
        index = _load_index(index_path)
        merged = 0

        # Lazy legacy-key migration: re-home any row whose on-disk key
        # no longer matches its entry's current ``index_key`` (span
        # suffix added, and any earlier key-format generation). The
        # entry CONTENT is untouched — fields are the source of truth
        # and keys are opaque handles — so this is lossless; latest-ts
        # wins if the new home is already occupied. Without re-homing,
        # a legacy coarse key would sit forever as a stale duplicate
        # of one of its per-site successors.
        rehomed = 0
        for old_key in list(index.keys()):
            try:
                entry = _entry_from_dict(index[old_key])
            except (TypeError, KeyError, ValueError):
                continue  # unreadable row: leave in place, never drop
            new_key = entry.index_key
            if new_key == old_key:
                continue
            existing = index.get(new_key)
            if existing is None or entry.ts > existing.get("ts", ""):
                index[new_key] = index[old_key]
            del index[old_key]
            rehomed += 1
        if rehomed:
            logger.info(
                "journal index: re-homed %d legacy-format key(s)", rehomed,
            )

        for entry in run_entries:
            key = entry.index_key
            existing = index.get(key)
            if existing is None or entry.ts > existing.get("ts", ""):
                index[key] = entry.to_dict()
                merged += 1

        if merged or rehomed:
            _write_index(index_path, index)

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
        subdirs = sorted(d for d in run_dir.iterdir() if d.is_dir())
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
        try:
            result[key] = _entry_from_dict(entry_dict)
        except (TypeError, KeyError, ValueError) as exc:
            logger.warning("journal index: skipping %s: %s", key, exc)
    return result


def _load_index(path: Path) -> dict[str, dict[str, Any]]:
    """Load raw index dict from disk (bounded — st_size gate before
    read; an oversize index degrades to the corrupt-index path)."""
    from core.json.utils import load_json

    if not path.is_file():
        return {}
    try:
        data = load_json(path, strict=True, max_bytes=_MAX_JOURNAL_BYTES)
    except (OSError, ValueError):
        logger.warning("journal: corrupt index at %s, starting fresh", path)
        return {}
    if not isinstance(data, dict):
        return {}
    return data.get("entries", {})


def _write_index(path: Path, entries: dict[str, dict[str, Any]]) -> None:
    """Atomic write of the index file."""
    index_data = {
        "schema_version": INDEX_SCHEMA_VERSION,
        "updated_at": now_iso(),
        "entries": entries,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(index_data, f, indent=2)
            f.write("\n")
        os.replace(tmp, str(path))
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


# ── Domain model hash ───────────────────────────────────────────────

def _find_domain_model_file(out_dir: Path) -> Path | None:
    """Locate domain-model.json in standard locations."""
    candidates = [
        out_dir / "domain-model.json",
        out_dir.parent / "concepts" / "domain-model.json",
        out_dir.parent / "domain-model.json",
    ]
    for c in candidates:
        if c.is_file():
            return c
    return None


def compute_domain_model_hash(out_dir: Path) -> str | None:
    """Compute SHA-256 prefix of domain-model.json for staleness comparison."""
    import hashlib

    path = _find_domain_model_file(out_dir)
    if path is None:
        return None
    try:
        content = path.read_bytes()
        return hashlib.sha256(content).hexdigest()[:8]
    except OSError:
        return None


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
    """
    import hashlib
    candidates = [
        (out_dir.parent / "concepts" / "domain-model.json", True),
        (out_dir.parent / "domain-model.json", True),
        (out_dir / "domain-model.json", False),
    ]
    for path, canonical in candidates:
        if not path.is_file():
            continue
        try:
            content = path.read_bytes()
            # Parse the same bytes the staleness hash below covers;
            # core.json.loads accepts bytes directly.
            raw = loads(content)
        except (OSError, ValueError):
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
