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
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import fcntl
    _HAS_FCNTL = True
except ImportError:
    _HAS_FCNTL = False

logger = logging.getLogger(__name__)

JOURNAL_FILENAME = "review-journal.jsonl"
INDEX_FILENAME = "review-journal-index.json"
INDEX_SCHEMA_VERSION = 1

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
    evidence_tools: list[str] = field(default_factory=list)
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
    schema_version: int = SCHEMA_VERSION

    @property
    def key(self) -> str:
        return make_function_key(self.file, self.function)

    @property
    def index_key(self) -> str:
        """Index key: (file, function, model, strategy_hash).

        Amendment §1 D1 widens the compaction key from
        ``(file, function)`` to preserve multi-model + multi-strategy
        history — otherwise Phase-5 context-aware staleness has no
        signal to work with.
        """
        strategy_hash = _canonical_strategy_hash(self.strategies)
        model = self.model or ""
        return (
            f"{encode_key_file(self.file)}:{self.function}"
            f":{model}:{strategy_hash}"
        )

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

def append_entry(out_dir: Path, entry: ReviewJournalEntry) -> None:
    """Atomic single-line append to review-journal.jsonl.

    Uses a single ``write()`` call (POSIX atomicity for writes <= PIPE_BUF).
    No per-entry fsync — the caller can ``flush_journal()`` at batch end.
    """
    journal_path = out_dir / JOURNAL_FILENAME
    out_dir.mkdir(parents=True, exist_ok=True)
    line = json.dumps(entry.to_dict(), separators=(",", ":")) + "\n"
    with open(journal_path, "a", encoding="utf-8") as f:
        f.write(line)


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

    entries: list[ReviewJournalEntry] = []
    lines = journal_path.read_text(encoding="utf-8").splitlines()

    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            if i == len(lines) - 1:
                logger.warning(
                    "journal: skipping corrupt trailing line in %s", journal_path,
                )
            else:
                logger.warning(
                    "journal: skipping corrupt line %d in %s", i + 1, journal_path,
                )
            continue
        try:
            entries.append(_entry_from_dict(raw))
        except (TypeError, KeyError) as exc:
            logger.warning(
                "journal: skipping malformed entry on line %d: %s", i + 1, exc,
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
        raise ValueError(
            f"unknown journal entry schema_version={version}; "
            f"this reader supports {SCHEMA_VERSION} only"
        )
    return ReviewJournalEntry(
        ts=raw["ts"],
        run_id=raw["run_id"],
        file=raw["file"],
        function=raw["function"],
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
        token_budget=raw.get("token_budget"),
        cost_usd=raw.get("cost_usd"),
        duration_s=raw.get("duration_s"),
        prior_review=raw.get("prior_review"),
        lesson=raw.get("lesson"),
        validate_verdict=raw.get("validate_verdict"),
        validate_reason=raw.get("validate_reason"),
        source_drifted=raw.get("source_drifted"),
        context_reduced=raw.get("context_reduced"),
        reused=raw.get("reused"),
        reused_from_run=raw.get("reused_from_run"),
        producer=raw.get("producer"),
        schema_version=version,
    )


def reviewed_set(out_dir: Path) -> set[str]:
    """Return ``{file:function}`` keys for fast resume lookup.

    Error verdicts are excluded — they represent transient failures
    (budget exceeded, API error, truncation) and must be retried on
    the next run, not suppressed as "already reviewed".
    """
    return {e.key for e in load_entries(out_dir) if e.verdict != "error"}


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
        for entry in run_entries:
            key = entry.index_key
            existing = index.get(key)
            if existing is None or entry.ts > existing.get("ts", ""):
                index[key] = entry.to_dict()
                merged += 1

        if merged:
            _write_index(index_path, index)

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
    keyed by ``index_key`` (``file:function:model:strategy_hash``).

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
    """Load raw index dict from disk."""
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
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


def load_domain_model(out_dir: Path) -> dict[str, Any] | None:
    """Load parsed domain-model.json for concept-level relevance checks."""
    path = _find_domain_model_file(out_dir)
    if path is None:
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
