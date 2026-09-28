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
import re
import threading
import time
import types
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field, replace
from dataclasses import fields as dataclass_fields
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Any, Union, get_args, get_origin, get_type_hints

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

#: Run-attribution sentinel: stamped into ``run_id`` by the record
#: CLI when the run dir's resolved basename is empty (the filesystem
#: root) or resolution fails. Rows written before the CLI resolved
#: its ``--out`` argument carry it for EVERY relative spelling
#: (``Path(".").name == ""``), so the sentinel is a standing part of
#: the install base, not only the pathological cases. By construction
#: it never names a run: readers that scope receipts by run identity
#: must grade it like an empty ``run_id`` (the marked
#: install-grandfather tier), never as an attribution to a foreign
#: run — and must refuse to use a run identity that EQUALS the
#: sentinel (a dir literally named like it would otherwise match
#: sentinel rows as the run's own record and mint run scope).
RUN_ID_UNATTRIBUTED = "cli-record"


def resolved_run_id(out_dir: Path | None) -> str:
    """Run-attribution identity for journal rows: the RESOLVED run-dir
    basename — the exact identity run-scoped consumers compare
    MAC-covered ``run_id`` stamps against (the journal-derived graded
    export resolves its own directory before comparing, and the record
    CLI stamps the same resolved shape). Unresolved, a relative
    ``out_dir`` spelling ("." from inside the run dir) has
    ``name == ""``, so the row would carry no attribution and the
    run's own record could never grade run-scoped. A still-empty
    resolved name (the filesystem root) or a resolution failure falls
    back toward the no-attribution sentinel, which run-scoped readers
    grade like an empty ``run_id`` (the marked install-grandfather
    tier) — a statement of NO attribution, never an attribution to a
    foreign run. ``None`` (no run dir at all) keeps the historical
    empty stamp, the sentinel's other consumer-side spelling.

    Every journal writer that derives ``run_id`` from a run-directory
    path stamps through this helper (the audit orchestrator via its
    ``_resolved_run_id`` delegate); the write-site census
    (core/audit/tests/test_run_id_stamp_census.py) trips on any new
    direct derivation.
    """
    if out_dir is None:
        return ""
    run_dir = Path(out_dir)
    try:
        name = run_dir.resolve().name
    except OSError:
        name = run_dir.name
    return name or RUN_ID_UNATTRIBUTED

# Byte budget for the journal loader's RETAINED entries and for the
# index document (which is read whole). Both files can arrive via a
# /project archive import, so the loader's memory must stay bounded —
# but the bound is on what the reader KEEPS, never a whole-file
# refusal: a resume-segment chain re-emits every reused verdict as a
# fresh row per segment, and a real multi-segment audit journal
# crossed a former file-size gate whose fail direction was "load
# nothing" — the resume then saw zero prior verdicts and re-reviewed
# the entire run (unbounded duplicate spend). Duplicate re-emission
# rows prune at load (newest per identity, see
# ``_prune_reemission_rows``); only a journal that stays over budget
# AFTER pruning reads as incomplete, and spend-authorizing callers
# refuse on that flag (:func:`require_complete_entries`).
_MAX_JOURNAL_BYTES = 256 * 1024 * 1024

# Per-line bound. Real rows are ~1 KiB; the largest legitimate rows
# (full review bodies, hypothesis lists, study receipts) reach tens
# of KiB, so 8 MiB is ~3 orders of magnitude of headroom while
# keeping a single hostile line from being buffered whole.
_MAX_JOURNAL_LINE_BYTES = 8 * 1024 * 1024

# Retained-entry COUNT bound. The byte budget alone does not bound
# the reader's memory: a parsed entry costs ~1 KiB of object overhead
# regardless of row size (the dataclass's per-entry default lists),
# so a flood of minimal ~60-byte rows under the byte budget would
# still retain millions of entries. Trade-off, both directions: too
# low and a legitimate mega-audit reads incomplete until compacted
# (bounded remedy — `raptor-audit journal compact`); too high and a
# hostile tiny-row flood OOMs the reader through object overhead the
# byte budget cannot see. 300k is ~3x the largest observed journal
# (a ~100k-row multi-segment incident journal).
_MAX_RETAINED_ENTRIES = 300_000

# Total-bytes-consumed multiplier over the retained budget: bounds
# the read LOOP (CPU/IO on a hostile multi-GiB plant, and a writer
# growing the file mid-read) while leaving room for the loader to
# stream past prunable duplicates several times the retained budget.
_READ_BUDGET_MULTIPLIER = 4

# ── Journal shards ───────────────────────────────────────────────────
#
# The retained budgets above are PER-SHARD bounds: the appender rolls
# to a numbered sibling (``review-journal.002.jsonl``, ``.003``, …)
# before the active file could cross them, and the loader reads the
# contiguous shard set as one journal. Kernel-scale runs journal more
# UNIQUE rows (hypothesis + verdict + study receipts per function ×
# 10^5 functions) than any single file budget can hold — compaction
# only folds duplicates, so without rolling, a big run's journal
# reads incomplete and `require_complete_entries` refuses the resume
# spend authorization for exactly the runs that need it most.
# ``review-journal.jsonl`` is always shard 1 — single-shard journals
# stay byte-identical to the historical format.

# Roll threshold for the ACTIVE shard. Trade-off, both directions:
# LOWER means more shard files (per-shard fixed load overhead, more
# fsync/compact targets); HIGHER pushes a full shard toward the
# loader's per-shard retained budget, whose prune-exit margin (90%)
# would read a legitimately full shard as incomplete. 3/4 of the
# retained budget leaves the loader a full prune margin.
_JOURNAL_SHARD_ROLL_BYTES = (_MAX_JOURNAL_BYTES * 3) // 4

# Shard-count bound. Trade-off, both directions: LOWER stops rolling
# on a legitimate mega-run (its final shard then grows past the
# reader budget and the journal reads incomplete until compacted);
# HIGHER scales a hostile plant fan-out and the loader's worst-case
# aggregate work linearly. 64 shards ≈ 12 GiB of journal — an order
# of magnitude past the largest projected kernel-scale journal.
_MAX_JOURNAL_SHARDS = 64

_JOURNAL_SHARD_RE = re.compile(r"^review-journal\.(\d{3,})\.jsonl$")


def _journal_shard_name(n: int) -> str:
    """On-disk name of shard *n* (1-based; shard 1 is the historical
    single file)."""
    if n == 1:
        return JOURNAL_FILENAME
    return f"review-journal.{n:03d}.jsonl"


def _journal_dir_snapshot(out_dir: Path) -> "frozenset[str] | None":
    """ONE directory listing serving both shard-set computations.

    The contiguity walk and the orphan classification were two
    separate directory reads; a load racing a concurrent appender
    roll could observe the fresh shard in the second read but not
    the first, transiently classifying it as an orphan (one-load
    incomplete flag). A caller that takes one snapshot and feeds it
    to BOTH :func:`journal_shard_paths` and
    :func:`_orphan_shard_names` sees a single consistent view — a
    roll is either wholly before the snapshot (in the set) or wholly
    after it (next load's business), never split across the pair.
    ``None`` = the listing failed; callers fall back to their
    self-probing behavior.
    """
    try:
        return frozenset(p.name for p in Path(out_dir).iterdir())
    except OSError as exc:
        # Transient listing failure (e.g. EMFILE in an fd-heavy
        # process): callers degrade to per-shard self-probing — the
        # pre-snapshot two-read pattern — so the race window this
        # snapshot closes is briefly back open. Log it: a silent
        # degrade would make a recurrence of the transient-orphan
        # flag undiagnosable.
        logger.debug("journal dir snapshot failed for %s (%s) — "
                     "falling back to per-shard probing", out_dir, exc)
        return None


def journal_shard_paths(
    out_dir: Path,
    *,
    snapshot: "frozenset[str] | None" = None,
) -> list[Path]:
    """The journal's contiguous shard set, in append order.

    Always starts with ``review-journal.jsonl`` (whether or not it
    exists yet) and extends through consecutively numbered siblings.
    The scan is contiguity-by-construction: a planted high-numbered
    file does not extend the set (the loader flags non-contiguous
    leftovers separately, see ``_orphan_shard_names``).

    ``snapshot`` (a :func:`_journal_dir_snapshot` result) computes
    contiguity from that single directory view instead of live
    per-shard probes — pass the SAME snapshot to
    ``_orphan_shard_names`` so a concurrent roll can never split the
    pair. ``None`` keeps the self-probing behavior.
    """
    out_dir = Path(out_dir)
    paths = [out_dir / JOURNAL_FILENAME]
    n = 2
    while n <= _MAX_JOURNAL_SHARDS:
        name = _journal_shard_name(n)
        if snapshot is not None:
            if name not in snapshot:
                break
        else:
            p = out_dir / name
            try:
                if not p.exists():
                    break
            except OSError:
                break
        paths.append(out_dir / name)
        n += 1
    return paths


def _orphan_shard_names(
    out_dir: Path,
    known: int,
    *,
    snapshot: "frozenset[str] | None" = None,
) -> list[str]:
    """Numbered shard files BEYOND the contiguous set — evidence that
    an interior shard was deleted (rows silently invisible), so the
    load must flag incomplete rather than pretend the survivors are
    the whole journal. ``snapshot`` classifies from the caller's
    single directory view (see :func:`_journal_dir_snapshot`);
    ``None`` takes its own listing."""
    names: list[str] = []
    if snapshot is not None:
        candidates = sorted(snapshot)
    else:
        try:
            candidates = sorted(p.name for p in Path(out_dir).iterdir())
        except OSError:
            return names
    for name in candidates:
        m = _JOURNAL_SHARD_RE.match(name)
        if m and int(m.group(1)) > known:
            names.append(name)
    return names[:8]


def _append_shard_path(out_dir: Path) -> Path:
    """The shard the next append lands in: the last contiguous shard,
    or — once it crosses the roll threshold — the next number.

    Cross-process note: two appenders can both observe the threshold
    crossing and both open the SAME next shard (O_CREAT without
    O_EXCL) — they simply share it, serialised by its flock. A shard
    can exceed the threshold by the appends that raced the roll; the
    threshold's margin below the reader budget absorbs that.
    """
    paths = journal_shard_paths(out_dir)
    last = paths[-1]
    try:
        size = last.stat().st_size
    except OSError:
        size = 0
    if size < _JOURNAL_SHARD_ROLL_BYTES:
        return last
    if len(paths) >= _MAX_JOURNAL_SHARDS:
        logger.warning(
            "journal: shard bound (%d) reached in %s — appending to "
            "the final shard past its roll threshold; %s",
            _MAX_JOURNAL_SHARDS, out_dir, compact_hint(out_dir),
        )
        return last
    return Path(out_dir) / _journal_shard_name(len(paths) + 1)

# domain-model.json is a small RAPTOR-written study artifact.
_MAX_DOMAIN_MODEL_BYTES = 64 * 1024 * 1024

# Per-run merge cap on the project-index merge: journals live inside
# sandbox write grants, and per-journal size caps alone let a hostile
# run push the INDEX past its own read budget across several subdir
# journals — after which (pre-guard) the next load read it as empty
# and the next merge destroyed all accumulated history. Applied to
# DISTINCT index identities (``merge_into_index`` collapses to the
# newest row per ``index_key`` first — a lossless step, since the
# merge is latest-wins per key). Sized from the write-boundary slim
# (``_slim_index_row``), honestly: a real post-slim index MIXES slim
# rows (~1.4 KiB median indent-2) with the protected fat rows the
# slim never touches (claims, findings, edges, echoes), and the
# measured MIXED mean is ~1,885 B/row (real 24k-identity mega-audit
# index). At that mix the merge write ceiling (the read budget minus
# the aggregates reserve, ~239 MiB) binds around ~130k rows: a
# cap-full 150k mixed run serializes to ~283 MB and byte-evicts its
# oldest identities — loudly, counts conserved — so above ~130k the
# BYTE ceiling, not this count cap, is the operative bound. The
# motivating shapes both fit as full rows (22.7k self-audit ≈ 43 MB;
# ~107k kernel scope ≈ 188 MB). Trade-off, both directions: too low
# and a legitimate mega-run (a 22k-identity self-audit, a
# ~10^5-function kernel-scope audit) reaches the index mostly as
# rollup aggregates (full rows carry verdict detail; aggregates
# carry only tallies); too high and the merge holds that many parsed
# entries in memory (~1 KiB object overhead each — the reader-side
# precedent is ``_MAX_RETAINED_ENTRIES = 300_000``, which this cap
# must stay under) while byte eviction, not this cap, ends up
# bounding every merge — the count cap must remain the COMMON bound
# so identities normally arrive as full rows and eviction stays the
# exception. Identities beyond the cap are NOT silently dropped:
# they roll up into the index's bounded ``aggregates`` section (see
# ``_aggregate_overflow``), so total counts are conserved and the
# truncation is disclosed machine-readably.
_MAX_MERGE_ENTRIES = 150_000

# Bounds on the index's overflow-aggregate section — the rollup rows
# that stand in for identities a mega-run pushed past
# ``_MAX_MERGE_ENTRIES``. Every bound trades detail for a hard size
# guarantee; none may be removed, because the aggregates section
# exists precisely so the OVERFLOW cannot re-inflate the index.
#
# Rollup rows per record. Too low and even a modest overflow
# cascades to directory/total granularity (per-file verdict tallies
# lost); too high and a hostile run fanning its overflow across
# many files writes that many rows into the index per merge.
_MAX_ROLLUP_ROWS = 512
# Aggregate records kept (one per merged run journal, newest-ts
# survive). Too low and a long project's older overflow disclosures
# age out quickly; too high and a hostile actor merging many
# overflowing run dirs accretes that many records.
_MAX_AGGREGATE_RECORDS = 64
# Serialized byte bound on the whole aggregates section, evicting
# the LARGEST record first (a single hostile giant record dies
# before it starves the honest ones). Too low and legitimate
# disclosure records evict each other; too high and the section
# crowds the entries dict inside the index's own
# ``_MAX_JOURNAL_BYTES`` write budget.
_MAX_AGGREGATE_BYTES = 16 * 1024 * 1024
# Path chars kept per rollup row. Too low and distinct deep paths
# truncate to one indistinguishable prefix — rollup rows mis-group
# and the disclosure stops naming where the overflow lives; too high
# and attacker-influencable file names (paths come from journal
# rows) smuggle megabytes into the index per row.
_AGGREGATE_PATH_CHARS = 256

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
    # ``run_path``: full resolved run-directory path, stamped by
    # ``append_entry`` at write time (never caller-supplied). The
    # finding re-import gate grants raw tool receipts only on a
    # full-path match — ``run_id`` is a basename and basenames
    # collide across projects (operator-chosen ``--out`` names), so
    # a byte-copied journal in a same-named sibling run dir must not
    # resurrect receipts minted against a different codebase. MAC-
    # covered when present; absent on pre-field rows (those demote
    # to the receipt-less tier at re-import, never refusal).
    run_path: str | None = None
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
    # ``seed_provenance``: external hypothesis seeds injected into
    # this review's context (``[{id, source}]`` from
    # core.audit.hypothesis_intake) — the audit-trail record of which
    # sibling-hypotheses.json claims this reviewer SAW. Provenance
    # only: a seed is a hint, never evidence, and this field carries
    # no verdict weight anywhere. Additive; absent on seedless rows.
    seed_provenance: list[dict] | None = None
    # ``seed_rereview``: this row is a seed-FORCED fresh review of an
    # already-covered function (``--seed-rereview`` scheduling by
    # core.audit.hypothesis_intake). Provenance only, like
    # ``seed_provenance`` — the prior verdicts stay in the history
    # and this row carries no extra verdict weight. Additive; absent
    # on ordinary rows.
    seed_rereview: bool | None = None
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
    # ``domain_slice_hash``: fingerprint of the per-function
    # domain-model prompt slice this review was briefed with
    # (core.audit.context.domain_slice_hash_for — the security
    # context, bug patterns, dynamic primers, and primer-conditional
    # domain-knowledge block build_context injected). Lets the gap
    # fold's context-staleness gate keep a verdict reuse-eligible
    # across a whole-model regeneration when THIS function's injected
    # slice is byte-identical; a missing or mismatching stamp keeps
    # the whole-model-hash behaviour (fail toward re-review).
    # Additive; absent on pre-field rows and model-less runs.
    domain_slice_hash: str | None = None
    # ``integrity``: HMAC provenance token over the row's canonical
    # JSON (this field excluded), stamped by append_entry. The gap
    # fold verifies before granting verdict-reuse authority; see
    # core.coverage.journal_mac. Additive; absent on pre-MAC rows.
    integrity: str | None = None
    # ``body_offload``: pointer stamped by ``journal compact
    # --slim-clean`` on clean/dormant STUB rows whose fat prose/context
    # fields (body, hypotheses, invariants_available,
    # domain_concepts_available) were moved to the run-local sidecar
    # (``core.coverage.journal_sidecar``). Shape: ``{"sidecar",
    # "offset", "bytes", "sha256", "fields"}``. Covered by the row MAC
    # on restamped stubs, so a verified stub's content hash
    # authenticates the sidecar record on read. Never set by live
    # writers; consumers that need the offloaded content hydrate
    # through the sidecar module and fail toward re-review when the
    # sidecar is unavailable. Additive; absent on non-stub rows.
    body_offload: dict | None = None
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


#: The field names THIS checkout's dataclass round-trip preserves.
#: ``_entry_from_dict`` compares persisted rows against this set to
#: detect a lossy projection (keys the local schema does not know)
#: and stash the raw-form provenance evidence — see
#: :data:`core.coverage.journal_mac.RAW_FORM_ATTR`.
_ENTRY_FIELD_NAMES: frozenset[str] = frozenset(
    f.name for f in dataclass_fields(ReviewJournalEntry)
)


def is_mechanical_echo(entry: Any) -> bool:
    """True for post-loop mechanically-minted rows.

    Two writers journal LLM-free rows after the review loop, both
    counted into the post-loop mechanical tally and neither an LLM
    review:

    * pattern-scan echoes — one ``[mechanical]`` row per finding,
      zero cost, no rationale, ``post-loop-mechanical`` strategy tag;
    * consistency-census synthesized outcomes — ``[consistency:...]``
      body, ``consistency-census`` strategy tag; the settled verdict
      is minted from census receipts, not from a review.

    Naive verdict counts that include either kind inflate by one row
    per mechanical finding, and coverage credit for either retires a
    never-reviewed function. Accepts a :class:`ReviewJournalEntry` or
    a raw journal dict — the single counting/screening rule for every
    summary and coverage consumer.
    """
    if isinstance(entry, dict):
        strategies = entry.get("strategies")
        body = entry.get("body")
    else:
        strategies = getattr(entry, "strategies", None)
        body = getattr(entry, "body", None)
    strategies = strategies or []
    return (
        "post-loop-mechanical" in strategies
        or "consistency-census" in strategies
        or (body or "").startswith(("[mechanical]", "[consistency:"))
    )


def is_agent_mark(entry: Any) -> bool:
    """True for ``--mark`` review assertions minted OUTSIDE an
    operator context.

    ``raptor-coverage-summary --mark`` journals ``producer="mark"``
    rows and stamps ``model`` from the invocation context:
    ``operator`` only under the mark path's strict live-context
    discipline (``live_context_grants_operator``), else
    ``agent-mark``. A review assertion is operator-tier authority —
    an agent context asserting "reviewed" carries no evidence gate
    (unlike ``raptor-audit record``), so readers must not let it earn
    review-grade coverage; granting it review weight is a
    self-coverage laundering channel (a mapping session could retire
    every function it merely read).

    BOUNDARY — what this screen does and does not close. It closes
    the CLI-MEDIATED route: a session that reaches review-grade
    coverage through ``raptor-coverage-summary`` gets the writer's
    context stamp, and this predicate keys weight on it (the stamp is
    MAC-covered on stamped rows, so it cannot be edited after the
    fact without demoting the row). It does NOT close the run-dir /
    same-user trust tier: a key-holding in-session process can call
    ``append_entry`` directly with ``model="operator"`` and a valid
    MAC — the journal MAC attests "this install's writer-key signed
    this content", never WHO held the key — and an UNSTAMPED forged
    ``model="operator"`` row passes this screen into the pre-existing
    unstamped tier (exact-source-hash-gated fold credit, no verdict
    reuse, no store import authority beyond that). Those bounds are
    the journal MAC's own documented trust model, and no claim here
    exceeds it.

    Grandfathering: rows from the era before the invocation-context
    stamp landed all carry the then-hardcoded ``model="operator"``
    and grandfather at operator tier. That bound is CIRCUMSTANTIAL,
    not mechanical — no per-row fact distinguishes an operator's
    pre-era mark from an agent's, so the benefit of doubt follows the
    /annotate legacy clause; the stamp era itself is the mechanism
    boundary going forward (a ts fence would add nothing: post-era
    stamped rows come only from the disciplined writer or a
    key-holder, and a key-holder chooses ts too).

    Accepts a :class:`ReviewJournalEntry` or a raw journal dict.
    """
    if isinstance(entry, dict):
        producer = entry.get("producer")
        model = entry.get("model")
    else:
        producer = getattr(entry, "producer", None)
        model = getattr(entry, "model", None)
    return producer == "mark" and model != "operator"


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

#: Bounded reopen retries for the post-flock inode re-validation in
#: :func:`append_entry`. A compactor's tempfile+rename swap can land
#: between an appender's ``open`` and its ``flock`` — the appender
#: then holds the ARCHIVED inode, and a row written there is silently
#: invisible to the live journal. Each mismatch closes and reopens by
#: NAME (the rename is atomic, so the name always resolves to the
#: live file). Trade-off, both directions: too low and back-to-back
#: swaps (each one waking this appender onto a just-archived inode)
#: exhaust the retries and fail an append that one more reopen would
#: have landed; too high and a pathological rename storm keeps a
#: single append spinning open/flock cycles instead of failing loud.
#: One swap costs exactly one retry, and nothing legitimate swaps the
#: journal in a tight loop — 5 covers generous compactor overlap.
_APPEND_REOPEN_ATTEMPTS = 5


def _fd_at_path(fd: int, path: Path) -> bool:
    """True when the open *fd* is still the file the NAME resolves to.

    The (dev, ino) identity check behind the appender's post-flock
    re-validation: a rename swap between open and flock leaves the fd
    pointing at the renamed-away (archived) inode while the name
    already resolves to the replacement. Any stat failure on the path
    reads as "not the live file" — the caller retries and the reopen
    surfaces the real error loudly (O_NOFOLLOW refuses a symlink
    planted in the window).
    """
    held = os.fstat(fd)
    try:
        now = os.stat(path)
    except OSError:
        return False
    return (held.st_dev, held.st_ino) == (now.st_dev, now.st_ino)


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

    Appends land in the journal's ACTIVE shard
    (:func:`_append_shard_path`): once a shard crosses the roll
    threshold, subsequent rows open the next numbered sibling, so no
    single file grows past the loader's per-shard retained budgets.

    Rename-swap safety: after the ``flock`` is acquired, the held fd
    is re-validated against the file the shard NAME currently
    resolves to (:func:`_fd_at_path`). A compactor's tempfile+rename
    swap holds the flock across both passes and the swap, so a
    foreign appender that opened the pre-swap inode blocks on the
    lock and wakes up holding the ARCHIVED file — pre-fix its row
    landed there, silently invisible to every live-journal reader. On
    a (dev, ino) mismatch the fd is released and the open/flock
    sequence retried by name (bounded by
    ``_APPEND_REOPEN_ATTEMPTS``, loud OSError on exhaustion); the
    shard path is re-resolved per attempt so a roll that raced the
    wait is honoured too. With the flock held and the identity
    verified, no cooperating compactor can swap the file until this
    append releases the lock — the compactor's own flock acquisition
    on the live inode blocks behind ours.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    # Provenance stamp (core.coverage.journal_mac): the fold trusts
    # rows for review suppression and $0 verdict reuse, so each row
    # carries a MAC over its own canonical content. Stamped on the
    # entry object too, so a caller that keeps it sees the same row
    # a reader would load. No usable key → the row persists unstamped
    # and demotes to the hash-gated legacy tier on read.
    from core.coverage import journal_mac
    # ``run_path`` is stamped HERE, never caller-supplied: the full
    # resolved run-dir path is where the row physically lands, and
    # binding it under the MAC is what lets the finding re-import
    # gate refuse receipt replay from a byte-copied journal in a
    # same-BASENAME sibling run dir (run_id alone is a basename).
    try:
        entry.run_path = str(Path(out_dir).resolve())
    except OSError:
        entry.run_path = str(out_dir)
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
    # No load-cache invalidation on append, by design: this writer
    # only ever ADDS whole newline-terminated lines to the ACTIVE
    # (last) shard past any cached reader offset (O_APPEND under
    # flock; short writes rolled back below, so no torn tail
    # survives), and a roll only CREATES the next shard file — the
    # reader's extension arm picks up appended rows from the cached
    # offset and a rolled set through its new-shard arm, while
    # sealed shards are never written again. Invalidating here would
    # only convert those O(delta) reads back into the full re-parse
    # the cache exists to avoid. Writers that REPLACE shard files
    # (compaction) call invalidate_load_cache.
    with _append_lock:
        for reopen in range(1, _APPEND_REOPEN_ATTEMPTS + 1):
            # Re-resolved per attempt: a mismatch below means the
            # shard set was rewritten (or rolled) while this appender
            # waited on the flock, so the active shard must be
            # re-derived, not assumed.
            journal_path = _append_shard_path(out_dir)
            fd = os.open(
                str(journal_path),
                os.O_WRONLY | os.O_APPEND | os.O_CREAT
                | _O_NOFOLLOW | _O_CLOEXEC | _O_NONBLOCK,
                0o644,
            )
            locked = False
            try:
                if not _fd_is_regular(fd):
                    # A planted FIFO (with a reader — the reader-less
                    # case already failed the open with ENXIO thanks
                    # to O_NONBLOCK) or device node: writing the
                    # journal into it silently discards MAC-stamped
                    # rows and every journal writer queues behind this
                    # one on _append_lock. Same disposition as the
                    # symlink plant (O_NOFOLLOW → ELOOP): raise,
                    # journal untouched.
                    msg = (
                        f"journal path {journal_path} is not a regular "
                        "file — refusing to append"
                    )
                    raise OSError(msg)
                if _HAS_FCNTL:
                    fcntl.flock(fd, fcntl.LOCK_EX)
                    locked = True
                    if not _fd_at_path(fd, journal_path):
                        # A compactor's rename swapped the file between
                        # our open and the flock: this fd is the
                        # ARCHIVED inode — a row written here is lost
                        # from the live journal. Release and reopen by
                        # name (only meaningful under flock: without
                        # fcntl there is no cross-process swap
                        # discipline to re-validate against).
                        if reopen == _APPEND_REOPEN_ATTEMPTS:
                            msg = (
                                f"journal at {journal_path} was "
                                f"swapped from under the appender "
                                f"{_APPEND_REOPEN_ATTEMPTS} times — "
                                "giving up without writing (row NOT "
                                "appended; the held fd was the "
                                "archived inode every attempt)"
                            )
                            raise OSError(msg)
                        logger.debug(
                            "journal append: %s renamed between open "
                            "and flock (attempt %d/%d) — reopening the "
                            "live file", journal_path, reopen,
                            _APPEND_REOPEN_ATTEMPTS,
                        )
                        continue
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
                return
            finally:
                if locked:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)


def flush_journal(out_dir: Path) -> None:
    """fsync the journal file(s) — call at batch/run boundaries.

    Same fd discipline as the appender: the pre-fix bare ``O_RDONLY``
    open followed a planted symlink (fsync of a FOREIGN file) and
    blocked forever on a writer-less FIFO (a read-side open of a FIFO
    waits for a writer). Best-effort: a refused/missing journal is
    silently skipped, like the old ``is_file()`` probe's negative.
    Every shard is synced — a batch can span a roll boundary, so the
    just-sealed shard needs the sync as much as the active one.
    """
    from core.source import open_regular
    for shard in journal_shard_paths(out_dir):
        fh = open_regular(shard, "rb")
        if fh is None:
            continue
        with fh:
            os.fsync(fh.fileno())


# ── Read ─────────────────────────────────────────────────────────────

class JournalIncomplete(RuntimeError):
    """The journal exists but could not be loaded COMPLETELY within
    the loader's memory bounds (retained-entry budget or read budget
    exceeded after duplicate pruning). Read-only consumers may degrade
    to the partial view; spend-authorizing consumers (same-run resume,
    the own-run reuse fold) must refuse — an incomplete verdict set
    silently re-buys every missing review, which is the maximum-spend
    fail direction a bounded read must never take."""


@dataclass
class JournalLoad:
    """Result of :func:`load_entries_checked`.

    ``complete`` is False only when rows were LOST — the loader
    stopped before end-of-file or gave up retaining. Duplicate
    re-emission rows pruned at load (``pruned``) do not clear the
    flag: the newest row of each identity survives, so no verdict,
    coverage key, or spend evidence is lost (only zero-cost duplicate
    rows prune — see ``_reemission_identity``)."""

    entries: list[ReviewJournalEntry] = field(default_factory=list)
    complete: bool = True
    pruned: int = 0
    reason: str | None = None


def compact_hint(out_dir: Path | str) -> str:
    """The operator remedy line for an over-budget journal.

    Names EVERY compaction tier unconditionally: whether the lossless
    duplicate prune can free enough is not knowable at message-render
    time (it needs the same two-pass census the compactor runs), a
    wedged operator whose journal holds no prunable duplicates must
    still be told the actionable remedy — and a claim-dominated
    journal of distinct latest rows can stay over budget even after
    superseding, which only the slim tier can shrink further.
    """
    return (
        "compact it first: libexec/raptor-audit journal compact "
        f"{out_dir} — if that frees too little (no duplicate "
        "rows to drop), add --supersede to keep only the newest "
        "verdict per identity (the full journal is archived as "
        "review-journal.jsonl.pre-supersede*, spend floor preserved) "
        "— and if the journal is still over budget (distinct latest "
        "rows dominate), use --slim-clean to move clean/dormant rows' "
        "prose and context-snapshot fields to the "
        "review-journal-bodies.jsonl sidecar (verdicts, spend, and "
        "claim rows stay inline; the full journal is archived as "
        "review-journal.jsonl.pre-slim*)"
    )


def require_complete_entries(out_dir: Path) -> list[ReviewJournalEntry]:
    """Load journal entries, REFUSING a partial load.

    The chokepoint for spend-authorizing consumers: ``raptor-audit
    resume`` and the own-run reuse fold import prior verdicts at $0,
    so a silently partial entry list converts directly into duplicate
    LLM spend for every missing row. Raises :class:`JournalIncomplete`
    with the compaction remedy; returns the (possibly load-pruned,
    never lossy) entry list otherwise.
    """
    # fresh=True: spend authorization never trusts the process-local
    # load cache. A cached view that drifted from the bytes on disk
    # (however unlikely the guards make it) would either re-buy every
    # missing verdict or — worse — treat a verdict set the shards no
    # longer carry as this run's prior state, so this chokepoint
    # always re-parses the journal.
    loaded = load_entries_checked(out_dir, fresh=True)
    if not loaded.complete:
        raise JournalIncomplete(
            f"review journal in {out_dir} could not be loaded "
            f"completely ({loaded.reason}) — refusing to treat a "
            f"partial verdict set as the run's prior state; "
            + compact_hint(out_dir)
        )
    return loaded.entries


def load_entries(
    out_dir: Path, *, fresh: bool = False,
) -> list[ReviewJournalEntry]:
    """Load all valid entries from review-journal.jsonl.

    Skips corrupt trailing line (truncated write) with a warning.
    Interior corrupt lines are also skipped with warnings. Degrades
    to a bounded PARTIAL list (loud warning) when the journal exceeds
    the loader's memory bounds — read-only consumers keep working;
    spend-authorizing consumers must use
    :func:`require_complete_entries` instead.

    ``fresh=True`` bypasses (and repopulates) the process-local load
    cache — see :func:`load_entries_checked` for the contract.
    """
    return load_entries_checked(out_dir, fresh=fresh).entries


# ── process-local incremental load cache ────────────────────────────
#
# A mega-audit's read-only journal consumers (reports, FP feedback,
# the collector's strategy snapshot, survival telemetry, coverage
# records) each call load_entries() per invocation, and every call
# used to stream and re-parse the WHOLE shard set from byte 0 — one
# observed audit segment re-loaded a ~255 MB journal 468 times. The
# journal's legitimate writers are APPEND-ONLY to the ACTIVE (last)
# shard under flock (``append_entry``; torn tails rolled back), a
# roll only ADDS a new shard file, and compaction swaps shard inodes
# — so a loader that remembers each shard's parse can serve an
# unchanged shard set from memory, parse only the active shard's
# appended delta, and absorb a roll by sealing the old active shard
# and parsing the new files from scratch. The cache is
# process-local, keyed by resolved run dir, guarded by the
# identity/fingerprint checks below, and NEVER consulted by
# spend-authorizing consumers (``fresh=True`` — see
# require_complete_entries): a wrong cached view there converts
# directly into duplicate LLM spend or trusted-but-absent verdicts.

#: Tail fingerprint length for the ACTIVE shard. Before extending a
#: cached parse (and on every identity-serve), the loader re-reads
#: the last up-to-64 raw bytes ending at the cached offset and
#: compares — an in-place rewrite of the bytes AT the boundary would
#: otherwise be silently glued onto the cached parse. SEALED shards
#: (all but the last) carry no fingerprint: they are pinned to their
#: exact ``(dev, ino, size, mtime_ns)`` instead, so any rewrite that
#: the filesystem metadata reflects forces a cold parse. Trade-off,
#: both directions: shorter and a rewrite that happens to preserve
#: the boundary bytes slips through more easily; longer costs a
#: larger pinned buffer per cached path while the residual below
#: stays open regardless (the check is O(1) evidence at the
#: boundary, not a hash of the whole prefix).
#:
#: ACCEPTED STALE-SERVE RESIDUAL (all guards combined). Two routes
#: remain by which a writer with run-dir write access can keep a
#: cached view alive over rewritten bytes:
#:
#: * active-shard extension arm — a rewrite strictly below
#:   ``offset - 64`` in the ACTIVE shard followed by any growth
#:   passes the fingerprint, so the rewritten head stays glued to
#:   every later extension until something forces a cold parse
#:   (identity change, truncation, budget/backend change,
#:   fresh=True, eviction). A SEALED shard has no such route: its
#:   exact pins catch any size/mtime/inode-visible rewrite;
#: * identity arms — ``os.utime`` backdating restores a recorded
#:   mtime, defeating both the mtime equality (active and sealed
#:   pins alike) and the racy window (that rule defends against
#:   ACCIDENTAL same-tick rewrites, never a deliberately
#:   timestamp-forging writer).
#:
#: Accepted because the outcome class does not change: a stale
#: serve reaches read-only consumers only — every spend, verdict
#: and index authority path reads fresh=True and never consults the
#: cache — and an actor who can rewrite journal bytes in place is
#: already inside the journal MAC's documented trust boundary
#: (same-user run-dir writers can forge rows outright; the MAC, not
#: this cache, is the row-authenticity mechanism).
#:
#: One further OBSERVABLE divergence (no rewrite needed): the read
#: budget is per consume call, so an extension chain can report
#: complete=True where a single cold parse of the same bytes would
#: exhaust its one budget and flag incomplete. Safe direction (more
#: data, honestly labelled complete because every byte WAS parsed),
#: and spend authorizers read fresh — they always get the single
#: cold parse's verdict.
_TAIL_FINGERPRINT_BYTES = 64

#: Cached-run-dir count bound (LRU eviction). Each record retains
#: its parsed entry lists — and a SHARDED journal multiplies the
#: worst case: one record can pin up to ``_MAX_JOURNAL_SHARDS`` x
#: the per-shard retained budget — so an unbounded dict would grow
#: with every run dir a long-lived process touches (cross-run
#: report/correlate tools walk dozens). Trade-off, both directions:
#: too low and alternating consumers thrash back to a full re-parse
#: per call (today's pre-cache cost, never worse); too high and a
#: long-lived session pins N x the retained budget of parsed
#: entries. 4 covers the audit loop's real working set (run root,
#: its ``autonomous/`` subdir, a project sibling) with one slot
#: spare. The count cap does not bound MEMORY once shards multiply
#: the per-record worst case — ``_LOAD_CACHE_MAX_BYTES`` below is
#: the byte bound.
_LOAD_CACHE_MAX_PATHS = 4

#: Aggregate byte bound on the cache, computed from each record's
#: summed per-shard ``retained_bytes`` (the loader's own accounting
#: of raw row bytes kept; Python object overhead rides on top, in a
#: ratio the per-shard retained budgets already bound). Stores evict
#: LRU-oldest until under the cap. A SINGLE record over the cap
#: sheds at SHARD granularity instead of refusing to cache: sealed
#: shards' parsed rows are evicted earliest-shard-first
#: (:func:`_shed_sealed_rows`) until the record fits, so a
#: kernel-scale multi-shard journal keeps PARTIAL caching — retained
#: shards serve from memory, only the shed shards (plus the active
#: shard's delta) re-parse per load. The pre-shed refusal gave such
#: a journal ZERO caching, returning the reload storm this cache
#: exists to collapse exactly at the scale where a full re-parse
#: hurts most. Only a record with nothing sheddable that still
#: exceeds the cap (single-shard or incomplete — no sealed rows to
#: shed) is not cached at all, at the pre-cache cost for that run
#: dir. Trade-off, both directions: too low and mega-journals
#: re-parse most of their shards per load (bounded regression
#: toward the pre-cache cost, never worse); too high and a
#: long-lived multi-run process pins gibibytes of parsed rows (a
#: fully-sharded record alone can reach _MAX_JOURNAL_SHARDS x the
#: per-shard budget ≈ 16 GiB). 1 GiB holds ~4 max-size single-shard
#: journals, or the hottest ~5 shards of a mega-journal.
_LOAD_CACHE_MAX_BYTES = 1 << 30

#: Racy-mtime window (ns), git's racy-lstat rule: a shard whose
#: mtime falls within this window of the record's creation cannot be
#: trusted by (size, mtime) identity alone — a same-size in-place
#: rewrite inside one coarse-clock tick (filesystems stamp mtime_ns
#: at jiffy resolution) would be indistinguishable from "unchanged".
#: A racy ACTIVE shard still EXTENDS normally (the tail fingerprint
#: guards that arm) but refuses identity-serves; a racy SEALED pin
#: refuses serves AND extensions (sealed shards have only the pin —
#: reusing their cached rows IS an identity-serve of that shard).
#: EVERY refused attempt inside the window pays a full parse (the
#: re-store stays racy while the mtime is still within the window
#: of "now"); the first attempt after the window elapses re-stores
#: non-racy and later calls serve. Trade-off, both directions: too
#: small and a coarse-clock or NFS-granularity same-size rewrite can
#: be served stale; too large and every load of an unchanged journal
#: within the window re-parses it (bounded in TIME by the window,
#: not in call count — sealed-pin raciness additionally re-parses
#: for one window after each ROLL, which is rare by construction).
#: 2s covers every observed kernel tick and NFS timestamp
#: granularity.
_MTIME_RACE_WINDOW_NS = 2_000_000_000


@dataclass
class _ShardLoadState:
    """One shard's streaming-parse state plus its cache pin.

    The parse fields are the loader's exact in-stream accounting,
    shared verbatim between a cold shard load (empty initial state)
    and an active-shard cache extension (state restored from the
    record), so the two paths cannot drift: the per-line transition
    depends only on (state, next line), which is what makes an
    extended load equal a cold parse of the same bytes. There is no
    per-shard end-of-load dedup — the cross-shard final pass runs on
    a COPY of the concatenated lists — so the cached per-shard state
    is ALWAYS the pristine in-stream state.
    """

    name: str
    entries: list[ReviewJournalEntry] = field(default_factory=list)
    sizes: list[int] = field(default_factory=list)  # raw line length per retained entry
    retained_bytes: int = 0
    pruned: int = 0
    line_no: int = -1        # absolute index of the last consumed line
    corrupt_total: int = 0   # quarantined lines across all consume calls
    at_line_boundary: bool = True  # last consumed byte was a newline
    io_error: bool = False   # a mid-read OSError degraded this shard
    missing: bool = False    # file absent entirely
    refused: bool = False    # exists but refused the disciplined open
    reason: str | None = None
    # ── cache pin, captured from the OPEN fd at parse end ──
    pin_ok: bool = False
    dev: int = -1
    ino: int = -1
    size: int = -1
    mtime_ns: int = -1
    racy: bool = True
    offset: int = 0          # byte offset after the last fully-consumed line
    tail: bytes = b""        # raw bytes ending at ``offset`` (fingerprint)
    #: Parsed rows evicted under the cache byte cap
    #: (:func:`_shed_sealed_rows`): ``entries``/``sizes`` were dropped
    #: to free memory while the rest of the record stays cached. Set
    #: only on SEALED shards of a COMPLETE record; a shed shard is
    #: re-parsed cold on the next load, never served or extended from
    #: this state.
    rows_evicted: bool = False


@dataclass
class _CachedLoad:
    """One run dir's cached journal parse (see the section note).

    ``shard_states`` is the contiguous shard set in append order; the
    LAST state is the active shard. A ``complete`` record serves when
    every sealed shard matches its exact ``(dev, ino, size,
    mtime_ns)`` pin and the active shard passes the r-style
    identity/fingerprint checks; it extends by delta-parsing the
    active shard and, when new shard files appeared, sealing the old
    active at its EOF and parsing the new files from byte 0. An
    INCOMPLETE record is pinned whole — every shard (active
    included) must match its exact pin — and is never extended: a
    budget-bounded parse is deterministic for the same bytes, but
    resuming it is not.
    """

    shard_states: list[_ShardLoadState]
    complete: bool
    reason: str | None
    pruned_total: int        # aggregate, including the final dedup pass
    #: Final post-dedup view, or ``None`` once any shard's rows were
    #: shed under the byte cap (the memoized result aliases every
    #: shard's entry objects, so keeping it would pin the memory the
    #: shed just freed) — a shed record rebuilds per serve by
    #: re-parsing only the shed shards.
    result_entries: list[ReviewJournalEntry] | None
    extensible: bool         # complete AND active shard ended at a boundary
    #: Loader knobs this parse depended on (budgets + JSON backend):
    #: a view computed under different budgets or a different parser
    #: is NOT equivalent to a cold load under the current ones (rows
    #: quarantine differently, budgets bind at different rows), so a
    #: mismatch — budget tunables, or the containment tests'
    #: monkeypatched budgets/backends — forces a full reload.
    config: tuple[int, int, int, int, int, bool]
    #: Memoized latest-per-key collapse of ``result_entries``
    #: (:func:`latest_entries`): built lazily on the first
    #: latest-view consumer, carried incrementally across
    #: active-shard extensions (:func:`_carry_latest_view` folds only
    #: the delta rows), and reset to ``None`` whenever it can no
    #: longer be locally proven equal to a from-scratch collapse of
    #: the served result — shed rows, an in-stream prune during the
    #: delta, non-monotone delta timestamps — after which the next
    #: consumer rebuilds it from scratch. The values alias winner
    #: entries out of ``result_entries`` (no extra row memory beyond
    #: the key strings and dict), so it is never kept on a shed
    #: record, where it would pin the memory the shed just freed.
    latest_view: dict[str, ReviewJournalEntry] | None = None
    #: Max ``entry.ts`` across every row the view covers (equal to
    #: the max over the winners: the globally newest row always wins
    #: its own key). The strict-monotonicity guard for the
    #: incremental fold — a delta row folds in O(1) only when its
    #: ``ts`` is strictly newer than everything already covered;
    #: otherwise a back-dated twin could flip which duplicate the
    #: cross-shard prune keeps, and the fold cannot prove
    #: equivalence locally (see :func:`_carry_latest_view`).
    latest_view_ts_max: str = ""
    #: Duplicate-row prune count already disclosed for this cache
    #: generation. The prune warning's inputs are stable across
    #: extensions — finalize re-aggregates the SAME cached per-shard
    #: in-stream counts, and the cross-shard dedup re-run re-finds
    #: the SAME historical duplicates — so without this baseline
    #: every consumer load that finalized re-warned one
    #: byte-identical line (hundreds per run at production load
    #: frequency). With it, an extension warns only when NEW rows
    #: pruned beyond the baseline (delta + cumulative, so a growing
    #: problem stays visible; same convention as the corrupt-line
    #: counter, which never re-warns lines a prior call reported). A
    #: whole-record drop (invalidate_load_cache, uncacheable outcome,
    #: LRU eviction) resets to cold-parse semantics: the next
    #: generation warns its full count again — a fresh process never
    #: loses the signal, since the on-disk duplicate rows persist
    #: until an offline compact.
    warned_pruned: int = 0

    def cached_bytes(self) -> int:
        """The record's live cost under ``_LOAD_CACHE_MAX_BYTES``:
        summed per-shard retained raw bytes, EXCLUDING shed shards
        (their rows are gone — counting them would double-charge a
        shed record and starve the shards it still retains).
        Computed from the shard states so shedding can never desync
        an accounting field."""
        return sum(
            0 if s.rows_evicted else s.retained_bytes
            for s in self.shard_states
        )


_load_cache: dict[str, _CachedLoad] = {}
#: Guards the cache dict AND every record's lists, held across the
#: whole load: an extension mutates the cached lists in place, and
#: two threads extending one record concurrently would interleave
#: rows. Holding it across the parse also means N workers racing to
#: load the same journal serialize into one parse plus N-1 cache
#: hits — exactly the reload storm this cache exists to collapse.
#: Cross-path contention is bounded by one journal parse; served
#: results are copies, so no consumer ever holds the lock.
_load_cache_lock = threading.Lock()


def _loader_config() -> tuple[int, int, int, int, int, bool]:
    """The knobs a cached parse is only valid under (see
    ``_CachedLoad.config``). The roll threshold is included: it
    decides which shard the appender writes next, and the shard-set
    tests monkeypatch it."""
    from core.json import utils as _json_utils
    return (
        _MAX_JOURNAL_BYTES,
        _MAX_JOURNAL_LINE_BYTES,
        _MAX_RETAINED_ENTRIES,
        _READ_BUDGET_MULTIPLIER,
        _JOURNAL_SHARD_ROLL_BYTES,
        _json_utils._orjson is not None,
    )


def invalidate_load_cache(out_dir: Path | str) -> None:
    """Drop the process-local load-cache record for *out_dir*.

    For writers that REPLACE journal shard files rather than
    appending lines (compaction's per-shard tempfile+rename swaps):
    the reader's ``(dev, ino)`` identity checks catch the common
    inode change, but freed inode numbers can be recycled
    immediately on some filesystems (a hardlink-backup-then-rename
    swap frees and reallocates within one call), so the swapper
    drops the record explicitly instead of betting on the identity
    check. Appends need no invalidation — see the note in
    :func:`append_entry`.
    """
    key = os.path.realpath(out_dir)
    with _load_cache_lock:
        _load_cache.pop(key, None)


def _shed_sealed_rows(record: _CachedLoad) -> bool:
    """Evict sealed shards' parsed rows from *record*, earliest shard
    first, until it fits ``_LOAD_CACHE_MAX_BYTES``. Returns True when
    it fits.

    Shard-granular partial caching for records too big to cache
    whole: the shed shards' ``entries``/``sizes`` are dropped (and
    the memoized ``result_entries``, which aliases the same entry
    objects — keeping it would pin the memory just freed) while
    their pins and the remaining shards' rows stay. The next load
    reuses the retained shards' rows and re-parses only the shed
    shards from byte 0 (:func:`_serve_or_extend_set`).

    Eviction order is earliest-shard-first, deterministically: every
    serve touches every shard of the set, so per-shard recency is
    uniform within a record (record-level LRU still orders records
    against each other) — any fixed choice re-parses the same byte
    count, and a stable one keeps repeated shed/rebuild cycles
    re-parsing the SAME shards instead of thrashing across the set.

    Only COMPLETE records shed: an incomplete record is served
    solely by its exact whole-set pin (never rebuilt or extended),
    so shedding any part of it would leave nothing servable — and
    the ACTIVE shard's rows never shed (they are the extension arm's
    resume state, and the roll threshold bounds them well under the
    cap).
    """
    if not record.complete:
        return False
    for state in record.shard_states[:-1]:
        if record.cached_bytes() <= _LOAD_CACHE_MAX_BYTES:
            break
        if state.rows_evicted:
            continue
        state.entries = []
        state.sizes = []
        state.rows_evicted = True
        record.result_entries = None
        # The memoized latest view aliases the same entry objects as
        # the memoized result: keeping either would pin the memory
        # this shed just freed (a unique-key mega-journal's view is
        # nearly every row).
        record.latest_view = None
        record.latest_view_ts_max = ""
    return record.cached_bytes() <= _LOAD_CACHE_MAX_BYTES


def _cache_store(cache_key: str, record: _CachedLoad) -> None:
    """Insert/refresh *record* at LRU-newest; evict past the count
    AND aggregate-byte caps. Caller holds ``_load_cache_lock``.

    A record alone over the byte cap sheds sealed shards' rows
    (:func:`_shed_sealed_rows`) rather than refusing outright —
    partial caching for mega-journals. A record that cannot fit even
    fully shed (nothing sheddable: single-shard, or incomplete) is
    not cached at all — and never at other records' expense (routing
    it through the eviction loop would flush every older record
    before self-evicting); the load already returned normally
    (pre-cache cost).
    """
    _load_cache.pop(cache_key, None)
    if (record.cached_bytes() > _LOAD_CACHE_MAX_BYTES
            and not _shed_sealed_rows(record)):
        return
    _load_cache[cache_key] = record
    while (len(_load_cache) > _LOAD_CACHE_MAX_PATHS
           or sum(r.cached_bytes() for r in _load_cache.values())
           > _LOAD_CACHE_MAX_BYTES):
        # Evict LRU-oldest first; terminates before evicting the
        # just-inserted record — alone it satisfies both caps (count
        # 1, bytes gated above).
        _load_cache.pop(next(iter(_load_cache)))


def _cached_result(cached: _CachedLoad) -> JournalLoad:
    # Shallow copy on every serve: later extensions rebuild the
    # cached result list, and a caller's own list mutations must
    # never leak into the cache (or into another caller's earlier
    # result). The entry OBJECTS are shared — frozen by contract: no
    # journal consumer mutates a loaded entry (audited; corrections
    # are appended as NEW rows, never edited onto loaded ones).
    if cached.result_entries is None:
        # A shed record has no memoized result; callers rebuild via
        # _finalize_set instead of serving. Failing loud beats
        # serving an empty view as the journal's content.
        msg = "internal: identity-serve of a shed cache record"
        raise RuntimeError(msg)
    return JournalLoad(
        entries=list(cached.result_entries),
        complete=cached.complete,
        pruned=cached.pruned_total,
        reason=cached.reason,
    )


def load_entries_checked(
    out_dir: Path, *, fresh: bool = False,
) -> JournalLoad:
    """Streaming, memory-bounded journal load with completeness flag.

    Reads the journal's whole CONTIGUOUS shard set
    (:func:`journal_shard_paths`) as one journal, in append order.
    The memory bounds below apply PER SHARD (the appender rolls
    before a shard can cross them); completeness requires every shard
    to load completely, and a missing interior shard or a
    non-contiguous leftover (evidence of a deleted shard) flags the
    load incomplete. Duplicate re-emission rows are pruned across
    shard boundaries at the end of a multi-shard load — resume
    segments re-emit reused verdicts, and segment boundaries need not
    align with shard rolls.

    Memory bounds (the old whole-file st_size refusal failed OPEN —
    an over-cap journal loaded as ``[]`` and a resume re-reviewed the
    entire run):

    * per line: ``_MAX_JOURNAL_LINE_BYTES`` — an over-long line is
      quarantined as a row and streamed past in bounded chunks;
    * retained: ``_MAX_JOURNAL_BYTES`` raw bytes /
      ``_MAX_RETAINED_ENTRIES`` rows — crossing either prunes
      duplicate re-emission rows in place (lossless: newest per
      identity, zero-cost rows only); only when pruning cannot get
      back under budget does the load stop, flagged incomplete;
    * consumed: ``_READ_BUDGET_MULTIPLIER`` x the retained budget —
      bounds the read loop itself against multi-GiB plants and
      writers growing the file mid-read. The budget bounds ONE
      consume call per shard (the historical per-call semantics), so
      a cache extension gets a full fresh budget for its delta.

    Results may be served from the process-local incremental cache
    (unchanged shard set → cached copy; grown active shard or a
    rolled shard set → cached prefix plus a parse of only the new
    bytes/files). A shard set too large to cache whole is cached
    PARTIALLY: sealed shards' rows shed earliest-first under the
    cache byte cap and re-parse per load while the retained shards
    serve from memory (``_LOAD_CACHE_MAX_BYTES``). In every case,
    for any in-budget byte sequence the served result equals a cold
    parse of the same bytes (pinned by the equivalence test in
    core/coverage/tests/test_journal_load_cache.py).
    ``fresh=True`` bypasses the cache for this call and repopulates
    it from the fresh parse — the mandatory contract for
    spend-authorizing consumers (:func:`require_complete_entries`,
    the resume spend floor, drift computation, the project-index
    merge).

    The returned ``entries`` list is the caller's own (a copy); the
    entry objects themselves are shared with the cache and are
    frozen by contract.
    """
    out_dir = Path(out_dir)
    # Resolved cache key: two spellings of one run dir (symlinked
    # parents, relative vs absolute --out) share a record — distinct
    # keys would not be wrong, just cold and double-retained.
    cache_key = os.path.realpath(out_dir)
    with _load_cache_lock:
        return _load_checked_locked(out_dir, cache_key, fresh=fresh)


def _load_checked_locked(
    out_dir: Path, cache_key: str, *, fresh: bool,
) -> JournalLoad:
    """Cache-aware shard-set load; caller holds ``_load_cache_lock``."""
    if not fresh:
        cached = _load_cache.get(cache_key)
        if cached is not None:
            served = _serve_or_extend_set(out_dir, cache_key, cached)
            if served is not None:
                return served
    # Cold parse of the whole shard set — ONE directory snapshot
    # feeds both the contiguity walk and finalize's orphan
    # classification (see _journal_dir_snapshot).
    snap = _journal_dir_snapshot(out_dir)
    states = [
        _load_shard_cold(shard)
        for shard in journal_shard_paths(out_dir, snapshot=snap)
    ]
    return _finalize_set(out_dir, cache_key, states, snapshot=snap)


def _serve_or_extend_set(
    out_dir: Path, cache_key: str, cached: _CachedLoad,
) -> JournalLoad | None:
    """Serve or extend *cached* against the shard set on disk.
    ``None`` means the caller must fall back to a full cold parse.
    Caller holds ``_load_cache_lock``."""
    if cached.config != _loader_config():
        return None
    snap = _journal_dir_snapshot(out_dir)
    shards_now = journal_shard_paths(out_dir, snapshot=snap)
    names_now = [p.name for p in shards_now]
    cached_names = [s.name for s in cached.shard_states]
    if (len(names_now) < len(cached_names)
            or names_now[:len(cached_names)] != cached_names):
        # The shard set shrank or was renumbered: the cached parse
        # describes files that no longer form this journal.
        return None
    if _orphan_shard_names(out_dir, len(shards_now), snapshot=snap):
        # Contiguity anomaly: cold behavior flags it per load, and
        # anomalous states are never cached — matching that exactly
        # means never serving through one either.
        #
        # Contract with the cold loader (fulfilled): this re-check
        # consumes the SAME snapshot as the journal_shard_paths call
        # above — a roll is wholly in or wholly after the snapshot,
        # never split across the pair; re-scanning here would
        # reintroduce the two-read race one layer up.
        return None
    if not cached.complete:
        # Pinned incomplete record (the observed reload storm was an
        # over-budget journal, static between calls): serve the exact
        # bytes it was pinned to — EVERY shard, active included —
        # and never extend (a budget-bounded parse is deterministic
        # for the same bytes; resuming it is not).
        if len(names_now) != len(cached_names):
            return None
        for state in cached.shard_states:
            if state.racy or not _shard_pin_matches(
                    out_dir, state, check_tail=True):
                return None
        _cache_store(cache_key, cached)   # refresh LRU recency
        return _cached_result(cached)
    sealed = cached.shard_states[:-1]
    active = cached.shard_states[-1]
    for state in sealed:
        if state.rows_evicted:
            # Shed shard (_shed_sealed_rows): no cached rows to
            # vouch for, so no pin to honor — it is re-parsed cold
            # below either way, reading exactly the bytes a cold
            # load of the current file would read.
            continue
        # Sealed shards never legitimately change: exact pins only.
        # A racy pin (sealed less than one clock tick before the
        # store — i.e. just after a roll) cannot vouch for itself,
        # and reusing a sealed shard's cached rows IS an identity-
        # serve of that shard, so raciness here refuses extension
        # too, not just the full-set serve.
        if state.racy or not _shard_pin_matches(
                out_dir, state, check_tail=False):
            return None
    shed = any(s.rows_evicted for s in sealed)
    # Incremental latest-view fold inputs, captured BEFORE the delta
    # parse mutates the active state in place (_carry_latest_view).
    old_view = cached.latest_view
    old_view_ts_max = cached.latest_view_ts_max
    old_active_len = len(active.entries)
    old_active_pruned = active.pruned
    # Same-generation continuation: the popped record's disclosed
    # prune count carries into the re-finalize so only NEW prunes
    # warn (a cold parse — record dropped or absent — starts at 0
    # and warns the full count again).
    warned_pruned = cached.warned_pruned
    new_names = names_now[len(cached_names):]
    from core.source import open_regular
    fh = open_regular(out_dir / active.name, "rb")
    if fh is None:
        return None
    resumed = False
    try:
        try:
            st = os.fstat(fh.fileno())
        except OSError:
            return None
        if (st.st_dev, st.st_ino) != (active.dev, active.ino):
            return None
        if not new_names and st.st_size == active.offset:
            # Unchanged journal — the hot path of the reload storm.
            # mtime + tail fingerprint still gate the serve: a
            # same-size in-place rewrite keeps (dev, ino, size), and
            # the racy mark covers rewrites inside one clock tick.
            if (active.racy
                    or getattr(st, "st_mtime_ns", None)
                    != active.mtime_ns
                    or not _tail_matches(fh, active)):
                return None
            if not shed:
                _cache_store(cache_key, cached)
                return _cached_result(cached)
            # Shed record over an unchanged set: the retained shard
            # states are reusable verbatim but the memoized result
            # is gone — fall through to rebuild by re-parsing ONLY
            # the shed shards (partial caching's steady state). Pop
            # first, same rationale as the extension arm below.
            _load_cache.pop(cache_key, None)
            resumed = True
        else:
            if st.st_size < active.offset:
                # Truncated below the consumed prefix.
                return None
            if not cached.extensible:
                # Complete but the active shard's parse ended
                # mid-line: a writer completing that line merges it
                # with the next append into ONE line a cold parse
                # reads differently — never resume past an
                # unterminated tail.
                return None
            if not _tail_matches(fh, active):
                return None            # head rewritten in place
            # Pop the record BEFORE handing its lists to the
            # extension: a BaseException (KeyboardInterrupt,
            # SystemExit) escaping the streaming loop mid-extension
            # must leave this key COLD — a torn record whose lists
            # already carry part of the delta but whose offset still
            # points at the old boundary would re-consume the delta
            # on the next call and serve duplicated entries.
            # _finalize_set re-stores the finished record on success.
            _load_cache.pop(cache_key, None)
            resumed = True
            _consume_shard_stream(fh, out_dir / active.name, active)
            _finish_shard_pin(fh, active)
    finally:
        # Close errors on a read-only fd carry no data-loss risk for
        # the reader; the parse (and any degrade decision) is done.
        with contextlib.suppress(OSError):
            fh.close()
    if not resumed:
        return None
    states = list(cached.shard_states)
    for name in new_names:
        # A roll happened since the record was stored: the old active
        # shard was just delta-parsed to ITS EOF and sealed above;
        # every newly-appeared shard is parsed from byte 0, and the
        # new last shard becomes the active one.
        states.append(_load_shard_cold(out_dir / name))
    if shed:
        # Re-parse exactly the shed shards from byte 0; every
        # retained shard's rows are reused verbatim. The re-parsed
        # state carries a fresh pin, so _finalize_set stores a whole
        # record again (which _cache_store may shed again — the
        # deterministic earliest-first order re-sheds the SAME
        # shards, so the per-load re-parse set stays stable).
        states = [
            _load_shard_cold(out_dir / s.name) if s.rows_evicted else s
            for s in states
        ]
    result = _finalize_set(
        out_dir, cache_key, states, snapshot=snap,
        warned_pruned=warned_pruned,
    )
    if old_view is not None and not shed:
        # Pure extension of an unshed record: carry the memoized
        # latest view forward by folding only the delta rows. A shed
        # record re-parsed sealed shards from CURRENT bytes the old
        # view never covered (shed shards skip the pin check), so it
        # never carries — its view rebuilds from scratch lazily.
        _carry_latest_view(
            cache_key, old_view, old_view_ts_max, states,
            len(cached.shard_states) - 1,
            old_active_len, old_active_pruned,
        )
    return result


def _carry_latest_view(
    cache_key: str,
    old_view: dict[str, ReviewJournalEntry],
    old_ts_max: str,
    states: list[_ShardLoadState],
    active_idx: int,
    old_active_len: int,
    old_active_pruned: int,
) -> None:
    """Carry a record's memoized latest-per-key view across an
    active-shard extension by folding ONLY the delta rows — O(delta)
    per load instead of O(journal) per consumer call. Caller holds
    ``_load_cache_lock``.

    A silent no-op (the view rebuilds lazily from scratch on the
    next :func:`latest_entries` call) whenever LOCAL reasoning
    cannot prove the fold equal to a from-scratch collapse of the
    new served result:

    * the extended record did not survive the store (uncacheable
      outcome, shed under the byte cap) or is incomplete — nothing
      provably current to maintain;
    * the in-stream prune fired during the delta parse
      (``state.pruned`` moved): it rewrites the active list in
      place, so the positional slice no longer identifies exactly
      the appended rows;
    * any delta row's ``ts`` is not strictly newer than everything
      already covered: the cross-shard final prune keeps the LAST
      positional twin while the collapse keeps the highest-``ts``
      first-position row, and only strict monotonicity makes those
      provably pick the same winner — genuine appends carry
      strictly-monotone microsecond stamps (see
      :func:`latest_entries`), so a back-dated or tied delta row is
      hostile input and pays one full recollapse, never a wrong
      view. Pinned by the differential-equivalence test in
      core/coverage/tests/test_journal_latest_view.py.
    """
    record = _load_cache.get(cache_key)
    if (record is None or record.shard_states is not states
            or not record.complete
            or record.result_entries is None):
        return
    active = states[active_idx]
    if active.pruned != old_active_pruned:
        return
    delta = active.entries[old_active_len:]
    for state in states[active_idx + 1:]:
        delta.extend(state.entries)
    ts_max = old_ts_max
    for entry in delta:
        if entry.ts <= ts_max:
            return
        ts_max = entry.ts
    # The old record was popped before the extension began and served
    # results are copies, so its view dict is exclusively ours to
    # reuse in place — no O(keys) copy per extension.
    for entry in delta:
        old_view[entry.key] = entry
    record.latest_view = old_view
    record.latest_view_ts_max = ts_max


def _shard_pin_matches(
    out_dir: Path, state: _ShardLoadState, *, check_tail: bool,
) -> bool:
    """True when the shard file on disk matches *state*'s exact pin
    (and, for ``check_tail``, its boundary fingerprint). Opens via
    the disciplined ``open_regular`` and checks the OPEN fd — never
    a by-name stat, which races a swap."""
    from core.source import open_regular
    fh = open_regular(out_dir / state.name, "rb")
    if fh is None:
        return False
    try:
        try:
            st = os.fstat(fh.fileno())
        except OSError:
            return False
        if (st.st_dev, st.st_ino) != (state.dev, state.ino):
            return False
        if st.st_size != state.size:
            return False
        if getattr(st, "st_mtime_ns", None) != state.mtime_ns:
            return False
        if check_tail and not _tail_matches(fh, state):
            return False
        return True
    finally:
        with contextlib.suppress(OSError):
            fh.close()


def _tail_matches(fh: IO[bytes], state: _ShardLoadState) -> bool:
    """Re-read and compare the cached tail fingerprint; leaves *fh*
    positioned at ``state.offset`` on a match."""
    tail_len = len(state.tail)
    try:
        fh.seek(state.offset - tail_len)
        return fh.read(tail_len) == state.tail
    except OSError:
        return False


def _load_shard_cold(journal_path: Path) -> _ShardLoadState:
    """Cold parse of ONE journal shard file under the per-shard
    bounds, from byte 0, capturing the cache pin at parse end."""
    state = _ShardLoadState(name=journal_path.name)
    # fd-discipline open (core.source.open_regular): the journal sits
    # in the sandbox-writable run dir, and the previous
    # is_symlink()/is_file() probes raced a swap — a symlink swapped
    # in between check and open read a FOREIGN journal into this
    # run's merge, and a planted FIFO blocked the open forever.
    # O_NOFOLLOW + O_NONBLOCK + fstat(S_ISREG) on the OPENED fd close
    # both windows. The cache pins reuse this fd — NEVER a bare
    # by-name stat, which would race the same swap.
    from core.source import open_regular
    fh = open_regular(journal_path, "rb")
    if fh is None:
        # Absent journal: empty AND complete (a run with no reviews
        # has no prior state to protect; the multi-shard caller flags
        # a missing INTERIOR shard itself). A journal that EXISTS but
        # refused the disciplined open (permissions, planted
        # non-regular file) is incomplete: for a resume, "cannot read
        # the verdicts" must not read as "there are none".
        exists = False
        with contextlib.suppress(OSError):
            exists = journal_path.exists()
        if exists:
            state.refused = True
            state.reason = "journal exists but refused the read open"
        else:
            state.missing = True
        return state
    try:
        _consume_shard_stream(fh, journal_path, state)
        _finish_shard_pin(fh, state)
    finally:
        with contextlib.suppress(OSError):
            fh.close()
    return state


def _finish_shard_pin(fh: IO[bytes], state: _ShardLoadState) -> None:
    """Capture *state*'s cache pin from the still-open fd; a pin that
    cannot be captured soundly leaves ``pin_ok`` False (the record is
    then not cacheable)."""
    state.pin_ok = False
    if state.io_error:
        # A mid-read I/O failure is not deterministic: a cold load of
        # the same unchanged file may well succeed, so the degraded
        # view must never be pinned and re-served.
        return
    try:
        end_st = os.fstat(fh.fileno())
        pos = fh.tell()
    except OSError:
        return
    mtime_ns = getattr(end_st, "st_mtime_ns", None)
    if not isinstance(mtime_ns, int):
        # A stat_result without a nanosecond mtime (synthetic stat
        # objects from test shims; exotic platforms) leaves the pin
        # identity incomplete — refuse to cache rather than pin on a
        # weaker identity.
        return
    if state.reason is None and pos != end_st.st_size:
        # Complete parse but the file grew between our EOF and the
        # pin fstat: a cold load of the pinned identity would see the
        # extra bytes — do not pin a view the identity cannot vouch
        # for. (Budget-bounded incomplete parses stop mid-file by
        # construction and stay deterministic for the same bytes, so
        # they pin fine.)
        return
    tail = _read_tail(fh, pos)
    if tail is None:
        return                      # racing truncation mid-probe
    state.dev = end_st.st_dev
    state.ino = end_st.st_ino
    state.size = end_st.st_size
    state.mtime_ns = mtime_ns
    state.racy = (
        abs(time.time_ns() - mtime_ns) < _MTIME_RACE_WINDOW_NS
    )
    state.offset = pos
    state.tail = tail
    state.pin_ok = True


def _read_tail(fh: IO[bytes], pos: int) -> bytes | None:
    """The up-to-``_TAIL_FINGERPRINT_BYTES`` raw bytes ending at
    *pos*, or ``None`` when they cannot be read back (racing
    truncation, I/O error). Restores no position — callers are done
    streaming."""
    tail_len = min(_TAIL_FINGERPRINT_BYTES, pos)
    try:
        fh.seek(pos - tail_len)
        tail = fh.read(tail_len)
    except OSError:
        return None
    if len(tail) != tail_len:
        return None
    return tail


def _consume_shard_stream(
    fh: IO[bytes],
    journal_path: Path,
    state: _ShardLoadState,
) -> None:
    """Run the bounded streaming parse from *fh*'s CURRENT position,
    extending *state* in place. Never raises: a mid-read OSError
    degrades (keep what loaded, flag incomplete) like the historical
    loader.

    Reads raw BYTES and hands each line to the parser individually. A
    whole-file ``read_text()`` decoded BEFORE any per-line quarantine
    could run, so one undecodable byte (anything with the run-dir
    write grant can append ``b"\\x80"``) crashed every journal
    consumer at once; per-row parsing contains a bad encoding to the
    row that carries it (both JSON backends decode per input).

    STREAMS the lines instead of materialising a whole-file
    ``splitlines()``: a degenerate journal of 2-3 byte rows costs one
    small bytes object PER LINE when split eagerly (~20x the file
    size in peak RSS — an at-cap journal of tiny rows OOM-killed the
    reader that exists to contain hostile bytes). Iterating the file
    keeps one line alive at a time, so the byte budgets bound the
    reader's own memory, not just the file. Pinned by the RSS-bounded
    test in core/coverage/tests/test_journal_containment.py.
    """
    row_warnings = 0
    corrupt = 0
    # Fresh per CALL: the read budget bounds what one consume call
    # may take (CPU/IO on a hostile plant, a writer growing the file
    # mid-read) — the historical per-call semantics, so an extension
    # gets a full budget for its delta.
    read_budget = _READ_BUDGET_MULTIPLIER * _MAX_JOURNAL_BYTES

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

    entries = state.entries
    sizes = state.sizes
    try:
        while True:
            # Bounded readline: a plain ``for line in fh``
            # materialised one multi-GiB line whole before any
            # budget check fired. readline(cap + 1) bounds the
            # worst case to one capped chunk; the read budget arm
            # of the min() keeps that chunk within what the loop
            # is still allowed to consume at all.
            line_cap = min(_MAX_JOURNAL_LINE_BYTES, read_budget)
            line = fh.readline(line_cap + 1)
            if not line:
                break
            state.line_no += 1
            state.at_line_boundary = line.endswith(b"\n")
            read_budget -= len(line)
            if len(line) > line_cap and not line.endswith(b"\n"):
                # Over-long line: quarantine the ROW and stream
                # past it in bounded chunks (never buffer it).
                skipped, budget_hit, at_newline = _discard_to_newline(
                    fh, read_budget)
                read_budget -= skipped
                state.at_line_boundary = at_newline
                corrupt += 1
                _row_warning(
                    "journal: skipping over-long line %d in %s "
                    "(exceeds the %d byte per-line bound)",
                    state.line_no + 1, journal_path, line_cap,
                )
                if budget_hit or read_budget <= 0:
                    state.reason = (
                        f"read budget "
                        f"({_READ_BUDGET_MULTIPLIER}x"
                        f"{_MAX_JOURNAL_BYTES} bytes) exhausted"
                    )
                    break
                continue
            if read_budget <= 0:
                # Also covers a writer growing the file mid-read:
                # the loop consumes at most the read budget no
                # matter what st_size claimed at open.
                state.reason = (
                    f"read budget ({_READ_BUDGET_MULTIPLIER}x"
                    f"{_MAX_JOURNAL_BYTES} bytes) exhausted"
                )
                break
            raw_len = len(line)
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
                    state.line_no + 1, journal_path,
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
                    state.line_no + 1, type(raw).__name__,
                )
                continue
            try:
                entries.append(_entry_from_dict(raw))
                sizes.append(raw_len)
                state.retained_bytes += raw_len
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
                    state.line_no + 1, exc,
                )
                continue
            if (state.retained_bytes > _MAX_JOURNAL_BYTES
                    or len(entries) > _MAX_RETAINED_ENTRIES):
                # Over the retained budget: prune duplicate
                # re-emission rows in place (lossless — newest per
                # identity, zero-cost rows only) and continue only
                # with >=10% headroom back, so repeated prunes
                # amortize instead of running per row.
                freed_rows, freed_bytes = _prune_reemission_rows(
                    entries, sizes)
                state.pruned += freed_rows
                state.retained_bytes -= freed_bytes
                if (state.retained_bytes * 10 > _MAX_JOURNAL_BYTES * 9
                        or len(entries) * 10
                        > _MAX_RETAINED_ENTRIES * 9):
                    state.reason = (
                        "retained-entry budget exceeded "
                        f"({len(entries)} rows / "
                        f"{state.retained_bytes} "
                        "bytes retained; duplicate pruning freed "
                        "too little)"
                    )
                    break
    except OSError as exc:
        # Read failure mid-iteration (EIO): keep whatever already
        # loaded (degrade, never propagate) and warn.
        logger.warning(
            "journal: failed to read %s: %s", journal_path, exc,
        )
        state.io_error = True
        state.reason = state.reason or f"read failed: {exc}"
    if corrupt:
        # THIS call's quarantined lines: an extension must not
        # re-warn for lines a prior call already reported.
        logger.warning(
            "journal: skipped %d corrupt line(s) in %s "
            "(%d entries loaded)",
            corrupt, journal_path, len(entries),
        )
    state.corrupt_total += corrupt


def _finalize_set(
    out_dir: Path,
    cache_key: str,
    states: list[_ShardLoadState],
    *,
    snapshot: "frozenset[str] | None" = None,
    warned_pruned: int = 0,
) -> JournalLoad:
    """Aggregate the shard states into one JournalLoad, emit the
    set-level warnings, and store/drop the cache record. Caller holds
    ``_load_cache_lock``.

    *warned_pruned* is the prune count the popped predecessor record
    already disclosed (0 on a cold parse — a new cache generation
    always warns its full count): the prune warning fires only for
    rows BEYOND it (see ``_CachedLoad.warned_pruned``).

    The cross-shard final dedup runs on a COPY of the concatenated
    lists, so the cached per-shard states always stay the pristine
    in-stream parse state — that is what keeps a later extension
    equal to a cold parse (the pass that rewrites the result never
    contaminates the state the extension resumes from).
    """
    incomplete_reason: str | None = None
    anomalous = False
    for i, state in enumerate(states):
        if state.missing:
            anomalous = True
            if len(states) > 1:
                # Numbered shards exist but this one is gone: rows
                # were lost, not never written.
                incomplete_reason = incomplete_reason or (
                    f"journal shard {state.name} is missing from a "
                    f"multi-shard journal"
                )
            continue
        if state.refused or state.io_error:
            anomalous = True
        if state.reason and incomplete_reason is None:
            incomplete_reason = (
                f"{state.name}: {state.reason}" if i else state.reason
            )
    orphans = _orphan_shard_names(out_dir, len(states), snapshot=snapshot)
    if orphans:
        # Anomalous by definition; also never served through the
        # cache (the serve path re-checks orphans per call), so
        # cached and cold behavior stay identical under a plant.
        anomalous = True
        if incomplete_reason is None:
            incomplete_reason = (
                "non-contiguous journal shard file(s) "
                f"{', '.join(orphans)} — an interior shard was deleted"
            )
    entries: list[ReviewJournalEntry] = []
    sizes: list[int] = []
    pruned_total = 0
    for state in states:
        entries.extend(state.entries)
        sizes.extend(state.sizes)
        pruned_total += state.pruned
    if pruned_total or len(states) > 1:
        # Final pass so the load is FULLY deduplicated across shard
        # boundaries too (single-shard loads without any budget
        # crossing keep their historical row-for-row output). Runs
        # on the freshly-concatenated lists — never on the cached
        # per-shard state (see the docstring).
        freed_rows, _freed = _prune_reemission_rows(entries, sizes)
        pruned_total += freed_rows
    if pruned_total > warned_pruned:
        # Once per cache generation, then delta-only: an extension
        # finalize re-derives the same historical count, so re-warning
        # it verbatim on every consumer load is pure console noise
        # that scales with load frequency. New prunes beyond the
        # disclosed baseline still warn, with the cumulative count so
        # a growing duplicate problem stays visible. The prune itself
        # is unchanged either way.
        if warned_pruned:
            logger.warning(
                "journal: %s pruned %d NEW duplicate re-emission "
                "row(s) at load (%d total this load generation; "
                "newest per identity kept; no verdict or spend "
                "evidence lost); %s",
                out_dir / JOURNAL_FILENAME,
                pruned_total - warned_pruned, pruned_total,
                compact_hint(out_dir),
            )
        else:
            logger.warning(
                "journal: %s exceeded the retained-entry budget or "
                "spans shards — pruned %d duplicate re-emission "
                "row(s) at load (newest per identity kept; no "
                "verdict or spend evidence lost); %s",
                out_dir / JOURNAL_FILENAME, pruned_total,
                compact_hint(out_dir),
            )
    if incomplete_reason:
        logger.warning(
            "journal: PARTIAL load of %s — %s (%d entries loaded); "
            "read-only consumers degrade, spend-authorizing consumers "
            "refuse; %s",
            out_dir / JOURNAL_FILENAME, incomplete_reason, len(entries),
            compact_hint(out_dir),
        )
    complete = incomplete_reason is None
    cacheable = not anomalous and all(s.pin_ok for s in states)
    if cacheable:
        _cache_store(cache_key, _CachedLoad(
            shard_states=states,
            complete=complete,
            reason=incomplete_reason,
            pruned_total=pruned_total,
            result_entries=entries,
            extensible=complete and states[-1].at_line_boundary,
            config=_loader_config(),
            # Everything up to pruned_total is now disclosed; max()
            # is belt-and-braces (append-only bytes cannot lower the
            # re-derived count, but a lower one must never re-arm a
            # warning already emitted).
            warned_pruned=max(warned_pruned, pruned_total),
        ))
    else:
        # Uncacheable outcome (missing/refused shard, I/O degrade,
        # orphan anomaly, EOF race): a stale prior record for this
        # run dir must not survive it.
        _load_cache.pop(cache_key, None)
    return JournalLoad(
        # Copy: the record keeps ``entries`` as its served result and
        # callers own their lists (uniform aliasing contract).
        entries=list(entries),
        complete=complete,
        pruned=pruned_total,
        reason=incomplete_reason,
    )


def _discard_to_newline(
    fh: IO[bytes], budget: int,
) -> tuple[int, bool, bool]:
    """Stream past the remainder of an over-long line in bounded
    chunks. Returns ``(bytes_consumed, budget_hit, at_newline)`` —
    *at_newline* reports whether the discard ended at a line
    terminator (EOF inside the over-long line leaves the stream
    mid-line, which the load cache must know: state ending mid-line
    is never extensible)."""
    consumed = 0
    chunk_cap = 1 << 20
    while budget - consumed > 0:
        chunk = fh.readline(min(chunk_cap, budget - consumed))
        if not chunk:
            return consumed, False, False   # EOF mid-line
        consumed += len(chunk)
        if chunk.endswith(b"\n"):
            return consumed, False, True
    return consumed, True, False


def _reemission_identity(entry: ReviewJournalEntry) -> tuple | None:
    """Load-prune identity for a duplicate re-emission row, or None
    when the row must never prune.

    A resume-segment chain re-emits every reused verdict as a fresh
    ``reused=true`` row per segment (per-segment completeness — see
    ``core.audit.verdict_reuse``), so identical rows dominate a long
    run's journal. Prunable rows are exactly the ones whose loss is
    provably invisible to every consumer once a NEWER identical row
    survives:

    * ``reused`` only — live reviews, corrections, echoes never prune;
    * zero-cost only — ``journal_spend_usd`` sums per-row ``cost_usd``,
      so a $-bearing row is spend evidence and always survives;
    * no ``validate_verdict``/``lesson`` — survival stats and FP
      feedback read those fields from non-latest rows;
    * never ``finding``/``suspicious`` — claim rows keep every
      emission (re-validation sweeps can stamp differing evidence);
    * never ``provisional`` — not a settled verdict.

    The identity spans every field the per-key consumers key on
    (``key`` carries the edge suffix; ``line_start`` the site).
    """
    if not entry.reused or entry.cost_usd:
        return None
    if entry.validate_verdict or entry.lesson or entry.provisional:
        return None
    if entry.verdict in ("finding", "suspicious"):
        return None
    return (
        entry.key, entry.line_start or 0, entry.source_hash,
        entry.verdict, entry.model or "",
        _canonical_strategy_hash(entry.strategies),
    )


def _prune_reemission_rows(
    entries: list[ReviewJournalEntry],
    sizes: list[int],
) -> tuple[int, int]:
    """Drop all-but-the-NEWEST duplicate re-emission row per identity,
    in place, preserving order. Returns ``(rows_freed, bytes_freed)``.

    "Newest" is the row the latest-wins consumers elect: strict
    ``entry.ts > winner.ts``, first-in-file winning a ``ts`` tie
    (matching :func:`latest_entries` and ``merge_into_index``).
    Election is by ``ts``, never file position, so the prune is
    invisible to the per-key latest election even when re-emission
    ``ts`` order disagrees with append order (journals merged from
    concurrent segments, foreign appenders): keeping a lower-``ts``
    twin while dropping the group's max-``ts`` one could otherwise
    hand the key's election to a DIFFERENT, non-pruned row sitting
    between the twins' timestamps. The rows this prune folds are
    zero-cost reused re-emissions whose identity pins every
    verdict-relevant field (key, site, source hash, verdict, model,
    strategy hash), so surviving twins differ only in non-identity
    fields.
    """
    idents = [_reemission_identity(entry) for entry in entries]
    winner: dict[tuple, tuple[str, int]] = {}
    for idx, ident in enumerate(idents):
        if ident is None:
            continue
        prev = winner.get(ident)
        if prev is None or entries[idx].ts > prev[0]:
            winner[ident] = (entries[idx].ts, idx)
    winning = {idx for _ts, idx in winner.values()}
    keep = [True] * len(entries)
    freed_rows = 0
    freed_bytes = 0
    for idx, ident in enumerate(idents):
        if ident is None or idx in winning:
            continue
        keep[idx] = False
        freed_rows += 1
        freed_bytes += sizes[idx]
    if freed_rows:
        entries[:] = [e for e, k in zip(entries, keep) if k]
        sizes[:] = [s for s, k in zip(sizes, keep) if k]
    return freed_rows, freed_bytes


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
    entry = _entry_from_validated(raw, _ls, _le, version)
    _stash_raw_form(entry, raw)
    return entry


def _stash_raw_form(entry: ReviewJournalEntry, raw: dict[str, Any]) -> None:
    """Stash raw-form provenance evidence on a freshly loaded entry.

    When the persisted row carries keys this checkout's dataclass does
    not know, the ``entry.to_dict()`` round-trip is LOSSY — a token
    minted over the persisted bytes can never verify over the
    projection, so projection-only verification reads the honest row
    as tampered (the mass-demotion class: a follow-on audit of a large
    C codebase forfeited 1,490 paid verdicts this way). Stash the
    persisted row's canonical hash plus the extra key names as
    :data:`journal_mac.RAW_FORM_ATTR`; ``entry_provenance_detail``
    uses them as the raw-form ladder rung, bounded by the shipped
    generation vocabulary. Attribute-only (never a dataclass field):
    it attests the AS-LOADED bytes and must not survive ``replace`` /
    ``asdict`` copies, whose content is no longer those bytes.
    """
    extra = frozenset(raw) - _ENTRY_FIELD_NAMES
    if not extra:
        return
    from core.coverage import journal_mac
    if not raw.get(journal_mac.TOKEN_KEY):
        return
    setattr(
        entry,
        journal_mac.RAW_FORM_ATTR,
        (journal_mac.row_sha256(raw), extra),
    )


def _entry_from_validated(
    raw: dict[str, Any],
    _ls: int,
    _le: int | None,
    version: int,
) -> ReviewJournalEntry:
    return ReviewJournalEntry(
        ts=raw["ts"],
        run_id=raw["run_id"],
        file=raw["file"],
        function=raw["function"],
        function_qualified=raw.get("function_qualified"),
        verdict=raw["verdict"],
        source_hash=raw.get("source_hash", ""),
        run_path=raw.get("run_path"),
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
        seed_provenance=raw.get("seed_provenance"),
        seed_rereview=raw.get("seed_rereview"),
        provisional=raw.get("provisional"),
        domain_slice_hash=raw.get("domain_slice_hash"),
        integrity=raw.get("integrity"),
        body_offload=raw.get("body_offload"),
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
      itself as reviewed;
    * ``[mechanical]`` echo rows (:func:`is_mechanical_echo`) —
      post-loop pattern-scan findings journalled for cross-layer
      visibility. No review examined the function, so a durable mark
      would read it as reviewed in every store-derived view
      (including the gap-audit residual) and silently retire it from
      review scheduling;
    * agent-context ``--mark`` assertions (:func:`is_agent_mark`) —
      review-grade marks are operator-tier; a non-operator context's
      assertion carries no evidence gate and must not retire the
      function from review.

    Same direction as :func:`reviewed_set`, but stricter: the two
    differ on edge rows (see its docstring) AND on the last two
    screens — ``reviewed_set`` keeps mechanical echoes and agent
    marks. That is deliberate scope, not drift: ``reviewed_set`` is a
    raw "did this run's journal already record this key" lookup (its
    one production consumer is verdict-reuse's per-pass idempotence
    guard, where an echo/mark row still means the key was journalled
    this run), never a coverage authority. Every lane that projects
    rows into durable coverage or review-retirement must screen
    through THIS predicate.
    """
    return (
        entry.verdict not in ("error", "dark")
        and not entry.edge_callee
        and not is_mechanical_echo(entry)
        and not is_agent_mark(entry)
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

#: Witness-backlog drain entries (``raptor-audit backlog drain``
#: journaling a synthesized-checker receipt for ONE parked dark
#: hypothesis). Finding-grade like /agentic and /validate entries: a
#: mechanical witness for a single hypothesis is evidence at that
#: site, never a function review — drain rows must not suppress audit
#: gaps, fold into coverage, or be reused as $0 verdicts. Only
#: stamped explicitly by the drain writer.
PRODUCER_BACKLOG_DRAIN = "backlog-drain"

#: Producers whose entries record per-FINDING work, not function
#: reviews. Everything else (audit, unknown-but-legacy) is
#: function-grade.
_FINDING_GRADE_PRODUCERS = frozenset({
    PRODUCER_AGENTIC,
    PRODUCER_VALIDATE,
    PRODUCER_BACKLOG_DRAIN,
})

#: Machine-generated run-id shapes that identify /agentic-side
#: producers for legacy entries written before the ``producer`` field
#: was stamped: the bare tool name; the tool name followed by a
#: separator and a digit (timestamp-first dirs, both the project-mode
#: hyphen and standalone underscore spellings); or the standalone
#: target-bearing shape ``command_target_YYYYMMDD_HHMMSS[...]``
#: (core.run.output: ``{command}_{target}_{unique_run_suffix}``). A
#: bare ``startswith`` demoted every review in a hand-named dir like
#: ``scan-of-x`` to finding-grade; requiring a machine shape keeps
#: the heuristic to the names the launcher actually generated.
#: Trade-off: a legacy pre-field /agentic run under a hand-picked
#: non-machine name now classifies audit/function-grade — narrower
#: exposure (custom-named legacy agentic runs) than the previous
#: blanket demotion of every scan*/agentic* operator name, and modern
#: rows carry the explicit field either way.
_AGENTIC_RUN_ID_RE = re.compile(
    r"^(?:agentic|scan)"
    r"(?:$"                                       # bare tool name
    r"|[-_]\d.*$"                                 # timestamp-first
    r"|_.+_\d{8}_\d{6}(?:_pid\d+)?(?:_\d+)?$"     # _target_timestamp
    r")"
)


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
    if _AGENTIC_RUN_ID_RE.match(run_id):
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


def _latest_collapse(
    entries: Iterable[ReviewJournalEntry],
) -> dict[str, ReviewJournalEntry]:
    """Latest-per-``entry.key`` collapse over pre-loaded *entries*:
    strict ``>`` on ``entry.ts``, first-in-file winning ties — THE
    tie-break convention (see :func:`latest_entries`), shared by the
    fresh path, the memoized view build, and the incremental
    extension fold's equivalence oracle so they cannot drift."""
    best: dict[str, ReviewJournalEntry] = {}
    for entry in entries:
        existing = best.get(entry.key)
        if existing is None or entry.ts > existing.ts:
            best[entry.key] = entry
    return best


def latest_entries(
    out_dir: Path, *, fresh: bool = False,
) -> dict[str, ReviewJournalEntry]:
    """Return the most recent entry per ``file:function`` key.

    Uses strict ``>`` on ``entry.ts`` (a microsecond-precision UTC
    ISO string emitted by :func:`now_iso`). Two entries can only
    tie if written within the same microsecond, which never happens
    for sequential Python appends — so first-in-file wins on the
    theoretically-possible tie, matching :func:`merge_into_index`
    and preserving idempotent-merge semantics.

    Served from the load cache's memoized latest-per-key view when
    the run dir's record is current: the collapse runs once per
    cached parse (built lazily here, carried incrementally across
    active-shard extensions by :func:`_carry_latest_view`), so
    per-function consumers — the audit context builder calls this
    twice per reviewed function — pay one view-sized dict copy per
    call instead of re-collapsing the whole journal. The maintained
    view always equals a from-scratch collapse of the same served
    load (pinned by the differential-equivalence test in
    core/coverage/tests/test_journal_latest_view.py). The returned
    dict is the caller's own; the entry objects are shared and
    frozen by contract, matching :func:`load_entries`.

    ``fresh`` threads through to :func:`load_entries` for callers on
    the spend/resume side (drift computation) that must never read
    the process-local load cache — the fresh path collapses its own
    fresh parse and never touches the memoized view.
    """
    if fresh:
        return _latest_collapse(load_entries(out_dir, fresh=True))
    out_dir = Path(out_dir)
    cache_key = os.path.realpath(out_dir)
    with _load_cache_lock:
        loaded = _load_checked_locked(out_dir, cache_key, fresh=False)
        record = _load_cache.get(cache_key)
        if record is not None and record.result_entries is not None:
            # The record at this key was stored/refreshed by the load
            # above under this same lock hold, so its memoized result
            # IS the served view. (A record shed by that store has no
            # memoized result — fall through to a transient collapse
            # that pins nothing.)
            if record.latest_view is None:
                record.latest_view = _latest_collapse(
                    record.result_entries)
                record.latest_view_ts_max = max(
                    (e.ts for e in record.latest_view.values()),
                    default="",
                )
            return dict(record.latest_view)
    return _latest_collapse(loaded.entries)


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


def _row_provenance_ok(row: Any) -> bool:
    """True when a raw row carries a token that verifies over the
    row's own content — i.e. the exact dict a fold would read back.

    Replacement authority for the merge's same-``ts`` repair
    tie-break: verification requires THIS install's MAC key, so a
    planted row (archive import, hand-edited index) can never satisfy
    it. Tokenless and non-dict rows read False — no valid token, no
    replacement authority, and no repair TARGET status either (see
    the merge loop: only a verifying incoming row may replace, and
    only a non-verifying stored row may be replaced).
    """
    from core.coverage import journal_mac
    if not isinstance(row, dict):
        return False
    token = row.get(journal_mac.TOKEN_KEY)
    if not isinstance(token, str) or not token:
        return False
    return journal_mac.verify_row(row, token)


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


def _verdict_tally(entries: Iterable[ReviewJournalEntry]) -> dict[str, int]:
    """Verdict counts with a bounded key space: anything outside
    ``VALID_VERDICTS`` buckets as ``other`` (journal rows arrive via
    archive import — a hostile run must not mint one tally key per
    row)."""
    tally: dict[str, int] = {}
    for e in entries:
        v = e.verdict if e.verdict in VALID_VERDICTS else "other"
        tally[v] = tally.get(v, 0) + 1
    return tally


def _aggregate_overflow(
    overflow: list[ReviewJournalEntry],
) -> dict[str, Any]:
    """Roll the identities a merge could not carry as full rows into
    one bounded aggregate record.

    Granularity cascades so the record itself can never blow up:
    per-file rollups first; over ``_MAX_ROLLUP_ROWS`` distinct files,
    per-top-level-directory; over the cap again, a single total row.
    Each rollup carries the identity count, a verdict tally, and the
    ts span — every group PARTITIONS the overflow, so the summed
    ``identities`` equals the overflow size at any granularity (count
    conservation, pinned by test).
    """
    def rows_for(
        key_of: Callable[[ReviewJournalEntry], str], scope: str,
    ) -> list[dict[str, Any]]:
        groups: dict[str, list[ReviewJournalEntry]] = {}
        for e in overflow:
            groups.setdefault(key_of(e), []).append(e)
        return [
            {
                "scope": scope,
                # Truncation is display-only (grouping used the full
                # path): journal rows are attacker-influencable and a
                # megabyte file name must not ride into the index.
                "path": path[:_AGGREGATE_PATH_CHARS],
                "identities": len(group),
                "verdicts": _verdict_tally(group),
                "oldest_ts": min(e.ts for e in group),
                "newest_ts": max(e.ts for e in group),
            }
            for path, group in sorted(groups.items())
        ]

    granularity = "file"
    rows = rows_for(lambda e: e.file, "file")
    if len(rows) > _MAX_ROLLUP_ROWS:
        granularity = "dir"
        rows = rows_for(
            lambda e: e.file.split("/", 1)[0], "dir")
    if len(rows) > _MAX_ROLLUP_ROWS:
        granularity = "total"
        rows = rows_for(lambda e: "", "total")
    return {
        "ts": now_iso(),
        "identities": len(overflow),
        "granularity": granularity,
        "rollups": rows,
        "reason": (
            f"run exceeded the {_MAX_MERGE_ENTRIES}-identity merge "
            "cap; these identities reached the index as aggregates "
            "only (the run journal keeps every row)"
        ),
    }


def _aggregate_run_key(run_dir: Path) -> str:
    """Aggregates-section key for a merged run journal: the run dir's
    last two path segments (``<run>/autonomous`` subdir merges stay
    distinct from the run root's)."""
    run_dir = Path(run_dir)
    return f"{run_dir.parent.name}/{run_dir.name}"


# Minimum serialized payload (bytes across the offloadable fields)
# before the index write boundary slims a row. Trade-off, both
# directions: too low and the stub pointer (~250 serialized bytes)
# exceeds the savings — slimming short-prose rows GROWS the index;
# too high and mid-sized prose rows keep their fat inline, eroding
# the bounded-row arithmetic the merge-entry cap rests on (a
# below-floor eligible row serializes to at most roughly its slim
# base plus this floor). Half the run-side compactor's floor
# (``journal_compact._SLIM_MIN_OFFLOAD_BYTES``): the index slim
# writes no sidecar record, so break-even sits at the pointer size
# alone.
_INDEX_SLIM_MIN_BYTES = 512


def _slim_index_row(row: dict[str, Any]) -> dict[str, Any] | None:
    """Slimmed replacement for an index *row*, or ``None`` to keep it.

    The project index is a cross-run VERDICT store, not a prose
    archive: the producing run journal keeps every row whole, and on
    a real mega-project index ~90% of the bytes sat in cold prose no
    index consumer needs inline (``body``, ``hypotheses``, the
    per-row domain-snapshot lists). Dropping those fields at the
    write boundary is what keeps a merge-cap-sized index under the
    write budget; because the merge rewrites the whole document,
    already-written fat rows slim on their next pass through the
    same chokepoint.

    Eligibility mirrors the run-side slim tier
    (``journal_compact._slim_eligible`` — same consumers, one
    analysis): only settled non-claim verdicts (``clean`` /
    ``dormant``); no corrections or feedback
    (``validate_verdict`` / ``lesson``); never provisional; never
    edge-contract rows (small, and the edge re-review suppressor
    requires their original token to keep verifying); never
    mechanical echoes (the body PREFIX is their single
    counting/coverage rule); never finding-grade producer rows
    (prior-claims context injection quotes their bodies of EVERY
    verdict); never spend carriers; never an already-offloaded stub
    (idempotence). Rows whose offloadable payload is below
    ``_INDEX_SLIM_MIN_BYTES`` stay whole, and rows the reader's own
    parse quarantines stay whole (consumers skip them anyway).

    The replacement is a loader-valid stub: fat fields cleared plus
    a ``body_offload`` pointer in the ``journal_sidecar`` shape with
    an EMPTY sidecar name — there is no sidecar route from the
    project dir, and every pointer-resolution failure already
    degrades to the stub view. Stub-aware consumers therefore treat
    index stubs through their existing arms: the $0 reuse import
    renders the offload marker instead of prose, and the
    context-staleness gate hydrate-fails toward re-review only when
    the domain-model hash actually changed (a hash-fresh row
    short-circuits before ever needing the offloaded lists).

    MAC discipline — authenticate-then-re-attest, never upgrade
    (the run-side slim's contract): a row whose token VERIFIES and
    whose content round-trips this reader's dataclass exactly is
    rebuilt through the dataclass and freshly stamped, so the stub
    keeps verified-tier authority ($0 verdict reuse, edge
    suppression); anything else keeps its original token field
    verbatim — unstamped stays unstamped, token-invalid stays
    tampered — because the merge must never mint over content it
    could not verify. A mint failure (no usable key) only demotes
    the stub to the unstamped tier, the safe direction.
    """
    from core.coverage import journal_mac
    from core.coverage.journal_compact import is_spend_carrier
    from core.coverage.journal_sidecar import OFFLOAD_FIELDS, fields_sha256

    if row.get("body_offload"):
        return None
    if row.get("verdict") not in ("clean", "dormant"):
        return None
    if (row.get("validate_verdict") or row.get("lesson")
            or row.get("provisional") or row.get("edge_callee")):
        return None
    extracted = {f: row[f] for f in OFFLOAD_FIELDS if row.get(f)}
    if not extracted:
        return None
    payload_len = sum(
        len(json.dumps(v, separators=(",", ":"), default=str))
        for v in extracted.values())
    if payload_len < _INDEX_SLIM_MIN_BYTES:
        return None
    try:
        entry = _entry_from_dict(row)
    except Exception:  # noqa: BLE001 — quarantined rows never slim
        return None
    if (not is_function_grade(entry) or is_mechanical_echo(entry)
            or is_spend_carrier(entry)):
        return None

    pointer: dict[str, Any] = {
        "sidecar": "",
        "offset": 0,
        "bytes": 0,
        "sha256": fields_sha256(extracted),
        "fields": sorted(extracted),
    }
    token = row.get(journal_mac.TOKEN_KEY)
    roundtrip = entry.to_dict()
    dataclass_shaped = (
        {k: v for k, v in row.items() if k != journal_mac.TOKEN_KEY}
        == {k: v for k, v in roundtrip.items()
            if k != journal_mac.TOKEN_KEY})
    if (isinstance(token, str) and token and dataclass_shaped
            and journal_mac.verify_row(row, token)):
        cleared: dict[str, Any] = {
            f: ("" if f == "body" else []) for f in extracted}
        stub_entry = replace(
            entry, integrity=None, body_offload=pointer, **cleared)
        slim = stub_entry.to_dict()
        slim.pop(journal_mac.TOKEN_KEY, None)
        fresh = journal_mac.mint_row(slim)
        if fresh:
            slim[journal_mac.TOKEN_KEY] = fresh
        return slim
    slim = dict(row)
    for f in extracted:
        slim[f] = "" if f == "body" else []
    slim["body_offload"] = pointer
    return slim


def _journal_read_problem(out_dir: Path, load: JournalLoad) -> bool:
    """True when a journal load's emptiness/incompleteness signals a
    read failure rather than a genuinely empty journal.

    The loader degrades every failure shape to an empty (or partial)
    entry list plus a log line: a refused open (permissions, journal
    path is a directory) surfaces as ``complete=False``; fully
    malformed content surfaces as zero entries from a non-empty file.
    An absent journal or a zero-byte file is NOT a problem — those
    are the normal "nothing recorded" shapes.
    """
    if not load.complete:
        return True
    if load.entries:
        return False
    journal_path = out_dir / JOURNAL_FILENAME
    try:
        return journal_path.is_file() and journal_path.stat().st_size > 0
    except OSError:
        return True


def merge_into_index(project_dir: Path, run_dir: Path, *,
                     stats: dict[str, int] | None = None) -> int:
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

    A run whose distinct identities exceed ``_MAX_MERGE_ENTRIES``
    merges the newest cap-full as full rows; the older identities
    roll up into the index's bounded ``aggregates`` section
    (:func:`_aggregate_overflow`) — counts and verdict tallies reach
    the index, per-identity detail stays in the run journal. The
    same degradation guards BYTES: a merge whose document would
    exceed the merge write ceiling (the read budget minus an
    aggregates reserve) sheds its oldest incoming identities to the
    aggregates section — restoring any prior rows they displaced —
    until the write fits, so a fat run degrades to disclosure
    instead of freezing the index for the whole project. Unlike the
    deterministic count cap, byte eviction depends on the index's
    current headroom, so a merge that writes with NO overflow drops
    this run's own prior disclosure record (refreshing it when the
    eviction arm fires again) — re-merging a run dir converges the
    disclosure to the index as written instead of preserving a
    stale "aggregates only" claim about rows that since landed.

    Rows are slimmed at the write boundary (:func:`_slim_index_row`):
    eligible settled rows drop their cold prose fields for an offload
    stub, existing fat rows included — the merge rewrites the whole
    document, so the on-disk index converges to slim rows without a
    separate migration.

    Returns the number of entries merged (new or updated); rollup
    aggregates do not count.

    ``stats`` (optional out-param) receives the merge's strip/heal
    disclosures as counts — the same events the log lines report,
    which the return value alone cannot distinguish (a healed row
    counts as merged). Accumulated with ``+=`` under the caller's
    keys (``"stripped"``, ``"healed"``), so one dict threads through
    many merges (the project-wide reindex sweep aggregates per-run
    and total counts this way). ``"unreadable"`` counts journal
    locations whose read failed or yielded no rows despite non-empty
    content — the loader degrades those to a logged warning and an
    empty list, which the ``0`` return alone cannot distinguish from
    a genuinely empty journal.
    """
    # fresh=True: this merge writes the DURABLE project index that
    # cross-run verdict reuse imports at $0 — durable authority never
    # trusts the process-local load cache. One fresh parse per run
    # completion is negligible at this boundary.
    load = load_entries_checked(run_dir, fresh=True)
    run_entries = load.entries
    if stats is not None and _journal_read_problem(run_dir, load):
        stats["unreadable"] = stats.get("unreadable", 0) + 1
    if not run_entries:
        return 0
    if len(run_entries) > _MAX_MERGE_ENTRIES:
        # Collapse to the newest row per index_key BEFORE the cap:
        # the merge below is latest-wins per index_key, so a
        # non-latest sibling can never change the outcome — dropping
        # it here is lossless. The previous raw newest-N truncation
        # let duplicate re-emission rows (newest, per-segment
        # completeness) crowd distinct identities' ONLY rows out of
        # the window, so their verdicts silently never reached the
        # project index. Tie on ts keeps the first-in-file row,
        # matching the merge's strict-``>`` convention.
        collapsed: dict[str, ReviewJournalEntry] = {}
        for e in run_entries:
            k = e.index_key
            prev = collapsed.get(k)
            if prev is None or e.ts > prev.ts:
                collapsed[k] = e
        run_entries = list(collapsed.values())
    overflow: list[ReviewJournalEntry] = []
    if len(run_entries) > _MAX_MERGE_ENTRIES:
        run_entries = sorted(run_entries, key=lambda e: e.ts)
        overflow = run_entries[:-_MAX_MERGE_ENTRIES]
        run_entries = run_entries[-_MAX_MERGE_ENTRIES:]
        logger.warning(
            "journal: run %s carries %d distinct entry identities — "
            "merging the newest %d as full rows; the OLDEST %d "
            "identities reach the project index as rollup aggregates "
            "only (per-file/per-directory counts and verdict tallies "
            "in the index's 'aggregates' section; the run journal "
            "keeps every row)",
            run_dir, len(run_entries) + len(overflow),
            _MAX_MERGE_ENTRIES, len(overflow))

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

        from core.coverage import journal_mac

        # A transient MAC-key outage (unreadable or wrongly-
        # permissioned key file, a different XDG_DATA_HOME) makes
        # EVERY verify fail without saying anything about the rows —
        # stripping then would durably unstamp honest tokens that
        # verify the moment the key is back. Under an unusable key
        # the merge carries tokens verbatim (the pre-rule posture,
        # which self-heals on restore); folds already demote
        # unverifiable rows transiently and safely.
        key_ok = journal_mac.key_usable()

        stripped = 0
        upgraded = 0
        healed = 0
        # Each merged key remembers the PRE-RUN value it displaced so
        # the byte-eviction arm below can RESTORE it: an evicted
        # incoming identity reaches the index as an aggregate, and the
        # prior on-disk history for that key stays a full row. One
        # slot per key ([newest entry, pre-run prior, rows counted])
        # — a run that merges several rows for the same key must
        # restore the value from BEFORE the run, not an intermediate.
        merged_rows: dict[str, list[Any]] = {}
        for entry in run_entries:
            key = entry.index_key
            row = entry.to_dict()
            token = row.get(journal_mac.TOKEN_KEY)
            if key_ok and token:
                if not journal_mac.verify_row(row, token):
                    # A token is persisted ONLY with content it
                    # verifies over. The dataclass round-trip above is
                    # lossy for any journal field this checkout's
                    # schema does not know (version skew: a newer
                    # writer stamped a field — e.g. the slim-clean
                    # ``body_offload`` pointer — that an older merge
                    # silently drops), and a token carried verbatim
                    # over the reduced row makes every future fold
                    # read an HONEST row as tampered, permanently
                    # revoking its verdict-reuse authority. Strip the
                    # token instead: the row lands in the honest
                    # unstamped tier (exact-hash fold credit, no
                    # verdict reuse) — the same tier a failing token
                    # demotes to, minus the false tamper attribution
                    # and with repair possible (a later skew-free
                    # merge's verifying copy replaces it via the
                    # same-``ts`` tie-break below). Never re-mint over
                    # the reduced row instead: a re-stamped reduced
                    # copy would pass _row_provenance_ok and block
                    # that same-``ts`` heal forever — the strip is
                    # load-bearing for healability, not an
                    # optimization target.
                    row.pop(journal_mac.TOKEN_KEY, None)
                    stripped += 1
                elif (journal_mac.token_generation(token)
                        != journal_mac.GENERATION_CURRENT):
                    # Legacy-generation upgrade: the token verifies
                    # (same authority as a current-form token), so the
                    # index copy is re-stamped at the CURRENT
                    # generation — the ladder's live population
                    # shrinks at every merge instead of growing until
                    # a rung falls off. Only ever after a successful
                    # verify: re-stamping is a restatement of already-
                    # proven provenance, never a laundering of an
                    # unverified row. Mint failure (key outage mid-
                    # merge) keeps the verified legacy token — losing
                    # authority to an upgrade attempt would invert the
                    # feature.
                    fresh = journal_mac.mint_row(row)
                    if fresh:
                        row[journal_mac.TOKEN_KEY] = fresh
                        upgraded += 1
            existing = index.get(key)
            if existing is None or entry.ts > _row_ts(existing):
                slot = merged_rows.get(key)
                if slot is None:
                    merged_rows[key] = [entry, existing, 1]
                else:
                    slot[0] = entry
                    slot[2] += 1
                index[key] = row
                merged += 1
            elif (entry.ts == _row_ts(existing)
                    and _row_provenance_ok(row)
                    and not _row_provenance_ok(existing)):
                # Same-``ts`` repair tie-break. Strict latest-wins
                # kept a broken stored copy forever: a row whose
                # stamped field was dropped by a version-skewed merge
                # ties on ``ts`` with the intact run-journal row, so
                # the index could never heal from its own source of
                # truth. A row that verifies under this install's key
                # replaces a same-key, same-``ts`` copy that does not
                # (absent or failing token). Never fires across
                # timestamps — history is not rewound — and never
                # replaces a verifying row. Healed keys register in
                # ``merged_rows`` with the same slot discipline so the
                # byte-eviction arm restores their pre-run priors too.
                slot = merged_rows.get(key)
                if slot is None:
                    merged_rows[key] = [entry, existing, 1]
                else:
                    slot[0] = entry
                    slot[2] += 1
                index[key] = row
                healed += 1
                merged += 1

        if stripped:
            logger.warning(
                "journal: %d row(s) from %s carry a provenance token "
                "that does not verify over the merged row shape — "
                "token stripped, row(s) indexed unstamped (version "
                "skew: a reader on this checkout dropped a stamped "
                "field it does not know — or a foreign or edited "
                "token; exact-hash fold credit only until a "
                "skew-free merge re-projects them)",
                stripped, run_dir,
            )
        if upgraded:
            logger.info(
                "journal index: re-stamped %d row(s) from a legacy "
                "canonicalisation generation at the current "
                "generation (verified first; authority unchanged)",
                upgraded,
            )
        if healed:
            logger.info(
                "journal index: repaired %d row(s) whose stored copy "
                "failed provenance — replaced by the run journal's "
                "verifying copy at the same timestamp", healed,
            )
        if stats is not None:
            # Caller-visible mirror of the disclosures above, recorded
            # at the point they are logged. The byte-eviction arm
            # below sheds ROWS, never the strip/heal events that
            # already happened on the way in — so these counts always
            # match the log lines.
            stats["stripped"] = stats.get("stripped", 0) + stripped
            stats["healed"] = stats.get("healed", 0) + healed

        # Slim at the write boundary — incoming rows AND any fat rows
        # an earlier writer left behind (the merge rewrites the whole
        # document, so one pass converges the on-disk index; slimmed
        # rows re-enter as offload stubs and return None next time).
        slimmed = 0
        for key, row in index.items():
            if not isinstance(row, dict):
                continue   # planted non-object values stay in place
            slim = _slim_index_row(row)
            if slim is not None:
                index[key] = slim
                slimmed += 1
        if slimmed:
            logger.info(
                "journal index: slimmed %d row(s) at the write "
                "boundary (cold prose offloaded from the index; the "
                "producing run journals keep the full rows)", slimmed)

        aggregates: dict[str, Any] | None = None
        if overflow:
            # Read-modify-write inside the flock; ``None`` (the
            # no-overflow common case) tells the writer to preserve
            # whatever aggregates the file already carries.
            aggregates = _read_aggregates(index_path)
            aggregates[_aggregate_run_key(run_dir)] = (
                _aggregate_overflow(overflow))
        elif merged or rehomed or slimmed:
            # Byte eviction is STATE-dependent (the count cap is
            # deterministic, its record idempotently overwritten
            # above): a re-merge of the same run dir at more headroom
            # lands the previously-evicted identities as full rows,
            # and preserving the old disclosure would keep claiming
            # they "reached the index as aggregates only". A merge of
            # this run that writes with no count-cap overflow drops
            # the run's OWN prior record — other runs' records stay
            # untouched — and if the byte-eviction arm below fires
            # after all, it re-adds the key with the NEW counts, so
            # the disclosure always describes the index as written.
            prior_aggregates = _read_aggregates(index_path)
            if _aggregate_run_key(run_dir) in prior_aggregates:
                del prior_aggregates[_aggregate_run_key(run_dir)]
                aggregates = prior_aggregates

        if merged or rehomed or overflow or slimmed:
            # Merge write ceiling: the read budget minus a reserve for
            # the aggregates section (its own byte bound plus envelope
            # slack), floored at half the budget so scaled-down test
            # budgets keep a usable ceiling. A merge that fills the
            # index right up to the read budget would leave no room
            # for a FUTURE merge to even record its overflow
            # disclosure; under this ceiling, an aggregates-only
            # follow-up merge always fits — hostile floods can degrade
            # one run's rows to aggregates but can never freeze the
            # index. Module globals read at call time so tests can
            # scale them.
            ceiling = max(
                _MAX_JOURNAL_BYTES // 2,
                _MAX_JOURNAL_BYTES - _MAX_AGGREGATE_BYTES - (1 << 20),
            )
            pending = sorted(
                merged_rows.items(), key=lambda kv: kv[1][0].ts)
            evicted_total = 0
            attempts = 0
            while True:
                try:
                    _write_index(index_path, index,
                                 aggregates=aggregates, budget=ceiling)
                    break
                except IndexWriteOverBudget as e:
                    attempts += 1
                    if not pending:
                        # Nothing left to shed — the on-disk document
                        # was already over the ceiling before this run
                        # merged anything (or this merge added no
                        # rows). Same loud-refusal convention as
                        # IndexUnreadable: the index on disk stays
                        # readable AND writable (compaction included),
                        # and the run journal keeps every row — a
                        # refused merge loses nothing durable.
                        logger.error(
                            "journal: %s — run %s NOT merged (the run "
                            "journal keeps its rows)", e, run_dir)
                        # Engagement contact: when this project
                        # carries an artifact ledger, a frozen index
                        # merge is a governor-visible event (depth
                        # policy relies on journal verdicts reaching
                        # the index). Only THIS terminal refusal arm
                        # is contact: an eviction-resolved merge
                        # above still lands (disclosure recorded,
                        # counts conserved, re-merge at headroom
                        # re-lands full rows), and escalating on that
                        # designed degradation would burn the
                        # per-kind escalation bound on non-failures
                        # and mask a later genuine freeze. Best
                        # effort — the journal never grows a hard
                        # engagement dependency, and a project
                        # without a ledger is a no-op.
                        try:
                            from core.engagement.governor import (
                                record_escalation,
                            )
                            record_escalation(
                                project_dir,
                                kind="journal_index_over_budget",
                                message=str(e),
                            )
                        except Exception:
                            logger.debug(
                                "journal: governor escalation not "
                                "recorded", exc_info=True)
                        return 0
                    # Shed the OLDEST incoming identities until the
                    # estimated savings cover the overshoot (25%
                    # proportional slack for envelope drift — a fixed
                    # slack would over-shed at scaled-down test
                    # budgets), restoring each displaced prior row.
                    # Bounded retries: the terminal attempt sheds
                    # everything this run merged.
                    need = int(max(e.size - ceiling, 1) * 1.25) + 512
                    if attempts >= 8:
                        need = e.size
                    freed = 0
                    evicted: list[ReviewJournalEntry] = []
                    while pending and freed < need:
                        key, (entry, prior, counted) = pending.pop(0)
                        try:
                            freed += len(json.dumps(
                                index.get(key), indent=2, default=str))
                        except Exception:  # noqa: BLE001 — size estimate only
                            pass
                        if prior is None:
                            index.pop(key, None)
                        else:
                            if isinstance(prior, dict):
                                prior = _slim_index_row(prior) or prior
                            index[key] = prior
                            try:
                                freed -= len(json.dumps(
                                    prior, indent=2, default=str))
                            except Exception:  # noqa: BLE001 — size estimate only
                                pass
                        evicted.append(entry)
                        merged -= counted
                    evicted_total += len(evicted)
                    if aggregates is None:
                        aggregates = _read_aggregates(index_path)
                    overflow = overflow + evicted
                    aggregates[_aggregate_run_key(run_dir)] = (
                        _aggregate_overflow(overflow))
            if evicted_total:
                logger.warning(
                    "journal: index write for run %s exceeded the merge "
                    "byte ceiling (%d bytes) — the OLDEST %d merged "
                    "identities reach the project index as rollup "
                    "aggregates only (%d remain as full rows; the run "
                    "journal keeps every row)",
                    run_dir, ceiling, evicted_total, merged)

    return merged


def merge_run_into_index(project_dir: Path, run_dir: Path, *,
                         stats: dict[str, int] | None = None) -> int:
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

    Returns total entries merged. ``stats`` threads through to every
    :func:`merge_into_index` call (root and subdirs) — see there.
    """
    run_dir = Path(run_dir)
    merged = merge_into_index(project_dir, run_dir, stats=stats)
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
            merged += merge_into_index(project_dir, sub, stats=stats)
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
    """The serialized index would exceed the write ceiling — the write
    refuses so the ON-DISK index always stays readable. Writing past
    the read budget manufactured a permanently frozen index: every
    later read degraded to empty (accumulated history invisible) and
    every writer — including compaction, the in-band remedy — refused
    via :class:`IndexUnreadable`. The per-run merge-entry cap bounds
    row COUNT, not bytes (indent-2 re-serialization inflates
    list-heavy rows several-fold), so the byte bound must sit at the
    write. ``size`` carries the serialized document's byte count so
    the merge's eviction arm can size its response."""

    def __init__(self, message: str, size: int = 0) -> None:
        super().__init__(message)
        self.size = size


def _read_aggregates(path: Path) -> dict[str, Any]:
    """The index file's ``aggregates`` section (overflow rollups), or
    ``{}``. Degrades to empty on ANY failure: aggregates are
    disclosure metadata, never verdict authority — the fail-closed
    arms (:class:`IndexUnreadable` before a write,
    :class:`IndexWriteOverBudget` at it) belong to the entries."""
    from core.json.utils import load_json
    if not path.is_file():
        return {}
    try:
        data = load_json(path, strict=True, max_bytes=_MAX_JOURNAL_BYTES)
    except Exception:  # noqa: BLE001 — metadata containment boundary
        return {}
    if not isinstance(data, dict):
        return {}
    aggregates = data.get("aggregates", {})
    return aggregates if isinstance(aggregates, dict) else {}


def load_index_aggregates(project_dir: Path) -> dict[str, Any]:
    """Machine-readable overflow disclosure: one record per merged
    run journal whose distinct identities exceeded the merge cap
    (``{run_key: {ts, identities, granularity, rollups, reason}}``).
    Empty for projects that never overflowed."""
    return _read_aggregates(Path(project_dir) / INDEX_FILENAME)


def _bound_aggregates(aggregates: dict[str, Any]) -> dict[str, Any]:
    """Sanitation chokepoint for the aggregates section: every write
    passes through here, so the section is bounded on disk no matter
    which writer produced it (and no matter what an archive import
    planted in it).

    Drops malformed records, truncates rollup lists, keeps the
    newest ``_MAX_AGGREGATE_RECORDS`` records, then evicts LARGEST
    first until the section serializes under
    ``_MAX_AGGREGATE_BYTES`` — a single hostile giant record dies
    before it starves the honest ones. Unserializable records drop
    (aggregates are disclosure metadata; the entries' round-trip
    proof is :func:`_validate_serializable`).
    """
    from core.json.utils import dumps_artifact
    bounded: dict[str, Any] = {}
    for key, record in aggregates.items():
        if not isinstance(key, str) or not isinstance(record, dict):
            continue
        rollups = record.get("rollups")
        if (isinstance(rollups, list)
                and len(rollups) > _MAX_ROLLUP_ROWS):
            record = dict(record)
            record["rollups"] = rollups[:_MAX_ROLLUP_ROWS]
            record["rollups_truncated"] = True
        bounded[key[:_AGGREGATE_PATH_CHARS]] = record
    if len(bounded) > _MAX_AGGREGATE_RECORDS:
        newest = sorted(
            bounded.items(), key=lambda kv: _row_ts(kv[1]),
        )[-_MAX_AGGREGATE_RECORDS:]
        bounded = dict(newest)
    sizes: dict[str, int] = {}
    for key in list(bounded.keys()):
        try:
            sizes[key] = len(dumps_artifact(bounded[key]))
        except Exception:  # noqa: BLE001 — metadata containment boundary
            del bounded[key]
    while bounded and sum(sizes.values()) > _MAX_AGGREGATE_BYTES:
        largest = max(sizes, key=lambda k: sizes[k])
        del bounded[largest]
        del sizes[largest]
    return bounded


def _write_index(
    path: Path,
    entries: dict[str, dict[str, Any]],
    aggregates: dict[str, Any] | None = None,
    budget: int | None = None,
) -> None:
    """Atomic write of the index file, bounded by the read budget.

    Raises :class:`IndexWriteOverBudget` (file untouched) when the
    serialized document would exceed *budget* (default
    ``_MAX_JOURNAL_BYTES``, the read budget) — an index the writer
    cannot re-read is destroyed history, so it must never reach disk.
    The merge passes a LOWER ceiling that reserves aggregates
    headroom (see :func:`merge_into_index`); direct callers keep the
    hard read-budget backstop. Serialization matches
    :func:`core.json.save_json` (same encoder arms, newline, atomic
    tempfile + rename).

    *aggregates*: the overflow-rollup section. ``None`` (default)
    preserves whatever the on-disk file already carries, so writers
    that never think about aggregates (legacy migration) cannot
    silently destroy a prior overflow disclosure. Bounded via
    :func:`_bound_aggregates` either way; an EMPTY section is omitted
    entirely — the no-overflow document stays byte-identical to the
    pre-aggregates format.
    """
    from core.atomic_fs import write_text_atomically
    from core.json.utils import dumps_artifact

    if aggregates is None:
        aggregates = _read_aggregates(path)
    aggregates = _bound_aggregates(aggregates)
    index_data: dict[str, Any] = {
        "schema_version": INDEX_SCHEMA_VERSION,
        "updated_at": now_iso(),
        "entries": entries,
    }
    if aggregates:
        index_data["aggregates"] = aggregates
    content = dumps_artifact(index_data) + "\n"
    size = len(content.encode("utf-8"))
    limit = _MAX_JOURNAL_BYTES if budget is None else budget
    if size > limit:
        raise IndexWriteOverBudget(
            f"journal index at {path} would serialize to {size} bytes "
            f"(over the {limit} byte write ceiling; read budget "
            f"{_MAX_JOURNAL_BYTES}) — refusing to write an index past "
            "its own reader's budget",
            size=size,
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
    except Exception as exc:  # noqa: BLE001 — containment boundary
        # Fail CLOSED: the parent probe is the legacy pin-less
        # fallback, decided by the pin resolution itself (authoritative
        # False). An internal ERROR here must not re-open the
        # standalone-run foreign domain-model adoption the run pin
        # exists to prevent — no parent, no import.
        logger.warning(
            "run-pin resolution failed for %s (%s: %s); refusing the "
            "parent-dir domain-model probe", out_dir,
            type(exc).__name__, exc)
        return None


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
