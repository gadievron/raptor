"""Witness-backlog consumer — the static drain lane.

``/validate``'s findings import routes dark rows (hypotheses no tool
could adjudicate either way) into ``witness-backlog.json``; until now
nothing drained that queue. This module works it with NON-EXECUTING
witnesses only: the existing Mode-2 on-demand checker synthesis
(``checker_synthesis.synthesize_verification_rule``) is retargeted at
each dark row's stated hypothesis, and the synthesized rule's
mechanical controls are the only thing that can move a row.

Verdict doctrine (load-bearing):

* The consumer NEVER mints verdicts. A row leaves the backlog only on
  a landed tool verdict: a synthesized checker that passed BOTH
  mechanical controls (positive control at the row's site, dual
  control on fixtures) and whose journal row actually landed through
  the same write path the orchestrator uses
  (``collector.append_journal_for_outcome``, promotion-alarm
  chokepoint included).
* Witnessed rows land at ``suspicious`` — the exact grade the
  orchestrator's own on-demand lane leaves for a receipt it may not
  promote. Drain rules are seeded from the row's own function, so the
  receipt is self-matched (``is_self_match_synth_receipt``): it
  corroborates the hypothesis mechanically but may not serve as
  promoting evidence on its own seed. Promotion stays with the review
  lanes, which re-enter through the journal as usual.
* Failed or refused synthesis leaves the row dark, with a
  drain-attempt record in ``drain-report.json`` (attempted is not
  witnessed) and a capped attempt counter persisted on the backlog
  row (flood discipline). The counter is keyed on the SITE, not the
  row object: duplicate listings of one site collapse at intake and
  share one counter, and one drain dispatches at most one synthesis
  per ``file:function`` site — N copies of a hypothesis never buy N
  dispatches or mint N journal rows.

Ranking (cheapest-available-witness):

* Rows whose hypothesis names a pattern Mode-2 synthesis can target
  (a concrete cluster-class CWE, or a mechanism
  ``infer_cwe_from_hypothesis`` recognises) rank first; a declared
  cluster CWE outranks an inferred one.
* Rows with PENDING study questions on the same function/file rank
  behind their questions (study-first ordering): a row that is dark
  because a domain contract is unknown is cheaper to drain after the
  study loop answers the question, so held rows are attempted only
  after unheld ones.
* Rows the on-demand policy refuses
  (``ondemand_synthesis_refusal_reason`` — not-tool-verifiable
  classes, no stated harm) are recorded, never attempted: refusal
  over mis-attribution.

Coverage is untouched: drain entries are journaled with the
finding-grade ``backlog-drain`` producer, so they never suppress audit
gaps, fold into coverage, or serve as reused verdicts.

Artifact discipline: the backlog lives in an agent-writable run dir
and its fields are attacker-influenced free text. Reads are bounded,
site rows are validated per-row (a malformed row is refused loudly
and recorded, it never aborts the drain — one hostile row must not
deny the queue), stored strings are capped, free-prose fields (id,
title) are additionally escaped at intake via the log-sanitisation
contract (they quote the scanned target), and rendering sites apply
the same conventions again before any value reaches a terminal. A
drain also refuses a run directory whose recorded worker is still
alive (``.raptor-run.json`` ``status=running`` + a live identity-
checked pid): drains are post-run passes, and a live producer racing
the artifact write-back could lose rows.
"""

from __future__ import annotations

import logging
import math
import random
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, TYPE_CHECKING

from core.security.log_sanitisation import sanitise_for_terminal

if TYPE_CHECKING:
    from collections.abc import Sequence

logger = logging.getLogger(__name__)

#: The producer artifact this consumer drains (written by
#: ``raptor-validation-helper``'s findings import).
BACKLOG_FILENAME = "witness-backlog.json"

#: Per-drain report artifact written into the run dir.
DRAIN_REPORT_FILENAME = "drain-report.json"

#: Byte budget for the backlog artifact. The producer bounds the
#: listing (50 sites/cluster, 100 clusters, capped strings), so a
#: legitimate artifact is well under 8 MiB; anything larger is a
#: planted file and is refused before it is read into memory.
MAX_BACKLOG_BYTES = 8 * 1024 * 1024

#: Byte budget for a study-answers ledger (matches
#: ``core.concepts.study_answers``'s own read budget).
MAX_STUDY_BYTES = 8 * 1024 * 1024

#: Byte budget for a graded findings export handed to ``reimport``
#: (matches the audit report's own graded-file read budget).
MAX_GRADED_BYTES = 64 * 1024 * 1024

#: Flood discipline: a site that failed this many synthesis attempts
#: across drains stays parked until an operator clears its counter —
#: re-spending on the same refusing hypothesis every drain is how a
#: hostile artifact would milk the budget. Persisted as the additive
#: ``drain_attempts`` key on every listed copy of the site (consumers
#: tolerate extra keys); duplicate listings share the counter (max at
#: load, bumped together), so copies never buy extra attempts.
MAX_ROW_ATTEMPTS = 3

#: Per-invocation dispatch cap, budget notwithstanding: one drain run
#: is a bounded pass over the queue, not an unbounded crawl.
DEFAULT_MAX_DISPATCH = 25

#: Bounded-read caps for a hostile artifact that ignores the
#: producer's own listing bounds.
_MAX_CLUSTERS_READ = 200
_MAX_SITES_PER_CLUSTER_READ = 100

#: Sites per cluster ``reimport`` writes — the producer's own chunk
#: size (``raptor-validation-helper``'s ``_BACKLOG_SITES_PER_CLUSTER``),
#: kept under ``_MAX_SITES_PER_CLUSTER_READ`` so every appended site
#: is readable at the next intake.
_SITES_PER_CLUSTER_WRITE = 50

#: Per-row records kept in the drain report (counts stay exact).
_MAX_REPORT_ROWS = 2000

#: Stored-string caps, mirroring the producer's site caps.
_ID_CAP = 120
_FILE_CAP = 300
_FUNCTION_CAP = 200
_TITLE_CAP = 300
_REASON_CAP = 500

#: Source window handed to the synthesis prompt as the seed snippet
#: (the engine's positive control re-reads the real file either way).
_SNIPPET_BEFORE_LINES = 40
_SNIPPET_AFTER_LINES = 80
_SNIPPET_CHAR_CAP = 8000

_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)


class BacklogError(RuntimeError):
    """Artifact-level refusal: missing, oversized, non-regular, or
    structurally unusable ``witness-backlog.json``. Loud by contract —
    the CLI surfaces the message and exits non-zero."""


@dataclass
class DarkRow:
    """One validated backlog site row."""

    id: str
    file: str
    function: str
    line: int
    title: str
    cluster_class: str
    attempts: int
    #: Live references into the loaded artifact, so a witnessed row
    #: can be removed (and an attempted row's counter bumped) without
    #: re-locating it. Never serialized.
    site: dict[str, Any] = field(repr=False, default_factory=dict)
    cluster: dict[str, Any] = field(repr=False, default_factory=dict)
    #: Duplicate listings of this same site (identical file, function,
    #: line, and title) collapsed at intake. They share this row's
    #: attempt counter and leave the backlog with it — duplicates are
    #: one site, never extra dispatches or extra journal rows.
    dups: list[DarkRow] = field(repr=False, default_factory=list)


@dataclass
class RowPlan:
    """A ranked drain decision for one row."""

    row: DarkRow
    cwe: str = ""
    #: "cluster" (declared cluster-class CWE) | "inferred"
    #: (``infer_cwe_from_hypothesis``) | "" (no channel).
    cwe_source: str = ""
    #: Non-empty = never attempted (policy refusal / no channel).
    refusal: str = ""
    #: Pending study questions holding this row (capped labels).
    held_by: list[str] = field(default_factory=list)

    @property
    def attemptable(self) -> bool:
        return not self.refusal

    @property
    def held(self) -> bool:
        return bool(self.held_by)


@dataclass
class _RowOutcome:
    """Adapter shape for the reused machinery.

    Duck-typed against exactly what
    ``checker_synthesis.synthesize_verification_rule`` and
    ``collector.append_journal_for_outcome`` read via ``getattr`` —
    the drain reuses both, it does not fork them.
    """

    file: str
    function: str
    status: str
    body: str = ""
    hypothesis: str = ""
    hypotheses: list[dict[str, Any]] | None = None
    evidence_tool: str = ""
    review_result: dict[str, Any] | None = None
    line: int = 0
    model: str = ""
    cost_usd: float = 0.0
    duration_s: float = 0.0
    tools_dispatched: set[str] | None = None
    tools_skipped: set[str] | None = None
    function_qualified: str = ""


@dataclass
class _SynthConfig:
    """The config slice ``synthesize_verification_rule`` reads."""

    target_path: Path
    out_dir: Path
    models: list[str] = field(default_factory=lambda: ["default"])


@dataclass
class DrainReport:
    """Aggregate result of one drain (or ranking) pass."""

    run_id: str = ""
    budget_usd: float = 0.0
    spent_usd: float = 0.0
    dispatched: int = 0
    witnessed: int = 0
    attempted: int = 0
    refused: int = 0
    held_rows: int = 0
    malformed: int = 0
    rows: list[dict[str, Any]] = field(default_factory=list)
    rows_truncated: bool = False
    stopped: str = ""  # "" | "budget" | "dispatch-cap" | "no-llm"
    sample: dict[str, Any] | None = None
    study: dict[str, Any] = field(default_factory=dict)
    backlog: dict[str, Any] = field(default_factory=dict)

    def add_row(self, record: dict[str, Any]) -> None:
        if len(self.rows) >= _MAX_REPORT_ROWS:
            self.rows_truncated = True
            return
        self.rows.append(record)


def _coerce_text(value: Any) -> str:
    """Coerce an artifact value to stripped text (None -> \"\")."""
    if not isinstance(value, str):
        value = "" if value is None else str(value)
    return value.strip()


def _cap(value: Any, cap: int) -> str:
    value = _coerce_text(value)
    if len(value) > cap:
        return value[: cap - 1] + "…"
    return value


#: Cluster-class cap — the producers' own class cap (both the
#: findings import and :func:`reimport` write classes capped to this).
_CLASS_CAP = 100


def _class_key(value: Any) -> str:
    """Canonical, capped form of a cluster-class string — used both to
    WRITE appended cluster classes and to MATCH classes during
    reconciliation. Every side of a class comparison must go through
    this one function: two different cappings silently never match a
    class longer than the cap. Trailing whitespace exposed by the cap
    is dropped so the key is idempotent — a written class re-keys to
    itself at the next reimport."""
    return _coerce_text(value)[:_CLASS_CAP].rstrip()


def _is_bad_path(file_path: str) -> bool:
    """Reject traversal-shaped row paths before any filesystem use.
    Same policy as the synthesis substrate's ``_validate_seed_path``
    (belt here, so a hostile row is refused at intake, not deep in an
    engine run)."""
    if not file_path or file_path.startswith(("/", "\\")):
        return True
    parts = PurePosixPath(file_path.replace("\\", "/")).parts
    return any(p == ".." for p in parts) or bool(
        parts and ":" in parts[0])


def load_backlog(
    run_dir: Path,
) -> tuple[dict[str, Any], list[DarkRow], list[dict[str, Any]]]:
    """Load and validate the backlog artifact.

    Returns ``(artifact, rows, malformed)`` — the artifact dict is the
    live object the drain writes back (unknown keys preserved), rows
    are the validated listed sites, malformed carries one capped
    record per refused row. Free-prose fields (id, title) are escaped
    and bounded at intake (log-sanitisation contract) — every stored
    string is inert from here on. Duplicate listings of one site
    (identical file, function, line, title — the id is producer
    bookkeeping, not identity) collapse into the FIRST row, which
    carries the copies in ``dups`` and their shared attempt counter
    (max across copies): a flooded queue never buys extra dispatches.
    Artifact-level problems raise :class:`BacklogError` (loud refusal,
    never a silent empty queue).
    """
    import os
    import stat as _stat

    path = Path(run_dir) / BACKLOG_FILENAME
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise BacklogError(
            f"no {BACKLOG_FILENAME} in {run_dir} — nothing to drain "
            f"({exc.__class__.__name__})"
        ) from exc
    if not _stat.S_ISREG(st.st_mode):
        raise BacklogError(
            f"{BACKLOG_FILENAME} is not a regular file "
            f"(mode=0o{st.st_mode:o}) — planted special? refusing"
        )

    from core.json import load_json
    try:
        data = load_json(path, strict=True, max_bytes=MAX_BACKLOG_BYTES)
    except Exception as exc:
        raise BacklogError(
            f"{BACKLOG_FILENAME} unreadable/malformed/oversized: {exc}"
        ) from exc
    if not isinstance(data, dict) or not isinstance(
            data.get("clusters"), list):
        raise BacklogError(
            f"{BACKLOG_FILENAME} has no clusters list — not a "
            f"witness-backlog artifact"
        )

    rows: list[DarkRow] = []
    malformed: list[dict[str, Any]] = []

    def _refuse(cluster_i: int, site_i: int, reason: str) -> None:
        malformed.append({
            "cluster": cluster_i,
            "site": site_i,
            "reason": _cap(reason, _REASON_CAP),
        })

    clusters = data["clusters"][:_MAX_CLUSTERS_READ]
    for ci, cluster in enumerate(clusters):
        if not isinstance(cluster, dict):
            _refuse(ci, -1, "cluster is not an object")
            continue
        sites = cluster.get("sites")
        if not isinstance(sites, list):
            _refuse(ci, -1, "cluster has no sites list")
            continue
        cls = _cap(cluster.get("class"), 100)
        for si, site in enumerate(sites[:_MAX_SITES_PER_CLUSTER_READ]):
            if not isinstance(site, dict):
                _refuse(ci, si, "site is not an object")
                continue
            file_raw = site.get("file")
            if not isinstance(file_raw, str) or not file_raw.strip():
                _refuse(ci, si, "site has no file")
                continue
            file_path = _cap(file_raw, _FILE_CAP)
            if _is_bad_path(file_path):
                _refuse(
                    ci, si,
                    f"site file path is absolute or traversal-shaped: "
                    f"{file_path}",
                )
                continue
            function = site.get("function", "")
            title = site.get("title", "")
            if function is not None and not isinstance(function, str):
                _refuse(ci, si, "site function is not a string")
                continue
            if title is not None and not isinstance(title, str):
                _refuse(ci, si, "site title is not a string")
                continue
            line = site.get("line")
            if isinstance(line, bool) or not isinstance(line, int) \
                    or line < 0:
                line = 0
            attempts = site.get("drain_attempts")
            if isinstance(attempts, bool) or not isinstance(attempts, int) \
                    or attempts < 0:
                attempts = 0
            rows.append(DarkRow(
                id=sanitise_for_terminal(
                    _coerce_text(site.get("id")), max_len=_ID_CAP),
                file=file_path,
                function=_cap(function, _FUNCTION_CAP),
                line=line,
                title=sanitise_for_terminal(
                    _coerce_text(title), max_len=_TITLE_CAP),
                cluster_class=cls,
                attempts=attempts,
                site=site,
                cluster=cluster,
            ))

    deduped: dict[tuple[str, str, int, str], DarkRow] = {}
    kept: list[DarkRow] = []
    for row in rows:
        key = (row.file, row.function, row.line, row.title)
        primary = deduped.get(key)
        if primary is None:
            deduped[key] = row
            kept.append(row)
            continue
        primary.attempts = max(primary.attempts, row.attempts)
        primary.dups.append(row)
    return data, kept, malformed


def load_pending_questions(
    run_dir: Path,
    explicit: Path | None = None,
    *,
    max_siblings: int = 12,
) -> tuple[list[dict[str, Any]], str]:
    """Pending study questions for study-first ordering.

    Resolution order: an explicit ledger path wins; else the run dir's
    own ``study-answers.json``; else the NEWEST sibling run dir (same
    parent, bounded scan) that carries one — the /audit run whose
    findings this /validate run imported is a sibling in project
    layouts. Returns ``(pending_rows, source_label)``; no ledger found
    is ``([], "")`` (ordering degrades, the drain still runs).
    """
    from core.concepts.study_answers import ANSWERS_FILENAME
    from core.json import load_json

    def _pending_from(path: Path) -> list[dict[str, Any]] | None:
        if not path.is_file():
            return None
        raw = load_json(path, max_bytes=MAX_STUDY_BYTES)
        if not isinstance(raw, dict):
            return None
        answers = raw.get("answers")
        if not isinstance(answers, list):
            return None
        return [
            a for a in answers
            if isinstance(a, dict) and a.get("status") == "pending"
        ]

    if explicit is not None:
        pending = _pending_from(Path(explicit))
        if pending is None:
            raise BacklogError(
                f"--study-answers {explicit}: not a readable "
                f"study-answers ledger"
            )
        return pending, str(explicit)

    own = Path(run_dir) / ANSWERS_FILENAME
    pending = _pending_from(own)
    if pending is not None:
        return pending, str(own)

    try:
        siblings = [
            d for d in Path(run_dir).parent.iterdir()
            if d.is_dir() and d != Path(run_dir)
            and (d / ANSWERS_FILENAME).is_file()
        ]
    except OSError:
        siblings = []

    def _ledger_mtime(d: Path) -> float:
        try:
            return (d / ANSWERS_FILENAME).stat().st_mtime
        except OSError:
            return 0.0

    siblings.sort(key=_ledger_mtime, reverse=True)
    for d in siblings[:max_siblings]:
        pending = _pending_from(d / ANSWERS_FILENAME)
        if pending is not None:
            return pending, str(d / ANSWERS_FILENAME)
    return [], ""


def _held_questions(
    row: DarkRow, pending: Sequence[dict[str, Any]],
) -> list[str]:
    """Pending study questions that hold *row* (study-first ordering).

    A question holds a row when it originates from the same file AND
    either names the same function, or is file-scoped (no function /
    the study loop's ``interstitial:`` spans). A question about a
    DIFFERENT function in the same file does not hold the row.
    """
    held: list[str] = []
    for q in pending:
        if q.get("source_file") != row.file:
            continue
        src_fn = q.get("source_function") or ""
        if not isinstance(src_fn, str):
            continue
        if (not src_fn or src_fn == row.function
                or src_fn.startswith("interstitial")):
            held.append(_cap(q.get("question"), 200))
            if len(held) >= 5:
                break
    return held


def plan_rows(
    rows: Sequence[DarkRow],
    pending_questions: Sequence[dict[str, Any]],
) -> list[RowPlan]:
    """Rank rows by cheapest-available-witness.

    Order among attemptable rows: unheld before study-held, declared
    cluster CWE before inferred, artifact order last (stable). Refused
    rows (no synthesis channel, or the on-demand policy refuses) sort
    to the tail and are never attempted.
    """
    from packages.checker_synthesis.languages import detect_engine

    from .checker_synthesis import ondemand_synthesis_refusal_reason
    from .cwe_dispatch import infer_cwe_from_hypothesis

    plans: list[RowPlan] = []
    for row in rows:
        plan = RowPlan(row=row)
        plan.held_by = _held_questions(row, pending_questions)
        if _CWE_RE.fullmatch(row.cluster_class.strip()):
            plan.cwe = row.cluster_class.strip().upper()
            plan.cwe_source = "cluster"
        else:
            inferred = infer_cwe_from_hypothesis(row.title) if row.title \
                else None
            if inferred:
                plan.cwe = inferred
                plan.cwe_source = "inferred"

        if not row.function:
            plan.refusal = "row names no function — synthesis needs a seed"
        elif not row.title:
            plan.refusal = "row states no hypothesis — nothing to verify"
        elif detect_engine(row.file) is None:
            plan.refusal = "no synthesis engine for this file type"
        else:
            # The on-demand lane's own policy gates, reused verbatim
            # (not-tool-verifiable classes, harm gate). review=None:
            # backlog rows carry no structured review.
            plan.refusal = ondemand_synthesis_refusal_reason(
                plan.cwe, row.title, None,
            )
        plans.append(plan)

    order = {id(p): i for i, p in enumerate(plans)}

    def _key(p: RowPlan) -> tuple[int, int, int, int]:
        return (
            0 if p.attemptable else 1,
            1 if p.held else 0,
            {"cluster": 0, "inferred": 1}.get(p.cwe_source, 2),
            order[id(p)],
        )

    plans.sort(key=_key)
    return plans


def _read_snippet(target_path: Path, file: str, line: int) -> str:
    """Bounded source window for the synthesis prompt (best-effort —
    the engine's positive control re-reads the real file).

    Containment-checked capped read (the row's path is
    hostile-artifact data; ``_is_bad_path`` at intake is only the
    belt) and \\n-only line splitting (the row's line number pairs
    with scanner line models, and target bytes are plantable)."""
    from core.source.contained import read_contained
    from core.source.lines import split_lines

    text = read_contained(
        Path(target_path), file,
        max_chars=4 * _SNIPPET_CHAR_CAP, newline="",
    )
    if not text:
        return ""
    lines = split_lines(text)
    if not lines:
        return ""
    centre = min(max(line, 1), len(lines))
    start = max(0, centre - 1 - _SNIPPET_BEFORE_LINES)
    window = "\n".join(lines[start:centre + _SNIPPET_AFTER_LINES])
    return window[:_SNIPPET_CHAR_CAP]


def _journal_bytes(run_dir: Path) -> int:
    """Total on-disk journal size (main file + shards) — the landed
    check: ``append_journal_for_outcome`` is best-effort by contract
    (it swallows write failures), and a row may leave the backlog
    only when its journal entry actually landed."""
    from core.coverage.journal import JOURNAL_FILENAME, journal_shard_paths
    total = 0
    for p in [Path(run_dir) / JOURNAL_FILENAME,
              *journal_shard_paths(Path(run_dir))]:
        try:
            total += p.stat().st_size
        except OSError:
            continue
    return total


def _refuse_live_run(run_dir: Path) -> None:
    """Refuse to drain a run directory whose recorded worker is still
    alive — drains are post-run passes, and a live producer racing the
    drain could regenerate ``witness-backlog.json`` under the write-
    back (last writer wins, rows lost either way).

    Same shape (and the same liveness chokepoint,
    ``worker_liveness_for_meta``) as the journal-compact guard: the
    metadata read fails CLOSED — a ``.raptor-run.json`` that exists
    but cannot be read or parsed refuses the drain, because the file
    is run-dir content any writer can corrupt and corrupting it must
    not disable this refusal. An ABSENT file stays permissive: foreign
    and hand-built directories carry no run metadata and must remain
    drainable, and a crashed run's stale ``status=running`` with a
    dead (or unstamped) worker pid drains normally.
    """
    from core.json import load_json
    from core.run.metadata import (
        RUN_METADATA_FILE,
        RUN_METADATA_MAX_BYTES,
        STATUS_RUNNING,
        worker_liveness_for_meta,
    )
    meta_path = Path(run_dir) / RUN_METADATA_FILE
    try:
        meta = load_json(meta_path, strict=True,
                         max_bytes=RUN_METADATA_MAX_BYTES)
    except (OSError, ValueError, RecursionError) as exc:
        raise BacklogError(
            f"run metadata at {meta_path} exists but cannot be read "
            f"({sanitise_for_terminal(str(exc), max_len=200)}) — "
            "refusing to drain: an unreadable record cannot prove the "
            "run is not in flight. Repair or remove the file, then "
            "retry."
        ) from exc
    if meta is None and not meta_path.exists():
        return
    if not isinstance(meta, dict):
        raise BacklogError(
            f"run metadata at {meta_path} is not a JSON object — "
            "refusing to drain: a malformed record cannot prove the "
            "run is not in flight. Repair or remove the file, then "
            "retry."
        )
    if meta.get("status") != STATUS_RUNNING:
        return
    alive, detail = worker_liveness_for_meta(meta)
    if alive:
        raise BacklogError(
            f"run at {run_dir} is still in flight ({detail}) — "
            "drains are post-run passes; wait for the run to finish "
            "or kill it first."
        )


def _remove_site(artifact: dict[str, Any], row: DarkRow) -> int:
    """Drop a witnessed row — and every collapsed duplicate of it —
    from the live artifact, keeping counts exact. Unlisted rows behind
    a ``sites_truncated`` marker stay counted — the drain only ever
    removes what it witnessed. Returns the number of sites removed."""
    for r in (row, *row.dups):
        sites = r.cluster.get("sites")
        if isinstance(sites, list):
            r.cluster["sites"] = [s for s in sites if s is not r.site]
        count = r.cluster.get("count")
        if isinstance(count, int) and not isinstance(count, bool) \
                and count > 0:
            r.cluster["count"] = count - 1
        total = artifact.get("total")
        if isinstance(total, int) and not isinstance(total, bool) \
                and total > 0:
            artifact["total"] = total - 1
    return 1 + len(row.dups)


def _bump_attempts(row: DarkRow) -> None:
    """Persist a failed attempt on the site — the shared counter lands
    on the row AND every collapsed duplicate, so the cap holds no
    matter which copy a future import lists first."""
    row.attempts += 1
    for r in (row, *row.dups):
        r.site["drain_attempts"] = row.attempts


def _declared_total(artifact: dict[str, Any]) -> int | None:
    """The artifact's self-declared queue size, or None when unusable
    (missing, non-int, bool, negative). Self-declared means hostile-
    influenceable: consumers only ever trust it UPWARDS (a producer-
    truncated listing declares more than it lists) — the row count
    actually seen is the floor, so an under-declared total can never
    make the drain report an emptier queue than it walked."""
    total = artifact.get("total")
    if isinstance(total, bool) or not isinstance(total, int) or total < 0:
        return None
    return total


def _plan_record(plan: RowPlan) -> dict[str, Any]:
    row = plan.row
    record: dict[str, Any] = {
        "id": row.id,
        "file": row.file,
        "function": row.function,
        "line": row.line,
        "class": row.cluster_class,
        "cwe": plan.cwe,
        "cwe_source": plan.cwe_source,
        "drain_attempts": row.attempts,
    }
    if plan.held_by:
        record["study_held"] = True
        record["held_by"] = list(plan.held_by)
    if plan.refusal:
        record["refusal"] = _cap(plan.refusal, _REASON_CAP)
    return record


def rank(
    run_dir: Path,
    *,
    study_answers: Path | None = None,
) -> tuple[list[RowPlan], DrainReport]:
    """Plan-only pass (the ``backlog list`` surface): load, rank,
    report — no LLM spend, no writes."""
    artifact, rows, malformed = load_backlog(Path(run_dir))
    pending, study_source = load_pending_questions(
        Path(run_dir), study_answers,
    )
    plans = plan_rows(rows, pending)
    report = DrainReport()
    report.malformed = len(malformed)
    report.refused = sum(1 for p in plans if not p.attemptable)
    report.held_rows = sum(1 for p in plans if p.held and p.attemptable)
    report.study = {
        "source": study_source,
        "pending_questions": len(pending),
    }
    seen = len(rows) + sum(len(r.dups) for r in rows)
    declared = _declared_total(artifact)
    report.backlog = {
        "total": seen if declared is None else max(declared, seen),
        "listed": len(rows),
        "duplicates_collapsed": seen - len(rows),
        "listing_truncated": declared is not None and declared > seen,
    }
    for plan in plans:
        report.add_row(_plan_record(plan))
    for bad in malformed:
        report.add_row({"malformed": True, **bad})
    return plans, report


@dataclass
class ReimportReport:
    """Aggregate result of one ``reimport`` pass."""

    graded_total: int = 0
    dark_rows: int = 0
    already_listed: int = 0
    appended: int = 0
    witnessed_excluded: int = 0
    skipped_unusable: int = 0
    listed_before: int = 0
    listed_after: int = 0
    clusters_before: int = 0
    clusters_after: int = 0
    total_before: int = 0
    total_after: int = 0
    changed: bool = False


def _graded_site(finding: dict[str, Any]) -> dict[str, Any]:
    """A backlog site dict in the producer's shape — the same field
    picks, caps, and line coercion ``raptor-validation-helper``'s
    ``_site()`` applies, so a reimported row is byte-shaped like an
    import-time listing of the same graded row."""
    line = finding.get("line")
    if isinstance(line, bool) or not isinstance(line, int):
        line = 0
    return {
        "id": str(finding.get("id") or "")[:_ID_CAP],
        "file": str(finding.get("file")
                    or finding.get("file_path") or "")[:_FILE_CAP],
        "function": str(finding.get("function") or "")[:_FUNCTION_CAP],
        "line": line,
        "title": str(finding.get("title")
                     or finding.get("hypothesis") or "")[:_TITLE_CAP],
    }


def _graded_cluster_class(finding: dict[str, Any]) -> str:
    """The producer's cluster-class fallback (``cwe_id`` → ``cwe`` →
    ``vuln_type`` → ``"unclassified"``), capped through
    :func:`_class_key` — reimported rows land in the same class their
    import-time listing would have used, and the class doubles as the
    reconciliation match key."""
    for key in ("cwe_id", "cwe"):
        cwe = finding.get(key)
        if isinstance(cwe, str) and cwe.strip():
            return _class_key(cwe.upper())
    vt = finding.get("vuln_type")
    if isinstance(vt, str) and vt.strip():
        return _class_key(vt.lower())
    return "unclassified"


def _site_identity(site: dict[str, Any]) -> tuple[str, str, int, str] | None:
    """The consumer-side identity of a site dict — EXACTLY the
    coercions :func:`load_backlog` applies when building a
    :class:`DarkRow` (file/function caps, line clamp, title
    sanitisation), so a site compared here matches its own listing at
    the next intake. ``None`` when intake would refuse the site (no
    usable file path)."""
    file_raw = site.get("file")
    if not isinstance(file_raw, str) or not file_raw.strip():
        return None
    file_path = _cap(file_raw, _FILE_CAP)
    if _is_bad_path(file_path):
        return None
    function = site.get("function", "")
    title = site.get("title", "")
    if function is not None and not isinstance(function, str):
        return None
    if title is not None and not isinstance(title, str):
        return None
    line = site.get("line")
    if isinstance(line, bool) or not isinstance(line, int) or line < 0:
        line = 0
    return (
        file_path,
        _cap(function, _FUNCTION_CAP),
        line,
        sanitise_for_terminal(_coerce_text(title), max_len=_TITLE_CAP),
    )


def _load_graded_findings(path: Path) -> list[dict[str, Any]]:
    """Load a graded findings export for :func:`reimport` — bounded,
    regular-file-only, loud on refusal (same artifact discipline as
    :func:`load_backlog`). Accepts the canonical ``{"findings": [...]}``
    container or a bare findings list."""
    import os
    import stat as _stat

    path = Path(path)
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise BacklogError(
            f"graded findings file {path} unreadable "
            f"({exc.__class__.__name__}) — nothing to reimport"
        ) from exc
    if not _stat.S_ISREG(st.st_mode):
        raise BacklogError(
            f"graded findings file {path} is not a regular file "
            f"(mode=0o{st.st_mode:o}) — planted special? refusing"
        )
    from core.json import load_json
    try:
        data = load_json(path, strict=True, max_bytes=MAX_GRADED_BYTES)
    except Exception as exc:
        raise BacklogError(
            f"graded findings file unreadable/malformed/oversized: {exc}"
        ) from exc
    findings = data.get("findings") if isinstance(data, dict) else data
    if not isinstance(findings, list):
        raise BacklogError(
            f"graded findings file {path} carries no findings list — "
            f"not a graded export"
        )
    return findings


def _witnessed_site_keys(
    run_dir: Path, witnessed_total: int,
) -> set[tuple[str, str, int]]:
    """Identities of rows past drains removed on a landed witness,
    recovered from the run dir's drain report — a reimport must never
    resurrect them.

    The report is overwritten per drain, so only the LAST drain's rows
    are recoverable: when the ledger's accumulated ``witnessed_total``
    exceeds what the report lists, the missing identities are
    unrecoverable and the reimport refuses loudly (fresh ``--out`` is
    the escape hatch). Report rows carry no title, so exclusion is by
    ``(file, function, line)`` — conservative in the safe direction
    (never re-lists any hypothesis at a witnessed site)."""
    from core.json import load_json

    path = Path(run_dir) / DRAIN_REPORT_FILENAME
    refusal = (
        f"the backlog's drained ledger records {witnessed_total} "
        f"witnessed removal(s) but their identities are not "
        f"recoverable from {DRAIN_REPORT_FILENAME} — a reimport could "
        f"resurrect witnessed rows; refusing. Re-import into a fresh "
        f"--out instead."
    )
    try:
        report = load_json(path, strict=True, max_bytes=MAX_BACKLOG_BYTES)
    except Exception as exc:
        raise BacklogError(f"{refusal} ({exc.__class__.__name__})") from exc
    rows = report.get("rows") if isinstance(report, dict) else None
    if not isinstance(rows, list):
        raise BacklogError(refusal)
    keys: set[tuple[str, str, int]] = set()
    listed = 0
    for row in rows:
        if not isinstance(row, dict) or row.get("action") != "witnessed":
            continue
        listed += 1
        file_path = _cap(row.get("file"), _FILE_CAP)
        function = _cap(row.get("function"), _FUNCTION_CAP)
        line = row.get("line")
        if isinstance(line, bool) or not isinstance(line, int) or line < 0:
            line = 0
        if not file_path:
            raise BacklogError(refusal)
        keys.add((file_path, function, line))
    if listed < witnessed_total:
        raise BacklogError(refusal)
    return keys


def reimport(run_dir: Path, graded_path: Path) -> ReimportReport:
    """Additively re-list dark rows from a graded findings export into
    the run's ``witness-backlog.json`` (mechanical — no LLM spend).

    The recovery path for a listing the producer truncated on disk:
    graded dark rows whose identity ``(file, function, line, title)``
    is not already listed are appended as same-class clusters of
    <= ``_SITES_PER_CLUSTER_WRITE`` sites. Additive by contract:

    * existing site dicts are never modified (``drain_attempts``
      untouched by construction) and no row is ever removed;
    * the ``drained`` ledger is never touched;
    * an already-listed identity is never listed twice (idempotent);
    * witnessed rows never resurrect — when the ledger records
      witnessed removals their identities are excluded, refusing
      loudly when they cannot be recovered;
    * ``total`` never decreases, and stays exact when the reimported
      export is the one the artifact was produced from: appended rows
      are debited against the artifact-level truncation surplus
      (declared total minus site rows listed on disk — the rows the
      producer counted but never listed, whether whole clusters were
      dropped by the cluster cap or sites behind a legacy per-cluster
      ``sites_truncated`` marker), and ``total`` rises only for
      appended rows past that surplus. Legacy ``sites_truncated``
      clusters additionally get their per-cluster count debited, the
      marker dropping once the cluster lists what it counts;
    * the surplus debit is attribution-blind — a count, not
      identities: the artifact does not record WHICH rows it counted
      but never listed, so on a DIVERGENT graded export it is a
      heuristic, not an exactness contract — never-counted rows can
      consume the surplus, clearing the ``total > listed`` truncation
      signal while originally counted rows stay unlisted, until a
      reimport of the original export re-lists them (raising ``total``
      for any surplus already consumed).

    The artifact is only written when something was appended — a
    no-op reimport leaves the file byte-identical.
    """
    from core.schema_constants import is_dark_row

    run_dir = Path(run_dir)
    _refuse_live_run(run_dir)
    artifact, rows, _malformed = load_backlog(run_dir)
    findings = _load_graded_findings(graded_path)
    dark = [f for f in findings if isinstance(f, dict) and is_dark_row(f)]

    report = ReimportReport(
        graded_total=len(findings),
        dark_rows=len(dark),
        listed_before=len(rows),
        clusters_before=len(artifact["clusters"]),
    )
    declared = _declared_total(artifact)
    report.total_before = declared if declared is not None else len(rows)

    witnessed_keys: set[tuple[str, str, int]] = set()
    drained = artifact.get("drained")
    if isinstance(drained, dict):
        witnessed_total = drained.get("witnessed_total")
        if isinstance(witnessed_total, int) \
                and not isinstance(witnessed_total, bool) \
                and witnessed_total > 0:
            witnessed_keys = _witnessed_site_keys(run_dir, witnessed_total)

    listed_keys = {(r.file, r.function, r.line, r.title) for r in rows}
    new_by_class: dict[str, list[dict[str, Any]]] = {}
    for finding in dark:
        site = _graded_site(finding)
        key = _site_identity(site)
        if key is None:
            report.skipped_unusable += 1
            continue
        if key in listed_keys:
            report.already_listed += 1
            continue
        if (key[0], key[1], key[2]) in witnessed_keys:
            report.witnessed_excluded += 1
            continue
        listed_keys.add(key)
        new_by_class.setdefault(
            _graded_cluster_class(finding), []).append(site)
        report.appended += 1

    clusters = artifact["clusters"]
    new_cluster_count = sum(
        math.ceil(len(sites) / _SITES_PER_CLUSTER_WRITE)
        for sites in new_by_class.values()
    )
    if report.appended and \
            len(clusters) + new_cluster_count > _MAX_CLUSTERS_READ:
        raise BacklogError(
            f"reimport would list {len(clusters) + new_cluster_count} "
            f"clusters — past the consumer read bound "
            f"({_MAX_CLUSTERS_READ}); appended rows would be "
            f"unreadable. Re-import into a fresh --out instead."
        )

    # The artifact-level truncation surplus: rows the producer counted
    # but never listed, whatever shape dropped them — whole clusters
    # dropped by the cluster cap (``clusters_truncated``: the rows
    # appear in NO cluster, marker or otherwise) or sites behind a
    # legacy per-cluster ``sites_truncated`` marker. Measured
    # pre-merge, straight off the artifact bytes: the declared total
    # counts every routed row, the on-disk site rows are what it
    # actually lists (junk entries inflate the on-disk count, which
    # only ever shrinks the surplus — errors point upward).
    listed_on_disk = sum(
        len(c["sites"]) for c in clusters
        if isinstance(c, dict) and isinstance(c.get("sites"), list)
    )
    surplus = (
        declared - listed_on_disk
        if declared is not None and declared > listed_on_disk
        else 0
    )

    for cls, sites in sorted(
            new_by_class.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        existing = list(clusters)  # snapshot: reconcile pre-merge clusters
        for start in range(0, len(sites), _SITES_PER_CLUSTER_WRITE):
            chunk = sites[start:start + _SITES_PER_CLUSTER_WRITE]
            clusters.append(
                {"class": cls, "count": len(chunk), "sites": chunk})
        # Per-cluster bookkeeping for legacy ``sites_truncated``
        # clusters of the same class: debit the unlisted remainder the
        # rows just listed came out of, so per-cluster counts stay
        # exact and the marker drops once the cluster lists what it
        # counts. This never drives ``total`` — the artifact-level
        # surplus above does.
        remaining = len(sites)
        for cluster in existing:
            if remaining <= 0:
                break
            if not isinstance(cluster, dict) \
                    or not cluster.get("sites_truncated") \
                    or _class_key(cluster.get("class")) != cls:
                continue
            count = cluster.get("count")
            cluster_sites = cluster.get("sites")
            if isinstance(count, bool) or not isinstance(count, int) \
                    or not isinstance(cluster_sites, list):
                continue
            slack = count - len(cluster_sites)
            if slack <= 0:
                continue
            take = min(slack, remaining)
            cluster["count"] = count - take
            remaining -= take
            if cluster["count"] == len(cluster_sites):
                del cluster["sites_truncated"]

    report.listed_after = report.listed_before + report.appended
    # ``total`` reconciliation: appended rows are debited against the
    # truncation surplus first — a counted row re-listed must not be
    # re-counted — and ``total`` rises only for appended rows past it.
    # Attribution-blind by construction (see the docstring): the debit
    # is a count, exact on the artifact's own source export, heuristic
    # on a divergent one; ``total`` never decreases either way. A
    # missing/unusable declared total is left alone: upward-only
    # trust, same as ``_declared_total``.
    uncounted = max(0, report.appended - surplus)
    if uncounted and declared is not None:
        artifact["total"] = declared + uncounted
    declared_after = _declared_total(artifact)
    report.total_after = (
        declared_after if declared_after is not None
        else report.listed_after
    )
    report.clusters_after = len(clusters)

    if report.appended:
        from core.json import save_json
        save_json(run_dir / BACKLOG_FILENAME, artifact)
        report.changed = True
    return report


def drain(
    run_dir: Path,
    target_path: Path,
    budget_usd: float,
    *,
    sample: int | None = None,
    sample_seed: int = 0,
    study_answers: Path | None = None,
    max_dispatch: int = DEFAULT_MAX_DISPATCH,
    models: Sequence[str] = (),
) -> DrainReport:
    """Drain the queue under an explicit budget.

    Every synthesis dispatch spends LLM money and is metered against
    *budget_usd* (stop-condition semantics: no further dispatch once
    the meter reaches the cap; the attempt that crossed it completes).
    Mechanical engine runs are free. ``sample`` restricts the pass to
    a seeded random calibration sample of the attemptable rows
    (sampling-as-calibration), recorded in the report.
    """
    # Fail-closed guard, not just a sign check: nan passes every <=
    # comparison (all False), which would make the budget stop
    # condition below inert — an unmetered pass behind a "$nan" cap.
    if not math.isfinite(budget_usd) or budget_usd <= 0:
        raise BacklogError(
            "--budget must be a positive, finite USD amount")

    run_dir = Path(run_dir)
    target_path = Path(target_path)
    if not target_path.is_dir():
        raise BacklogError(f"target path is not a directory: {target_path}")
    _refuse_live_run(run_dir)

    artifact, rows, malformed = load_backlog(run_dir)
    pending, study_source = load_pending_questions(run_dir, study_answers)
    plans = plan_rows(rows, pending)

    run_id = "backlog-drain-" + datetime.now(timezone.utc).strftime(
        "%Y%m%d-%H%M%S")
    report = DrainReport(run_id=run_id, budget_usd=float(budget_usd))
    report.malformed = len(malformed)
    report.held_rows = sum(1 for p in plans if p.held and p.attemptable)
    report.study = {
        "source": study_source,
        "pending_questions": len(pending),
    }
    seen = len(rows) + sum(len(r.dups) for r in rows)
    declared = _declared_total(artifact)
    report.backlog = {
        "total_before": seen if declared is None else max(declared, seen),
        "listed": len(rows),
        "duplicates_collapsed": seen - len(rows),
    }

    attemptable = [p for p in plans if p.attemptable]
    refused = [p for p in plans if not p.attemptable]
    report.refused = len(refused)

    if sample is not None:
        if sample <= 0:
            raise BacklogError("--sample must be a positive count")
        rng = random.Random(sample_seed)
        n = min(sample, len(attemptable))
        chosen = set(rng.sample(range(len(attemptable)), n))
        report.sample = {
            "requested": sample,
            "drawn": n,
            "seed": sample_seed,
            "population": len(attemptable),
        }
        attemptable = [
            p for i, p in enumerate(attemptable) if i in chosen
        ]

    from .checker_synthesis import (
        is_self_match_synth_receipt,
        synthesize_verification_rule,
    )

    synth_config = _SynthConfig(
        target_path=target_path,
        out_dir=run_dir,
        models=[m for m in models if m] or ["default"],
    )

    changed = False
    removed_sites = 0
    #: Per-drain dispatch identity — the journal is function-grained,
    #: so one drain buys at most ONE synthesis (and at most one
    #: suspicious journal row) per ``file:function`` site, however
    #: many near-duplicate rows (title/line variants survive the
    #: intake collapse) a hostile artifact lists for it.
    dispatched_sites: set[tuple[str, str]] = set()
    for plan in attemptable:
        row = plan.row
        record = _plan_record(plan)

        if report.stopped:
            record["action"] = "not-attempted"
            record["reason"] = f"stopped: {report.stopped}"
            report.add_row(record)
            continue
        if report.spent_usd >= budget_usd:
            report.stopped = "budget"
            record["action"] = "not-attempted"
            record["reason"] = "stopped: budget"
            report.add_row(record)
            continue
        if report.dispatched >= max_dispatch:
            report.stopped = "dispatch-cap"
            record["action"] = "not-attempted"
            record["reason"] = "stopped: dispatch-cap"
            report.add_row(record)
            continue
        if (row.file, row.function) in dispatched_sites:
            record["action"] = "not-attempted"
            record["reason"] = (
                "site already dispatched this drain (one synthesis "
                "per file:function per drain)"
            )
            report.add_row(record)
            continue
        if row.attempts >= MAX_ROW_ATTEMPTS:
            record["action"] = "attempt-capped"
            record["reason"] = (
                f"{row.attempts} prior drain attempts (cap "
                f"{MAX_ROW_ATTEMPTS}) — parked"
            )
            report.add_row(record)
            continue

        outcome = _RowOutcome(
            file=row.file,
            function=row.function,
            # Candidate grade for the verification lane's eligibility
            # contract — the ledger state, not a minted verdict:
            # nothing is journaled unless a tool receipt lands below.
            status="dark",
            hypothesis=row.title,
            line=row.line,
            review_result={"hypothesis": row.title},
        )
        snippet = _read_snippet(target_path, row.file, row.line)
        dispatched_sites.add((row.file, row.function))
        try:
            synth = synthesize_verification_rule(
                outcome,
                synth_config,
                cwe=plan.cwe,
                source_snippet=snippet,
                synthesis_count=report.dispatched,
                max_per_run=max_dispatch,
            )
        except Exception as exc:
            logger.warning(
                "backlog drain: synthesis errored for %s:%s",
                row.file, row.function, exc_info=True,
            )
            record["action"] = "attempted"
            record["reason"] = _cap(f"synthesis error: {exc}", _REASON_CAP)
            _bump_attempts(row)
            changed = True
            report.attempted += 1
            report.dispatched += 1
            report.add_row(record)
            continue

        if synth is None:
            # With the pre-checks above, None means the LLM plumbing
            # is unavailable — no configured client, OR its imports
            # failed (the channel builder converts an ImportError of
            # the LLM substrate into the same None) — and every
            # further dispatch would skip identically. Stop loudly
            # rather than reporting a queue of no-op attempts.
            report.stopped = "no-llm"
            record["action"] = "not-attempted"
            record["reason"] = (
                "synthesis unavailable (no LLM client configured, or "
                "the LLM substrate failed to import) — drain stopped"
            )
            report.add_row(record)
            continue

        report.dispatched += 1
        report.spent_usd += float(synth.cost_usd or 0.0)
        record["cost_usd"] = round(float(synth.cost_usd or 0.0), 6)

        if not (synth.confirmed and synth.stamp):
            record["action"] = "attempted"
            record["reason"] = (
                "no rule survived the mechanical controls — still dark"
            )
            if synth.rule_id:
                record["rule_id"] = _cap(synth.rule_id, _ID_CAP)
            _bump_attempts(row)
            changed = True
            report.attempted += 1
            report.add_row(record)
            continue

        # A confirmed receipt: positive control at the row's site plus
        # dual control on fixtures. Route it through the orchestrator's
        # journal-write path; the row leaves the backlog only if the
        # entry lands.
        self_match = is_self_match_synth_receipt(
            synth.stamp, row.file, row.function,
        )
        journal_outcome = _RowOutcome(
            file=row.file,
            function=row.function,
            # The grade the orchestrator's own on-demand lane leaves
            # for a receipt it may not promote: the drain never
            # promotes (see module docstring).
            status="suspicious",
            hypothesis=row.title,
            hypotheses=[{"mechanism": row.title, "confidence": "unknown"}],
            line=row.line,
            body=(
                f"witness-backlog drain: synthesized checker "
                f"{synth.stamp} passed positive control at "
                f"{row.file}:{row.line} and dual control on fixtures. "
                + (
                    "Receipt is self-matched (rule distilled from this "
                    "site's own shape), so it corroborates the parked "
                    "hypothesis without promoting it — promotion stays "
                    "with the review lanes."
                    if self_match else
                    "Receipt retained as confirming evidence; promotion "
                    "stays with the review lanes."
                )
            ),
            # A self-matched receipt may not serve as promoting
            # evidence on its own seed (checker_synthesis doctrine) —
            # it must not read as a confirming receipt downstream
            # (feedback referee, verdict-weight consumers).
            evidence_tool="" if self_match else synth.stamp,
            tools_dispatched={synth.tool} if synth.tool else None,
            cost_usd=float(synth.cost_usd or 0.0),
            review_result={
                "hypothesis": row.title,
                "cwe": plan.cwe or None,
                "ondemand_synth_receipt": synth.stamp,
                **(
                    {"ondemand_synth_blocked":
                        "self-match: rule synthesized from this "
                        "function's own shape"}
                    if self_match else {}
                ),
                "backlog_drain": {
                    "source": BACKLOG_FILENAME,
                    "row_id": row.id,
                    "cluster_class": row.cluster_class,
                    "cwe_source": plan.cwe_source,
                    "study_held": plan.held,
                },
            },
        )
        before = _journal_bytes(run_dir)
        from core.coverage.journal import PRODUCER_BACKLOG_DRAIN

        from .collector import append_journal_for_outcome
        append_journal_for_outcome(
            out_dir=run_dir,
            target_path=target_path,
            run_id=run_id,
            outcome=journal_outcome,
            gap={"line_start": row.line, "line_end": row.line},
            producer=PRODUCER_BACKLOG_DRAIN,
        )
        if _journal_bytes(run_dir) > before:
            removed_sites += _remove_site(artifact, row)
            changed = True
            record["action"] = "witnessed"
            record["receipt"] = synth.stamp
            record["engine"] = synth.tool
            record["self_match"] = self_match
            record["journal"] = "appended"
            report.witnessed += 1
        else:
            # The write path swallowed a failure — the row must not
            # leave the backlog on an unlanded entry.
            record["action"] = "attempted"
            record["receipt"] = synth.stamp
            record["reason"] = "journal write did not land — row stays dark"
            _bump_attempts(row)
            changed = True
            report.attempted += 1
        report.add_row(record)

    for plan in refused:
        record = _plan_record(plan)
        record["action"] = "refused"
        report.add_row(record)
    for bad in malformed:
        report.add_row({"malformed": True, **bad})

    # ``total_after`` is derived from the rows this drain actually
    # walked and removed, floored against the artifact's (updated)
    # self-declared total — same upward-only trust as
    # ``_declared_total``: an under-declared total must not let the
    # drain print an empty queue while attemptable rows remain.
    declared_after = _declared_total(artifact)
    remaining = seen - removed_sites
    report.backlog["total_after"] = (
        remaining if declared_after is None
        else max(declared_after, remaining)
    )

    from core.json import save_json
    if changed:
        prior_drained = artifact.get("drained")
        prior_total = 0
        if isinstance(prior_drained, dict):
            raw = prior_drained.get("witnessed_total")
            if isinstance(raw, int) and not isinstance(raw, bool) \
                    and raw > 0:
                prior_total = raw
        artifact["drained"] = {
            "last_run_id": run_id,
            "last_report": DRAIN_REPORT_FILENAME,
            "witnessed_total": prior_total + report.witnessed,
        }
        save_json(run_dir / BACKLOG_FILENAME, artifact)

    # The report payload IS the dataclass (field names are the
    # schema), plus a schema tag, a timestamp, and a rounded spend.
    from dataclasses import asdict
    payload = asdict(report)
    payload["schema"] = 1
    payload["ts"] = datetime.now(timezone.utc).isoformat()
    payload["spent_usd"] = round(report.spent_usd, 6)
    save_json(run_dir / DRAIN_REPORT_FILENAME, payload)
    return report


__all__ = [
    "BACKLOG_FILENAME",
    "BacklogError",
    "DEFAULT_MAX_DISPATCH",
    "DRAIN_REPORT_FILENAME",
    "DarkRow",
    "DrainReport",
    "MAX_BACKLOG_BYTES",
    "MAX_GRADED_BYTES",
    "MAX_ROW_ATTEMPTS",
    "ReimportReport",
    "RowPlan",
    "drain",
    "load_backlog",
    "load_pending_questions",
    "plan_rows",
    "rank",
    "reimport",
]
