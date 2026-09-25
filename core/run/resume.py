"""Same-run resume substrate — the pipeline-agnostic primitives.

A run killed by an external supervisor (harness background-shell cap,
SIGTERM, OOM) leaves coherent artifacts behind. Re-entering that run
AS THE SAME RUN needs the same mechanical pieces regardless of which
pipeline owned it:

* **run-config pinning** — the run's resolved options, persisted at
  start so a resume recomputes the remaining work against the
  ORIGINAL configuration, never fresh CLI flags;
* **eligibility** — refuse to resume a completed run (its results are
  final) or a run whose recorded worker is still alive; ``--reopen``
  handles the contradicted-completion case (status ``completed`` with
  no completion artifact on disk);
* **the drift gate** — compare hashes recorded while the run was
  alive against the target tree NOW (``core.staleness`` span hashing,
  common-prefix comparison), so a resume never silently reuses state
  computed against a different tree;
* **spend evidence** — bounded, clamped spend figures read from
  run-dir JSON, an incremental ``spend-floor.json`` sidecar for
  segments killed before their ledger reconciled, and the
  max-of-evidence rule (booking only the immediately-prior ledger
  once dropped ~99% of a multi-segment run's real spend);
* **budget math** — remaining budget = original cap minus booked
  spend, with an epsilon floor so "exhausted" never reads as
  "uncapped".

Pipeline-specific state stays with the pipeline: /audit's review
journal legs live in ``core.audit.resume`` (a consumer of this
module), /understand's per-model checkpoints live in
``packages.code_understanding.checkpoint``.
"""

from __future__ import annotations

import hashlib
import logging
import math
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.json.utils import load_json, save_json

logger = logging.getLogger(__name__)

# Byte budget for resume-time JSON reads (run configs, spend
# evidence). Real payloads are a few KiB; 8 MiB is generous headroom
# while keeping a planted oversize file unread.
_RESUME_JSON_MAX_BYTES = 8 * 1024 * 1024


# ── Run-config persistence ───────────────────────────────────────────

def save_run_config(
    out_dir: Path, config: dict[str, Any], *, filename: str,
) -> Path:
    """Atomically persist the run's resolved options.

    Written once at run start (segment 1). Resume reads it back so
    segment N runs under the ORIGINAL configuration; it never
    re-derives options from fresh CLI flags.
    """
    out_dir = Path(out_dir)
    path = out_dir / filename
    save_json(path, config)
    return path


def load_run_config(
    out_dir: Path, *, filename: str,
    max_bytes: int = _RESUME_JSON_MAX_BYTES,
) -> dict[str, Any] | None:
    """Load a pinned run config, or ``None`` when absent/corrupt.

    Bounded load: resume reads whatever directory the operator points
    it at, so the st_size gate (before any read) keeps an oversize
    config from being buffered — it degrades to ``None`` like a
    corrupt one. Real run configs are a few KiB.
    """
    path = Path(out_dir) / filename
    if not path.is_file():
        return None
    try:
        data = load_json(path, strict=True, max_bytes=max_bytes)
    except (OSError, ValueError):
        logger.warning("could not read %s", path, exc_info=True)
        return None
    return data if isinstance(data, dict) else None


# ── Eligibility ──────────────────────────────────────────────────────

def resume_ineligibility(
    out_dir: Path,
    *,
    completion_artifacts: Sequence[str],
    reopen: bool = False,
    completed_hint: str = "",
    contradiction_example: str = "",
) -> str | None:
    """Why *out_dir* may NOT be resumed. ``None`` when eligible.

    Refusals:
    * no run metadata — not a run directory;
    * status ``completed`` — final results (*completed_hint* is
      appended so the pipeline can point at its own new-run path);
    * status ``running`` with the recorded worker still alive — the
      run is actually in flight, resuming would double-drive it.

    ``completion_artifacts`` names the file(s) a genuinely completed
    run of this pipeline always leaves behind. ``completed`` with
    NONE of them present means the status was stamped by a step that
    did not own the run (*contradiction_example* names the observed
    shape, e.g. a mapping-phase lifecycle complete). With
    ``reopen=True`` that contradiction — and only that contradiction —
    flips the run back to ``interrupted`` and the resume proceeds; a
    completed run WITH its artifact stays final regardless of the
    flag.
    """
    from core.run.metadata import (
        RESUMABLE_STATUSES,
        STATUS_RUNNING,
        _tool_pid_alive,
        load_run_metadata,
        reopen_run,
    )

    out_dir = Path(out_dir)
    meta = load_run_metadata(out_dir)
    if not meta:
        return f"no .raptor-run.json in {out_dir} — not a run directory"
    status = meta.get("status")
    if status == "completed":
        names = " / ".join(completion_artifacts)
        contradicted = not any(
            (out_dir / name).is_file() for name in completion_artifacts
        )
        if contradicted and reopen:
            reopen_run(
                out_dir,
                note="resume --reopen: completed status contradicted "
                     f"by missing {names}",
            )
            return None
        if contradicted:
            return (
                f"run status is 'completed' but there is no {names} — "
                "the completion was probably stamped by a step that "
                f"did not own this run{contradiction_example}. "
                "Pass --reopen to flip it back to 'interrupted' and "
                "resume."
            )
        return (
            "run is completed — completed runs are never resumed. "
            + completed_hint
        )
    if status not in RESUMABLE_STATUSES:
        return f"run status {status!r} is not resumable"
    if status == STATUS_RUNNING and _tool_pid_alive(meta.get("tool_pid")):
        return (
            "run is still in flight (recorded worker process is "
            "alive) — resuming now would double-drive it. Wait for "
            "it to stop, or kill it first."
        )
    return None


# ── Drift gate ───────────────────────────────────────────────────────

@dataclass
class SpanDriftRecord:
    """One recorded hash to re-verify against the target tree.

    ``line_start=None`` means whole-file (:func:`hash_whole_file`);
    otherwise the ``core.staleness.hash_spans`` span hash. Records
    with an empty ``stored_hash`` cannot be verified and are skipped
    (not counted).
    """

    file: str          # target-relative path (untrusted run artifact)
    label: str         # pipeline identity for messages (function, model)
    stored_hash: str
    line_start: int | None = None
    line_end: int | None = None


@dataclass
class SpanDrift:
    """One record whose source has changed since it was hashed."""

    file: str
    label: str
    stored_hash: str
    current_hash: str  # "" when the file/span is gone or unreadable


# Matches core.staleness's SHA-256[:12] short-hash convention so
# whole-file and span evidence render alike in operator messages.
_HASH_PREFIX_LEN = 12


def hash_whole_file(path: Path) -> str:
    """SHA-256[:12] of a file's full text, ``""`` when unverifiable.

    Reads via ``core.source.contained.read_text_capped`` — resume
    consumers run against untrusted target trees, and a bare read
    blocks forever on a planted reader-less FIFO and loads planted
    multi-GB files whole. A truncated read returns ``""`` (cannot
    verify the whole file from a partial read); producers hashing at
    record time hit the same cap, so both sides agree.
    """
    from core.source.contained import read_text_capped

    got = read_text_capped(Path(path))
    if got is None:
        return ""
    text, truncated = got
    if truncated:
        return ""
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return digest[:_HASH_PREFIX_LEN]


def spans_drift(
    target_path: Path,
    records: Sequence[SpanDriftRecord],
) -> tuple[list[SpanDrift], int]:
    """Re-verify recorded hashes against the target tree NOW.

    Returns ``(drifted, checked)`` where *checked* counts the records
    that carried a verifiable ``stored_hash``. Span records use the
    same hashing as the /audit cross-run reuse fold
    (``core.staleness.hash_spans``, common-prefix comparison — stored
    and current hashes may be recorded at different prefix lengths),
    so a resume gate and an in-run fold can never disagree about what
    "changed" means.

    Recorded paths are run artifacts, not trusted input: each is
    confined under *target_path* (``..`` segments and escapes
    rejected); an unresolvable or missing file re-hashes to ``""``,
    which reads as drift against any non-empty stored hash.

    Record order is preserved per file; files are processed in first-
    appearance order (callers wanting sorted output sort *records*).
    """
    from core.staleness import hash_spans

    target_path = Path(target_path)
    by_file: dict[str, list[SpanDriftRecord]] = {}
    for record in records:
        if not record.stored_hash:
            continue
        by_file.setdefault(record.file, []).append(record)

    drifted: list[SpanDrift] = []
    checked = 0
    for file_path, group in by_file.items():
        resolved = _safe_target_join(target_path, file_path)
        readable = resolved is not None and resolved.is_file()
        span_group = [r for r in group if r.line_start is not None]
        if span_group and readable:
            spans = [
                (r.line_start, r.line_end or r.line_start)
                for r in span_group
            ]
            span_hashes = iter(hash_spans(resolved, spans))
        else:
            span_hashes = iter([""] * len(span_group))
        whole_hash: str | None = None
        for record in group:
            if record.line_start is not None:
                current = next(span_hashes)
            else:
                if whole_hash is None:
                    whole_hash = (
                        hash_whole_file(resolved) if readable else ""
                    )
                current = whole_hash
            checked += 1
            stored = record.stored_hash
            if not current or current[:len(stored)] != stored[:len(current)]:
                drifted.append(SpanDrift(
                    file=record.file,
                    label=record.label,
                    stored_hash=stored,
                    current_hash=current,
                ))
    return drifted, checked


def _safe_target_join(target_path: Path, rel: str) -> Path | None:
    """Join a recorded relative path under the target root, refusing
    traversal — recorded paths are run artifacts, not trusted path
    input. Same policy as /audit's join: a lexical ``..``-segment
    pre-reject (even non-escaping ``a/../b``) on top of
    ``core.paths.confine``'s filesystem-aware containment."""
    from core.paths import confine

    if ".." in rel.split("/"):
        return None
    return confine(target_path, rel)


# ── Spend evidence ───────────────────────────────────────────────────

#: Per-value ceiling on any single spend-evidence figure read from
#: run-dir JSON. Orders of magnitude above any real run's spend, so it
#: never clips genuine evidence — its job is keeping the budget math
#: finite, not modelling budgets.
_MAX_SPEND_EVIDENCE_USD = 1e7


def _spend_value(value: Any) -> float | None:
    """A finite, bounded, non-negative spend figure from run-dir JSON
    evidence — ``None`` for non-numeric shapes.

    Prior-spend evidence lives inside the sandbox-writable run dir. A
    planted ``1.6e308`` summed to ``inf``, and a booked ``inf``
    reported the run's budget as exhausted on every later resume while
    the floor writer detonated on the encoder's non-finite refusal.
    Clamps keep the fail direction refuse-to-spend without granting
    the writer anything a plain forged number would not: an overclaim
    (``inf``/oversize) clamps to the ceiling, an underclaim
    (``-inf``/``NaN``/negative) clamps to $0.
    """
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None
    v = float(value)
    if not math.isfinite(v):
        v = _MAX_SPEND_EVIDENCE_USD if v > 0 else 0.0
    return min(max(0.0, v), _MAX_SPEND_EVIDENCE_USD)


SPEND_FLOOR_FILENAME = "spend-floor.json"


def persist_spend_floor(
    out_dir: Path,
    spend_usd: float,
    segment: int | None = None,
) -> None:
    """Atomically persist an incremental whole-run spend floor.

    Reconciled ledgers are only written at reconciliation/salvage, so
    a segment killed hard (SIGKILL, OOM) booked $0 and the next
    segment's remaining budget overspent the cap by the dead segment's
    whole spend. This sidecar is updated cheaply during the run; the
    resume budget math takes the max of the surviving evidence
    sources.

    Monotonic: never lowers the recorded figure (a resumed segment's
    ledger starts below the whole-run floor until it re-books the
    prior segments).

    Single-writer assumption: the read-compare-write below is not
    atomic ACROSS processes — two concurrent writers could interleave
    and let the lower figure land last. Pipelines run one segment per
    run directory at a time (resume replaces, never overlaps), so
    within that contract the file write itself being atomic
    (save_json tempfile+rename) is sufficient; no locking machinery
    here. In-process concurrent bumpers (thread-pool dispatch) must
    serialise their own calls.
    """
    out_dir = Path(out_dir)
    if not out_dir.is_dir():
        return
    clamped = _spend_value(spend_usd)
    if clamped is None:
        return
    spend_usd = clamped
    if spend_usd <= spend_floor_usd(out_dir):
        return
    payload: dict[str, Any] = {"spend_usd": round(spend_usd, 6)}
    if segment is not None:
        payload["segment"] = segment
    path = out_dir / SPEND_FLOOR_FILENAME
    save_json(path, payload)


def spend_floor_usd(out_dir: Path) -> float:
    """The persisted incremental spend floor, $0 when absent/corrupt."""
    path = Path(out_dir) / SPEND_FLOOR_FILENAME
    if not path.is_file():
        return 0.0
    data = load_json(path, max_bytes=_RESUME_JSON_MAX_BYTES)
    if not isinstance(data, dict):
        return 0.0
    spend = _spend_value(data.get("spend_usd"))
    return 0.0 if spend is None else spend


def max_of_evidence(
    evidence: Sequence[tuple[float, str]],
) -> tuple[float, str]:
    """Resolve booked spend from multiple evidence sources.

    Returns ``(booked_usd, note)`` — the MAX value across the
    ``(value, note)`` pairs, the FIRST maximal source's note winning
    ties (callers order sources most-authoritative-first). Booking
    only one source used to drop every segment before the
    immediately-prior one whenever a segment died unreconciled
    (observed live: segment 4 booked $47.29 of a ~$4,534 run — a ~99%
    under-report in the final ledger).

    Values are clamped through :func:`_spend_value`; non-numeric
    entries read as $0. An empty sequence books $0 with an empty note.
    """
    booked = 0.0
    note = ""
    for value, source_note in evidence:
        clamped = _spend_value(value)
        v = 0.0 if clamped is None else clamped
        if v > booked or not note:
            booked = v
            note = source_note
    return booked, note


# ── Budget math ──────────────────────────────────────────────────────

#: Effective cap handed to a pipeline when the remaining budget is
#: zero or negative: small enough that reservation gates refuse every
#: LLM call, while the $0 state re-import, the mechanical passes, and
#: the final report still run.
EXHAUSTED_BUDGET_EPSILON_USD = 1e-6


def remaining_budget_usd(
    original_cap: float | None,
    booked: float,
) -> float | None:
    """Remaining budget = original cap minus booked spend.

    ``None`` (no cap) stays ``None``. A fully-consumed cap returns
    :data:`EXHAUSTED_BUDGET_EPSILON_USD` rather than 0/negative —
    ``max_cost_usd=0`` reads as "no cap" in cost-gate consumers, which
    would be the exact opposite of the operator's intent.
    """
    if original_cap is None:
        return None
    remaining = float(original_cap) - max(0.0, booked)
    if remaining <= 0:
        return EXHAUSTED_BUDGET_EPSILON_USD
    return remaining
