"""Bounded, shape-validated cache for per-function taint summaries.

The summary pass is demand-driven but repeat runs revisit the same
functions; a summary is a pure function of

* the function's SOURCE (the span content hash, in the
  ``core.staleness`` convention — SHA-256[:12] of the span's lines),
* the MATCHING VOCABULARY it was computed against (packs + learned
  intake — a new sink spec must invalidate every cached summary, or
  a stale cache would silently miss the new class), and
* the extractor's own semantics (``SUMMARY_VERSION``).

so the cache key is exactly those three plus the function identity.
Anything less would serve stale transfer facts; anything more would
just lower the hit rate.

Trust posture: a persisted cache file lives in the RUN OUTPUT
directory (operator-controlled), but its content round-trips
target-derived strings, so loading is fail-closed per entry — an
entry that does not validate back into the summary shape is dropped
and counted, never partially admitted. A poisoned or truncated cache
degrades to recomputation, never to wrong summaries.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any
from collections.abc import Iterable

from core.json import dumps_canonical
from core.source.gated import read_text_gated
from core.taint.learned_intake import LearnedIntake
from core.taint.packs import PackSet
from core.taint.summaries import (
    SUMMARY_VERSION,
    CallChannel,
    Flow,
    FunctionSummary,
    SanitizerEvent,
    SinkEvent,
    SourceEvent,
)

# ── named caps ───────────────────────────────────────────────────────

#: Entries held/loaded. Sized to the propagation phase's own visit
#: ceiling (2x the 20k function-visit cap): higher keeps giant
#: monorepos fully cached, lower bounds memory and the size of a
#: poisoned cache file we will parse entries out of. When full, new
#: puts are REFUSED (counted) — a full cache degrades to
#: recomputation, which is always correct; evicting would make hit
#: behaviour order-dependent for no soundness gain.
MAX_CACHE_ENTRIES = 40_000

#: Byte budget for a persisted cache file (gated read). Higher
#: admits bigger caches; lower bounds what a planted or corrupted
#: file can make the loader parse. Over-budget loads count as one
#: refusal and yield an EMPTY cache.
MAX_CACHE_FILE_BYTES = 64 * 1024 * 1024

#: Bound on list fields while validating one persisted entry —
#: mirrors the extractor's own entry caps so a hand-edited cache
#: cannot smuggle in summaries larger than the pass could produce.
_MAX_LIST_FIELD = 4096

_STR = str
_INT = int


def vocabulary_digest(
    packs: PackSet, learned: LearnedIntake | None = None,
) -> str:
    """Stable digest of the MATCHING-relevant spec content.

    Covers every field the extractor's tables key or copy from —
    names, kinds, classes, args/kwargs, unless-kwargs literals,
    semantics, flows, tiers. Deliberately EXCLUDES prose fields
    (rationale) so a comment edit does not invalidate a corpus of
    summaries, and INCLUDES learned specs — a changed project store
    changes what a summary would contain. ``learned=None`` and an
    EMPTY intake digest identically (both mean "no learned specs
    matched anything"; two spellings of the same vocabulary must not
    split the cache).
    """
    learned = learned if learned is not None else LearnedIntake()
    def sink_row(s: Any) -> list:
        return [s.kind, s.match, s.sink_class, s.cwe, list(s.args),
                list(s.kwargs), s.receiver_hint, s.confidence,
                [list(p) for p in s.unless_kwargs], s.store_key, s.tier]

    payload: dict[str, Any] = {
        "version": SUMMARY_VERSION,
        "sources": sorted(
            [s.kind, s.match, list(s.taint_classes), s.store_key, s.tier]
            for s in packs.sources
        ),
        "sinks": sorted(sink_row(s) for s in packs.sinks),
        "sanitizers": sorted(
            [s.kind, s.match, s.semantics, list(s.sink_classes), s.tier]
            for s in packs.sanitizers
        ),
        "propagators": sorted(
            [s.kind, s.match, [[e.src, e.dst] for e in s.flows],
             s.narrowing, s.tier]
            for s in packs.propagators
        ),
    }
    payload["learned"] = sorted(
        [s.role, s.function, list(s.taint_classes),
         list(s.params_affected), s.return_tainted, s.semantics,
         [[e.src, e.dst] for e in s.added_flows], s.tier]
        for role in (learned.sources, learned.sinks,
                     learned.sanitizers, learned.propagators)
        for s in role
    )
    blob = dumps_canonical(payload)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def cache_key(
    function_id: str, content_hash: str, vocab_digest: str,
) -> str:
    return f"{function_id}|{content_hash}|{vocab_digest}|v{SUMMARY_VERSION}"


# ── shape validation (fail-closed per entry) ─────────────────────────


class _Invalid(ValueError):
    pass


def _need(data: dict, key: str, kind: type) -> Any:
    value = data.get(key)
    if not isinstance(value, kind) or isinstance(value, bool) != (kind is bool):
        raise _Invalid(key)
    return value


def _str_tuple(data: dict, key: str) -> tuple[str, ...]:
    raw = data.get(key, [])
    if (not isinstance(raw, list) or len(raw) > _MAX_LIST_FIELD
            or any(not isinstance(v, str) for v in raw)):
        raise _Invalid(key)
    return tuple(raw)


def _flow_from(data: Any) -> Flow:
    if not isinstance(data, dict):
        raise _Invalid("flow")
    return Flow(
        origin=_need(data, "origin", _STR),
        classes=_str_tuple(data, "classes"),
        killed=_str_tuple(data, "killed"),
        hops=_str_tuple(data, "hops"),
        markers=_str_tuple(data, "markers"),
    )


def _flows_from(data: dict, key: str) -> tuple[Flow, ...]:
    raw = data.get(key, [])
    if not isinstance(raw, list) or len(raw) > _MAX_LIST_FIELD:
        raise _Invalid(key)
    return tuple(_flow_from(f) for f in raw)


def _records_from(data: dict, key: str, build) -> tuple:
    raw = data.get(key, [])
    if not isinstance(raw, list) or len(raw) > _MAX_LIST_FIELD:
        raise _Invalid(key)
    return tuple(build(item) for item in raw)


def _channel_from(data: Any) -> CallChannel:
    if not isinstance(data, dict):
        raise _Invalid("call_channel")
    return CallChannel(
        callee=_need(data, "callee", _STR),
        resolution=_need(data, "resolution", _STR),
        line=_need(data, "line", _INT),
        arg=_need(data, "arg", _INT),
        kwarg=_need(data, "kwarg", _STR),
        star=_need(data, "star", _STR),
        flows=_flows_from(data, "flows"),
    )


def _sink_from(data: Any) -> SinkEvent:
    if not isinstance(data, dict):
        raise _Invalid("sink_event")
    return SinkEvent(
        sink_class=_need(data, "sink_class", _STR),
        cwe=_need(data, "cwe", _STR),
        match=_need(data, "match", _STR),
        line=_need(data, "line", _INT),
        confidence=_need(data, "confidence", _STR),
        tier=_need(data, "tier", _STR),
        pack=_need(data, "pack", _STR),
        flows=_flows_from(data, "flows"),
    )


def _source_from(data: Any) -> SourceEvent:
    if not isinstance(data, dict):
        raise _Invalid("source_event")
    return SourceEvent(
        kind=_need(data, "kind", _STR),
        match=_need(data, "match", _STR),
        line=_need(data, "line", _INT),
        classes=_str_tuple(data, "classes"),
        tier=_need(data, "tier", _STR),
    )


def _sanitizer_from(data: Any) -> SanitizerEvent:
    if not isinstance(data, dict):
        raise _Invalid("sanitizer_event")
    demoted = data.get("demoted")
    if not isinstance(demoted, bool):
        raise _Invalid("demoted")
    return SanitizerEvent(
        match=_need(data, "match", _STR),
        semantics=_need(data, "semantics", _STR),
        applied=_need(data, "applied", _STR),
        demoted=demoted,
        demotion_reason=_need(data, "demotion_reason", _STR),
        line=_need(data, "line", _INT),
        classes=_str_tuple(data, "classes"),
        tier=_need(data, "tier", _STR),
    )


def summary_from_dict(data: Any) -> FunctionSummary:
    """Rebuild one summary from its ``to_dict`` form; raises
    ``ValueError`` on ANY shape violation (fail-closed — the caller
    drops and counts, never patches)."""
    if not isinstance(data, dict):
        raise _Invalid("summary")
    if data.get("version") != SUMMARY_VERSION:
        raise _Invalid("version")
    opaque = data.get("opaque")
    if not isinstance(opaque, bool):
        raise _Invalid("opaque")
    stats_raw = data.get("stats", {})
    if (not isinstance(stats_raw, dict) or len(stats_raw) > _MAX_LIST_FIELD
            or any(not isinstance(k, str)
                   or not isinstance(v, int) or isinstance(v, bool)
                   for k, v in stats_raw.items())):
        raise _Invalid("stats")
    return FunctionSummary(
        function_id=_need(data, "function_id", _STR),
        qualname=_need(data, "qualname", _STR),
        file=_need(data, "file", _STR),
        line_start=_need(data, "line_start", _INT),
        line_end=_need(data, "line_end", _INT),
        content_hash=_need(data, "content_hash", _STR),
        params=_str_tuple(data, "params"),
        returns=_flows_from(data, "returns"),
        call_channels=_records_from(data, "call_channels", _channel_from),
        sink_events=_records_from(data, "sink_events", _sink_from),
        source_events=_records_from(data, "source_events", _source_from),
        sanitizer_events=_records_from(data, "sanitizer_events",
                                       _sanitizer_from),
        global_names=_str_tuple(data, "global_names"),
        markers=_str_tuple(data, "markers"),
        opaque=opaque,
        stats=tuple(sorted((k, v) for k, v in stats_raw.items())),
    )


# ── the cache ────────────────────────────────────────────────────────


class SummaryCache:
    """Bounded in-memory summary cache with optional JSON persistence.

    Keys are :func:`cache_key` strings — function identity, span
    content hash, vocabulary digest, extractor version. ``stats``
    counts hits/misses/refusals so a run summary can report cache
    behaviour honestly.
    """

    def __init__(self, *, max_entries: int = MAX_CACHE_ENTRIES) -> None:
        self.max_entries = max_entries
        self._entries: dict[str, FunctionSummary] = {}
        self.stats: dict[str, int] = {
            "hits": 0, "misses": 0, "puts": 0,
            "put_refused_full": 0, "load_dropped": 0,
            "load_refused_file": 0, "empty_hash_refused": 0,
            "save_refused_over_budget": 0,
        }

    def __len__(self) -> int:
        return len(self._entries)

    def get(
        self, function_id: str, content_hash: str, vocab_digest: str,
    ) -> FunctionSummary | None:
        if not content_hash:
            # "" is the span hasher's cannot-hash answer (invalid or
            # out-of-range span). Two unhashable functions must never
            # alias to one cache slot — an empty hash keys NOTHING
            # (belt for any upstream line-model drift).
            self.stats["empty_hash_refused"] += 1
            return None
        found = self._entries.get(
            cache_key(function_id, content_hash, vocab_digest),
        )
        self.stats["hits" if found is not None else "misses"] += 1
        return found

    def put(self, summary: FunctionSummary, vocab_digest: str) -> bool:
        if not summary.content_hash:
            self.stats["empty_hash_refused"] += 1
            return False
        key = cache_key(summary.function_id, summary.content_hash,
                        vocab_digest)
        if key not in self._entries and len(self._entries) >= self.max_entries:
            # Full cache refuses (counted): recomputation is always
            # correct; eviction would only make hits order-dependent.
            self.stats["put_refused_full"] += 1
            return False
        self._entries[key] = summary
        self.stats["puts"] += 1
        return True

    # -- persistence ----------------------------------------------------

    def save(self, path: str | Path) -> None:
        """Persist atomically (tempfile + rename in the destination
        directory): a crash mid-write must leave either the old cache
        or the new one, never a truncated file — truncation is
        recoverable (load refuses it, counted) but silently losing a
        good cache to a partial write is not worth saving a fsync.

        The LOAD byte budget is enforced HERE too: writing a file
        every later load refuses would be a silent cache death (the
        refusal is a counter on the loader, not an error the writer
        sees — that loudness gap is why the writer refuses first).
        An over-budget save counts ``save_refused_over_budget`` and
        raises ``ValueError``; the in-memory cache stays usable and
        the previous on-disk file stays intact."""
        target = Path(path)
        payload = {
            "version": SUMMARY_VERSION,
            "entries": {
                key: summary.to_dict()
                for key, summary in self._entries.items()
            },
        }
        blob = json.dumps(payload, sort_keys=True)
        if len(blob.encode("utf-8")) > MAX_CACHE_FILE_BYTES:
            self.stats["save_refused_over_budget"] += 1
            msg = (
                f"summary cache serialises to more than "
                f"{MAX_CACHE_FILE_BYTES} bytes; refusing to write a "
                f"file every load would refuse"
            )
            raise ValueError(msg)
        fd, tmp_name = tempfile.mkstemp(
            dir=str(target.parent), prefix=f".{target.name}.", suffix=".tmp",
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(blob)
            os.replace(tmp_name, target)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    def load(self, path: str | Path) -> int:
        """Merge entries from a persisted cache file; returns how many
        were admitted. Fail-closed at every level: unreadable /
        over-budget / malformed files count one refusal and admit
        nothing; per-entry shape violations drop that entry counted;
        keys that disagree with their entry's identity/version are
        dropped (a renamed key must not serve another function's
        summary)."""
        try:
            text = read_text_gated(path, MAX_CACHE_FILE_BYTES)
            payload = json.loads(text)
        except (ValueError, OSError):
            self.stats["load_refused_file"] += 1
            return 0
        if (not isinstance(payload, dict)
                or payload.get("version") != SUMMARY_VERSION
                or not isinstance(payload.get("entries"), dict)):
            self.stats["load_refused_file"] += 1
            return 0
        admitted = 0
        for key, raw in payload["entries"].items():
            if len(self._entries) >= self.max_entries:
                self.stats["put_refused_full"] += 1
                continue
            try:
                summary = summary_from_dict(raw)
            except (ValueError, TypeError):
                self.stats["load_dropped"] += 1
                continue
            if (not isinstance(key, str)
                    or not key.startswith(f"{summary.function_id}|"
                                          f"{summary.content_hash}|")
                    or not key.endswith(f"|v{SUMMARY_VERSION}")):
                self.stats["load_dropped"] += 1
                continue
            self._entries[key] = summary
            admitted += 1
        return admitted

    def summaries(self) -> Iterable[FunctionSummary]:
        return self._entries.values()


__all__ = [
    "MAX_CACHE_ENTRIES",
    "MAX_CACHE_FILE_BYTES",
    "SummaryCache",
    "cache_key",
    "summary_from_dict",
    "vocabulary_digest",
]
