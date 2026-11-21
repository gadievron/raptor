"""Offline I/O correlation over one frida run's events.

Joins ingest payloads (seed-harvest's ``args.data_hex``) against
string-valued arguments of LATER events in the same run — exec argv,
command strings, sink arguments. A byte sequence the target received
from outside reappearing inside an ``execve`` argument is direct,
cheap evidence that external input steers command execution: crude
taint, no taint engine.

Both event families must come from ONE session (separate runs are
separate executions, so cross-run correlation is meaningless) — run
``--template seed-harvest+exec-and-load`` (add ``+sink-watch`` for
sink arguments) and the CLI invokes this automatically after the run.

Everything is bounded and every truncation is counted in the manifest:
the events channel lives inside the (potentially hostile) target
process, so no input may steer memory or output size.
"""

from __future__ import annotations

from typing import Any

from pathlib import Path

from . import parse_events

__all__ = ["correlate_run"]

# Minimum shared substring that counts as a correlation. Below ~8
# printable bytes, matches are coincidence (common words, flag chars).
_MIN_MATCH = 8

# Bounds: payloads indexed, candidate strings scanned, matches kept.
_MAX_PAYLOADS = 128
_MAX_PAYLOAD_INDEX_BYTES = 4096
_MAX_CANDIDATES = 2048
_MAX_CANDIDATE_LEN = 4096
_MAX_MATCHES = 64
_MATCH_EXCERPT = 64
# Global gram-membership work bound: a hostile target can maximise
# payload and candidate volume; the join must stay cheap on every run.
_MAX_GRAM_CHECKS = 2_000_000

# Argument keys that are not sink-side content.
_SKIP_KEYS = frozenset({"data_hex"})


def _printable(data: bytes) -> str:
    """Lenient text view of raw payload bytes for substring matching."""
    return data.decode("latin-1")


def _iter_strings(value: Any, depth: int = 0):
    """Yield candidate strings from an args structure (bounded)."""
    if depth > 3:
        return
    if isinstance(value, str):
        if _MIN_MATCH <= len(value):
            yield value[:_MAX_CANDIDATE_LEN]
    elif isinstance(value, list):
        for item in value[:64]:
            yield from _iter_strings(item, depth + 1)
    elif isinstance(value, dict):
        for key, item in list(value.items())[:64]:
            if key in _SKIP_KEYS:
                continue
            yield from _iter_strings(item, depth + 1)


def _grams(text: str, n: int = _MIN_MATCH):
    for i in range(len(text) - n + 1):
        yield text[i:i + n]


def _extend_match(payload_text: str, candidate: str, gram: str) -> str:
    """Grow a seed n-gram to the longest shared run around it."""
    c_at = candidate.find(gram)
    p_at = payload_text.find(gram)
    start_c, start_p = c_at, p_at
    while (start_c > 0 and start_p > 0
           and candidate[start_c - 1] == payload_text[start_p - 1]):
        start_c -= 1
        start_p -= 1
    end_c, end_p = c_at + len(gram), p_at + len(gram)
    while (end_c < len(candidate) and end_p < len(payload_text)
           and candidate[end_c] == payload_text[end_p]):
        end_c += 1
        end_p += 1
    return candidate[start_c:end_c]


def correlate_run(run_dir: Path | str) -> dict[str, Any]:
    """Correlate ingest payloads with later event arguments.

    Returns the manifest dict; writes ``io-correlation.json`` into the
    run dir when at least one correlation is found.
    """
    run_dir = Path(run_dir)

    payloads: list[dict[str, Any]] = []   # {seq, ts, fn, text, grams}
    dropped_payloads = 0
    candidates_seen = 0
    dropped_candidates = 0
    matches: list[dict[str, Any]] = []
    seen_matches: set[tuple[str, str, str]] = set()
    dropped_matches = 0
    gram_checks = 0
    dropped_work = 0

    for seq, record in enumerate(parse_events(run_dir / "events.jsonl")):
        if record.get("type") != "send":
            continue
        payload = record.get("payload")
        if not isinstance(payload, dict) or "_meta" in payload:
            continue
        args = payload.get("args")
        category = payload.get("category")
        fn = payload.get("fn")

        if isinstance(args, dict) and isinstance(args.get("data_hex"), str):
            if len(payloads) >= _MAX_PAYLOADS:
                dropped_payloads += 1
                continue
            try:
                data = bytes.fromhex(
                    args["data_hex"][:2 * _MAX_PAYLOAD_INDEX_BYTES])
            except ValueError:
                continue
            if len(data) < _MIN_MATCH:
                continue
            text = _printable(data)
            payloads.append({
                "seq": seq,
                "ts": record.get("ts"),
                "fn": fn if isinstance(fn, str) else "",
                "text": text,
                "grams": set(_grams(text)),
            })
            continue

        if category == "ingest" or args is None:
            continue

        for candidate in _iter_strings(args):
            candidates_seen += 1
            if candidates_seen > _MAX_CANDIDATES:
                dropped_candidates += 1
                continue
            cand_grams = list(_grams(candidate))
            if not cand_grams:
                continue
            for source in payloads:
                if source["seq"] >= seq:
                    continue          # only ingest → LATER sink
                gram_checks += len(cand_grams)
                if gram_checks > _MAX_GRAM_CHECKS:
                    dropped_work += 1
                    break
                hit = next((g for g in cand_grams
                            if g in source["grams"]), None)
                if hit is None:
                    continue
                excerpt = _extend_match(source["text"], candidate, hit)
                key = (source["fn"], str(fn), excerpt[:_MATCH_EXCERPT])
                if key in seen_matches:
                    break
                seen_matches.add(key)
                if len(matches) >= _MAX_MATCHES:
                    dropped_matches += 1
                    break
                matches.append({
                    "source": {"fn": source["fn"], "seq": source["seq"],
                               "ts": source["ts"]},
                    "sink": {"category": category, "fn": fn, "seq": seq,
                             "ts": record.get("ts")},
                    "match": excerpt[:_MATCH_EXCERPT],
                    "match_len": len(excerpt),
                })
                break                 # one match per candidate string

    manifest: dict[str, Any] = {
        "matches": matches,
        "match_count": len(matches),
        "ingest_payloads_indexed": len(payloads),
        "dropped_payloads_over_cap": dropped_payloads,
        "dropped_candidates_over_cap": dropped_candidates,
        "dropped_matches_over_cap": dropped_matches,
        "dropped_work_over_budget": dropped_work,
        "min_match_len": _MIN_MATCH,
    }
    if matches:
        # Grade in the evidence_grade exact-spelling vocabulary: ingest
        # bytes reappearing in a later sink/exec argument of the same
        # instrumented run is an ATTRIBUTED execution fact —
        # verification role, the one frida receipt family that can back
        # a recorded finding. A match-less run writes no manifest and
        # mints no stamp: the correlation proved nothing, and there is
        # no spelling for "no flow observed" (presence, never absence).
        from core.audit.evidence_grade import registered_spelling_role

        manifest["receipt_stamp"] = "frida:token-at-sink"
        manifest["evidence_role"] = registered_spelling_role(
            manifest["receipt_stamp"])

        from core.json import save_json

        save_json(run_dir / "io-correlation.json", manifest)
    return manifest
