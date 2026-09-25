"""Recovery of scanner-dropped per-unit verdicts from OpenAnt scan artifacts.

The pinned upstream reporter deduplicates caller/callee findings when it
builds ``pipeline_output.json`` (``core/reporter.py``,
``_dedup_caller_callee``): a confirmed (vulnerable/bypassable) unit with
EXACTLY ONE static caller in the call graph is deleted from the findings
list when that caller is also confirmed with the same nonzero CWE.
Same-CWE chains collapse transitively to the topmost caller because the
removal set is computed against the pre-removal population. The per-unit
verdicts themselves survive on disk — in ``results.json`` (or
``results_verified.json``) and in the ``analyze_checkpoints/`` per-unit
files upstream preserves as a permanent artifact — but the report ships
only aggregate counts (``results.deduplicated``), no per-finding identity.

The collapse premise ("same class as my only caller" == "same finding")
is a heuristic, not an identity: a callee can be independently
exploitable through paths the class match says nothing about. Until
upstream retains these, RAPTOR recovers the dropped verdicts from the
artifacts it already has and surfaces them as HINT-TIER candidates:

* every recovered record carries
  ``metadata.provenance_tier == RECOVERED_TIER`` and ``level: "note"`` —
  a model verdict the scanner itself did not stand behind in its report
  must weigh below a normal scanner finding at every downstream consumer
  (dedup, /validate import, reports), and is never blended silently into
  the regular findings (callers count it separately);
* ``metadata.deduplicated_into`` names the surviving ancestor the scanner
  collapsed the verdict into — the exact claim downstream validation
  adjudicates.

FAIL-OPEN CONTRACT: recovery is best-effort. Missing/corrupt/unparseable
artifacts, schema drift, or an upstream rule change degrade to ZERO
recovered records with a loud log line — never a crash, never a blocked
findings path. The primary lane re-derives the upstream dedup rule
exactly and cross-checks its removal count against the report's own
``results.deduplicated``; a mismatch means the pinned rule changed under
us, so nothing is recovered (recovering the wrong population is worse
than recovering none). The pinned-checkout contract tests
(``tests/test_recovery_pinned_contract.py``) execute the pinned core's
own reporter/checkpoint code against the same expectations, so a pin
bump that changes the format fails CI visibly instead of silently
recovering nothing.

TRUST: everything read here was written by the sandboxed scan child over
an untrusted repository — every load is byte-bounded, every field is
shape-coerced and capped, and rendering surfaces (markdown, terminal)
escape the content (``core.security.markdown_render`` /
``log_sanitisation``); this module stores capped raw strings, matching
the translator's convention for the same artifact class.
"""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any, Optional

from core.coverage.record import RUN_ARTIFACT_MAX_BYTES as _ARTIFACT_MAX_BYTES
from core.json import load_json
from core.logging import get_logger
from core.security.log_sanitisation import sanitise_for_terminal as _sft

from .translator import (
    _ATTACK_VECTOR_CAP,
    _ID_CAP,
    _MESSAGE_CAP,
    _NAME_CAP,
    _SNIPPET_CAP,
    _canonical_cwe,
    _coerce_str,
)

logger = get_logger()

# The downstream provenance marker. ONE stable spelling for every
# consumer; the finer-grained cause rides in metadata.recovery_source.
RECOVERED_TIER = "recovered_checkpoint_verdict"

# The verdicts worth recovering — the same pair the upstream reporter's
# confirmed-filter admits into findings (its "vulnerable/bypassable"
# tuple). safe/protected/inconclusive are the scanner's own negative or
# undecided verdicts: absence from the report is their CORRECT outcome,
# never a drop to recover.
_RECOVERABLE_VERDICTS = frozenset({"vulnerable", "bypassable"})

# Reserved sidecar filenames inside a checkpoint dir (upstream
# ``core/checkpoint.py`` ``_RESERVED_FILES``: the step summary and the
# backend-identity fingerprint). Pinned by the checkpoint contract test.
_RESERVED_CHECKPOINT_FILES = frozenset({"_summary.json", "_fingerprint.json"})

# Cap on the survivor-chain walk. The reverse call graph is a scan
# artifact over a hostile repo — a crafted cycle or a pathological chain
# must terminate; genuine single-caller collapse chains are shallow.
_CHAIN_WALK_MAX = 64

# Hard ceiling on recovered records per run, BOTH lanes. The artifacts
# are child-written over a hostile repo, so the candidate population is
# attacker-influenced: a forged-but-consistent results/call-graph pair
# (or planted checkpoint files in the fallback lane) could otherwise
# mint an unbounded number of hint-tier records, each of which becomes
# a validation candidate downstream — a memory/artifact/spend
# amplifier. 500 is deliberately generous against genuine runs (a real
# collapse set is a fraction of a run's confirmed findings — dozens on
# a ~1k-unit scan) while bounding the artifact to single-digit MBs and
# the validation fan-out to review-able scale; anything past it on a
# degenerate artifact is noise, not signal. Not lower: a legitimately
# huge monorepo scan with a deep utility-helper collapse pattern can
# plausibly reach the low hundreds, and silently starving it would be
# a recall regression. Truncation is stated loudly ("recovered N of M
# candidates") and record construction STOPS at the cap — candidates
# past it are counted, never built.
RECOVERED_RECORD_CAP = 500


def recover_dropped_verdicts(
    scan_dir: str | Path,
    pipeline_output: dict[str, Any],
) -> list[dict[str, Any]]:
    """Recover vulnerable-class unit verdicts the scanner's report dropped.

    Reads the scan artifacts beside ``pipeline_output.json`` in
    *scan_dir* and returns RAPTOR-schema finding records (hint tier, see
    module docstring) for units whose verdict is vulnerable-class but
    which have no corresponding record in ``pipeline_output['findings']``
    (matched by unit identity, never by index). Best-effort: any failure
    degrades to ``[]`` with a warning.
    """
    try:
        if not isinstance(pipeline_output, dict):
            return []
        return _recover(Path(scan_dir), pipeline_output)
    except Exception as e:  # noqa: BLE001 — fail-open by contract
        logger.warning(
            "openant: checkpoint-verdict recovery failed — recovering "
            "nothing (the scanner's own findings are unaffected): %s",
            _sft(str(e), max_len=400),
        )
        return []


def _recover(
    scan_dir: Path,
    pipeline_output: dict[str, Any],
) -> list[dict[str, Any]]:
    finding_keys = _finding_identity_keys(pipeline_output)

    experiment = _load_results(scan_dir)
    if experiment is not None:
        recovered = _recover_from_results(
            scan_dir, experiment, pipeline_output, finding_keys)
    else:
        # Fallback lane: no readable results file — diff the per-unit
        # analyze checkpoints against the findings output instead.
        # Coarser (no dedup attribution, and a deliberate
        # post-checkpoint downgrade by the consistency pass is
        # indistinguishable from a drop), hence the loud lane
        # announcement.
        logger.warning(
            "openant: no readable results.json/results_verified.json in "
            "%s — checkpoint-verdict recovery falling back to the raw "
            "analyze-checkpoint diff", scan_dir,
        )
        recovered = _recover_from_checkpoints(scan_dir, finding_keys)

    # Serializability self-check: the records land in
    # openant_findings.json ALONGSIDE the translator's findings, so a
    # value json can't emit (a non-finite float that slipped a field
    # gate) must fail HERE, inside recovery's own fail-open wrapper —
    # never at the shared artifact write, where it would void the
    # scanner's own findings too. Cheap at the record cap.
    json.dumps(recovered, allow_nan=False)
    return recovered


# ---------------------------------------------------------------------------
# Primary lane: re-derive the reporter's caller/callee dedup exactly
# ---------------------------------------------------------------------------


def _load_results(scan_dir: Path) -> Optional[dict[str, Any]]:
    """The results document the pinned reporter itself consumed —
    ``results_verified.json`` when the verify stage ran (the scanner
    passes it as ``active_results_path``), else ``results.json``.

    An unreadable candidate falls THROUGH to the next one, loudly — a
    torn two-byte results_verified.json (the child owns the scan dir)
    must not demote the whole recovery to the checkpoint-diff lane
    while a readable results.json sits beside it. Narrow known lane:
    upstream adopts results_verified.json only when its verify stage
    SUCCEEDED, so a verified doc that was written but not adopted can
    steer this reader at a population the reporter did not use — the
    ``results.deduplicated`` count tripwire then mismatches and
    recovery degrades to nothing (fail-closed), which is the intended
    outcome for that ambiguity.
    """
    for name in ("results_verified.json", "results.json"):
        path = scan_dir / name
        if not path.is_file():
            continue
        data = load_json(path, max_bytes=_ARTIFACT_MAX_BYTES)
        if isinstance(data, dict):
            return data
        logger.warning(
            "openant: %s exists but is not a readable JSON object — "
            "trying the next results document", path)
    return None


def _confirmed_rows(experiment: dict[str, Any]) -> list[dict[str, Any]]:
    """The reporter's confirmed-findings population, mirrored exactly:
    ``confirmed_findings`` when the key is present (the verified-results
    path), else the manual vulnerable/bypassable filter over ``results``.
    Non-dict elements are dropped at each step, as upstream does."""
    if "confirmed_findings" in experiment:
        confirmed = experiment.get("confirmed_findings")
        rows = confirmed if isinstance(confirmed, list) else []
    else:
        results = experiment.get("results")
        rows = [
            r for r in (results if isinstance(results, list) else [])
            if isinstance(r, dict)
            and str(r.get("finding") or r.get("verdict", "")).lower()
            in _RECOVERABLE_VERDICTS
        ]
    return [r for r in rows if isinstance(r, dict)]


def _row_key(row: dict[str, Any]) -> str:
    """Upstream's dedup identity for a confirmed row."""
    return _coerce_str(row.get("route_key")) or _coerce_str(row.get("unit_id"))


def _removal_keys(
    confirmed: list[dict[str, Any]],
    all_results: list[dict[str, Any]],
    reverse_cg: dict[str, Any],
) -> set[str]:
    """The upstream ``_dedup_caller_callee`` removal set, re-derived.

    Mirror precisely: a callee with EXACTLY ONE caller is removed when
    both ends are confirmed and share the same nonzero CWE. Computed
    against the PRE-removal set, so same-CWE chains collapse
    transitively to the topmost caller. Any deviation here is caught by
    the ``results.deduplicated`` cross-check and the pinned-checkout
    contract test.
    """
    # First-occurrence index over all_results, built ONCE: upstream's
    # cwe backfill is a per-row `next(...)` linear rescan, and
    # mirroring that spelling here made the PARENT quadratic in row
    # count — a hostile results.json of cwe-less confirmed rows
    # (child-writable, up to the artifact byte budget) turned recovery
    # into a multi-hour parent hang before the count tripwire ever
    # ran. setdefault keeps first-match-wins, so the derived values
    # equal upstream's exactly.
    first_by_key: dict[str, dict[str, Any]] = {}
    for r in all_results:
        first_by_key.setdefault(_row_key(r), r)
    cwe_by_key: dict[str, Any] = {}
    for f in confirmed:
        rk = _row_key(f)
        cwe = f.get("cwe_id")
        if cwe is None:
            full = first_by_key.get(rk)
            cwe = full.get("cwe_id", 0) if full else 0
        cwe_by_key[rk] = cwe

    remove: set[str] = set()
    for callee_key, callers in reverse_cg.items():
        if not isinstance(callers, list) or len(callers) != 1:
            continue
        caller_key = callers[0]
        if not isinstance(callee_key, str) or not isinstance(caller_key, str):
            continue
        if caller_key not in cwe_by_key or callee_key not in cwe_by_key:
            continue
        caller_cwe = cwe_by_key[caller_key]
        callee_cwe = cwe_by_key[callee_key]
        if caller_cwe and caller_cwe != 0 and caller_cwe == callee_cwe:
            remove.add(callee_key)
    return remove


def _surviving_ancestor(
    route_key: str,
    reverse_cg: dict[str, Any],
    remove_keys: set[str],
) -> Optional[str]:
    """The nearest call-graph ancestor that SURVIVED the dedup — the
    finding the scanner collapsed this verdict into. Walks the
    single-caller chain upward past removed intermediates (the
    transitive-collapse case); bounded and cycle-safe because the graph
    is a scan artifact over a hostile repo."""
    seen: set[str] = set()
    cur = route_key
    for _ in range(_CHAIN_WALK_MAX):
        if cur in seen:
            return None
        seen.add(cur)
        callers = reverse_cg.get(cur)
        if not isinstance(callers, list) or len(callers) != 1:
            return None
        parent = callers[0]
        if not isinstance(parent, str):
            return None
        if parent not in remove_keys:
            return parent
        cur = parent
    return None


def _recover_from_results(
    scan_dir: Path,
    experiment: dict[str, Any],
    pipeline_output: dict[str, Any],
    finding_keys: set[str],
) -> list[dict[str, Any]]:
    results = experiment.get("results")
    all_results = [
        r for r in (results if isinstance(results, list) else [])
        if isinstance(r, dict)
    ]
    confirmed = _confirmed_rows(experiment)

    cg = load_json(scan_dir / "call_graph.json",
                   max_bytes=_ARTIFACT_MAX_BYTES)
    reverse_cg = (cg or {}).get("reverse_call_graph") if isinstance(
        cg, dict) else None
    if not isinstance(reverse_cg, dict):
        # Upstream skips the dedup entirely without a readable call
        # graph, so nothing was dropped by it — the cross-check below
        # still runs (a nonzero reported dedup count with no graph on
        # disk is drift).
        reverse_cg = {}

    remove_keys = _removal_keys(confirmed, all_results, reverse_cg)
    # ROW count for the tripwire (duplicates included): upstream's
    # ``deduplicated`` counter is confirmed_before_dedup minus the
    # post-filter list length, so two confirmed rows sharing one
    # removed key count as TWO there — the arithmetic here must match
    # (verified against the pinned reporter). Record construction below
    # dedups by key so one unit never emits two same-finding_id records
    # into one artifact.
    removed_row_count = sum(
        1 for f in confirmed if _row_key(f) in remove_keys)
    removed_rows: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    for f in confirmed:
        rk = _row_key(f)
        if rk in remove_keys and rk not in seen_keys:
            seen_keys.add(rk)
            removed_rows.append(f)

    # DRIFT TRIPWIRE: the report's own aggregate must equal the
    # re-derivation. The pinned reporter always writes
    # results.deduplicated (= confirmed_before_dedup - len(findings));
    # an absent field or a differing count means the upstream rule or
    # schema changed at a pin bump — recover NOTHING, loudly, rather
    # than recover the wrong population.
    reported = pipeline_output.get("results")
    reported_dedup = (reported.get("deduplicated")
                      if isinstance(reported, dict) else None)
    if not isinstance(reported_dedup, int) or isinstance(reported_dedup, bool):
        logger.warning(
            "openant: pipeline_output carries no integer "
            "results.deduplicated — upstream schema drift; recovering "
            "no checkpoint verdicts (re-verify the pinned commit)",
        )
        return []
    if reported_dedup != removed_row_count:
        logger.warning(
            "openant: dedup re-derivation mismatch (re-derived %d "
            "dropped verdict(s), report says %d) — the upstream dedup "
            "rule drifted; recovering no checkpoint verdicts "
            "(re-verify the pinned commit)",
            removed_row_count, reported_dedup,
        )
        return []

    code_by_route = experiment.get("code_by_route")
    if not isinstance(code_by_route, dict):
        code_by_route = {}

    recovered: list[dict[str, Any]] = []
    truncated = 0
    for row in removed_rows:
        route_key = _row_key(row)
        if route_key in finding_keys:
            # The report kept a record for this unit after all —
            # recovery must never duplicate an existing finding.
            continue
        if len(recovered) >= RECOVERED_RECORD_CAP:
            truncated += 1  # counted, never built (see the cap rationale)
            continue
        survivor = _surviving_ancestor(route_key, reverse_cg, remove_keys)
        snippet = _coerce_str(code_by_route.get(route_key))
        recovered.append(_recovered_record(
            row, route_key,
            snippet=snippet,
            source="dedup_rederivation",
            survivor=survivor,
        ))
    if truncated:
        logger.warning(
            "openant: recovered %d of %d dropped-verdict candidate(s) — "
            "%d truncated at the recovery record cap (%d); a candidate "
            "population this size means a degenerate or forged artifact, "
            "not a healthy scan",
            len(recovered), len(recovered) + truncated, truncated,
            RECOVERED_RECORD_CAP,
        )
    if recovered:
        logger.info(
            "openant: recovered %d scanner-deduplicated checkpoint "
            "verdict(s) as hint-tier findings", len(recovered))
    else:
        logger.debug("openant: no dropped checkpoint verdicts to recover")
    return recovered


# ---------------------------------------------------------------------------
# Fallback lane: raw analyze-checkpoint diff
# ---------------------------------------------------------------------------


def _recover_from_checkpoints(
    scan_dir: Path,
    finding_keys: set[str],
) -> list[dict[str, Any]]:
    ckpt_dir = scan_dir / "analyze_checkpoints"
    if not ckpt_dir.is_dir():
        logger.debug(
            "openant: no analyze_checkpoints dir in %s — nothing to "
            "recover", scan_dir)
        return []

    recovered: list[dict[str, Any]] = []
    unreadable = 0
    truncated = 0
    for entry in sorted(ckpt_dir.iterdir()):
        if (not entry.is_file() or entry.suffix != ".json"
                or entry.name in _RESERVED_CHECKPOINT_FILES):
            continue
        if len(recovered) >= RECOVERED_RECORD_CAP:
            # Counted, never read: past the cap the remaining files are
            # only tallied for the honest truncation line — this lane
            # has no consistency cross-check at all (planted checkpoint
            # files recover directly), so the cap is its ONLY volume
            # bound.
            truncated += 1
            continue
        data = load_json(entry, max_bytes=_ARTIFACT_MAX_BYTES)
        if not isinstance(data, dict):
            unreadable += 1  # load_json already warned with the path
            continue
        result = data.get("result")
        if not isinstance(result, dict):
            continue  # not an analyze-style checkpoint (schema drift)
        verdict = _coerce_str(
            result.get("finding") or result.get("verdict")).lower()
        if verdict not in _RECOVERABLE_VERDICTS:
            continue
        route_key = (_coerce_str(data.get("route_key"))
                     or _coerce_str(result.get("route_key"))
                     or _coerce_str(data.get("id")))
        if not route_key or route_key in finding_keys:
            continue
        recovered.append(_recovered_record(
            result, route_key,
            snippet=_coerce_str(data.get("code_for_route")),
            source="analyze_checkpoint",
            survivor=None,
        ))
    if truncated:
        logger.warning(
            "openant: recovered %d checkpoint verdict(s) — %d further "
            "checkpoint file(s) left unexamined at the recovery record "
            "cap (%d)",
            len(recovered), truncated, RECOVERED_RECORD_CAP,
        )
    if unreadable:
        logger.warning(
            "openant: %d unreadable analyze checkpoint file(s) skipped "
            "during verdict recovery", unreadable)
    if recovered:
        logger.info(
            "openant: recovered %d checkpoint verdict(s) absent from the "
            "scanner's report (checkpoint-diff fallback lane)",
            len(recovered))
    return recovered


# ---------------------------------------------------------------------------
# Shared: identity + record shape
# ---------------------------------------------------------------------------


def _finding_identity_keys(pipeline_output: dict[str, Any]) -> set[str]:
    """Unit identities (route_key spellings) present in the findings.

    Upstream guarantees ``location.file + ":" + location.function ==
    route_key`` (the cli.py round-trip contract); a route_key with no
    ``:`` is stored as file="unknown", function=<route key>. Reconstruct
    exactly that route_key — never a looser spelling: a bare function
    name matched a DIFFERENT file's same-named function, silently
    withholding a genuinely dropped verdict. Matching is by unit
    identity, never by index.
    """
    keys: set[str] = set()
    findings = pipeline_output.get("findings")
    for f in findings if isinstance(findings, list) else []:
        if not isinstance(f, dict):
            continue
        loc = f.get("location")
        if not isinstance(loc, dict):
            continue
        file_ = _coerce_str(loc.get("file"))
        func = _coerce_str(loc.get("function"))
        if not func:
            continue
        if file_ and file_ != "unknown":
            keys.add(f"{file_}:{func}")
        else:
            keys.add(func)
    return keys


def _recovered_finding_id(route_key: str) -> str:
    """Deterministic identity-keyed id — NEVER positional. A resumed or
    re-run scan recovers the same unit under the same id, so cross-run
    merge/correlation collapses duplicates instead of double-counting.

    Ids are identifiers, not content: they land in logs, jsonl records
    and report headings across consumers that treat them as opaque
    printable tokens, so a route_key smuggling control/format
    characters (ESC/BEL/bidi — the key derives from hostile-repo
    symbol names) is neutralised to ``?`` here rather than stored raw.
    Whenever the readable part is lossy (neutralised OR truncated at
    the cap) a hash of the FULL route_key restores injectivity — two
    hostile keys differing only in a control run must not collide."""
    readable = "".join(
        ch if ch.isprintable() else "?" for ch in route_key[:_ID_CAP])
    if readable != route_key:
        digest = hashlib.sha256(
            route_key.encode("utf-8", "replace")).hexdigest()[:12]
        return f"openant-recovered:{readable}:{digest}"
    return f"openant-recovered:{readable}"


def _recovered_record(
    row: dict[str, Any],
    route_key: str,
    *,
    snippet: str,
    source: str,
    survivor: Optional[str],
) -> dict[str, Any]:
    """A RAPTOR-schema finding record for one recovered verdict.

    Shape mirrors ``translator._translate_finding`` so every downstream
    consumer reads it unchanged; ``level`` is pinned to ``note`` (below
    a normal vulnerable-verdict ``warning``) because the scanner's own
    report did not stand behind this verdict. All row fields are
    untrusted model output over an untrusted target: coerced and capped
    here, escaped at render sites.
    """
    verdict = _coerce_str(
        row.get("finding") or row.get("verdict")).lower()[:_ID_CAP]
    cwe = _canonical_cwe(row.get("cwe_id"))
    # file is capped like every other stored field (the route_key it
    # splits from is hostile-repo-derived; an uncapped path bloated the
    # artifact and every downstream join key).
    file_rel = (route_key.split(":")[0]
                if ":" in route_key else "")[:_NAME_CAP]
    func = (route_key.split(":", 1)[1] if ":" in route_key
            else route_key)[:_NAME_CAP]
    message = _coerce_str(row.get("reasoning"))
    name = _coerce_str(row.get("cwe_name"))[:_NAME_CAP]

    metadata: dict[str, Any] = {
        "function": func,
        "attack_vector": _coerce_str(
            row.get("attack_vector"))[:_ATTACK_VECTOR_CAP],
        "stage1_verdict": verdict,
        "stage2_verdict": "",
        "route_key": route_key[:_NAME_CAP],
        "vuln_name": name,
        "provenance_tier": RECOVERED_TIER,
        "recovery_source": source,
    }
    if survivor:
        metadata["deduplicated_into"] = survivor[:_NAME_CAP]
    confidence = row.get("confidence")
    if (isinstance(confidence, (int, float))
            and not isinstance(confidence, bool)
            and math.isfinite(float(confidence))):
        # Finite-only, dropped otherwise (present-only semantics): a
        # non-finite confidence carries no signal, and a copied inf/NaN
        # poisons the shared findings-artifact write downstream (json
        # cannot emit it) — the stdlib parser accepts 1e999 as inf even
        # though the non-finite LITERALS are rejected at load.
        metadata["confidence"] = float(confidence)

    return {
        "finding_id": _recovered_finding_id(route_key),
        "rule_id": f"openant/{cwe}" if cwe else "openant/unknown",
        "file": file_rel,
        "startLine": None,
        "endLine": None,
        "snippet": snippet[:_SNIPPET_CAP] if snippet else "",
        "message": message[:_MESSAGE_CAP] if message else "",
        "level": "note",
        "cwe_id": cwe,
        "tool": "openant",
        "has_dataflow": False,
        "metadata": metadata,
    }
