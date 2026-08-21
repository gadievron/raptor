"""Mechanism attribution for corpus scoring.

Corpus labels carry ``expected_mechanism`` — the pipeline component
that *should* produce the verdict (a refutation gate, the concept
compiler, a struct-accessor/dispatch-table detector, an SMT check...).
Verdict-only scoring cannot see the difference between "the expected
gate fired" and "an unrelated path happened to land on the same
verdict".  The second case is the dangerous quiet cell: the corpus
looks green while the mechanism under calibration is not exercised at
all.

This module joins a run's receipts back to each label:

* the result row itself — ``evidence_tool`` and the ``[<gate>: ...]``
  demotion marker the orchestrator prefixes onto the hypothesis;
* ``.audit-log.jsonl`` — ``refutation_gate`` records (channel
  receipts: which gate fired, on which function, applied or not) and
  the ``evidence_tool`` carried by ``orchestrator_review`` /
  ``sweep_promotion`` records;
* ``review-journal.jsonl`` — per-function ``evidence_tools`` lists and
  ``study_receipts`` (verdicts whose re-review was driven by study
  answers — harvested as ``study`` / ``study:<tier>`` tokens so an
  expected_mechanism of ``study`` can bind);
* ``mechanical-findings.json`` — per-function detector hits.

Observed signals are normalised to canonical mechanism tokens and
matched against the label's expectation.  Every row lands in exactly
one attribution cell:

* ``attributed``     — right verdict, expected mechanism left a receipt
* ``misattributed``  — right verdict, but a DIFFERENT mechanism
                       produced it (flagged loudly — see above)
* ``unattributed``   — right verdict, no mechanism receipt at all
                       (LLM-only verdict, or results predating
                       attribution — degrade honestly, don't guess)
* ``wrong_verdict``  — verdict mismatch; mechanism is moot
* ``error``          — pipeline never adjudicated the label
* ``no_expectation`` — label carries no ``expected_mechanism``

Attribution is receipt-based: "the mechanism left a receipt on this
function" is the closest observable to "the mechanism produced the
verdict" with today's plumbing.  Mechanisms that inject context
without writing receipts land in ``unattributed`` — that is pressure
to add receipts, not a licence to infer.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

ATTRIBUTION_CELLS = (
    "attributed",
    "misattributed",
    "unattributed",
    "wrong_verdict",
    "error",
    "no_expectation",
)

# Refutation-gate names (audit-log ``refutation_gate.gate`` and the
# ``[<gate>: ...]`` hypothesis demotion marker) -> canonical mechanism.
GATE_TO_MECHANISM = {
    "architecture": "refutation:architecture",
    "lifecycle": "refutation:lifecycle",
    "contract": "refutation:contract",
    "input_bound_t0": "refutation:known_return_type",
    "anti_self_refutation": "anti_self_refutation",
    "callee_inheritance": "refutation:callee_inheritance",
}

# Evidence-tool / detector names -> canonical mechanism.  Applied to
# whole tokens after lowercasing; unmapped tokens keep their own name
# plus their channel prefix, so novel tools still match a bare-channel
# expectation (e.g. expected "smt" matches "smt:check-overflow").
TOOL_TO_MECHANISM = {
    "callback_lifetime_local": "callback_lifetime",
    "callback_lifetime_cross": "callback_lifetime",
    "callback_under_lock": "callback_lifetime",
    "invariant_rule": "concept_compiler",
    "capability_displacement": "dispatch_table",
    "dispatch_completeness": "dispatch_table",
    "struct_accessor": "struct_co_accessor",
}

# Legacy / shorthand spellings accepted in labels.
EXPECTED_ALIASES = {
    "anti_self_refute": "anti_self_refutation",
    "refutation:input_bound_t0": "refutation:known_return_type",
}

_GATE_MARKER_RE = re.compile(r"^\[([a-z0-9_]+):")


@dataclass
class SignalIndex:
    """Per-function mechanism receipts harvested from run directories."""

    # function key "file:function" -> set of raw signal tokens
    tools: Dict[str, Set[str]] = field(default_factory=dict)
    gates: Dict[str, Set[str]] = field(default_factory=dict)
    detectors: Dict[str, Set[str]] = field(default_factory=dict)

    def add(self, bucket: Dict[str, Set[str]], key: str, token: str) -> None:
        if key and token:
            bucket.setdefault(key, set()).add(token)


def _strip_line_suffix(key: str) -> str:
    """``file:function:123`` -> ``file:function``."""
    head, _, tail = key.rpartition(":")
    if head and tail.isdigit():
        return head
    return key


def _iter_jsonl(path: Path) -> Iterable[dict]:
    try:
        with open(path) as f:
            for raw in f:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    entry = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if isinstance(entry, dict):
                    yield entry
    except OSError:
        logger.debug("attribution: cannot read %s", path, exc_info=True)


def build_signal_index(run_dirs: Iterable[Path]) -> SignalIndex:
    """Harvest mechanism receipts from audit run directories."""
    index = SignalIndex()
    seen: Set[Path] = set()
    for run_dir in run_dirs:
        run_dir = Path(run_dir)
        if not run_dir.is_dir() or run_dir in seen:
            continue
        seen.add(run_dir)

        for log_path in sorted(run_dir.rglob(".audit-log.jsonl")):
            for entry in _iter_jsonl(log_path):
                action = entry.get("action", "")
                key = _strip_line_suffix(entry.get("key", ""))
                # Receiver-qualified alias: corpus labels use
                # ``file:Class.method`` function_ids; without this the
                # receipt join silently missed every qualified label
                # (bare log keys never equal a dotted function_id).
                keys = [key]
                qualified = entry.get("function_qualified") or ""
                if qualified and ":" in key:
                    keys.append(f"{key.rsplit(':', 1)[0]}:{qualified}")
                if action in (
                    "refutation_gate", "refutation_gate_post_promote",
                ):
                    if entry.get("applied") is False:
                        continue
                    for k in keys:
                        index.add(index.gates, k, entry.get("gate", ""))
                elif action in ("orchestrator_review", "sweep_promotion"):
                    et = entry.get("evidence_tool") or ""
                    for k in keys:
                        index.add(index.tools, k, et)

        for jpath in sorted(run_dir.rglob("review-journal.jsonl")):
            for entry in _iter_jsonl(jpath):
                key = (
                    f"{entry.get('file', '')}:{entry.get('function', '')}"
                )
                if key == ":":
                    continue
                keys = [key]
                qualified = entry.get("function_qualified") or ""
                if qualified:
                    keys.append(f"{entry.get('file', '')}:{qualified}")
                for tool in entry.get("evidence_tools") or []:
                    for k in keys:
                        index.add(index.tools, k, str(tool))
                # Study receipts: verdicts produced by a study-driven
                # re-review carry the answers' receipts (question,
                # tier, file, line, sha256, verified). The study
                # channel writes no evidence_tool of its own, so
                # without this harvest an expected_mechanism of
                # "study" could never attribute. The tier is the
                # study sub-token ("study:<tier>"), matchable by an
                # expectation pinning a specific tier; a bare "study"
                # expectation matches on channel.
                for receipt in entry.get("study_receipts") or []:
                    if not isinstance(receipt, dict):
                        continue
                    for k in keys:
                        index.add(index.tools, k, "study")
                    tier = str(receipt.get("tier") or "").strip()
                    if tier:
                        for k in keys:
                            index.add(index.tools, k, f"study:{tier}")

        for mpath in sorted(run_dir.rglob("mechanical-findings.json")):
            try:
                mf = json.loads(mpath.read_text())
            except (OSError, json.JSONDecodeError):
                logger.debug(
                    "attribution: cannot read %s", mpath, exc_info=True,
                )
                continue
            if not isinstance(mf, dict):
                continue
            for key, hits in mf.items():
                if not isinstance(hits, list):
                    continue
                for hit in hits:
                    if isinstance(hit, dict):
                        index.add(
                            index.detectors, key,
                            str(hit.get("detector", "")),
                        )
    return index


# Evidence strings can embed free-text prose (``llm-claimed:<whole
# hypothesis>``); tokens longer than this carry no matchable mechanism
# identity, so only their channel prefix is kept.
_MAX_TOKEN_LEN = 64


def _tool_tokens(raw: str) -> Set[str]:
    """Normalise one evidence-tool/detector string to mechanism tokens."""
    tok = str(raw).strip().lower()
    if not tok:
        return set()
    channel = tok.split(":", 1)[0].strip()
    out = {tok} if len(tok) <= _MAX_TOKEN_LEN else set()
    if channel:
        out.add(channel)
    for part in (tok, channel):
        mapped = TOOL_TO_MECHANISM.get(part)
        if mapped:
            out.add(mapped)
    return out


def _gate_tokens(gate: str) -> Set[str]:
    gate = str(gate).strip().lower()
    if not gate:
        return set()
    mapped = GATE_TO_MECHANISM.get(gate)
    return {mapped} if mapped else {f"refutation:{gate}"}


def normalise_expected(mechanism: str) -> str:
    mech = str(mechanism or "").strip().lower()
    return EXPECTED_ALIASES.get(mech, mech)


def observed_mechanisms(
    row: Dict[str, Any],
    index: Optional[SignalIndex] = None,
) -> Set[str]:
    """Collect normalised mechanism tokens observed for one result row.

    Row-level signals (``evidence_tool``, hypothesis gate marker) are
    always used; run-directory receipts are joined when *index* is
    provided.  Old results without run directories therefore degrade
    to partial, row-level attribution rather than fabricated receipts.
    """
    observed: Set[str] = set()

    observed |= _tool_tokens(row.get("evidence_tool") or "")

    hyp = row.get("hypothesis") or ""
    if isinstance(hyp, str):
        m = _GATE_MARKER_RE.match(hyp)
        if m and m.group(1) in GATE_TO_MECHANISM:
            observed |= _gate_tokens(m.group(1))

    if index is not None:
        fid = row.get("function_id", "")
        for gate in index.gates.get(fid, ()):
            observed |= _gate_tokens(gate)
        for tool in index.tools.get(fid, ()):
            observed |= _tool_tokens(tool)
        for det in index.detectors.get(fid, ()):
            observed |= _tool_tokens(det)

    observed.discard("")
    return observed


def mechanism_matches(expected: str, observed: Set[str]) -> bool:
    """Does the expected mechanism appear among the observed tokens?

    Exact token match, or a bare-channel expectation (no ``:``)
    matching any observed token in that channel.  An expectation WITH
    a specific sub-tool never matches on channel alone — "some SMT
    check fired" is not evidence for "this SMT check fired".
    """
    e = normalise_expected(expected)
    if not e:
        return False
    if e in observed:
        return True
    if ":" not in e:
        return any(tok.split(":", 1)[0] == e for tok in observed)
    return False


def attribute_row(
    row: Dict[str, Any],
    index: Optional[SignalIndex] = None,
) -> Dict[str, Any]:
    """Compute the attribution cell for one result row.

    Returns ``{"observed_mechanisms", "mechanism_match", "attribution"}``.
    """
    observed = observed_mechanisms(row, index)
    expected = normalise_expected(row.get("expected_mechanism", ""))
    matched = mechanism_matches(expected, observed) if expected else None

    # ``no_expectation`` is checked FIRST: a label without an
    # expected_mechanism has nothing to attribute regardless of its
    # verdict, and counting its errors/mismatches into the other cells
    # made the report internally inconsistent (a v5 header said "23
    # label(s) with expectations" over rows summing to 55 because
    # wrong_verdict absorbed 32 expectation-less rows).  With this
    # order the five verdict cells sum exactly to the header's count.
    if not expected:
        cell = "no_expectation"
    elif row.get("actual") == "error":
        cell = "error"
    elif not row.get("match"):
        cell = "wrong_verdict"
    elif matched:
        cell = "attributed"
    elif observed:
        cell = "misattributed"
    else:
        cell = "unattributed"

    return {
        "observed_mechanisms": sorted(observed),
        "mechanism_match": matched,
        "attribution": cell,
    }


def annotate_results(
    results: List[Dict[str, Any]],
    run_dirs: Iterable[Path],
) -> Tuple[int, int]:
    """Annotate result rows in place with attribution fields.

    Returns ``(annotated_count, receipt_source_count)`` where the
    second number is how many run directories contributed receipts —
    zero means row-level-only attribution (partial).
    """
    dirs = [Path(d) for d in run_dirs if Path(d).is_dir()]
    index = build_signal_index(dirs) if dirs else None
    annotated = 0
    for row in results:
        row.update(attribute_row(row, index))
        annotated += 1
    return annotated, len(dirs)
