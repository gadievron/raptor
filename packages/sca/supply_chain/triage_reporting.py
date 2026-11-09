"""Portable views over captured candidate, proposal and re-audit outcomes."""
from __future__ import annotations

from dataclasses import asdict
import sys

from core.reporting.document import StageEnvelope
from core.reporting.results import NativeResult, complete_native_result
from core.security.prompt_output_sanitise import sanitise_string
from core.security.redaction import redact_secrets

DETAIL_LIMIT = 100


def _safe(value):
    if isinstance(value, str):
        return sanitise_string(redact_secrets(value), max_chars=2000)
    if isinstance(value, dict):
        return {key: _safe(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_safe(item) for item in value[:DETAIL_LIMIT]]
    return value


def triage_result(args, capture, *, denylist_path, reviewed_legit_path):
    payload = {"mode": "reaudit" if args.reaudit else "candidates", "LLM requested": args.llm,
               "LLM available": capture.get("llm_available"), "recorded model": capture.get("model")}
    metrics = {}
    notes = ["Near-name candidates and LLM proposals are not confirmed typosquats. Existing gate dispositions and human-confirmation requirements remain authoritative.",
             "Report captures at most 100 entries per ecosystem/category and 2000 characters per text field. Counts retain full recorded totals."]
    state = "completed"
    if args.reaudit:
        flags = capture.get("flags", {})
        payload["flags"] = {eco: entries[:DETAIL_LIMIT] for eco, entries in flags.items()}
        metrics["Re-audit flags"] = sum(len(entries) for entries in flags.values())
        enriched = capture.get("reexamined", {})
        payload["reexamined"] = {eco: [{"name": name, "flag reason": reason, "LLM proposal": asdict(verdict),
                                        "recommendation": recommendation}
                                       for name, reason, verdict, recommendation in entries[:DETAIL_LIMIT]]
                                 for eco, entries in enriched.items()}
        metrics["LLM re-examinations"] = sum(len(entries) for entries in enriched.values())
        notes.append("The native re-audit records flagged entries, not a verified total population or complete registry coverage. No flags does not establish package safety.")
    else:
        candidates = capture.get("candidates", {})
        requested = list(args.only) if args.only else list(args._report_ecosystems)
        missing = sorted(set(requested) - set(candidates))
        payload["requested generation parameters"] = {"feed depth": args.top_n, "rank ratio": args.ratio,
                                                       "minimum rank": args.min_pos, "minimum name length": args.min_len}
        payload["candidate counts"] = {eco: len(entries) for eco, entries in candidates.items()}
        payload["candidates"] = {eco: [entry._asdict() for entry in entries[:DETAIL_LIMIT]] for eco, entries in candidates.items()}
        payload["unrecorded requested ecosystems"] = missing
        metrics["Candidate entries"] = sum(len(entries) for entries in candidates.values())
        outcomes = capture.get("outcomes", {})
        captured = {}
        for eco, entries in outcomes.items():
            captured[eco] = [{"candidate": entry.candidate._asdict(),
                              "evidence": {key: value for key, value in asdict(entry.evidence).items() if key != "candidate"},
                              "LLM proposal": asdict(entry.verdict),
                              "gate": {"disposition": entry.gate_result.disposition.value, "reason": entry.gate_result.reason}}
                             for entry in entries[:DETAIL_LIMIT]]
        payload["triage outcomes"] = captured
        metrics["Triage outcomes"] = sum(capture.get("outcome_counts", {}).values())
        metrics.update({"Gate " + key: count for key, count in capture.get("gate_counts", {}).items()})
        if missing or (args.llm and metrics["Triage outcomes"] != metrics["Candidate entries"]):
            state = "partial"
            notes.append("Some requested feed/candidate results were not recorded; missing coverage or triage must not be interpreted as a clean verdict.")
    if args.llm and capture.get("llm_available") is False:
        state = "partial"
        notes.append("Requested LLM triage was unavailable; the native mechanical listing/flags are retained.")
    artifacts = [{"path": str(path)} for path in (denylist_path, reviewed_legit_path, args.out) if path is not None]
    return NativeResult("sca-triage", "typosquat curation", "sca-triage", _safe(payload), state=state,
                        diagnostics=notes, metrics=metrics, artifacts=artifacts,
                        stages=[StageEnvelope("typosquat " + payload["mode"], state, producer="sca")])


def complete_triage_report(args, options, capture, *, denylist_path, reviewed_legit_path):
    output = options.output
    root = output if output.is_dir() or not output.suffix else output.parent / ("." + output.stem + "-report")
    try:
        return complete_native_result(triage_result(args, capture, denylist_path=denylist_path,
                                                   reviewed_legit_path=reviewed_legit_path), root,
                                      stem="sca-triage", options=options, stream=sys.stderr)
    except (OSError, ValueError, TypeError) as error:
        print("Optional triage report unavailable (" + type(error).__name__ + "); native result retained", file=sys.stderr)
        return None
