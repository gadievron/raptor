"""Argument parsing for /analyze without initialising analysis providers."""

import argparse


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="RAPTOR Autonomous Security Agent"
    )
    ap.add_argument("--repo", required=True, help="Repository path")
    ap.add_argument("--sarif", nargs="+", help="SARIF files")
    ap.add_argument(
        "--findings",
        help="Validated findings.json from exploitability "
             "validation pipeline",
    )
    ap.add_argument("--out", help="Output directory")
    ap.add_argument(
        "--max-findings", type=int, default=None,
        help="Max findings to process. Unset = provider-aware: a local "
             "primary (ollama / loopback — free) processes ALL findings, a "
             "cloud primary defaults to 10. Explicit value overrides; 0 = no cap.",
    )
    ap.add_argument(
        "--prefer", action="append", default=None, metavar="GLOB",
        help=(
            "Prioritise findings whose file_path matches GLOB. Repeatable for "
            "multiple patterns (OR semantics). Sorts matching findings to the "
            "front before --max-findings caps; stable within each bucket."
        ),
    )
    ap.add_argument(
        "--exclude-dir", action="append", default=None, metavar="GLOB",
        dest="exclude_dir",
        help=(
            "Drop findings whose file_path matches GLOB before analysis. "
            "Repeatable (OR semantics). Operator escape hatch for vendored "
            "code, test fixtures, generated dirs the structural filters "
            "can't cover. Example: ``--exclude-dir 'vendor/*' "
            "--exclude-dir '**/tests/*'``"
        ),
    )
    ap.add_argument(
        "--checklist",
        help="Inventory checklist.json for function "
             "metadata lookup",
    )
    ap.add_argument(
        "--no-journal",
        action="store_true",
        dest="no_journal",
        help="Skip per-finding journal entry emission and the "
             "journal-derived coverage record",
    )
    ap.add_argument(
        "--no-checker-synthesis",
        action="store_true",
        help="Skip checker synthesis entirely: don't synthesise a "
             "rule per confirmed finding, don't emit variant "
             "annotations. Use to cut LLM cost on confirmed "
             "exploitable findings — at the price of losing variant "
             "discovery.",
    )
    ap.add_argument(
        "--no-checker-refinement",
        action="store_true",
        help="Run checker synthesis in single-shot mode instead of "
             "the iterative FP-elimination loop (up to 5 rounds). "
             "Faster but rules may have higher false-positive rates.",
    )
    ap.add_argument(
        "--no-verify-exploits",
        action="store_true",
        help="Skip the compile-verify step on LLM-emitted exploits "
             "(default on, ~140ms per finding). Use for "
             "benchmarks / CI surfaces where every second counts. "
             "When disabled, exploit_compiled stays unset on each "
             "finding (None — verification not attempted).",
    )
    ap.add_argument(
        "--execute-exploits",
        action="store_true",
        help="Run compiled LLM-emitted exploits in the sandbox and "
             "record the observed outcome (sanitizer report / crash "
             "signal / clean run) on each finding — the P9 execution "
             "oracle. Same posture as crash-agent's flag: network "
             "blocked, safe env, compile prerequisite required. "
             "Without an explicit flag the project 'dynamic' trust "
             "marker decides; default off.",
    )
    ap.add_argument(
        "--no-execute-exploits",
        action="store_true",
        help="Explicitly disable sandboxed exploit execution for this "
             "run, overriding the project 'dynamic' trust marker. "
             "Takes precedence over --execute-exploits.",
    )
    ap.add_argument(
        "--no-judge-intent",
        action="store_true",
        help="Skip the intent-match judge on LLM-emitted exploits "
             "(default on). Judge runs 4 cheap heuristics first; "
             "escalates ambiguous cases to a 2-step LLM tiebreak "
             "(~$0.001-0.01 per ambiguous finding). When disabled, "
             "intent_match stays unset on each finding (None — "
             "judge not invoked). See "
             "packages/llm_analysis/intent_match.py for design.",
    )
    ap.add_argument(
        "--no-record-witnesses",
        action="store_true",
        help="Skip recording LLM-emitted exploits as canonical "
             "Witnesses under <out>/witnesses/ (default on). "
             "Each successful exploit generation otherwise produces "
             "one Witness with source=LLM_EMIT_RUN, "
             "outcome=NOT_RUN, carrying the compile + intent-match "
             "verdicts in outcome_detail. Negligible wall-clock "
             "cost (single sha256 + JSON write per finding); the "
             "opt-out exists for benchmarks that compare runs "
             "byte-for-byte and for ephemeral CI runs that don't "
             "persist the out/ tree.",
    )
    ap.add_argument(
        "--no-verified-exemplars",
        action="store_true",
        help="Don't prime analysis prompts with RAPTOR's own prior "
             "verified outcomes (default on). When a project is active, "
             "each finding's nearest previously-confirmed outcomes "
             "(witness / CodeQL backends) are rendered as exemplars "
             "beside the curated CVE ones. No effect on a fresh run with "
             "no prior corpus; the opt-out exists for cost control and "
             "byte-for-byte run comparison.",
    )
    ap.add_argument(
        "--prep-only", action="store_true",
        help="Skip LLM analysis; produce structured "
             "findings for external orchestration",
    )
    ap.add_argument(
        "--max-parallel", type=int, default=0,
        help="Max parallel dispatch threads (0 = auto from model RPM)",
    )
    ap.add_argument(
        "--no-exploits",
        action="store_true",
        help="Skip LLM exploit generation for exploitable findings.",
    )
    ap.add_argument(
        "--no-patches",
        action="store_true",
        help="Skip LLM patch generation for exploitable findings.",
    )

    model_group = ap.add_argument_group(
        "multi-model analysis",
        "When any of these flags are provided, findings are prepped then "
        "dispatched through the parallel orchestrator with role support.",
    )
    model_group.add_argument("--model", metavar="MODEL", action="append", default=[],
                             help="Analysis model (repeatable for multi-model)")
    model_group.add_argument("--consensus", metavar="MODEL",
                             help="Blind second opinion model")
    model_group.add_argument("--judge", metavar="MODEL",
                             help="Non-blind review model")
    model_group.add_argument("--aggregate", metavar="MODEL",
                             help="Final synthesis model for multi-model results")
    model_group.add_argument("--exploit-model", metavar="MODEL",
                             help="Model for PoC/patch generation (falls back to code model)")

    # IRIS Tier 2/3 deep-validate gate. Mirrors raptor_agentic.py.
    # Without these flags /analyze can never reach Tier 4 SMT
    # refinement on findings the orchestrator passed through —
    # the auto-enable on path_conditions is the only path most
    # operators take, so we want it here too.
    ap.add_argument(
        "--deep-validate",
        action="store_true",
        help="Force-enable Tier 2 / Tier 3 of IRIS validation for ALL "
             "findings: when Tier 1 is inconclusive, ask the LLM to write "
             "source+sink predicates and retry on compile errors. Costs "
             "LLM tokens. Without this flag, Tier 2/3 auto-enables per-"
             "finding when the LLM emits `path_conditions` (usage-driven "
             "default); pass --no-deep-validate to disable even that auto-"
             "enable path.",
    )
    ap.add_argument(
        "--no-deep-validate",
        action="store_true",
        help="Hard kill-switch: disable Tier 2 / Tier 3 entirely, including "
             "the default usage-driven auto-enable. Takes precedence over "
             "--deep-validate.",
    )
    ap.add_argument(
        "--context-expansion",
        action="store_true",
        help="Opt-in second look for explicitly uncertain verdicts "
             "(confidence=low, or a full verdict abstention): re-run "
             "the finding once with a doubled context window plus "
             "1-hop caller/callee context. The re-run replaces the "
             "verdict only when strictly more confident; both "
             "verdicts land in the finding's analysis record. "
             "Bounded per run — each expansion is one extra "
             "analysis call (see "
             "packages/llm_analysis/context_expansion.py for the "
             "trigger, join rule, and caps). Default off.",
    )
    ap.add_argument(
        "--context-toolloop",
        action="store_true",
        help="Opt-in bounded retrieval tool loop for explicitly "
             "uncertain verdicts: instead of the one-shot expansion "
             "the model may REQUEST specific extra context through a "
             "closed read-only vocabulary (read_span / list_callers / "
             "list_callees, repo-confined) over at most a fixed number "
             "of turns, then must verdict on what it has. Shares the "
             "per-run budget with --context-expansion and supersedes "
             "it when both are on (see "
             "packages/llm_analysis/context_toolloop.py for the "
             "vocabulary, caps, and refusal accounting). Default off.",
    )

    return ap
