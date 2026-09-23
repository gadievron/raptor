#!/usr/bin/env python3
"""
RAPTOR OpenAnt Workflow

Runs OpenAnt (AST + LLM source-code vulnerability scanner) against a
repository and translates the results into the standard Raptor finding
schema for downstream validation and analysis.

Usage:
    raptor_openant.py --repo /path/to/code [options]
    python3 raptor.py openant --repo /path/to/code [options]
"""

import argparse
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.json import save_json
from core.logging import get_logger
from core.security.cc_trust import check_repo_claude_trust
from core.security.log_sanitisation import sanitise_for_terminal as _sft
from core.security.markdown_render import md_fence, md_inline, md_prose

logger = get_logger()

_BASE = Path(__file__).parent

# Report render order for finding levels; anything outside the known
# universe sorts last (kept visible, never dropped).
_LEVEL_RANK = {"error": 0, "warning": 1, "note": 2}


def _positive_int(value: str) -> int:
    """argparse type for caps that must be >= 1 (``type=int`` accepted
    negative values and silently sliced findings off the END)."""
    n = int(value)
    if n < 1:
        raise argparse.ArgumentTypeError(
            f"must be a positive integer, got {value}")
    return n


def _report_selection(findings: list, max_findings: int) -> list:
    """The report's severity-first cut: every error-level finding
    outranks every warning, which outranks every note; original order
    is kept within a level (stable sort). The pipeline-order slice
    this replaces dropped whatever OpenAnt emitted LAST — including
    confirmed error-level findings — while the header claimed the
    full count."""
    ranked = sorted(
        findings,
        key=lambda f: _LEVEL_RANK.get(f.get("level"), len(_LEVEL_RANK)),
    )
    return ranked[:max_findings]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="OpenAnt LLM-powered source-code vulnerability scan",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--repo",
        # No env default: raptor.py back-fills --repo through
        # resolve_default_target (active project target, then the
        # vetted caller dir with the volatile-target gate) like every
        # sibling analysis command. A raw RAPTOR_CALLER_DIR default
        # here bypassed both the project target and the gate.
        help="Path to repository to scan (required; back-filled from "
             "the active project / caller dir when run via raptor.py)",
    )
    parser.add_argument("--out", help="Output directory (injected by raptor.py lifecycle)")
    from packages.openant.config import env_choice

    parser.add_argument(
        "--model",
        # Documented operator knob: $OPENANT_MODEL seeds the default,
        # the explicit flag always wins. env_choice validates the env
        # value itself — argparse does NOT check string defaults
        # against choices, so an unvalidated env default would let a
        # typo'd knob silently steer the run.
        default=env_choice("OPENANT_MODEL", ("opus", "sonnet"), "sonnet"),
        choices=["opus", "sonnet"],
        help="OpenAnt LLM model (default: $OPENANT_MODEL or sonnet)",
    )
    parser.add_argument(
        "--level",
        default=env_choice(
            "OPENANT_LEVEL",
            ("all", "reachable", "codeql", "exploitable"),
            "reachable",
        ),
        choices=["all", "reachable", "codeql", "exploitable"],
        help="Analysis depth (default: $OPENANT_LEVEL or reachable)",
    )
    parser.add_argument("--no-enhance", action="store_true", help="Skip OpenAnt enhance phase")
    parser.add_argument("--verify", action="store_true", help="Enable OpenAnt stage-2 verification")
    parser.add_argument(
        "--language",
        default="auto",
        help="Override language detection (default: auto)",
    )
    parser.add_argument(
        "--openant-core",
        # default=None, NOT the env value: the flag is the consent-
        # gated surface (pre-approved argv), the env var is the
        # operator-owned default. main() back-fills $OPENANT_CORE
        # after the gate has seen whether the flag was explicit.
        default=None,
        help="Path to openant-core directory (default: $OPENANT_CORE). "
             "A core that is not a clean checkout of the pinned "
             "commit refuses at startup unless consented (see "
             "--openant-core-unpinned)",
    )
    parser.add_argument(
        "--openant-core-unpinned",
        action="store_true",
        help="Consent to run a --openant-core checkout that is not a "
             "clean checkout of the pinned commit — wrong commit, "
             "modified/untracked files at the pin, or unverifiable "
             "provenance (unverified external code executes with "
             "network access); the project 'config' trust marker "
             "grants the same standing consent",
    )
    parser.add_argument(
        "--max-findings",
        type=_positive_int,
        default=50,
        help="Maximum findings rendered in the markdown report, "
             "severity-first (default: 50). The openant_findings.json "
             "artifact is never capped — downstream merge/validation "
             "consumes it in full",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="OpenAnt parallel workers (default: 4)",
    )

    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if not args.repo:
        parser.error("--repo is required")
    repo_path = Path(args.repo).resolve()
    if not repo_path.exists():
        parser.error(f"--repo path does not exist: {repo_path}")

    # ------------------------------------------------------------------
    # --openant-core consent gate (flag surface only): refuse a
    # non-pinned core named on argv unless consented. Runs BEFORE the
    # output dir / lifecycle exist — a refused run leaves nothing
    # behind. The env / auto-detect default keeps warn-not-refuse.
    # ------------------------------------------------------------------
    openant_core_explicit = args.openant_core is not None
    if args.openant_core is None:
        args.openant_core = os.environ.get("OPENANT_CORE") or None
    if openant_core_explicit:
        from packages.openant.scanner import (
            OpenAntCoreConsentError,
            enforce_core_consent,
        )
        try:
            enforce_core_consent(
                Path(args.openant_core),
                consented=args.openant_core_unpinned,
                target_path=str(repo_path),
            )
        except OpenAntCoreConsentError as e:
            print(f"\n✗ {e}", file=sys.stderr)
            return 2

    # ------------------------------------------------------------------
    # Output directory: injected by raptor.py lifecycle; fall back to our
    # own timestamped directory so we can run standalone too.
    # ------------------------------------------------------------------
    if args.out:
        out_dir = Path(args.out)
    else:
        from core.run.output import get_output_dir
        out_dir = get_output_dir("openant", target_path=str(repo_path))
    out_dir.mkdir(parents=True, exist_ok=True)

    # Lifecycle (best-effort; raptor.py manages the outer lifecycle)
    try:
        from core.run import start_run
        start_run(out_dir, "openant", target=str(repo_path))
    except Exception as e:
        logger.debug(f"Run metadata: {e}")

    workflow_start = time.time()

    logger.info("=" * 70)
    logger.info("RAPTOR OPENANT WORKFLOW STARTED")
    logger.info("=" * 70)
    logger.info(f"Repository: {repo_path}")
    logger.info(f"Output:     {out_dir}")
    logger.info(f"Model:      {args.model}")
    logger.info(f"Level:      {args.level}")

    # ------------------------------------------------------------------
    # Trust check — scan a potentially untrusted repo
    # ------------------------------------------------------------------
    # Advisory by design: the openant pipeline never dispatches Claude
    # Code against the repo (packages/openant is API-transport only),
    # so there is no CC dispatch here for the verdict to gate — the
    # danger report (or the cannot-examine refusal line) prints for
    # the operator, and the CC-dispatching consumers of openant
    # findings re-check at their own dispatch sites. If openant ever
    # grows a CC dispatch path, gate it on this verdict — the
    # structural pin in .github/tests/test_openant_cc_advisory_pin.py
    # fails first.
    cc_blocked = check_repo_claude_trust(repo_path)
    if cc_blocked:
        logger.warning(
            "cc-trust verdict is blocking for this repo — advisory "
            "here (openant performs no Claude Code dispatch); "
            "CC-dispatching consumers re-check at their own sites")

    # ------------------------------------------------------------------
    # Build OpenAnt config
    # ------------------------------------------------------------------
    try:
        from packages.openant import get_config, run_openant_scan, translate_pipeline_output
        from packages.openant.config import OpenAntConfig

        if args.openant_core:
            oa_config = OpenAntConfig(core_path=Path(args.openant_core))
        else:
            oa_config = get_config(raptor_dir=_BASE)

        oa_config.model = args.model
        oa_config.level = args.level
        oa_config.enhance = not args.no_enhance
        oa_config.verify = args.verify
        oa_config.language = args.language
        oa_config.workers = args.workers

    except RuntimeError as e:
        # Not configured: OpenAnt is an optional add-on, so a missing
        # openant-core checkout is a documented skip (exit 0, run
        # completes), clearly distinct from a scan that RAN and failed
        # (hard error, exit 1 below).
        print(f"\n⚠️  OpenAnt not available: {_sft(str(e))}")
        print("  Set OPENANT_CORE to the openant-core directory path.")
        _write_empty_report(out_dir, repo_path, str(e))
        return 0

    # ------------------------------------------------------------------
    # PHASE 1: OPENANT SCAN
    # ------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("OPENANT SCAN")
    print("=" * 70)

    oa_out = out_dir / "openant_scan"
    oa_out.mkdir(exist_ok=True)

    try:
        scan_result = run_openant_scan(
            repo_path=str(repo_path),
            out_dir=str(oa_out),
            config=oa_config,
        )
    except RuntimeError as e:
        # Not-configured discovered at subprocess-env build time (the
        # core path vanished or is not an openant-core tree) — same
        # skip semantics as the discovery failure above.
        print(f"\n⚠️  OpenAnt not available: {_sft(str(e))}")
        _write_empty_report(out_dir, repo_path, str(e))
        return 0

    if scan_result.get("skipped"):
        error = scan_result.get("error", "unknown error")
        if scan_result.get("hard_error"):
            # The scan was attempted and failed (timeout, launch
            # failure, exit >= 2, missing pipeline output). Exit
            # non-zero so the lifecycle records a failed run — an
            # empty-findings exit 0 here would be indistinguishable
            # from a target that scanned clean.
            print(f"\n✗ OpenAnt scan failed: {_sft(error)}", file=sys.stderr)
            _write_empty_report(out_dir, repo_path, error)
            return 1
        print(f"\n⚠️  OpenAnt scan skipped: {_sft(error)}")
        _write_empty_report(out_dir, repo_path, error)
        return 0

    pipeline_output = scan_result.get("pipeline_output") or {}
    raw_findings = pipeline_output.get("findings") or []
    print(f"\n✓ OpenAnt scan complete: {len(raw_findings)} raw finding(s)")

    # ------------------------------------------------------------------
    # PHASE 2: TRANSLATE TO RAPTOR FINDING SCHEMA
    # ------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("TRANSLATING FINDINGS")
    print("=" * 70)

    translated = translate_pipeline_output(pipeline_output)
    print(f"✓ Translated: {len(translated)} finding(s) after suppression")

    # The durable artifact is NEVER capped: openant_findings.json is
    # what /validate, project merged views and cross-run correlation
    # consume, and the /agentic lane saves it uncapped — a capped
    # artifact silently lost findings (severity-blind, in pipeline
    # order) from every downstream view while every count surface
    # claimed the full total. --max-findings caps only the markdown
    # report below.
    findings_path = out_dir / "openant_findings.json"
    save_json(findings_path, translated)

    # ------------------------------------------------------------------
    # FINAL REPORT
    # ------------------------------------------------------------------
    duration = time.time() - workflow_start

    final_report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "repository": str(repo_path),
        "duration_seconds": round(duration, 2),
        "config": {
            "model": oa_config.model,
            "level": oa_config.level,
            "enhance": oa_config.enhance,
            "verify": oa_config.verify,
            "language": oa_config.language,
            "core_provenance": scan_result.get("core_provenance") or {},
        },
        "phases": {
            "openant_scan": {
                "completed": True,
                "raw_findings": len(raw_findings),
                "translated_findings": len(translated),
                "report_findings": min(len(translated), args.max_findings),
                "report_truncated": max(0, len(translated) - args.max_findings),
                "pipeline_output_path": str(scan_result.get("pipeline_output_path") or ""),
            },
        },
        "outputs": {
            "openant_findings": str(findings_path),
            "pipeline_output": str(oa_out / "pipeline_output.json"),
        },
    }

    report_path = out_dir / "raptor_openant_report.json"
    save_json(report_path, final_report)

    _write_markdown_report(
        out_dir, translated, repo_path, duration,
        max_findings=args.max_findings,
    )

    print("\n" + "=" * 70)
    print("OPENANT WORKFLOW COMPLETE")
    print("=" * 70)
    print(f"\n  Findings:  {len(translated)}")
    print(f"  Duration:  {duration:.1f}s")
    print(f"  Output:    {out_dir}")
    print(f"  Report:    {report_path}")

    return 0


def _write_empty_report(out_dir: Path, repo_path: Path, error: str) -> None:
    save_json(out_dir / "openant_findings.json", [])
    save_json(out_dir / "raptor_openant_report.json", {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "repository": str(repo_path),
        "error": error,
        "phases": {"openant_scan": {"completed": False, "error": error}},
        "outputs": {"openant_findings": str(out_dir / "openant_findings.json")},
    })


def _write_markdown_report(
    out_dir: Path,
    findings: list,
    repo_path: Path,
    duration: float,
    max_findings: int | None = None,
) -> None:
    # Every finding-derived value below is hostile-influenced: snippet
    # is verbatim target code (a repo being scanned is untrusted),
    # message / vuln_name are OpenAnt LLM output that can quote target
    # text, and file / function come from the scanned tree. Markdown
    # slots route through core.security.markdown_render so an embedded
    # ``` cannot terminate the snippet fence and inject live markdown
    # (autofetch links, forged headings, prompt text for a later LLM
    # pass reading the report) into openant-report.md.
    total = len(findings)
    if max_findings is not None and total > max_findings:
        findings = _report_selection(findings, max_findings)
    lines = [
        "# OpenAnt Vulnerability Report",
        "",
        f"**Repository:** `{md_inline(repo_path)}`  ",
        f"**Duration:** {duration:.1f}s  ",
        f"**Findings:** {total}",
        "",
    ]
    if len(findings) < total:
        # Fail-toward-visibility: the truncation is stated, the true
        # total stays in the header, and the cut is severity-first.
        lines += [
            f"**Report truncated:** showing the top {len(findings)} of "
            f"{total} finding(s) by severity (--max-findings "
            f"{max_findings}); the full set is in "
            f"openant_findings.json.",
            "",
        ]
    lines += [
        "---",
        "",
    ]

    if not findings:
        lines.append("No findings after suppression.")
    else:
        by_level = {"error": [], "warning": [], "note": []}
        for f in findings:
            lvl = f.get("level", "note")
            by_level.setdefault(lvl, []).append(f)

        for lvl, label in [("error", "High"), ("warning", "Medium"), ("note", "Low/Informational")]:
            group = by_level.get(lvl, [])
            if not group:
                continue
            lines.append(f"## {label} ({len(group)})")
            lines.append("")
            for f in group:
                meta = f.get("metadata") or {}
                lines.append(
                    f"### {md_inline(f.get('cwe_id') or 'Unknown')} — "
                    f"{md_inline(meta.get('vuln_name', ''))} "
                    f"[{md_inline(f.get('finding_id', ''))}]"
                )
                lines.append("")
                lines.append(f"**File:** `{md_inline(f.get('file', ''))}` — `{md_inline(meta.get('function', ''))}`  ")
                lines.append(
                    f"**Stage 1:** {md_inline(meta.get('stage1_verdict', ''))} / "
                    f"**Stage 2:** {md_inline(meta.get('stage2_verdict', '') or 'n/a')}  "
                )
                lines.append("")
                if f.get("message"):
                    lines.append(md_prose(f.get("message", "")))
                    lines.append("")
                if f.get("snippet"):
                    lines.append("```")
                    lines.append(md_fence(f.get("snippet", "")))
                    lines.append("```")
                    lines.append("")

    out_dir.joinpath("openant-report.md").write_text("\n".join(lines))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted")
        sys.exit(130)
    except Exception as e:
        print(f"\n✗ Fatal error: {_sft(str(e))}")
        import traceback
        # The traceback's last line re-renders the raw exception text
        # (which can quote hostile target content) — escape every
        # line; the per-line loop keeps the frames readable.
        for _tb_line in traceback.format_exc().splitlines():
            print(_sft(_tb_line, max_len=400), file=sys.stderr)
        sys.exit(1)
