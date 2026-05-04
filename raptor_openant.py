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

sys.path.insert(0, str(Path(__file__).parent))

from core.json import load_json, save_json
from core.config import RaptorConfig
from core.logging import get_logger
from core.security.cc_trust import check_repo_claude_trust

logger = get_logger()

_BASE = Path(__file__).parent


def main() -> int:
    parser = argparse.ArgumentParser(
        description="OpenAnt LLM-powered source-code vulnerability scan",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--repo",
        default=os.environ.get("RAPTOR_CALLER_DIR"),
        help="Path to repository to scan (required)",
    )
    parser.add_argument("--out", help="Output directory (injected by raptor.py lifecycle)")
    parser.add_argument(
        "--model",
        default="sonnet",
        choices=["opus", "sonnet"],
        help="OpenAnt LLM model (default: sonnet)",
    )
    parser.add_argument(
        "--level",
        default="reachable",
        choices=["all", "reachable", "codeql", "exploitable"],
        help="Analysis depth (default: reachable)",
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
        default=os.environ.get("OPENANT_CORE"),
        help="Path to openant-core directory (default: $OPENANT_CORE)",
    )
    parser.add_argument(
        "--max-findings",
        type=int,
        default=50,
        help="Maximum findings to include in report (default: 50)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="OpenAnt parallel workers (default: 4)",
    )

    args = parser.parse_args()

    if not args.repo:
        parser.error("--repo is required")
    repo_path = Path(args.repo).resolve()
    if not repo_path.exists():
        parser.error(f"--repo path does not exist: {repo_path}")

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
    check_repo_claude_trust(repo_path)

    # ------------------------------------------------------------------
    # Build OpenAnt config
    # ------------------------------------------------------------------
    try:
        from packages.openant import get_config, is_available, run_openant_scan, translate_pipeline_output
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
        print(f"\n✗ OpenAnt not available: {e}")
        print("  Set OPENANT_CORE to the openant-core directory path.")
        _write_empty_report(out_dir, repo_path, str(e))
        return 1

    # ------------------------------------------------------------------
    # PHASE 1: OPENANT SCAN
    # ------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("OPENANT SCAN")
    print("=" * 70)

    oa_out = out_dir / "openant_scan"
    oa_out.mkdir(exist_ok=True)

    scan_result = run_openant_scan(
        repo_path=str(repo_path),
        out_dir=str(oa_out),
        config=oa_config,
    )

    if scan_result.get("skipped"):
        print(f"\n⚠️  OpenAnt scan skipped: {scan_result.get('error', 'unknown error')}")
        _write_empty_report(out_dir, repo_path, scan_result.get("error", ""))
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

    translated = translate_pipeline_output(pipeline_output, str(repo_path))
    print(f"✓ Translated: {len(translated)} finding(s) after suppression")

    findings_path = out_dir / "openant_findings.json"
    save_json(findings_path, translated[:args.max_findings])

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
        },
        "phases": {
            "openant_scan": {
                "completed": True,
                "raw_findings": len(raw_findings),
                "translated_findings": len(translated),
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

    _write_markdown_report(out_dir, translated[:args.max_findings], repo_path, duration)

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
) -> None:
    lines = [
        "# OpenAnt Vulnerability Report",
        "",
        f"**Repository:** `{repo_path}`  ",
        f"**Duration:** {duration:.1f}s  ",
        f"**Findings:** {len(findings)}",
        "",
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
                lines.append(f"### {f.get('cwe_id', 'Unknown')} — {meta.get('vuln_name', '')} [{f.get('finding_id', '')}]")
                lines.append("")
                lines.append(f"**File:** `{f.get('file', '')}` — `{meta.get('function', '')}`  ")
                lines.append(f"**Stage 1:** {meta.get('stage1_verdict', '')} / **Stage 2:** {meta.get('stage2_verdict', '') or 'n/a'}  ")
                lines.append("")
                if f.get("message"):
                    lines.append(f.get("message", ""))
                    lines.append("")
                if f.get("snippet"):
                    lines.append("```")
                    lines.append(f.get("snippet", ""))
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
        print(f"\n✗ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
