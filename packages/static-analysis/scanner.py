#!/usr/bin/env python3
"""Automated Code Security Agent (Enhanced)
- Accepts a repo path or Git URL
- Supports --policy-groups (comma-separated list) to select rule categories
- Runs Semgrep across selected local rule directories IN PARALLEL
- Optionally runs CodeQL when --codeql is provided; requires codeql CLI and query packs
- Produces SARIF outputs and optional merged SARIF with deduplication
- Includes progress reporting and comprehensive metrics
- The output of this could be consumed by RAPTOR or other tools for further analysis for finding bugs/security issues
"""
import argparse
import json
import shutil
import sys
import tempfile
import time
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from core.config import RaptorConfig
from core.logging import get_logger
from core.sarif.parser import generate_scan_metrics
from core.git import clone_repository
from core.exec import run
from core.hash import sha256_tree
from core.semgrep import (
    semgrep_scan_parallel,
    semgrep_scan_sequential,
)

logger = get_logger()


def safe_clone(url: str, workdir: Path) -> Path:
    """Clone a git repository safely with URL validation."""
    repo_dir = workdir / "repo"
    clone_repository(url, repo_dir, depth=1)
    return repo_dir


# This is a WIP CodeQL runner; assumes codeql CLI is installed and query packs are available
# Expect this to change
def run_codeql(repo_path: Path, out_dir: Path, languages):
    out_dir.mkdir(parents=True, exist_ok=True)
    if shutil.which("codeql") is None:
        return []
    sarif_paths = []
    for lang in languages:
        db = out_dir / f"codeql-db-{lang}"
        sarif = out_dir / f"codeql_{lang}.sarif"
        # Database
        rc, so, se = run(
            ["codeql", "database", "create", str(db), "--language", lang, "--source-root", str(repo_path)],
            timeout=1800,
        )
        if rc != 0:
            continue
        # Queries
        query_dir = Path("codeql-queries") / lang
        if not query_dir.exists():
            continue
        rc, so, se = run(
            ["codeql", "query", "run", str(query_dir), "--database", str(db), "--output", str(sarif)],
            timeout=1800,
        )
        if rc == 0 and sarif.exists():
            sarif_paths.append(str(sarif))
    return sarif_paths



def main():
    ap = argparse.ArgumentParser(description="RAPTOR Automated Code Security Agent with parallel scanning")
    ap.add_argument("--repo", required=True, help="Path or Git URL")
    ap.add_argument("--policy_version", default=RaptorConfig.DEFAULT_POLICY_VERSION)
    ap.add_argument(
        "--policy_groups",
        default=RaptorConfig.DEFAULT_POLICY_GROUPS,
        help="Comma-separated list of rule group names (e.g. crypto,secrets,injection,auth,all)",
    )
    ap.add_argument("--codeql", action="store_true", help="Run CodeQL stage if available")
    ap.add_argument("--keep", action="store_true", help="Keep temp working directory")
    ap.add_argument("--sequential", action="store_true", help="Disable parallel scanning (for debugging)")
    args = ap.parse_args()

    start_time = time.time()
    tmp = Path(tempfile.mkdtemp(prefix="raptor_auto_"))
    repo_path = None

    logger.info(f"Starting automated code security scan")
    logger.info(f"Repository: {args.repo}")
    logger.info(f"Policy version: {args.policy_version}")
    logger.info(f"Policy groups: {args.policy_groups}")

    try:
        # Acquire repository
        if args.repo.startswith(("http://", "https://", "git@")):
            repo_path = safe_clone(args.repo, tmp)
        else:
            repo_path = Path(args.repo).resolve()
            if not repo_path.exists():
                raise RuntimeError(f"repository path does not exist: {repo_path}")

        # Determine local rule directories
        groups = [g.strip() for g in args.policy_groups.split(",") if g.strip()]
        rules_base = RaptorConfig.SEMGREP_RULES_DIR
        if "all" in groups:
            rules_dirs = [str(p) for p in sorted(rules_base.iterdir()) if p.is_dir()]
        else:
            rules_dirs = [str(rules_base / g) for g in groups]

        logger.info(f"Using {len(rules_dirs)} rule directories")

        # Generate output directory with repository name and timestamp
        repo_name = repo_path.name
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        out_dir = RaptorConfig.get_out_dir() / f"scan_{repo_name}_{timestamp}"
        out_dir.mkdir(parents=True, exist_ok=True)

        # Manifest
        logger.info("Computing repository hash...")
        repo_hash = sha256_tree(repo_path)

        manifest = {
            "agent": "auto_codesec",
            "version": "2.0.0",  # Updated version with parallel scanning
            "repo_path": str(repo_path),
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "input_hash": repo_hash,
            "policy_version": args.policy_version,
            "policy_groups": groups,
            "parallel_scanning": not args.sequential,
        }
        (out_dir / "scan-manifest.json").write_text(json.dumps(manifest, indent=2))

        # Semgrep stage - Use parallel scanning by default
        logger.info("Starting Semgrep scans...")
        if args.sequential:
            # Fallback to sequential for debugging
            logger.warning("Sequential scanning enabled (slower)")
            semgrep_sarifs = semgrep_scan_sequential(repo_path, rules_dirs, out_dir)
        else:
            semgrep_sarifs = semgrep_scan_parallel(repo_path, rules_dirs, out_dir)

        # CodeQL stage (optional)
        codeql_sarifs = []
        if args.codeql:
            # Basic language guess; you can make this dynamic later
            codeql_sarifs = run_codeql(repo_path, out_dir, languages=["java", "python", "go"])

        # Merge SARIFs if more than one
        sarif_inputs = semgrep_sarifs + codeql_sarifs
        merged = out_dir / "combined.sarif"
        if sarif_inputs:
            logger.info(f"Merging {len(sarif_inputs)} SARIF files...")
            # Use the shipped merge utility; all imports are module-scope
            merge_tool = RaptorConfig.ENGINE_DIR / "semgrep" / "tools" / "sarif_merge.py"
            rc, so, se = run(["python3", str(merge_tool), str(merged)] + sarif_inputs, timeout=300)
            if rc != 0:
                # Non-fatal: keep per-stage SARIFs
                logger.warning("SARIF merge failed, using individual files")
                (out_dir / "sarif_merge.stderr.log").write_text(se or "")
            else:
                logger.info(f"Merged SARIF created: {merged}")

        # Generate metrics
        logger.info("Generating scan metrics...")
        metrics = generate_scan_metrics(sarif_inputs)
        (out_dir / "scan_metrics.json").write_text(json.dumps(metrics, indent=2))

        logger.info(f"Scan complete: {metrics['total_findings']} findings in {metrics['total_files_scanned']} files")

        # Verification plan
        verification = {
            "verify": ["sarif_schema", "manifest_hash", "semgrep_exit_check"],
            "sarif_inputs": sarif_inputs,
            "metrics": metrics,
        }
        (out_dir / "verification.json").write_text(json.dumps(verification, indent=2))

        duration = time.time() - start_time
        logger.info(f"Total scan duration: {duration:.2f}s")

        result = {
            "status": "ok",
            "manifest": manifest,
            "sarif_inputs": sarif_inputs,
            "metrics": metrics,
            "duration": duration,
        }
        print(json.dumps(result, indent=2))
        sys.exit(0)
    finally:
        if not args.keep:
            try:
                shutil.rmtree(tmp)
            except Exception:
                pass


if __name__ == "__main__":
    main()


