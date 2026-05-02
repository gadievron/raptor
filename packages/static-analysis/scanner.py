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
import os
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, List, Optional, Tuple

# Add parent directory to path for imports
# packages/static-analysis/scanner.py -> repo root
sys.path.insert(0, str(Path(__file__).parents[2]))

from core.json import save_json
from core.config import RaptorConfig
from core.run.output import unique_run_suffix
from core.logging import get_logger
from core.git import clone_repository
from core.sarif.parser import generate_scan_metrics, validate_sarif
from core.hash import sha256_tree

logger = get_logger()


def run(cmd, cwd=None, timeout=RaptorConfig.DEFAULT_TIMEOUT, env=None,
        target=None, output=None, proxy_hosts=None, caller_label=None):
    """Execute a command in a network-isolated sandbox and return results.

    When `target` and `output` are supplied, Landlock is engaged — the
    child may read anywhere (Landlock default) but may only write to
    `output` and `/tmp`.

    Network policy:
      - Default (proxy_hosts=None): block_network=True at the user-ns
        layer. Child sees no interfaces at all.
      - proxy_hosts=[...] set: route outbound via the RAPTOR egress
        proxy with a hostname allowlist. Caller specifies which hosts
        are needed (`semgrep.dev` for registry pack fetches,
        `github.com`/`gitlab.com` for git clone, etc.). UDP blocked,
        DNS resolution delegated to the proxy. Net surface is strictly
        narrower than plain block_network=False and strictly wider
        than block_network=True.
    """
    from core.sandbox import run as sandbox_run
    net_kwargs = (
        {"use_egress_proxy": True, "proxy_hosts": list(proxy_hosts),
         "caller_label": caller_label or "scanner"}
        if proxy_hosts else
        {"block_network": True}
    )
    # tool_paths: speculative best-guess bind set so mount-ns isolation
    # can engage. For Python tools we need (a) the script's bin dir
    # and (b) the interpreter's stdlib dir at sys.prefix/lib/pythonX.Y.
    #
    # Outcome depends on the operator's install layout:
    #
    #   /usr/bin/semgrep (system install): cmd[0] already in mount
    #     tree, helper returns []; mount-ns engages cleanly, full
    #     isolation, silent.
    #
    #   ~/.local/bin/semgrep (pip --user) or /opt/homebrew/bin
    #     (brew): helper returns [bin_dir, stdlib_dir]; mount-ns
    #     tries with these. If semgrep then exec's native deps not
    #     in the bind set (semgrep-core, etc.), context.py's
    #     speculative-C retry catches the 126/empty-stderr and
    #     falls back to Landlock-only. Workflow proceeds; debug-
    #     level diagnostic only.
    tool_paths = _compute_python_tool_paths(cmd)
    p = sandbox_run(
        cmd,
        target=target,
        output=output,
        cwd=cwd,
        env=env or RaptorConfig.get_safe_env(),
        text=True,
        capture_output=True,
        timeout=timeout,
        tool_paths=tool_paths or None,
        **net_kwargs,
    )
    return p.returncode, p.stdout, p.stderr


def _compute_python_tool_paths(cmd) -> list:
    """Best-guess bind dirs for a Python-tool sandbox call.

    Reads cmd[0]'s shebang to find the interpreter, then computes:
      - script's bin dir (so cmd[0] resolves)
      - interpreter's bin dir (often same dir)
      - interpreter's stdlib dir, derived from interpreter path +
        version (e.g. /home/USER/bin/python3.13 →
        /home/USER/lib/python3.13)

    All paths are absolute. Skips dirs that already lie under a
    standard mount-ns bind prefix (/usr, /lib, etc.) — no point
    asking for a bind that's already there.

    Returns [] when cmd is empty, the shebang can't be read, or
    the layout doesn't match a recognisable Python install.
    Speculative: a wrong guess is caught by context.py's
    speculative-C retry (re-runs without tool_paths if the call
    exits 126/127 with empty stderr).
    """
    import re
    import sys
    from pathlib import Path
    if not cmd:
        return []
    cmd0 = cmd[0]
    # Prefix-skip set — paths already in the mount-ns bind tree.
    _SYS_PREFIXES = ("/usr/", "/lib/", "/lib64/", "/etc/", "/bin/", "/sbin/")
    def _interesting(p: str) -> bool:
        return p and not any(p == s.rstrip("/") or p.startswith(s)
                             for s in _SYS_PREFIXES)
    paths = set()
    # 1. Script's bin dir.
    if Path(cmd0).is_absolute():
        bin_dir = str(Path(cmd0).resolve().parent)
        if _interesting(bin_dir):
            paths.add(bin_dir)
    # 2. Read shebang to find the interpreter.
    interp = None
    try:
        with open(cmd0, "rb") as f:
            first_line = f.readline().decode("utf-8", errors="ignore").strip()
        if first_line.startswith("#!"):
            interp = first_line[2:].split()[0]
    except (OSError, IndexError, UnicodeDecodeError):
        pass
    # 3. Interpreter's bin dir + stdlib dir.
    # CRITICAL: use the UNRESOLVED interp path for stdlib computation,
    # NOT Path.resolve(). Python's sys.prefix is computed from the path
    # used to invoke the interpreter (i.e. sys.executable, which equals
    # the unresolved shebang path). For an interpreter at
    # /home/U/bin/python3.13 that's a symlink to /usr/bin/python3.13,
    # Python sets sys.prefix=/home/U and looks for stdlib at
    # /home/U/lib/python3.13. If we bind-mount the resolved location
    # (/usr/lib/python3.13 — already in mount tree) Python won't find
    # its stdlib because it's looking at sys.prefix-relative path.
    # The bin dir IS still added via Path.resolve() (so symlink targets
    # outside the mount tree get added too), but stdlib derivation
    # MUST follow the unresolved path.
    if interp and Path(interp).is_absolute() and Path(interp).is_file():
        # Bin dir for the interpreter. Add both the resolved AND
        # unresolved bin dirs so we cover the full symlink chain.
        for p in {str(Path(interp).parent), str(Path(interp).resolve().parent)}:
            if _interesting(p):
                paths.add(p)
        # Extract version from interpreter name. Try the SHEBANG name
        # first (typically `python3.13` — version-stamped); fall back
        # to the resolved name if the shebang name lacks a version.
        candidate_names = [Path(interp).name, Path(interp).resolve().name]
        ver = None
        for name in candidate_names:
            m = re.match(r"python(\d+\.\d+)", name)
            if m:
                ver = m.group(1)
                break
        if ver:
            # Stdlib at sys.prefix/lib/pythonX.Y where sys.prefix is
            # derived from the UNRESOLVED interp path (Python's view).
            stdlib = Path(interp).parent.parent / "lib" / f"python{ver}"
            if stdlib.is_dir() and _interesting(str(stdlib)):
                paths.add(str(stdlib))
    return sorted(paths)


def run_single_semgrep(
    name: str,
    config: str,
    repo_path: Path,
    out_dir: Path,
    timeout: int,
    progress_callback: Optional[Callable] = None
) -> Tuple[str, bool]:
    """
    Run a single Semgrep scan.

    Returns:
        Tuple of (sarif_path, success)
    """
    def sanitize_name(name: str) -> str:
        return name.replace("/", "_").replace(":", "_")

    suffix = sanitize_name(name)
    sarif = out_dir / f"semgrep_{suffix}.sarif"
    json_out = out_dir / f"semgrep_{suffix}.json"
    stderr_log = out_dir / f"semgrep_{suffix}.stderr.log"
    exit_file = out_dir / f"semgrep_{suffix}.exit"

    logger.debug(f"Starting Semgrep scan: {name}")

    if progress_callback:
        progress_callback(f"Scanning with {name}")

    # Use full path to semgrep to avoid broken venv installations
    semgrep_cmd = shutil.which("semgrep") or "/opt/homebrew/bin/semgrep"

    cmd = [
        semgrep_cmd,
        "scan",
        "--config", config,
        "--quiet",
        "--metrics", "off",
        "--error",
        "--sarif",
        "--json-output", str(json_out),
        "--timeout", str(RaptorConfig.SEMGREP_RULE_TIMEOUT),
        str(repo_path),
    ]

    # Create clean environment without venv contamination or dangerous vars
    clean_env = RaptorConfig.get_safe_env()
    clean_env.pop('VIRTUAL_ENV', None)
    clean_env.pop('PYTHONPATH', None)
    # Remove venv from PATH
    if 'PATH' in clean_env:
        path_parts = clean_env['PATH'].split(':')
        path_parts = [p for p in path_parts if 'venv' not in p.lower() and '/bin/pysemgrep' not in p]
        clean_env['PATH'] = ':'.join(path_parts)

    # Redirect HOME into the run's out_dir so semgrep's two stateful
    # files — semgrep.log (operational log) and settings.yml (metrics
    # opt-in, empty after first write) — land inside the sandbox
    # output rather than polluting the user's real ~/.semgrep.
    # semgrep 1.79.0 does NOT persistently cache registry packs on
    # disk — every invocation fetches the pack YAML from semgrep.dev
    # regardless of HOME / cache dir — so the redirect costs us
    # nothing (there's no cache to lose across scans). PR #196 ships
    # pack YAMLs under engine/semgrep/rules/registry-cache/ and
    # rewrites `p/security-audit` → local path BEFORE semgrep's
    # registry client runs — post-#196 the fetch path is cold.
    semgrep_home = out_dir / ".semgrep_home"
    semgrep_home.mkdir(parents=True, exist_ok=True)
    clean_env['HOME'] = str(semgrep_home)

    # Registry packs ("p/xxx", "category/xxx") fetch YAML from semgrep.dev
    # on every invocation — semgrep has no persistent on-disk cache. A slow
    # or stalled registry fetch otherwise consumes the full SEMGREP_TIMEOUT
    # (15 min) per pack, and at MAX_SEMGREP_WORKERS=4 can eat the whole
    # 30-min agentic budget for one bad network moment. Bound the per-pack
    # cost with a tighter ceiling so a stuck fetch drops that pack and the
    # remaining packs still run. Local rule directories keep the longer
    # timeout because they do real scan work without network.
    is_registry_pack = config.startswith("p/") or config.startswith("category/")
    effective_timeout = min(timeout, RaptorConfig.SEMGREP_PACK_TIMEOUT) if is_registry_pack else timeout

    try:
        # Engage Landlock via target + output. Writes pinned to out_dir
        # and /tmp. Reads Landlock-default-wide (semgrep is a
        # RAPTOR-chosen trusted tool, not attacker-controlled code).
        # Network: route via the egress proxy with semgrep.dev on the
        # allowlist — UDP blocked, hostname-allowlisted, resolved-IP-
        # screened by the proxy's is_global check.
        rc, so, se = run(
            cmd, timeout=effective_timeout, env=clean_env,
            target=str(repo_path), output=str(out_dir),
            proxy_hosts=["semgrep.dev", "registry.semgrep.dev",
                         "semgrep.app", "api.semgrep.dev"],
            caller_label="scanner-semgrep",
        )

        # Validate output
        if not so or not so.strip():
            logger.warning(f"Semgrep scan '{name}' produced empty output")
            so = '{"runs": []}'

        sarif.write_text(so)
        stderr_log.write_text(se or "")
        exit_file.write_text(str(rc))

        # Validate SARIF
        is_valid = validate_sarif(sarif)
        if not is_valid:
            logger.warning(f"Semgrep scan '{name}' produced invalid SARIF")

        success = rc in (0, 1) and is_valid
        logger.debug(f"Completed Semgrep scan: {name} (exit={rc}, valid={is_valid})")

        return str(sarif), success

    except Exception as e:
        logger.error(f"Semgrep scan '{name}' failed: {e}")
        # Write empty SARIF on error
        sarif.write_text('{"runs": []}')
        stderr_log.write_text(str(e))
        exit_file.write_text("-1")
        return str(sarif), False


def semgrep_scan_parallel(
    repo_path: Path,
    rules_dirs: List[str],
    out_dir: Path,
    timeout: int = RaptorConfig.SEMGREP_TIMEOUT,
    progress_callback: Optional[Callable] = None
) -> List[str]:
    """
    Run Semgrep scans in parallel for improved performance.

    Args:
        repo_path: Path to repository to scan
        rules_dirs: List of rule directory paths
        out_dir: Output directory for results
        timeout: Timeout per scan
        progress_callback: Optional callback for progress updates

    Returns:
        List of SARIF file paths
    """
    out_dir.mkdir(parents=True, exist_ok=True)

    # Build config list with BOTH local rules AND standard packs for each category
    configs: List[Tuple[str, str]] = []
    added_packs = set()  # Track which standard packs we've added to avoid duplicates

    # Add local rules + corresponding standard packs for each specified category
    for rd in rules_dirs:
        rd_path = Path(rd)
        if rd_path.exists():
            category_name = rd_path.name

            # Add local rules for this category
            configs.append((f"category_{category_name}", str(rd_path)))

            # Add corresponding standard pack if available
            if category_name in RaptorConfig.POLICY_GROUP_TO_SEMGREP_PACK:
                pack_name, pack_id = RaptorConfig.POLICY_GROUP_TO_SEMGREP_PACK[category_name]
                if pack_id not in added_packs:
                    resolved = RaptorConfig.get_semgrep_config(pack_id)
                    configs.append((pack_name, resolved))
                    added_packs.add(pack_id)
                    logger.debug(f"Added standard pack for {category_name}: {resolved}")
        else:
            logger.warning(f"Rule directory not found: {rd_path}")

    # Add baseline packs (unless already added)
    for pack_name, pack_identifier in RaptorConfig.BASELINE_SEMGREP_PACKS:
        if pack_identifier not in added_packs:
            configs.append((pack_name, RaptorConfig.get_semgrep_config(pack_identifier)))
            added_packs.add(pack_identifier)

    logger.info(f"Starting {len(configs)} Semgrep scans in parallel (max {RaptorConfig.MAX_SEMGREP_WORKERS} workers)")
    logger.info(f"  - Local rule directories: {len([c for c in configs if c[0].startswith('category_')])}")
    logger.info(f"  - Standard/baseline packs: {len([c for c in configs if not c[0].startswith('category_')])}")

    # Run scans in parallel
    sarif_paths: List[str] = []
    failed_scans: List[str] = []

    with ThreadPoolExecutor(max_workers=RaptorConfig.MAX_SEMGREP_WORKERS) as executor:
        future_to_config = {
            executor.submit(
                run_single_semgrep,
                name,
                config,
                repo_path,
                out_dir,
                timeout,
                progress_callback
            ): (name, config)
            for name, config in configs
        }

        completed = 0
        total = len(future_to_config)

        for future in as_completed(future_to_config):
            name, config = future_to_config[future]
            completed += 1

            try:
                sarif_path, success = future.result()
                sarif_paths.append(sarif_path)

                if not success:
                    failed_scans.append(name)

                if progress_callback:
                    progress_callback(f"Completed {completed}/{total} scans")

            except Exception as exc:
                logger.error(f"Semgrep scan '{name}' raised exception: {exc}")
                failed_scans.append(name)

    if failed_scans:
        logger.warning(f"Failed scans: {', '.join(failed_scans)}")

    logger.info(f"Completed {len(sarif_paths)} scans ({len(failed_scans)} failed)")
    return sarif_paths


def semgrep_scan_sequential(
    repo_path: Path,
    rules_dirs: List[str],
    out_dir: Path,
    timeout: int = RaptorConfig.SEMGREP_TIMEOUT
) -> List[str]:
    """Sequential scanning fallback for debugging."""
    out_dir.mkdir(parents=True, exist_ok=True)
    sarif_paths: List[str] = []

    # Build config list with BOTH local rules AND standard packs for each category
    configs: List[Tuple[str, str]] = []
    added_packs = set()  # Track which standard packs we've added to avoid duplicates

    # Add local rules + corresponding standard packs for each specified category
    for rd in rules_dirs:
        rd_path = Path(rd)
        if rd_path.exists():
            category_name = rd_path.name

            # Add local rules for this category
            configs.append((f"category_{category_name}", str(rd_path)))

            # Add corresponding standard pack if available
            if category_name in RaptorConfig.POLICY_GROUP_TO_SEMGREP_PACK:
                pack_name, pack_id = RaptorConfig.POLICY_GROUP_TO_SEMGREP_PACK[category_name]
                if pack_id not in added_packs:
                    resolved = RaptorConfig.get_semgrep_config(pack_id)
                    configs.append((pack_name, resolved))
                    added_packs.add(pack_id)

    # Add baseline packs (unless already added)
    for pack_name, pack_identifier in RaptorConfig.BASELINE_SEMGREP_PACKS:
        if pack_identifier not in added_packs:
            configs.append((pack_name, RaptorConfig.get_semgrep_config(pack_identifier)))
            added_packs.add(pack_identifier)

    for idx, (name, config) in enumerate(configs, 1):
        logger.info(f"Running scan {idx}/{len(configs)}: {name}")
        sarif_path, success = run_single_semgrep(name, config, repo_path, out_dir, timeout)
        sarif_paths.append(sarif_path)

    return sarif_paths


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
    ap.add_argument("--out", default=None, help="Output directory (from lifecycle). Overrides auto-generated path.")

    from core.sandbox import add_cli_args, apply_cli_args
    add_cli_args(ap)
    args = ap.parse_args()
    apply_cli_args(args)

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
            repo_path = tmp / "repo"
            clone_repository(args.repo, repo_path)
        else:
            repo_path = Path(args.repo).resolve()
            if not repo_path.exists():
                raise RuntimeError(f"repository path does not exist: {repo_path}")

        # Determine local rule directories
        groups = [g.strip() for g in args.policy_groups.split(",") if g.strip()]
        rules_base = RaptorConfig.SEMGREP_RULES_DIR
        _EXCLUDED_RULE_DIRS = {"registry-cache"}
        if "all" in groups:
            rules_dirs = [
                str(p) for p in sorted(rules_base.iterdir())
                if p.is_dir() and p.name not in _EXCLUDED_RULE_DIRS
            ]
        else:
            valid, unknown = [], []
            for g in groups:
                p = rules_base / g
                if g in _EXCLUDED_RULE_DIRS:
                    logger.warning(f"Policy group '{g}' is reserved and cannot be used directly")
                elif p.is_dir():
                    valid.append(str(p))
                else:
                    unknown.append(g)
            if unknown:
                logger.warning(f"Unknown policy groups (no rule directory found): {', '.join(unknown)}")
            rules_dirs = valid

        logger.info(f"Using {len(rules_dirs)} rule directories")

        # Output directory: use --out if provided (lifecycle), otherwise generate
        if args.out:
            out_dir = Path(args.out)
        else:
            repo_name = repo_path.name
            # Collision-prevention via unique_run_suffix — see core/run/output.py.
            out_dir = RaptorConfig.get_out_dir() / f"scan_{repo_name}_{unique_run_suffix('_')}"
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
        save_json(out_dir / "scan-manifest.json", manifest)

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
            codeql_sarifs = run_codeql(repo_path, out_dir, languages=["cpp", "java", "python", "go"])

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
        save_json(out_dir / "scan_metrics.json", metrics)

        logger.info(f"Scan complete: {metrics['total_findings']} findings in {metrics['total_files_scanned']} files")

        # Write coverage records and derive total_files_scanned from them
        try:
            from core.coverage.record import (
                build_from_semgrep, build_from_codeql, write_record, load_records,
            )
            # Semgrep coverage — find JSON outputs alongside SARIFs
            for sarif_path in semgrep_sarifs:
                json_path = Path(sarif_path).with_suffix(".json")
                if json_path.exists():
                    record = build_from_semgrep(
                        out_dir, json_path,
                        rules_applied=groups if groups else [str(Path(r).name) for r in rules_dirs],
                    )
                    if record:
                        write_record(out_dir, record, tool_name="semgrep")
                        break  # one record covers all (paths.scanned is cumulative)

            # CodeQL coverage — from SARIF artifacts
            for sarif_path in codeql_sarifs:
                record = build_from_codeql(Path(sarif_path))
                if record:
                    write_record(out_dir, record, tool_name="codeql")
                    break  # one record per run

            # Derive total_files_scanned from coverage records — these are
            # the canonical source of what was examined (not SARIF artifacts,
            # which Semgrep doesn't populate).
            all_covered = set()
            for rec in load_records(out_dir):
                all_covered.update(rec.get("files_examined", []))
            if all_covered:
                metrics["total_files_scanned"] = len(all_covered)
                save_json(out_dir / "scan_metrics.json", metrics)
        except Exception as e:
            logger.debug(f"Coverage record write failed (non-fatal): {e}")

        # Verification plan
        verification = {
            "verify": ["sarif_schema", "manifest_hash", "semgrep_exit_check"],
            "sarif_inputs": sarif_inputs,
            "metrics": metrics,
        }
        save_json(out_dir / "verification.json", verification)

        duration = time.time() - start_time
        logger.info(f"Total scan duration: {duration:.2f}s")

        # Print coverage summary if checklist exists
        try:
            from core.coverage.summary import compute_summary, format_summary
            cov = compute_summary(out_dir)
            if cov:
                print()
                print(format_summary(cov))
                print()
        except Exception:
            pass

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
