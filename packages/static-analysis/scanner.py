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
import re
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, List, Optional, Tuple

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from core.config import RaptorConfig
from core.logging import get_logger
from core.sarif.parser import generate_scan_metrics, validate_sarif

logger = get_logger()


def run(cmd, cwd=None, timeout=RaptorConfig.DEFAULT_TIMEOUT, env=None):
    """Execute a command and return results."""
    p = subprocess.run(
        cmd,
        cwd=cwd,
        env=env or os.environ.copy(),
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    return p.returncode, p.stdout, p.stderr


def validate_repo_url(url: str) -> bool:
    """Validate repository URL against allowed patterns."""
    allowed_patterns = [
        r'^https://github\.com/[\w\-]+/[\w.\-]+/?$',
        r'^https://gitlab\.com/[\w\-]+/[\w.\-]+/?$',
        r'^git@github\.com:[\w\-]+/[\w.\-]+\.git$',
        r'^git@gitlab\.com:[\w\-]+/[\w.\-]+\.git$',
    ]

    return any(re.match(pattern, url) for pattern in allowed_patterns)


def safe_clone(url: str, workdir: Path) -> Path:
    """Clone a git repository safely with URL validation."""
    # Validate URL
    if not validate_repo_url(url):
        logger.log_security_event(
            "invalid_repo_url",
            f"Rejected potentially unsafe repository URL: {url}"
        )
        raise ValueError(f"Invalid or untrusted repository URL: {url}")

    repo_dir = workdir / "repo"
    env = RaptorConfig.get_git_env()

    logger.info(f"Cloning repository: {url}")
    rc, so, se = run(
        ["git", "clone", "--depth", "1", "--no-tags", url, str(repo_dir)],
        timeout=RaptorConfig.GIT_CLONE_TIMEOUT,
        env=env,
    )
    if rc != 0:
        raise RuntimeError(f"git clone failed: {se.strip() or so.strip()}")

    logger.info(f"Repository cloned successfully to {repo_dir}")
    return repo_dir

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
        "--timeout", str(RaptorConfig.SEMGREP_RULE_TIMEOUT),
        str(repo_path),
    ]

    # Create clean environment without venv contamination
    clean_env = os.environ.copy()
    clean_env.pop('VIRTUAL_ENV', None)
    clean_env.pop('PYTHONPATH', None)
    # Remove venv from PATH
    if 'PATH' in clean_env:
        path_parts = clean_env['PATH'].split(':')
        path_parts = [p for p in path_parts if 'venv' not in p.lower() and '/bin/pysemgrep' not in p]
        clean_env['PATH'] = ':'.join(path_parts)

    try:
        rc, so, se = run(cmd, timeout=timeout, env=clean_env)

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
                    configs.append((pack_name, pack_id))
                    added_packs.add(pack_id)
                    logger.debug(f"Added standard pack for {category_name}: {pack_id}")
        else:
            logger.warning(f"Rule directory not found: {rd_path}")

    # Add baseline packs (unless already added)
    for pack_name, pack_identifier in RaptorConfig.BASELINE_SEMGREP_PACKS:
        if pack_identifier not in added_packs:
            configs.append((pack_name, pack_identifier))
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
                    configs.append((pack_name, pack_id))
                    added_packs.add(pack_id)

    # Add baseline packs (unless already added)
    for pack_name, pack_identifier in RaptorConfig.BASELINE_SEMGREP_PACKS:
        if pack_identifier not in added_packs:
            configs.append((pack_name, pack_identifier))
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


# ELF e_machine values → architecture name
_ELF_ARCH = {
    0x03: "x86",
    0x08: "mips",
    0x28: "arm",
    0x3E: "x86_64",
    0xB7: "aarch64",
    0xF3: "riscv",
}

# Filename substrings that indicate high-value targets in firmware
_HIGH_VALUE_NAMES = (
    "httpd", "lighttpd", "uhttpd", "nginx", "apache",
    "cgi", "telnetd", "sshd", "dropbear", "busybox",
    "upnpd", "miniupnpd", "boa", "goahead",
    "nvram", "cfgd", "ated", "wpa_supplicant",
)


def _elf_arch(path: Path) -> Optional[str]:
    """Return architecture string from ELF e_machine field, or None if not ELF."""
    try:
        header = path.read_bytes()[:20]
    except Exception:
        return None
    if header[:4] != b'\x7fELF':
        return None
    # e_machine is bytes 18-19, little-endian for LE targets, big-endian for BE
    # Try LE first; MIPS BE will still be identified by value
    e_machine = int.from_bytes(header[18:20], "little")
    arch = _ELF_ARCH.get(e_machine)
    if arch is None:
        # Try big-endian (MIPS EB, some MIPS variants)
        e_machine_be = int.from_bytes(header[18:20], "big")
        arch = _ELF_ARCH.get(e_machine_be, f"unknown(0x{e_machine:04x})")
    return arch


def _interest_score(name: str) -> int:
    """Score a binary filename by security interest (higher = more interesting)."""
    name_lower = name.lower()
    for substr in _HIGH_VALUE_NAMES:
        if substr in name_lower:
            return 10
    if name_lower.endswith(".cgi"):
        return 10
    if any(x in name_lower for x in ("web", "http", "net", "wan", "lan")):
        return 5
    return 1


def inventory_firmware(firmware_root: Path) -> dict:
    """
    Walk an extracted firmware root, find all ELF binaries, and return an
    inventory sorted by interest score then size.

    Returns a dict with:
      - binaries: list of {path, size_bytes, arch, interest_score}
      - detected_arch: most common architecture across all ELFs (or "unknown")
      - total_elfs: count
      - high_value_targets: subset with interest_score >= 10
    """
    binaries = []
    arch_counts: dict = {}

    for p in sorted(firmware_root.rglob("*")):
        if not p.is_file():
            continue
        arch = _elf_arch(p)
        if arch is None:
            continue
        size = p.stat().st_size
        score = _interest_score(p.name)
        binaries.append({
            "path": str(p.relative_to(firmware_root)),
            "size_bytes": size,
            "arch": arch,
            "interest_score": score,
        })
        arch_counts[arch] = arch_counts.get(arch, 0) + 1

    binaries.sort(key=lambda x: (-x["interest_score"], -x["size_bytes"]))

    detected_arch = max(arch_counts, key=arch_counts.get) if arch_counts else "unknown"

    return {
        "binaries": binaries,
        "detected_arch": detected_arch,
        "total_elfs": len(binaries),
        "high_value_targets": [b for b in binaries if b["interest_score"] >= 10],
    }


def sha256_tree(root: Path) -> str:
    """Hash directory tree with size limits and consistent chunk size."""
    import hashlib
    h = hashlib.sha256()
    skipped_files = []

    for p in sorted(root.rglob("*")):
        if p.is_file():
            stat = p.stat()
            # Skip very large files
            if stat.st_size > RaptorConfig.MAX_FILE_SIZE_FOR_HASH:
                skipped_files.append(str(p.relative_to(root)))
                continue

            h.update(p.relative_to(root).as_posix().encode())
            with p.open("rb") as f:
                for chunk in iter(lambda: f.read(RaptorConfig.HASH_CHUNK_SIZE), b""):
                    h.update(chunk)

    if skipped_files:
        logger.debug(f"Skipped {len(skipped_files)} large files during hashing")

    return h.hexdigest()

def main():
    ap = argparse.ArgumentParser(description="RAPTOR Automated Code Security Agent with parallel scanning")

    # Source — one of --repo or --firmware-root is required
    source_group = ap.add_mutually_exclusive_group(required=True)
    source_group.add_argument("--repo", help="Source code path or Git URL")
    source_group.add_argument(
        "--firmware-root",
        metavar="PATH",
        help="Extracted firmware filesystem root (enables firmware scan mode)",
    )

    ap.add_argument("--policy_version", default=RaptorConfig.DEFAULT_POLICY_VERSION)
    ap.add_argument(
        "--policy_groups",
        default=None,
        help=(
            "Comma-separated rule groups (e.g. crypto,secrets,injection,all). "
            "Defaults to 'firmware,injection,secrets' in firmware mode, "
            f"'{RaptorConfig.DEFAULT_POLICY_GROUPS}' otherwise."
        ),
    )
    ap.add_argument("--codeql", action="store_true", help="Run CodeQL stage if available")
    ap.add_argument("--keep", action="store_true", help="Keep temp working directory")
    ap.add_argument("--sequential", action="store_true", help="Disable parallel scanning (for debugging)")
    ap.add_argument("--output", metavar="PATH", help="Explicit output directory (auto-generated if omitted)")

    # Firmware-mode options
    ap.add_argument(
        "--arch",
        default="auto",
        choices=["auto", "arm", "aarch64", "mips", "mipseb", "mipsel", "x86", "x86_64", "riscv"],
        help="Target architecture (auto = detect from ELF headers)",
    )
    ap.add_argument("--kernel-version", metavar="VERSION", help="Kernel version string (recorded in manifest)")

    args = ap.parse_args()

    firmware_mode = args.firmware_root is not None

    # Apply default policy groups based on mode
    if args.policy_groups is None:
        args.policy_groups = "firmware,injection,secrets" if firmware_mode else RaptorConfig.DEFAULT_POLICY_GROUPS

    start_time = time.time()
    tmp = Path(tempfile.mkdtemp(prefix="raptor_auto_"))
    repo_path = None

    logger.info(f"Starting automated code security scan")
    if firmware_mode:
        logger.info(f"Mode: firmware  root={args.firmware_root}")
        logger.info(f"Arch: {args.arch}  kernel: {args.kernel_version or 'unspecified'}")
    else:
        logger.info(f"Repository: {args.repo}")
    logger.info(f"Policy version: {args.policy_version}")
    logger.info(f"Policy groups: {args.policy_groups}")

    try:
        if firmware_mode:
            repo_path = Path(args.firmware_root).resolve()
            if not repo_path.exists():
                raise RuntimeError(f"firmware-root does not exist: {repo_path}")
        elif args.repo.startswith(("http://", "https://", "git@")):
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

        # Generate output directory
        if args.output:
            out_dir = Path(args.output).resolve()
        else:
            label = "firmware" if firmware_mode else repo_path.name
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            out_dir = RaptorConfig.get_out_dir() / f"scan_{label}_{timestamp}"
        out_dir.mkdir(parents=True, exist_ok=True)

        # Firmware inventory (firmware mode only)
        firmware_inventory = None
        detected_arch = args.arch
        if firmware_mode:
            logger.info("Inventorying ELF binaries in firmware root...")
            firmware_inventory = inventory_firmware(repo_path)
            (out_dir / "firmware-inventory.json").write_text(
                json.dumps(firmware_inventory, indent=2)
            )
            if args.arch == "auto":
                detected_arch = firmware_inventory["detected_arch"]
                logger.info(f"Detected architecture: {detected_arch}")
            hvt = firmware_inventory["high_value_targets"]
            logger.info(
                f"Found {firmware_inventory['total_elfs']} ELFs, "
                f"{len(hvt)} high-value targets"
            )
            for t in hvt[:5]:
                logger.info(f"  {t['path']}  ({t['arch']}, {t['size_bytes']} bytes)")

        # Manifest
        logger.info("Computing repository hash...")
        repo_hash = sha256_tree(repo_path)

        manifest = {
            "agent": "auto_codesec",
            "version": "2.1.0",
            "repo_path": str(repo_path),
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "input_hash": repo_hash,
            "policy_version": args.policy_version,
            "policy_groups": groups,
            "parallel_scanning": not args.sequential,
            "firmware_mode": firmware_mode,
        }
        if firmware_mode:
            manifest["arch"] = detected_arch
            manifest["kernel_version"] = args.kernel_version or ""
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
        if firmware_inventory is not None:
            result["firmware_inventory"] = {
                "total_elfs": firmware_inventory["total_elfs"],
                "detected_arch": firmware_inventory["detected_arch"],
                "high_value_targets": firmware_inventory["high_value_targets"],
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


