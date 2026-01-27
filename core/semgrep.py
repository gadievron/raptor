#!/usr/bin/env python3
"""Semgrep scanning utilities."""

import os
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from core.config import RaptorConfig
from core.logging import get_logger
from core.sarif.parser import validate_sarif
from core.exec import run

logger = get_logger()


def get_semgrep_version() -> Optional[str]:
    """Get installed Semgrep version."""
    semgrep_cmd = shutil.which("semgrep") or "/opt/homebrew/bin/semgrep"
    try:
        rc, so, se = run([semgrep_cmd, "--version"], timeout=10)
        if rc == 0:
            return so.strip()
    except Exception as e:
        logger.debug(f"Could not get Semgrep version: {e}")
    return None


def run_semgrep(
    config: str,
    target: Path,
    output: Path,
    timeout: int = 300,
    max_memory: int = 4096
) -> Tuple[bool, Path]:
    """
    Run Semgrep scan and return SARIF output path.

    Args:
        config: Semgrep config (rule file path or registry name)
        target: Directory to scan
        output: Output file path for SARIF results
        timeout: Maximum execution time in seconds
        max_memory: Maximum memory in MB (currently unused, for future)

    Returns:
        Tuple of (success: bool, sarif_path: Path)
    """
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
        str(target),
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
            logger.warning(f"Semgrep scan produced empty output")
            so = '{"runs": []}'

        output.write_text(so)

        # Validate SARIF
        is_valid = validate_sarif(output)
        success = rc in (0, 1) and is_valid

        return success, output

    except Exception as e:
        logger.error(f"Semgrep scan failed: {e}")
        # Write empty SARIF on error
        output.write_text('{"runs": []}')
        return False, output


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

    Args:
        name: Descriptive name for this scan
        config: Semgrep config path or registry name
        repo_path: Repository path to scan
        out_dir: Output directory for results
        timeout: Timeout in seconds
        progress_callback: Optional callback for progress updates

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
