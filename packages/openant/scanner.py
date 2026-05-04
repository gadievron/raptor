"""OpenAnt integration — invoke OpenAnt via subprocess and collect output.

Runs OpenAnt as a subprocess with PYTHONPATH set to its core directory.
This avoids sys.path contamination: OpenAnt has its own `core/` package
that would shadow Raptor's if added to sys.path directly.

The subprocess exits 0 (no vulns) or 1 (vulns found) on success, 2 on error.
Output is written to out_dir; pipeline_output.json is the primary artifact.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

from core.config import RaptorConfig
from core.logging import get_logger

from .config import OpenAntConfig

logger = get_logger()


def run_openant_scan(
    repo_path: str | Path,
    out_dir: str | Path,
    config: OpenAntConfig,
    *,
    commit_sha: Optional[str] = None,
) -> dict[str, Any]:
    """Run OpenAnt scan and return a normalised result dict.

    Returns:
        pipeline_output_path (str | None)
        pipeline_output       (dict)
        token_usage           (dict)
        error                 (str | None)
        skipped               (bool)
    """
    repo_path = Path(repo_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    return _run_subprocess(repo_path, out_dir, config)


def _run_subprocess(
    repo_path: Path,
    out_dir: Path,
    config: OpenAntConfig,
) -> dict[str, Any]:
    """Run OpenAnt as a subprocess with PYTHONPATH=config.core_path.

    Using PYTHONPATH (subprocess-scoped) instead of sys.path.insert prevents
    OpenAnt's `core/` package from shadowing Raptor's `core/` in this process.
    """
    env = _build_subprocess_env(config)
    cmd = _build_command(repo_path, out_dir, config)

    logger.info(f"Running OpenAnt: {' '.join(str(c) for c in cmd)}")
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=config.timeout_seconds,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return _empty_result(
            f"OpenAnt timed out after {config.timeout_seconds}s"
        )
    except Exception as exc:  # noqa: BLE001
        return _empty_result(f"OpenAnt launch failed: {exc}")

    if proc.returncode not in (0, 1):
        snippet = (proc.stderr or "")[:600].strip()
        return _empty_result(
            f"OpenAnt exited {proc.returncode}: {snippet}"
        )

    pipeline_output_path = out_dir / "pipeline_output.json"
    pipeline_output = _load_json(pipeline_output_path)
    if not pipeline_output:
        return _empty_result(
            f"OpenAnt produced no pipeline_output.json in {out_dir}"
        )

    token_usage = _extract_usage(proc.stdout, pipeline_output)
    return {
        "pipeline_output_path": str(pipeline_output_path),
        "pipeline_output": pipeline_output,
        "token_usage": token_usage,
        "error": None,
        "skipped": False,
    }


def _build_command(
    repo_path: Path,
    out_dir: Path,
    config: OpenAntConfig,
) -> list[str]:
    cmd: list[str] = [
        sys.executable, "-m", "openant",
        "scan", str(repo_path),
        "--output", str(out_dir),
        "--model", config.model,
        "--level", config.level,
        "--language", config.language,
        "--workers", str(config.workers),
        "--no-report",
    ]
    if not config.enhance:
        cmd.append("--no-enhance")
    if config.verify:
        cmd.append("--verify")
    return cmd


def _build_subprocess_env(config: OpenAntConfig) -> dict[str, str]:
    safe = RaptorConfig.get_safe_env()
    safe["ANTHROPIC_API_KEY"] = os.environ.get("ANTHROPIC_API_KEY", "")
    existing_pythonpath = os.environ.get("PYTHONPATH", "")
    core_str = str(config.core_path)
    if existing_pythonpath:
        safe["PYTHONPATH"] = f"{core_str}{os.pathsep}{existing_pythonpath}"
    else:
        safe["PYTHONPATH"] = core_str
    return safe


def _load_json(path: Path) -> dict:
    try:
        with path.open(encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        logger.warning(f"Cannot load OpenAnt output {path}: {exc}")
        return {}


def _extract_usage(stdout: str, pipeline_output: dict) -> dict[str, Any]:
    try:
        data = json.loads(stdout)
        if isinstance(data, dict):
            usage = data.get("data", {}).get("usage")
            if usage:
                return usage
    except (json.JSONDecodeError, AttributeError):
        pass
    stats = pipeline_output.get("pipeline_stats") or {}
    costs = stats.get("costs") or {}
    total_cost = sum(
        v.get("actual", 0) for v in costs.values() if isinstance(v, dict)
    )
    return {"total_cost_usd": total_cost}


def _empty_result(error: str) -> dict[str, Any]:
    return {
        "pipeline_output_path": None,
        "pipeline_output": {"findings": []},
        "token_usage": {},
        "error": error,
        "skipped": True,
    }
