"""Semgrep runner — invoke semgrep, parse results, return structured output.

This module is intentionally minimal: build a command, run it via subprocess,
parse SARIF and JSON output. Callers add their own concerns on top:

  - Sandbox engagement (Landlock, mount-ns, network proxy) — see
    packages/static-analysis/scanner.py:run() which wraps build_cmd() with
    core.sandbox.run.
  - HOME redirect into a per-run directory — also scanner concern.
  - Output file layout (semgrep_<name>.sarif, .json, .stderr.log, .exit) —
    scanner persists; we hand back the raw strings.
  - Parallel orchestration across many configs — scanner uses
    ThreadPoolExecutor; we provide single-config run_rule() and a
    convenience run_rules() that runs sequentially.
"""

import json
import shutil
import subprocess
import time
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Dict, List, Optional, Tuple

from .models import SemgrepResult, parse_json_output, parse_sarif

_SEMGREP_BIN = "semgrep"
_DEFAULT_TIMEOUT = 900
_DEFAULT_RULE_TIMEOUT = 60


def is_available() -> bool:
    """Check whether semgrep is on PATH."""
    return shutil.which(_SEMGREP_BIN) is not None


def version() -> Optional[str]:
    """Return the semgrep version string, or None if unavailable."""
    if not is_available():
        return None
    try:
        proc = subprocess.run(
            [_SEMGREP_BIN, "--version"],
            capture_output=True, text=True, timeout=10,
        )
        out = (proc.stdout or proc.stderr or "").strip()
        return out.splitlines()[0] if out else None
    except (subprocess.TimeoutExpired, OSError):
        return None


def build_cmd(
    target: Path,
    config: str,
    *,
    json_output_path: Optional[Path] = None,
    rule_timeout: int = _DEFAULT_RULE_TIMEOUT,
    semgrep_bin: Optional[str] = None,
    extra_args: Optional[List[str]] = None,
) -> List[str]:
    """Build the semgrep command argv.

    Pure: no subprocess invocation. Callers can wrap this with their own
    runner (e.g. core.sandbox.run for sandboxed scans).

    Args:
        target: File or directory to scan.
        config: Rules directory path or pack identifier (e.g. "p/security-audit").
        json_output_path: Optional path for --json-output. When provided,
            semgrep writes JSON metadata (paths.scanned, errors, version)
            to this file in addition to SARIF on stdout.
        rule_timeout: Per-rule timeout in seconds.
        semgrep_bin: Override semgrep binary path. Defaults to PATH lookup.
        extra_args: Additional semgrep arguments to pass through.

    Returns:
        argv list ready for subprocess.run.
    """
    bin_path = semgrep_bin or shutil.which(_SEMGREP_BIN) or _SEMGREP_BIN
    cmd: List[str] = [
        bin_path,
        "scan",
        "--config", config,
        "--quiet",
        "--metrics", "off",
        "--error",
        "--sarif",
        "--timeout", str(rule_timeout),
    ]
    if json_output_path is not None:
        cmd.extend(["--json-output", str(json_output_path)])
    if extra_args:
        cmd.extend(extra_args)
    cmd.append(str(target))
    return cmd


def run_rule(
    target: Path,
    config: str,
    *,
    name: str = "",
    timeout: int = _DEFAULT_TIMEOUT,
    rule_timeout: int = _DEFAULT_RULE_TIMEOUT,
    env: Optional[Dict[str, str]] = None,
    json_output_path: Optional[Path] = None,
    semgrep_bin: Optional[str] = None,
    extra_args: Optional[List[str]] = None,
    subprocess_runner=None,
) -> SemgrepResult:
    """Run semgrep with one config against a target.

    Args:
        target: File or directory to scan.
        config: Rules directory path or pack identifier.
        name: Optional friendly name for the result (e.g. "category_injection").
        timeout: Overall semgrep process timeout in seconds.
        rule_timeout: Per-rule timeout (semgrep --timeout).
        env: Subprocess environment. Defaults to current environment.
            Untrusted-target callers should pass RaptorConfig.get_safe_env().
        json_output_path: Optional path for --json-output. If None, a
            temporary file is used and removed after parsing.
        semgrep_bin: Override semgrep binary path.
        extra_args: Additional semgrep arguments.
        subprocess_runner: Optional callable replacing subprocess.run. Must
            accept the same kwargs (capture_output, text, timeout, env)
            and return an object with returncode/stdout/stderr. Defaults
            to subprocess.run. Used by callers that need to engage a
            sandbox (e.g. core.sandbox.run) without reimplementing the
            semgrep invocation logic.

    Returns:
        SemgrepResult with parsed findings, files_examined, files_failed,
        and raw SARIF/JSON for caller persistence.
    """
    target = Path(target)
    name = name or _config_to_name(config)

    if not is_available():
        return SemgrepResult(
            name=name, config=config, target=str(target),
            errors=["semgrep is not installed (semgrep binary not found on PATH)"],
            returncode=-1,
        )

    cleanup_json = False
    json_path = json_output_path
    if json_path is None:
        tmp = NamedTemporaryFile(prefix="semgrep_", suffix=".json", delete=False)
        tmp.close()
        json_path = Path(tmp.name)
        cleanup_json = True

    cmd = build_cmd(
        target, config,
        json_output_path=json_path,
        rule_timeout=rule_timeout,
        semgrep_bin=semgrep_bin,
        extra_args=extra_args,
    )

    runner = subprocess_runner or subprocess.run

    start = time.monotonic()
    try:
        proc = runner(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        if cleanup_json:
            _safe_unlink(json_path)
        return SemgrepResult(
            name=name, config=config, target=str(target),
            errors=[f"Timeout after {timeout}s"],
            returncode=-1,
            elapsed_ms=int((time.monotonic() - start) * 1000),
        )
    except OSError as e:
        if cleanup_json:
            _safe_unlink(json_path)
        return SemgrepResult(
            name=name, config=config, target=str(target),
            errors=[str(e)],
            returncode=-1,
            elapsed_ms=int((time.monotonic() - start) * 1000),
        )
    elapsed = int((time.monotonic() - start) * 1000)

    sarif_text = proc.stdout or ""
    json_text = ""
    if json_path.exists():
        try:
            json_text = json_path.read_text()
        except OSError:
            json_text = ""
    if cleanup_json:
        _safe_unlink(json_path)

    findings = parse_sarif(sarif_text)
    parsed_json = parse_json_output(json_text)

    return SemgrepResult(
        name=name,
        config=config,
        target=str(target),
        findings=findings,
        files_examined=parsed_json["files_examined"],
        files_failed=parsed_json["files_failed"],
        semgrep_version=parsed_json["semgrep_version"],
        returncode=proc.returncode,
        stderr=proc.stderr or "",
        sarif=sarif_text,
        json_output=json_text,
        elapsed_ms=elapsed,
        errors=[],
    )


def run_rules(
    target: Path,
    configs: List[Tuple[str, str]],
    *,
    timeout: int = _DEFAULT_TIMEOUT,
    rule_timeout: int = _DEFAULT_RULE_TIMEOUT,
    env: Optional[Dict[str, str]] = None,
    semgrep_bin: Optional[str] = None,
    extra_args: Optional[List[str]] = None,
    subprocess_runner=None,
) -> List[SemgrepResult]:
    """Run multiple semgrep configurations sequentially.

    Args:
        target: File or directory to scan.
        configs: List of (name, config) tuples. Each is run independently.
        timeout: Per-config timeout.
        rule_timeout: Per-rule timeout.
        env: Subprocess environment.
        semgrep_bin: Override semgrep binary path.
        extra_args: Additional semgrep arguments applied to every run.

    Returns:
        One SemgrepResult per config, in input order.

    Note: Callers needing parallelism (e.g. scanner.py) should orchestrate
    their own ThreadPoolExecutor over run_rule(); this convenience helper
    is sequential to keep the package free of policy decisions about
    concurrency, worker counts, and progress reporting.
    """
    if not is_available():
        return [
            SemgrepResult(
                name=name, config=config, target=str(target),
                errors=["semgrep is not installed (semgrep binary not found on PATH)"],
                returncode=-1,
            )
            for name, config in configs
        ]

    results: List[SemgrepResult] = []
    for name, config in configs:
        result = run_rule(
            target, config,
            name=name,
            timeout=timeout,
            rule_timeout=rule_timeout,
            env=env,
            semgrep_bin=semgrep_bin,
            extra_args=extra_args,
            subprocess_runner=subprocess_runner,
        )
        results.append(result)
    return results


def _config_to_name(config: str) -> str:
    """Derive a friendly name from a config string."""
    if not config:
        return "semgrep"
    # Pack identifiers like "p/security-audit"
    if config.startswith("p/") or config.startswith("category/"):
        return config
    # Directory path — use the basename
    return Path(config).name or config


def _safe_unlink(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass
