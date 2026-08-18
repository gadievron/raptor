"""Semgrep runner — invoke semgrep, parse results, return structured output.

This module is intentionally minimal: build a command, run it, parse SARIF
and JSON output. Callers add their own concerns on top:

  - Sandbox POLICY. Execution is sandboxed BY DEFAULT: when no
    ``subprocess_runner`` is injected, run_rule() wraps the invocation in
    core.sandbox.run (Landlock scoped to the target, network blocked for
    local rule paths) and REFUSES to run when the sandbox is unavailable.
    Semgrep parses attacker-controlled source files, so parser bugs are a
    code-execution surface. Callers with their own sandbox pass
    ``subprocess_runner=`` (e.g. packages/static-analysis/scanner.py); the
    explicit escape hatch for trusted input is ``unsandboxed=True``.
  - HOME redirect into a per-run directory — scanner concern.
  - Output file layout (semgrep_<name>.sarif, .json, .stderr.log, .exit) —
    scanner persists; we hand back the raw strings.
  - Parallel orchestration across many configs — scanner uses
    ThreadPoolExecutor; we provide single-config run_rule() and a
    convenience run_rules() that runs sequentially.
"""

import shutil
import subprocess
import time
from pathlib import Path
from tempfile import NamedTemporaryFile

from core.run.toolprobe import probe

from .models import SemgrepResult, parse_json_output, parse_sarif

_SEMGREP_BIN = "semgrep"
_DEFAULT_TIMEOUT = 900
_DEFAULT_RULE_TIMEOUT = 60


def is_available() -> bool:
    """Check whether semgrep is on PATH."""
    return shutil.which(_SEMGREP_BIN) is not None


def version() -> str | None:
    """Return the semgrep version string, or None if unavailable.

    Delegates to core.run.toolprobe (safe env, resolved-path exec —
    the bare-name re-exec this used to do re-resolved PATH at exec
    time). Uncached: a diagnostic surface, and tests patch
    ``subprocess.run`` per-test.
    """
    info = probe(_SEMGREP_BIN)
    return info.first_line if info is not None else None


def build_cmd(
    target: Path,
    config: str,
    *,
    json_output_path: Path | None = None,
    rule_timeout: int = _DEFAULT_RULE_TIMEOUT,
    semgrep_bin: str | None = None,
    extra_args: list[str] | None = None,
) -> list[str]:
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
    cmd: list[str] = [
        bin_path,
        "scan",
        "--config", config,
        "--quiet",
        "--metrics", "off",
        # Defaults ON upstream: fires an HTTP GET to semgrep.dev after
        # every scan. Its 1-day cache lives under XDG_CACHE_HOME —
        # RAPTOR's throwaway fake HOME — so every pack invocation
        # re-pays the call (or a guaranteed-failing connect when the
        # sandbox blocks network).
        "--disable-version-check",
        "--error",
        "--sarif",
        "--disable-nosem",
        "--timeout", str(rule_timeout),
    ]
    if json_output_path is not None:
        cmd.extend(["--json-output", str(json_output_path)])
    if extra_args:
        cmd.extend(extra_args)
    cmd.append(str(target))
    return cmd


def _default_sandbox_runner(target: Path, config: str):
    """subprocess.run-shaped wrapper over core.sandbox.run, or None.

    Returns None when core.sandbox is unavailable on this host — the
    caller REFUSES to run in that case (mirrors patch_gate's
    no-sandbox-means-no-execution posture) rather than silently falling
    back to an unsandboxed subprocess.

    Registry configs (p/..., category/...) are fetched from semgrep.dev
    at run time, so those keep network access (still Landlock-confined);
    local rule paths run with the network blocked.
    """
    try:
        from core.sandbox.context import run as sandbox_run
    except ImportError:  # pragma: no cover - platform-dependent import
        return None

    needs_registry = str(config).startswith(("p/", "category/"))

    def _runner(cmd, **kwargs):
        # Fake HOME in a per-call scratch dir: semgrep unconditionally
        # appends to ``~/.semgrep/semgrep.log`` (and reads/writes
        # ``~/.semgrep/settings.yml``); the operator's real HOME is
        # not sandbox-writable, so every scan died rc=1 with
        # "write outside allowed paths denied to ~/.semgrep/semgrep.log".
        # fake_home requires output= (the Landlock-writable location
        # the .home dir materialises under). The scratch dir — and the
        # log noise semgrep writes there — is removed on return;
        # semgrep's stderr still carries any real failure.
        import tempfile

        with tempfile.TemporaryDirectory(prefix="semgrep-sbx-") as scratch:
            return sandbox_run(
                cmd,
                block_network=not needs_registry,
                target=str(target),
                caller_label="semgrep-runner",
                env_caller_filtered=True,
                output=scratch,
                fake_home=True,
                **{k: v for k, v in kwargs.items() if k != "shell"},
            )

    return _runner


_SANDBOX_REFUSAL = (
    "core.sandbox unavailable — refusing to run semgrep on the target "
    "outside a sandbox (semgrep parses untrusted source; parser bugs are "
    "a code-execution surface). Pass unsandboxed=True for trusted input, "
    "or inject subprocess_runner= with your own sandbox."
)


def run_rule(
    target: Path,
    config: str,
    *,
    name: str = "",
    timeout: int = _DEFAULT_TIMEOUT,
    rule_timeout: int = _DEFAULT_RULE_TIMEOUT,
    env: dict[str, str] | None = None,
    json_output_path: Path | None = None,
    semgrep_bin: str | None = None,
    extra_args: list[str] | None = None,
    subprocess_runner=None,
    unsandboxed: bool = False,
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
        subprocess_runner: Optional callable replacing the default
            sandboxed runner. Must accept the same kwargs
            (capture_output, text, timeout, env) and return an object
            with returncode/stdout/stderr. Used by callers that engage
            their own sandbox (e.g. core.sandbox.run) without
            reimplementing the semgrep invocation logic.
        unsandboxed: Explicit opt-out from the default sandbox — run via
            bare subprocess.run. For trusted input only. Ignored when
            subprocess_runner is given. Without it, run_rule REFUSES to
            execute when core.sandbox is unavailable.

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
        with NamedTemporaryFile(prefix="semgrep_", suffix=".json",
                                delete=False) as tmp:
            json_path = Path(tmp.name)
        cleanup_json = True

    # Wrap the entire subprocess + parse path in try/finally so an
    # unexpected exception (MemoryError, KeyboardInterrupt mid-parse,
    # any future exception type the runner adds) still unlinks the
    # tempfile. Pre-fix only TimeoutExpired / OSError were handled;
    # everything else leaked the tempfile.
    try:
        cmd = build_cmd(
            target, config,
            json_output_path=json_path,
            rule_timeout=rule_timeout,
            semgrep_bin=semgrep_bin,
            extra_args=extra_args,
        )

        if env is None:
            from core.config import RaptorConfig
            # Registry configs (p/..., category/...) are fetched from
            # semgrep.dev at run time — semgrep honours proxy env, so
            # the operator's proxy must survive for those or every
            # registry scan fails behind a mandatory egress proxy.
            # Local rule paths keep the stricter default.
            _needs_registry = str(config).startswith(("p/", "category/"))
            env = RaptorConfig.get_safe_env(preserve_proxy=_needs_registry)

        runner = subprocess_runner
        if runner is None:
            if unsandboxed:
                runner = subprocess.run
            else:
                runner = _default_sandbox_runner(target, config)
                if runner is None:
                    return SemgrepResult(
                        name=name, config=config, target=str(target),
                        errors=[_SANDBOX_REFUSAL],
                        returncode=-1,
                    )

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
            return SemgrepResult(
                name=name, config=config, target=str(target),
                errors=[f"Timeout after {timeout}s"],
                returncode=-1,
                elapsed_ms=int((time.monotonic() - start) * 1000),
            )
        except OSError as e:
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
                json_text = json_path.read_text(encoding="utf-8")
            except OSError:
                json_text = ""
    finally:
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
    configs: list[tuple[str, str]],
    *,
    timeout: int = _DEFAULT_TIMEOUT,
    rule_timeout: int = _DEFAULT_RULE_TIMEOUT,
    env: dict[str, str] | None = None,
    semgrep_bin: str | None = None,
    extra_args: list[str] | None = None,
    subprocess_runner=None,
    unsandboxed: bool = False,
) -> list[SemgrepResult]:
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

    results: list[SemgrepResult] = []
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
            unsandboxed=unsandboxed,
        )
        results.append(result)
    return results


def _config_to_name(config: str) -> str:
    """Derive a friendly name from a config string."""
    if not config:
        return "semgrep"
    # Pack identifiers like "p/security-audit"
    if config.startswith(("p/", "category/")):
        return config
    # Directory path — use the basename
    return Path(config).name or config


def _safe_unlink(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass
