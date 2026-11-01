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

import atexit
from concurrent.futures import Future
import logging
import os
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import TYPE_CHECKING

from core.run.toolprobe import probe

if TYPE_CHECKING:
    from collections.abc import Sequence

from .models import (
    _MAX_TOOL_OUTPUT_BYTES,
    SemgrepResult,
    parse_json_output,
    parse_sarif,
)

logger = logging.getLogger(__name__)

_SEMGREP_BIN = "semgrep"
_DEFAULT_TIMEOUT = 900
_DEFAULT_RULE_TIMEOUT = 60

# --x-ignore-semgrepignore-files shipped in the osemgrep Pro sync around
# semgrep 1.95 (Nov 2024).  Older CLIs reject it as unknown (rc=2).
# Version-gated: below-floor scans omit the flag and log a warning.
_SCOPE_ISOLATION_MIN_VERSION = (1, 95, 0)

# RAPTOR-owned scan-scope baseline, passed as repeated ``--exclude``
# args by build_cmd (gitignore-style patterns; trailing ``/`` = match
# directories only — verified honoured on semgrep 1.172.0, skips
# reported as ``cli_exclude_flags_match`` in paths.skipped).
#
# Why this exists: --x-ignore-semgrepignore-files (see build_cmd)
# disables not only the target's .semgrepignore files but ALSO
# semgrep's BUILT-IN default ignore set (which only applies when no
# .semgrepignore exists). This list restores the useful part of that
# default set from RAPTOR code, where a hostile target cannot edit it.
#
# Curation rule — dependency/build/artifact directories and generated
# files ONLY: names that by ecosystem convention hold third-party or
# machine-generated content nobody hand-edits. Deliberately ABSENT
# (diverging from semgrep's built-in defaults, probed on 1.172.0:
# .env/ .npm/ .tox/ .venv/ .yarn/ build/ dist/ node_modules/ test/
# tests/ vendor/):
#   - test/, tests/ — first-party code; skipping by NAME hands the
#     target a steerable hiding channel (mkdir tests/ && hide the bug;
#     demonstrated empirically on 1.172.0). Same reasoning keeps
#     examples/, docs/, scripts/ etc. out of this list.
#   - .env/ — the bare name collides with ``.env`` secret FILES;
#     excluding the pattern would blind secrets rules.
# Both-direction rationale: ADDING an entry re-opens a name-steerable
# hiding spot (any first-party-plausible name is a hole a target can
# mkdir its way into); REMOVING one buys back scan cost and finding
# noise on third-party code RAPTOR does not report on anyway.
# Operators extend per-run via extra_args --exclude / the scanner's
# exclude-glob filter; entries here must clear the curation rule.
SCOPE_EXCLUDE_BASELINE: tuple[str, ...] = (
    # dependency trees / package-manager state
    "node_modules/",
    "bower_components/",
    ".yarn/",
    ".npm/",
    "vendor/",
    "third_party/",
    "site-packages/",
    ".venv/",
    ".tox/",
    # build artifacts
    "build/",
    "dist/",
    # generated / minified assets
    "*.min.js",
    "*.min.css",
    # lockfiles (machine-written dependency manifests)
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Pipfile.lock",
    "Cargo.lock",
    "composer.lock",
    "Gemfile.lock",
    "go.sum",
)


def is_available() -> bool:
    """Check whether semgrep is on PATH."""
    return shutil.which(_SEMGREP_BIN) is not None


def _version_probe():
    from core.config import RaptorConfig
    if not RaptorConfig.SEMGREP_OFFLINE:
        return probe(_SEMGREP_BIN)
    from core.run.toolprobe import ToolInfo
    binary = shutil.which(_SEMGREP_BIN)
    if binary is None:
        return None
    runner = _default_sandbox_runner(Path.cwd(), "")
    if runner is None:
        return None
    result = runner(
        [str(Path(binary).resolve()), "--version", "--metrics", "off", "--disable-version-check"],
        env=RaptorConfig.get_safe_env(), capture_output=True, text=True, timeout=15,
    )
    if result.returncode:
        return None
    return ToolInfo(name=_SEMGREP_BIN, path=binary, returncode=result.returncode,
                    stdout=result.stdout, stderr=result.stderr)


def version() -> str | None:
    """Return the semgrep version string, or None if unavailable.

    Delegates to core.run.toolprobe (safe env, resolved-path exec —
    the bare-name re-exec this used to do re-resolved PATH at exec
    time). Uncached: a diagnostic surface, and tests patch
    ``subprocess.run`` per-test.
    """
    info = _version_probe()
    return info.first_line if info is not None else None


# Only the latest successful capability probe is retained. CLI scans and
# scanner worker threads share it; diagnostics through version() stay fresh.
_SCOPE_PROBE_LOCK = threading.Lock()
_SCOPE_PROBE_CACHE: tuple[tuple[object, ...], tuple[int, ...]] | None = None
_SCOPE_PROBE_PENDING: tuple[tuple[object, ...], Future[tuple[int, ...] | None]] | None = None


def _reset_scope_probe_cache() -> None:
    """Clear process state; also replace a possibly inherited locked mutex."""
    global _SCOPE_PROBE_LOCK, _SCOPE_PROBE_CACHE, _SCOPE_PROBE_PENDING
    _SCOPE_PROBE_LOCK = threading.Lock()
    _SCOPE_PROBE_CACHE = None
    _SCOPE_PROBE_PENDING = None


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_scope_probe_cache)


def _scope_probe_key() -> tuple[object, ...] | None:
    """Fingerprint the selected launcher and its dispatch/sandbox context."""
    from core.config import RaptorConfig

    binary = shutil.which(_SEMGREP_BIN)
    if binary is None:
        return None
    try:
        path = Path(binary).absolute()
        resolved = path.resolve(strict=True)
        stat = resolved.stat()
        return (str(path), str(resolved), stat.st_dev, stat.st_ino,
                stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns,
                os.environ.get("PATH", ""), str(Path.cwd()),
                RaptorConfig.SEMGREP_OFFLINE)
    except (OSError, RuntimeError):
        # Missing/unstatable launchers and symlink loops are never cached.
        return None


def _probe_scope_version(key: tuple[object, ...] | None) -> tuple[int, ...] | None:
    info = _version_probe()
    if info is None or info.returncode != 0:
        return None
    parsed = info.version_tuple()
    if key is None or parsed is None:
        return parsed
    try:
        same_tool = str(Path(info.path).resolve(strict=True)) == key[1]
    except (OSError, RuntimeError):
        same_tool = False
    return parsed if same_tool else None


def _scope_version() -> tuple[int, ...] | None:
    global _SCOPE_PROBE_CACHE, _SCOPE_PROBE_PENDING

    with _SCOPE_PROBE_LOCK:
        key = _scope_probe_key()
        future: Future[tuple[int, ...] | None] | None = None
        owner = False
        if key is not None:
            if _SCOPE_PROBE_CACHE is not None:
                cached_key, cached_version = _SCOPE_PROBE_CACHE
                if key == cached_key:
                    return cached_version
            if _SCOPE_PROBE_PENDING is not None and _SCOPE_PROBE_PENDING[0] == key:
                future = _SCOPE_PROBE_PENDING[1]
            else:
                future = Future()
                owner = True
                # Keep only one in-flight entry. A concurrent context switch
                # may probe independently, without an identity-keyed map.
                if _SCOPE_PROBE_PENDING is None:
                    _SCOPE_PROBE_PENDING = (key, future)
    if key is None:
        return _probe_scope_version(None)
    assert future is not None
    if not owner:
        parsed = future.result()
        return parsed if key == _scope_probe_key() else None

    try:
        parsed = _probe_scope_version(key)
        with _SCOPE_PROBE_LOCK:
            # Revalidate at publication, including changes during probing.
            if key != _scope_probe_key():
                parsed = None
            if parsed is not None:
                _SCOPE_PROBE_CACHE = (key, parsed)
            if _SCOPE_PROBE_PENDING is not None and _SCOPE_PROBE_PENDING[1] is future:
                _SCOPE_PROBE_PENDING = None
            future.set_result(parsed)
        return parsed
    except BaseException as exc:
        # Current waiters share this failure; a later call starts a fresh
        # attempt. Do not serialize repeated timeouts behind the same lock.
        with _SCOPE_PROBE_LOCK:
            if _SCOPE_PROBE_PENDING is not None and _SCOPE_PROBE_PENDING[1] is future:
                _SCOPE_PROBE_PENDING = None
            future.set_exception(exc)
        raise


def scope_isolation_available() -> bool:
    """True when semgrep supports ``--x-ignore-semgrepignore-files``.

    Below-floor versions let hostile targets steer scan scope via
    ``.semgrepignore`` files.  Callers should log a warning and pass
    ``scope_isolation=False`` to :func:`build_cmd`.
    """
    vt = _scope_version()
    return vt is not None and vt >= _SCOPE_ISOLATION_MIN_VERSION


def build_cmd(
    target: Path,
    config: str,
    *,
    json_output_path: Path | None = None,
    rule_timeout: int = _DEFAULT_RULE_TIMEOUT,
    semgrep_bin: str | None = None,
    extra_args: list[str] | None = None,
    extra_targets: "Sequence[Path]" = (),
    scope_isolation: bool = True,
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
        extra_targets: Additional scan targets appended after ``target``.
            Findings carry per-file artifact URIs, so callers can split
            results back per target.
        scope_isolation: Include ``--x-ignore-semgrepignore-files``.
            Set to ``False`` on semgrep versions below
            :data:`_SCOPE_ISOLATION_MIN_VERSION` — the flag is unknown
            and would cause rc=2.

    Returns:
        argv list ready for subprocess.run.
    """
    from core.config import RaptorConfig
    if RaptorConfig.SEMGREP_OFFLINE:
        config = RaptorConfig.get_semgrep_config(config)
    bin_path = semgrep_bin or shutil.which(_SEMGREP_BIN) or _SEMGREP_BIN
    cmd: list[str] = [
        bin_path,
        "scan",
        "--config", config,
        # --verbose, not --quiet (the two are mutually exclusive):
        # only verbose populates ``paths.skipped`` in the --json
        # output — the record of every path the scan did NOT examine
        # and why — which run_rule surfaces as skipped_summary.
        # --quiet also swallowed semgrep's own skipped-paths notice,
        # so scope suppression was doubly invisible. Verbose chatter
        # goes to stderr; stdout stays pure SARIF (verified on
        # semgrep 1.172.0).
        "--verbose",
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
        # Scan scope must be RAPTOR-owned, never target-owned. By
        # default semgrep honours the SCANNED repo's ignore files —
        # ``.semgrepignore`` (root and nested) and, inside a git
        # repo, ``.gitignore`` — so a hostile target could ship one
        # line of config and silently exempt its own subtrees from
        # the scan (clean exit, empty findings). --disable-nosem
        # above closes the inline suppression channel; these two
        # close the file-level one. --no-git-ignore additionally
        # stops semgrep shelling out to git inside the untrusted
        # tree. Side effect (verified on 1.172.0): killing the
        # .semgrepignore machinery also drops semgrep's BUILT-IN
        # default ignore set (node_modules/, tests/, vendor/, ...),
        # which only applies when no .semgrepignore file exists —
        # the SCOPE_EXCLUDE_BASELINE --exclude args below restore
        # the dependency/build/artifact part of it from RAPTOR code;
        # tests/-type first-party names stay deliberately IN scope.
        # RAPTOR-owned scope control (--exclude/--include via
        # extra_args, the scanner's exclude-glob filter) is
        # unaffected. --x-ignore-semgrepignore-files is documented
        # [INTERNAL] upstream: if a future semgrep removes it, every
        # scan fails LOUDLY (unknown option, rc=2 — surfaced as an
        # engine error by run_rule and the scanner) rather than
        # silently reverting to target-steered scope. Version-gated
        # via scope_isolation (see _SCOPE_ISOLATION_MIN_VERSION):
        # below-floor CLIs don't know the flag; callers log a warning.
        "--no-git-ignore",
        "--timeout", str(rule_timeout),
    ]
    if RaptorConfig.SEMGREP_OFFLINE:
        # Partial rule/config errors must fail the pack, even with findings.
        cmd.append("--strict")
    if scope_isolation:
        cmd.insert(cmd.index("--no-git-ignore") + 1,
                   "--x-ignore-semgrepignore-files")
    for pattern in SCOPE_EXCLUDE_BASELINE:
        cmd.extend(["--exclude", pattern])
    if json_output_path is not None:
        cmd.extend(["--json-output", str(json_output_path)])
    if extra_args:
        if RaptorConfig.SEMGREP_OFFLINE and any(
            arg in {"--config", "-c", "--pro", "--pro-intrafile", "--pro-languages", "--no-strict"}
            or arg.startswith(("--config=", "-c=", "--metrics", "--enable-version-check"))
            for arg in extra_args
        ):
            raise ValueError("Offline Semgrep refuses acquisition/telemetry overrides in extra_args")
        cmd.extend(extra_args)
    cmd.append(str(target))
    cmd.extend(str(t) for t in extra_targets)
    return cmd


# One sandbox scratch PARENT per process, one fake-HOME subdirectory
# per invocation. The parent amortises the per-process cost (created
# lazily, removed once at exit — its rmtree sweeps every invocation
# subdir with it); the per-invocation mkdtemp subdir is what each
# sandboxed child gets as its output/fake-HOME root. Per-invocation
# isolation is load-bearing, not hygiene: a sandboxed child has write
# access to ITS OWN output dir for its whole lifetime, so with a
# SHARED dir a still-live compromised child of call A could rewrite
# call B's ``.home`` between B's parent-side lstat sweep and makedirs
# (core.sandbox.context's symlink-TOCTOU check-then-act) — regaining
# the bounded parent-side write-outside escape that check exists to
# stop — and a damaged shared ``.home`` would also poison every later
# semgrep call in the process. With a fresh subdir per call, no child
# ever holds write access to another call's scratch, and the
# sandbox's fake-home materialisation validates each fresh ``.home``
# tree per call exactly as before. Scan RESULTS come exclusively from
# stdout SARIF and --json-output, both outside this dir.
_SCRATCH_LOCK = threading.Lock()
_scratch_parent: str | None = None


def _sandbox_scratch_parent() -> str:
    global _scratch_parent
    with _SCRATCH_LOCK:
        if _scratch_parent is None or not os.path.isdir(_scratch_parent):
            _scratch_parent = tempfile.mkdtemp(prefix="semgrep-sbx-")
            atexit.register(
                shutil.rmtree, _scratch_parent, ignore_errors=True,
            )
        return _scratch_parent


def _invocation_scratch_dir() -> str:
    """Fresh per-invocation scratch under the process-shared parent."""
    return tempfile.mkdtemp(prefix="inv-", dir=_sandbox_scratch_parent())


def _reset_sandbox_scratch() -> None:
    """Test hook: drop the shared scratch parent immediately."""
    global _scratch_parent
    with _SCRATCH_LOCK:
        if _scratch_parent is not None:
            shutil.rmtree(_scratch_parent, ignore_errors=True)
        _scratch_parent = None


def _default_sandbox_runner(target: Path, config: str, *, extra_targets=()):
    """subprocess.run-shaped wrapper over core.sandbox.run, or None.

    Returns None when core.sandbox is unavailable on this host — the
    caller REFUSES to run in that case (mirrors patch_gate's
    no-sandbox-means-no-execution posture) rather than silently falling
    back to an unsandboxed subprocess.

    Registry configs (p/..., category/...) are fetched from semgrep.dev
    at run time, so those get network — routed through the RAPTOR
    egress proxy with the shared semgrep hostname allowlist
    (``packages.semgrep._proxy_hosts``, the same posture the
    static-analysis scanner and the codeql pack-download lane carry:
    UDP blocked, hostname-allowlisted, resolved-IP-screened). This
    module's own threat statement is that semgrep parses
    attacker-controlled source, so the registry lane must not hand a
    compromised parser fully open egress. Local rule paths run with
    the network blocked entirely.
    """
    try:
        from core.sandbox.context import run as sandbox_run
    except ImportError:  # pragma: no cover - platform-dependent import
        return None

    from core.config import RaptorConfig
    offline = RaptorConfig.SEMGREP_OFFLINE
    needs_registry = not offline and str(config).startswith(("p/", "category/"))
    if needs_registry:
        from ._proxy_hosts import proxy_hosts_for_semgrep
        net_kwargs: dict = {
            "use_egress_proxy": True,
            "proxy_hosts": proxy_hosts_for_semgrep(),
        }
    else:
        net_kwargs = {"block_network": True}

    def _runner(cmd, **kwargs):
        if offline:
            from core.sandbox.python_paths import python_runtime_tool_paths
            binary = Path(shutil.which(cmd[0]) or cmd[0]).resolve()
            cmd = [str(binary), *cmd[1:]]
            paths = [str(binary.parent), *python_runtime_tool_paths()]
            if config and Path(config).exists():
                paths.append(str(Path(config).resolve()))
            kwargs.setdefault("tool_paths", paths)
        # Fake HOME in a per-invocation scratch dir: semgrep
        # unconditionally appends to ``~/.semgrep/semgrep.log`` (and
        # reads/writes ``~/.semgrep/settings.yml``); the operator's
        # real HOME is not sandbox-writable, so every scan died rc=1
        # with "write outside allowed paths denied to
        # ~/.semgrep/semgrep.log". fake_home requires output= (the
        # Landlock-writable location the .home dir materialises
        # under). Each invocation gets a fresh mkdtemp subdir of the
        # process-shared parent (see the _sandbox_scratch_parent
        # comment for why sharing one dir across concurrent
        # invocations would reopen the fake-home symlink-TOCTOU
        # window); the parent's atexit rmtree reclaims them all, and
        # semgrep's stderr still carries any real failure.
        from core.sandbox.python_paths import python_tool_paths
        tool_paths = python_tool_paths(cmd[0]) if cmd else []
        # Local rules are outside target/output in common run_rule calls.
        # Declare the exact rule path; do not expose its parent directory.
        if not needs_registry and Path(config).exists():
            tool_paths.append(str(Path(config).absolute()))
        options = {k: v for k, v in kwargs.items() if k != "shell"}
        tool_paths.extend(options.pop("tool_paths", []) or [])
        # A single-file scan needs an exact read-only bind, not its parent:
        # scanning ~/file.py must not expose sibling credentials in HOME.
        sandbox_target = str(target) if target.is_dir() else None
        if sandbox_target is None:
            tool_paths.append(str(target.absolute()))
        tool_paths.extend(str(Path(path).absolute()) for path in extra_targets)
        return sandbox_run(
            cmd,
            target=sandbox_target,
            caller_label="semgrep-runner",
            env_caller_filtered=True,
            output=_invocation_scratch_dir(),
            fake_home=True,
            tool_paths=list(dict.fromkeys(tool_paths)),
            **net_kwargs,
            **options,
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
    extra_targets: "Sequence[Path]" = (),
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
        extra_targets: Additional scan targets for the same invocation.
            The result's findings cover ALL targets (each finding's
            ``file`` names its origin) and the returncode follows the
            combined scan — callers split per target themselves.

    Returns:
        SemgrepResult with parsed findings, files_examined, files_failed,
        and raw SARIF/JSON for caller persistence.
    """
    # The private bind tree need not carry the caller's working directory.
    # Preserve file identity while making scan/rule arguments cwd-independent.
    target = Path(target).absolute()
    extra_targets = tuple(Path(path).absolute() for path in extra_targets)
    # Registry identifiers keep their meaning even if a hostile working
    # directory plants a colliding local p/<pack> or category/<name> path.
    if not str(config).startswith(("p/", "category/")) and Path(config).exists():
        config = str(Path(config).absolute())
    name = name or _config_to_name(config)
    from core.config import RaptorConfig
    if RaptorConfig.SEMGREP_OFFLINE:
        try:
            config = RaptorConfig.get_semgrep_config(config)
        except ValueError as exc:
            return SemgrepResult(name=name, config=config, target=str(target),
                                 errors=[str(exc)], returncode=-1)

    if not is_available():
        return SemgrepResult(
            name=name, config=config, target=str(target),
            errors=["semgrep is not installed (semgrep binary not found on PATH)"],
            returncode=-1,
        )

    scope_ok = scope_isolation_available()
    if not scope_ok:
        v = version() or "unknown"
        floor = ".".join(str(p) for p in _SCOPE_ISOLATION_MIN_VERSION)
        logger.warning(
            "semgrep %s < %s: --x-ignore-semgrepignore-files unavailable "
            "— .semgrepignore files in the scanned repo can hide findings "
            "(upgrade: uv tool install --upgrade semgrep)",
            v, floor,
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
            extra_targets=extra_targets,
            scope_isolation=scope_ok,
        )

        if env is None:
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
                runner = _default_sandbox_runner(target, config, extra_targets=extra_targets)
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

        # Budget gates on both tool outputs. Semgrep exits 0/1 on a
        # successful scan regardless of output size, so an over-budget
        # payload must surface as a scan ERROR — empty findings with
        # empty errors at rc 0 would read as a verified-clean scan,
        # handing a hostile repo a finding-suppression primitive
        # (inflate the output past the cap and every real finding
        # vanishes with the noise). The oversized text is also NOT
        # retained on the result, so downstream serialisers never
        # persist an attacker-sized payload.
        budget_errors: list[str] = []
        sarif_text = proc.stdout or ""
        # Measure BYTES, matching the budget's unit: len(str) counts
        # characters, and UTF-8 encodes up to 4 bytes per char — a
        # non-ASCII-heavy payload could weigh 4x the budget while
        # passing a character-count gate. chars <= bytes always, so
        # the cheap length check short-circuits the common case and
        # the encode only runs on strings already under the budget
        # in characters (bounded work).
        sarif_bytes = (
            len(sarif_text)
            if len(sarif_text) > _MAX_TOOL_OUTPUT_BYTES
            else len(sarif_text.encode("utf-8", errors="surrogatepass"))
        )
        if sarif_bytes > _MAX_TOOL_OUTPUT_BYTES:
            msg = (
                f"semgrep SARIF output is at least {sarif_bytes} bytes"
                f" — exceeds the {_MAX_TOOL_OUTPUT_BYTES}-byte budget;"
                " scan results unavailable (failed scan, not a clean"
                " one)"
            )
            logger.warning("%s", msg)
            budget_errors.append(msg)
            sarif_text = ""
        json_text = ""
        if json_path.exists():
            # Size gate BEFORE the read: the --json payload is
            # produced over the scanned (possibly hostile) repo,
            # which can inflate it arbitrarily.
            try:
                json_size = json_path.stat().st_size
                if json_size > _MAX_TOOL_OUTPUT_BYTES:
                    msg = (
                        f"semgrep --json output is {json_size} bytes"
                        f" — exceeds the {_MAX_TOOL_OUTPUT_BYTES}-byte"
                        " budget; scan metadata unavailable"
                    )
                    logger.warning("%s: %s", msg, json_path)
                    budget_errors.append(msg)
                else:
                    json_text = json_path.read_text(encoding="utf-8")
            except OSError:
                json_text = ""
    finally:
        if cleanup_json:
            _safe_unlink(json_path)

    findings = parse_sarif(sarif_text)
    parsed_json = parse_json_output(json_text)

    # Engine failure must never read as verified silence: surface the
    # budget refusals and the real errors array, and when semgrep
    # exits outside {0, 1} (0 = no findings / clean, 1 = findings
    # under --error) without a parseable errors payload (invalid rule
    # YAML, internal crash on a hostile source file, signal kill — the
    # tool never analysed the code, and semgrep sometimes emits empty
    # SARIF before --json-output is written), synthesise an error from
    # the returncode + stderr so every caller inherits the
    # error-vs-refuted distinction instead of reading empty findings
    # as a refutation.
    errors: list[str] = budget_errors + list(parsed_json["errors"])
    if proc.returncode not in (0, 1) and not errors:
        stderr_tail = (proc.stderr or "").strip()[-500:]
        errors.append(
            f"semgrep exited with code {proc.returncode}"
            + (f": {stderr_tail}" if stderr_tail else "")
        )

    # Excluded scope said out loud: every skipped path is a path the
    # scan did NOT examine, so an empty-findings result over a heavily
    # skipped tree must not read as a clean verdict. Counts only in
    # the log line — the sample paths are target-derived and stay on
    # the result; reason strings come from semgrep's own enum but are
    # escaped anyway before the operator's log stream.
    skipped_summary: dict = parsed_json.get("skipped_summary") or {}
    if skipped_summary:
        from core.security.log_sanitisation import escape_nonprintable
        per_reason = ", ".join(
            f"{escape_nonprintable(reason)}={info.get('count', 0)}"
            for reason, info in skipped_summary.get("reasons", {}).items()
        )
        logger.info(
            "semgrep '%s': %d path(s) skipped, not scanned — %s",
            name, skipped_summary.get("total", 0), per_reason,
        )

    return SemgrepResult(
        name=name,
        config=config,
        target=str(target),
        findings=findings,
        files_examined=parsed_json["files_examined"],
        files_failed=parsed_json["files_failed"],
        skipped_summary=skipped_summary,
        semgrep_version=parsed_json["semgrep_version"],
        returncode=proc.returncode,
        stderr=proc.stderr or "",
        sarif=sarif_text,
        json_output=json_text,
        elapsed_ms=elapsed,
        errors=errors,
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
        subprocess_runner: Optional callable replacing the default
            sandboxed runner; passed through unchanged to run_rule()
            for every config (see run_rule for the required contract).
        unsandboxed: Explicit opt-out from the default sandbox, passed
            through unchanged to run_rule() for every config. Ignored
            when subprocess_runner is given.

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
