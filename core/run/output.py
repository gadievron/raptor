"""Output directory resolution.

Centralises the logic for choosing where a command writes its output.
Checks (in order): explicit --out argument, active project, default out/ dir.
"""

import contextlib
import logging
import os
import re
import sys
import tempfile
import time
from pathlib import Path

from core.config import RaptorConfig

logger = logging.getLogger(__name__)


class TargetMismatchError(ValueError):
    """Raised when the scan target differs from the active project's target."""


def unique_run_suffix(separator: str = "_") -> str:
    """Sub-microsecond-unique suffix for run-dir names: timestamp +
    PID + monotonic-ns tail, joined by ``separator``. Use ``-`` for
    hyphen-style names (project mode), ``_`` for underscore-style
    (standalone mode). Only ``-`` and ``_`` are accepted to avoid
    strftime-directive injection (e.g., a caller passing ``%H`` would
    get the format string interpreted).

    Collision-prevention layers:

      1. Wall-clock second — gives chronological ordering.
      2. PID — disambiguates concurrent processes (cross-process).
      3. ``monotonic_ns() % 10_000`` 4-digit tail — disambiguates
         same-process calls within the same wall-clock second.

    Pre-fix the suffix was just `<timestamp>_pid<PID>`. The docstring
    noted "single process calling this multiple times within the same
    second would reuse its PID — not a concern for the lifecycle
    entry-point use case (one call per run start)" but that
    assumption is fragile: test harnesses iterating `start_run`,
    batch tooling, supervisor loops invoking subcommands serially,
    and any future caller that re-enters the lifecycle within a
    second all hit the in-process collision. Concrete consequences
    depend on the caller — `mkdir(exist_ok=True)` silently shares
    the dir (interleaved writes), `mkdir(exist_ok=False)` raises,
    downstream code may overwrite per-run files. The 4-digit
    monotonic tail closes that window without changing the
    user-visible name shape meaningfully (one extra suffix).
    """
    if separator not in ("_", "-"):
        msg = f"separator must be '_' or '-', got {separator!r}"
        raise ValueError(msg)
    fmt = f"%Y%m%d{separator}%H%M%S"
    # Modulo by 10_000 gives a 4-digit tail — short enough to keep
    # directory names readable, wide enough that collisions on
    # consecutive same-process calls are vanishingly rare
    # (`monotonic_ns()` resolution is ~1ns on Linux; the modulo
    # window cycles every 10 microseconds, so two consecutive calls
    # would have to land on the same modulo bucket within ~10us).
    ns_tail = time.monotonic_ns() % 10_000
    return (
        f"{time.strftime(fmt)}{separator}pid{os.getpid()}"
        f"{separator}{ns_tail:04d}"
    )


def _resolve_active_project() -> tuple[str, str, str] | None:
    """Resolve the current active project from the .active symlink.

    Returns (output_dir, name, target) or None if no project is active.
    The symlink is the single source of truth — no env var fallback.
    """
    try:
        from core.project.project import ProjectManager
        mgr = ProjectManager()
        active_name = mgr.get_active()
        if active_name:
            project = mgr.load(active_name)
            if project:
                return project.output_dir, project.name, project.target
    except Exception as exc:  # noqa: BLE001 — fall back to the default out/ dir
        logger.warning("active project resolution failed: %s", exc)

    return None


def volatile_target_reason(target: str | None) -> str | None:
    """Reason string when *target* is a scratch/volatile path, else None.

    Flags exactly three shapes (a stale machine-generated project once
    left ``/tmp`` as the active default target, and only an interactive
    ask caught it):

    * the system temp root itself (``/tmp``, ``/var/tmp``,
      ``tempfile.gettempdir()``) — subdirectories are legitimate
      checkouts and do NOT flag;
    * a nonexistent path;
    * an empty directory.
    """
    if not target:
        return None
    if _URL_SCHEME_RE.match(target):
        # A URL project target is fine for /web but is not a
        # filesystem default for code-scanning commands.
        return "is a URL — filesystem commands need a path (use /web for URL targets)"
    try:
        resolved = Path(target).resolve()
    except (OSError, ValueError):
        return "cannot be resolved"
    temp_roots = {Path("/tmp"), Path("/var/tmp")}
    with contextlib.suppress(OSError, ValueError):
        temp_roots.add(Path(tempfile.gettempdir()).resolve())
    if resolved in temp_roots:
        return "is the system temp directory"
    if not resolved.exists():
        return "does not exist"
    if resolved.is_dir():
        try:
            next(resolved.iterdir())
        except StopIteration:
            return "is an empty directory"
        except OSError:
            return "cannot be read"
    return None


def resolve_default_target() -> str | None:
    """CLAUDE.md DEFAULT TARGET DIRECTORY resolution: (1) active project,
    (2) ``RAPTOR_CALLER_DIR``, (3) None (caller asks the user).

    Pre-existing layering: ``_resolve_active_project`` returns the active
    project's target; ``raptor_agentic.py`` falls back to
    ``RAPTOR_CALLER_DIR``; ``scanner.py`` has neither (``required=True``).
    Centralising the chain here lets every dispatcher / entry script
    inherit the same behaviour without re-implementing it. Returns the
    resolved target path or None if neither signal is present — the
    caller is expected to error or prompt.

    Sanity gate: when the active project's target is scratch/volatile
    (the system temp dir itself, nonexistent, or an empty directory —
    e.g. a stale machine-generated corpus project pointing at /tmp),
    the DEFAULT resolution refuses with a loud banner and returns None
    instead of silently steering the run at scratch space. The caller
    then asks the operator (interactive sessions confirm via the
    documented structured prompt; non-interactive sessions stop). An
    EXPLICIT target path always bypasses this gate — it only guards
    the implicit default.
    """
    active = _resolve_active_project()
    if active is not None:
        _out, project_name, project_target = active
        reason = volatile_target_reason(project_target)
        if reason:
            banner = (
                f"REFUSING default target: active project "
                f"'{project_name}' points at {project_target}, which "
                f"{reason}. Not steering a no-path command at scratch "
                f"space.\n"
                f"  To proceed anyway: pass the target path explicitly.\n"
                f"  To fix the session: /project use <real-project> "
                f"or /project use none"
            )
            logger.warning("%s", banner)
            print(banner, file=sys.stderr)
            return None
        return project_target
    env = os.environ.get("RAPTOR_CALLER_DIR")
    return env or None


def get_output_dir(command: str, target_name: str = "",
                   explicit_out: str | None = None,
                   target_path: str | None = None) -> Path:
    """Resolve the output directory for a command run.

    Priority:
    1. explicit_out (from --out argument) — used as-is, no project check
    2. Active project (.active symlink — the single source of truth,
       no env-var fallback) — timestamped subdir
    3. Default: RaptorConfig.get_out_dir() with command prefix + timestamp

    Args:
        command: Command name (scan, agentic, validate, etc.)
        target_name: Target name for directory naming (e.g. repo name)
        explicit_out: Explicit output path from --out argument
        target_path: Actual path being analyzed (for project target validation)

    Returns:
        Path to the output directory (not yet created).

    Raises:
        TargetMismatchError: If target_path is outside the active project's target.
    """
    if explicit_out:
        active = _resolve_active_project()
        if active:
            logger.warning("--out overrides active project '%s' output directory", active[1])
            # --out is the sanctioned escape hatch for running against
            # a different tree while a project is active (results do
            # not land in the project dir), so a mismatch is not fatal
            # here — but it must be VISIBLE, and project trust must
            # not leak: core.project.trust gates every marker on the
            # run target matching the project target, --out runs
            # included.
            _proj_dir, project_name, project_target = active
            effective_target = target_path or os.environ.get("RAPTOR_CALLER_DIR")
            if effective_target and project_target:
                try:
                    _check_target_mismatch(
                        effective_target, project_name, project_target)
                except TargetMismatchError:
                    logger.warning(
                        "--out run targets %s, outside active project "
                        "'%s' (%s) — treated as standalone; project "
                        "trust markers do not apply",
                        effective_target, project_name, project_target,
                    )
        return Path(explicit_out).resolve()

    active = _resolve_active_project()

    if active:
        project_dir, project_name, project_target = active

        # Validate target matches the project
        effective_target = target_path or os.environ.get("RAPTOR_CALLER_DIR")
        if effective_target and project_target:
            _check_target_mismatch(effective_target, project_name,
                                   project_target, command=command)

        # Project mode: command-YYYYMMDD-HHMMSS-pidNNNNN (hyphens throughout).
        # See unique_run_suffix() for the collision-prevention rationale.
        return Path(project_dir) / f"{command}-{unique_run_suffix('-')}"

    # Standalone mode: command_target_YYYYMMDD_HHMMSS_pidNNNNN (underscores,
    # backwards compatible with existing directories created before project
    # support).
    suffix = unique_run_suffix("_")
    if target_name:
        dirname = f"{command}_{target_name}_{suffix}"
    else:
        dirname = f"{command}_{suffix}"

    return RaptorConfig.get_out_dir() / dirname


_URL_SCHEME_RE = re.compile(r"\A[a-zA-Z][a-zA-Z0-9+.-]*://")


def _check_target_mismatch(target_path: str, project_name: str,
                           project_target: str, command: str = "") -> None:
    """Raise TargetMismatchError if target is outside the active project's target.

    URL-shaped targets (``/web`` scans) are not filesystem paths —
    resolving ``https://example.com`` against the cwd and comparing it
    to a project directory is meaningless, so they skip the check.

    ``fuzz`` targets are binaries that routinely live OUTSIDE the
    project source tree (build dirs, installed paths, fuzzing
    harnesses); an out-of-tree binary warns instead of raising.
    """
    if _URL_SCHEME_RE.match(target_path):
        if _URL_SCHEME_RE.match(project_target):
            # Both sides are URLs: compare them (trailing-slash
            # tolerant) instead of skipping — /web --url https://B
            # must not silently land its run in project A.
            if target_path.rstrip("/") != project_target.rstrip("/"):
                raise TargetMismatchError(
                    f"Run target {target_path!r} does not match the active "
                    f"project's target {project_target!r}. Use --out to "
                    "direct the run elsewhere, or switch projects."
                )
        return

    resolved = Path(target_path).resolve()
    project_resolved = Path(project_target).resolve()

    # Exact match or subdirectory — OK
    try:
        resolved.relative_to(project_resolved)
        return
    except ValueError:
        pass

    if command == "fuzz":
        logger.warning(
            "fuzz target %s is outside project %s (%s) — binaries often "
            "live out-of-tree; proceeding, but check the active project "
            "if this is unexpected",
            target_path, project_name, project_target,
        )
        return

    # Operator-facing error: show the paths the operator actually
    # typed, not the resolved forms. Pre-fix the message printed
    # `resolved` and `project_resolved` directly. On macOS `/var`,
    # `/tmp` and several other top-levels are symlinks to
    # `/private/var`, `/private/tmp` etc. — `resolve()` rewrites
    # them. The operator who passed `--target /var/log/foo` then
    # saw an error claiming `/private/var/log/foo is outside
    # project (/private/var/log/proj)` and didn't recognise either
    # path. The remediation hint also suggested re-running with
    # the rewritten path, which works but reads as cargo-cult.
    # Echo the operator's strings instead; the resolved forms only
    # exist for the comparison.
    #
    # Remediation: pre-fix the hint said create-then-'/project use
    # none', which leaves the just-created project inactive AND the
    # mismatching one active — following it verbatim changed nothing.
    msg = (
        f"target {target_path} is outside project {project_name} ({project_target})\n"
        f"  A project tracks one target. To analyze a different codebase:\n"
        f"    /project create <name> --target {target_path}\n"
        f"    /project use <name>\n"
        f"  Or run without a project: /project use none"
    )
    raise TargetMismatchError(msg)
