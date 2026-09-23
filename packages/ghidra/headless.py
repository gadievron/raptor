"""Wrapper for Ghidra's ``analyzeHeadless`` command."""

from __future__ import annotations

import getpass
import os
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from core.security.log_sanitisation import sanitise_for_terminal

from .detect import get_project_dir, get_project_name
from .export_script_java import EXPORT_SCRIPT_JAVA
from .project_util import prepare_working_copy
from core.security.env_sanitisation import safe_subprocess_env
from core.security.log_sanitisation import escape_nonprintable

logger = logging.getLogger(__name__)


class GhidraError(Exception):
    """Raised when a Ghidra headless operation fails."""


class GhidraProjectExistsError(GhidraError):
    """A create destination is already occupied.

    Distinct from the general failure class so callers can treat it
    as terminal (operator must choose: reuse the existing .gpr
    explicitly, or remove it) instead of degrading to a fallback
    engine that would overwrite the existing project's artifacts.
    """


def _find_headless() -> str:
    """Locate ``analyzeHeadless`` on PATH.  Raises GhidraError if absent."""
    binary = shutil.which("analyzeHeadless")
    if not binary:
        raise GhidraError(
            "analyzeHeadless not found on PATH — install Ghidra and "
            "ensure analyzeHeadless is accessible"
        )
    return binary


def _safe_env() -> dict:
    """Build a sanitised environment for the analyzeHeadless subprocess.

    Sets ``GHIDRA_HEADLESS_MAXMEM`` to 4G if not already set — the
    default 2G is tight for large binaries with decompilation.
    The base comes from the shared fail-closed helper: when
    ``RaptorConfig`` is unavailable the JVM gets a minimal
    allowlisted environment, never the full caller environment
    (which would hand API keys to a JVM that parses
    attacker-controlled data and falsify the
    ``env_caller_filtered=True`` assertion at the sandbox call).
    """
    env = safe_subprocess_env()
    env.setdefault("GHIDRA_HEADLESS_MAXMEM", "4G")
    return env


def _install_read_paths(headless: str) -> list[str]:
    """Read-allowlist extras for the sandboxed JVM.

    With ``restrict_reads`` the sandbox allows system dirs, /tmp,
    target, and output only — the Ghidra install tree (often under
    $HOME) must be granted explicitly. Resolves through the
    ``analyzeHeadless`` symlink to the install root (the wrapper
    lives in ``<install>/support/``).
    """
    real = Path(headless).resolve()
    if real.parent.name == "support":
        paths = [str(real.parent.parent)]
    else:
        # A copied/wrapper analyzeHeadless outside <install>/support/
        # — parent.parent could be $HOME (e.g. ~/bin). Grant only the
        # wrapper's own directory rather than silently widening.
        logger.warning(
            "analyzeHeadless at %s is not under a support/ dir — "
            "granting only its directory to the sandbox read set",
            real,
        )
        paths = [str(real.parent)]
    install_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if install_dir:
        candidate = Path(install_dir)
        resolved = str(candidate.resolve())
        valid = (
            candidate.is_absolute()
            and (candidate / "support" / "analyzeHeadless").is_file()
        )
        if valid and resolved not in paths:
            paths.append(resolved)
        elif not valid:
            logger.warning(
                "GHIDRA_INSTALL_DIR=%s does not look like a Ghidra "
                "install (no support/analyzeHeadless) — not granting "
                "it to the sandbox read set", install_dir,
            )
    home = str(Path.home().resolve())
    for granted in paths:
        if granted == "/" or granted == home:
            logger.warning(
                "sandbox read grant %s covers the whole home/root — "
                "check the analyzeHeadless install layout", granted,
            )
    return paths


def _jvm_scoped_env(work_path: Path) -> dict:
    """Sanitised env pointing every JVM home/tmp surface at *work_path*.

    Ghidra's launcher demands a writable user home (launch prefs, JDK
    detection cache). $HOME alone is not enough: the JDK derives
    user.home from the passwd entry, and inside the sandbox user
    namespace the uid maps to nobody (Debian home /nonexistent).
    JAVA_TOOL_OPTIONS reaches every JVM the launcher spawns. Ghidra
    also buffers database work in java.io.tmpdir; host /tmp is not
    granted under restrict_reads, so it is pinned inside *work_path*
    too. prepare_working_copy stamps the project OWNER to the invoking
    OS user; the sandboxed JVM's passwd-derived user.name is nobody,
    so force it back to the stamped owner or Ghidra refuses the
    project (NotOwnerException).

    *work_path* must be inside the sandbox's writable scope.
    """
    jvm_tmp = work_path / "jvm-tmp"
    jvm_tmp.mkdir(exist_ok=True)
    env = _safe_env()
    return dict(
        env,
        HOME=str(work_path),
        TMPDIR=str(jvm_tmp),
        XDG_CONFIG_HOME=str(work_path / ".config"),
        XDG_CACHE_HOME=str(work_path / ".cache"),
        JAVA_TOOL_OPTIONS=(
            env.get("JAVA_TOOL_OPTIONS", "")
            + f" -Duser.home={work_path}"
            + f" -Djava.io.tmpdir={jvm_tmp}"
            + f" -Duser.name={getpass.getuser()}"
        ).strip(),
    )


def _project_process_args(
    project_name: str, program_name: Optional[str],
) -> tuple:
    """Resolve a possibly folder-qualified program name for headless.

    ``analyzeHeadless`` addresses programs in project subfolders by
    appending the folder path to the PROJECT NAME argument
    (``proj/sub/dir``); ``-process`` takes only the leaf program
    name. A bare name (no ``/``) passes through unchanged.
    """
    if not program_name:
        return project_name, ["-process"]
    stripped = program_name.strip("/")
    # Program names come from the analysed project's own database
    # (attacker-controlled): a dash-leading leaf would be parsed by
    # analyzeHeadless as its next SWITCH (-deleteProject and friends),
    # and an empty component would corrupt the project path. Refuse.
    parts = stripped.split("/")
    if any(not part or part.startswith("-") or part == ".." for part in parts):
        raise GhidraError(
            f"refusing suspicious program name: {program_name!r} "
            "(empty, dash-leading, or traversal component)"
        )
    if len(parts) == 1:
        return project_name, ["-process", stripped]
    folder = "/".join(parts[:-1])
    return f"{project_name}/{folder}", ["-process", parts[-1]]


def _refuse_hidden_path_elements(path: Path, what: str) -> None:
    """Fail fast when *path* contains a dot-prefixed element.

    Ghidra's ProjectLocator rejects any project path with a
    dot-prefixed element ("Path element starting with '.' is not
    permitted"), and the working copy analyzeHeadless opens lives
    under *path* — but the JVM-side failure is cryptic and surfaces
    only after a full launch. Refuse here with an actionable message
    instead.

    Validates the TEXTUAL absolute form (os.path.abspath — no
    symlink dereference): that is the string the JVM receives.
    resolve() would both falsely refuse a visible symlink into a
    hidden real directory (which Ghidra opens fine) and falsely pass
    a textual .hidden element whose final component symlinks to a
    visible directory (which Ghidra rejects).
    """
    hidden = [p for p in Path(os.path.abspath(str(path))).parts
              if p.startswith(".") and p not in (".", "..")]
    if hidden:
        raise GhidraError(
            f"cannot place the Ghidra {what} under {path}: path "
            f"element(s) {hidden!r} start with '.' and Ghidra "
            "refuses project paths containing hidden directories — "
            "use an output location without dot-prefixed components"
        )


def _refuse_symlinked_path(path: Path, what: str) -> Path:
    """Refuse *path* when any existing component is a symlink; return
    the normalized absolute form.

    The sandbox realpath-resolves its write grants, so a planted
    symlink at (or above) the destination redirects both this
    module's own ``mkdir`` and the JVM's whole write scope to the
    symlink's TARGET — outside the RAPTOR-owned output location the
    caller believes it granted. Textual abspath == realpath exactly
    when no component dereferences a symlink (not-yet-existing tail
    components resolve textually), same validation posture as
    ``_refuse_hidden_path_elements``. The returned abspath is what
    downstream argv/grants must use — normalization also keeps a
    relative destination from reaching analyzeHeadless's positional
    project-directory argument unanchored.
    """
    ab = os.path.abspath(str(path))
    if os.path.realpath(ab) != ab:
        raise GhidraError(
            f"cannot place the Ghidra {what} under {path}: a path "
            "component is a symlink — the sandboxed JVM's write "
            "grant would follow it outside the intended output "
            "location; use a symlink-free output path"
        )
    return Path(ab)


def _remove_created_project(project_dir: Path) -> None:
    """Best-effort removal of a failed create's own debris.

    Only ever called on the ``raptor.*`` set this module itself just
    created — a pre-existing project never reaches the failure paths
    (the occupied-destination refusal runs first). Without this, a
    half-written project makes every subsequent create refuse over
    debris that no operator placed.
    """
    shutil.rmtree(project_dir / "raptor.rep", ignore_errors=True)
    for leftover in (project_dir / "raptor.gpr",
                     project_dir / "raptor.lock"):
        try:
            leftover.unlink()
        except OSError:
            pass


def create_project_from_binary(
    binary_path: Path,
    project_dir: Path,
    *,
    timeout: int = 3600,
) -> Path:
    """Create a Ghidra project by importing a raw binary.

    Runs ``analyzeHeadless -import`` with full auto-analysis into
    *project_dir* (created if missing). The project is named
    ``raptor`` — a fixed, RAPTOR-chosen name, so the attacker-chosen
    binary filename never reaches analyzeHeadless's project-name
    argument (a dash-leading name would be parsed as a switch, same
    class as ``_project_process_args``'s refusal).

    Args:
        binary_path: The raw binary to import.
        project_dir: RAPTOR-owned directory to create the project in.
        timeout: Maximum seconds for the headless process. Default
            3600, not the 300s metadata-export cap — import runs full
            auto-analysis, which is minutes-long on large binaries.

    Returns:
        The created ``.gpr`` path.

    Raises:
        GhidraError: If Ghidra is not installed, the destination is
            already occupied, or the import fails.
    """
    _refuse_hidden_path_elements(project_dir, "project")
    project_dir = _refuse_symlinked_path(project_dir, "project")
    headless = _find_headless()
    binary_path = Path(binary_path).resolve()
    gpr_path = project_dir / "raptor.gpr"

    # Same posture as import_enrichments' destination check: a
    # pre-placed project would be silently trusted (and analyzeHeadless
    # refuses a conflicting program file anyway) — refuse instead of
    # guessing. The .rep directory and lock are as load-bearing as the
    # .gpr marker itself. Distinct exception type: callers must treat
    # this as terminal, never as a degrade-to-fallback condition.
    for leftover in (
        gpr_path,
        gpr_path.with_suffix(".rep"),
        project_dir / "raptor.lock",
    ):
        if leftover.exists():
            raise GhidraProjectExistsError(
                f"destination already exists: {leftover} — remove it, "
                f"or import the existing project by passing "
                f"{gpr_path} directly"
            )

    project_dir.mkdir(parents=True, exist_ok=True)
    # JVM home/tmp inside the writable scope (see export_project for
    # the /tmp-grant rationale).
    with tempfile.TemporaryDirectory(
        prefix="raptor-ghidra-create-", dir=project_dir,
    ) as work_dir:
        env = _jvm_scoped_env(Path(work_dir))

        cmd = [
            headless,
            str(project_dir),
            "raptor",
            "-import", str(binary_path),
        ]

        logger.info("running: %s", escape_nonprintable(" ".join(cmd)))

        try:
            # Same sandbox posture as export_project: the JVM parses
            # an attacker-supplied binary (loader + auto-analysis) —
            # network denied, reads restricted to system dirs, the
            # binary's directory, the project dir, and the Ghidra
            # install; writes scoped to the project dir.
            from core.sandbox import run as _sandbox_run
            result = _sandbox_run(
                cmd,
                block_network=True,
                target=str(binary_path.parent),
                output=str(project_dir),
                restrict_reads=True,
                readable_paths=_install_read_paths(headless),
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                # env comes from safe_subprocess_env() above —
                # already allowlist-filtered upstream.
                env_caller_filtered=True,
            )
        except subprocess.TimeoutExpired:
            # A killed mid-create leaves partial project files that
            # the occupied-destination refusal would blame on the
            # operator next run — remove our own debris on every
            # failure path.
            _remove_created_project(project_dir)
            raise GhidraError(
                f"analyzeHeadless -import timed out after {timeout}s — "
                "auto-analysis on large binaries can need more; "
                "consider increasing timeout"
            )
        except OSError as e:
            _remove_created_project(project_dir)
            raise GhidraError(f"failed to run analyzeHeadless: {e}")

    if result.returncode != 0:
        _remove_created_project(project_dir)
        stderr_tail = result.stderr[-500:] if result.stderr else "(no stderr)"
        raise GhidraError(
            f"analyzeHeadless -import exited {result.returncode}:\n"
            f"{stderr_tail}"
        )

    if not gpr_path.exists():
        _remove_created_project(project_dir)
        raise GhidraError(
            f"analyzeHeadless -import completed but no project was "
            f"created at {gpr_path}:\n"
            f"{(result.stdout or '')[-500:]}"
        )

    return gpr_path


def export_project(
    gpr_path: Path,
    output_path: Path,
    *,
    program_name: Optional[str] = None,
    decompile: bool = False,
    timeout: int = 300,
) -> Path:
    """Export a Ghidra project to RAPTOR's JSON format.

    Runs ``analyzeHeadless`` with the Java export script against the
    specified project.  Writes the result to *output_path*.

    Args:
        gpr_path: Path to the ``.gpr`` file.
        output_path: Where to write the exported JSON.
        program_name: Specific program within the project to export.
            If None, processes the default (first) program.
        decompile: If True, decompile every function (slow).
            Default False — import metadata only.
        timeout: Maximum seconds for the headless process.

    Returns:
        The output path (same as *output_path*).

    Raises:
        GhidraError: If Ghidra is not installed or the export fails.
    """
    _refuse_hidden_path_elements(output_path.parent, "working copy")
    headless = _find_headless()
    project_name_str, process_args = _project_process_args(
        get_project_name(gpr_path), program_name,
    )

    # The working copy lives INSIDE the output scope: the sandbox's
    # mount-namespace mode replaces host-/tmp extra grants with a
    # private scratch under restrict_reads, so a /tmp work dir would
    # be invisible to the JVM — only target=/output= binds survive.
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="raptor-ghidra-work-", dir=output_path.parent,
    ) as work_dir:
        work_path = Path(work_dir)

        work_gpr = prepare_working_copy(gpr_path, work_path)
        work_project_dir = str(get_project_dir(work_gpr))
        env = _jvm_scoped_env(work_path)

        script_dir = work_path / "scripts"
        script_dir.mkdir()
        (script_dir / "ExportRaptor.java").write_text(EXPORT_SCRIPT_JAVA, encoding="utf-8")

        script_args = [str(output_path)]
        if decompile:
            script_args.append("decomp")

        cmd = [
            headless,
            work_project_dir,
            project_name_str,
            *process_args,
            "-noanalysis",
            "-scriptPath", str(script_dir),
            "-postScript", "ExportRaptor.java", *script_args,
        ]

        # The argv embeds project/program names sourced from the
        # hostile project database — scrub control bytes and bound
        # the length before they reach the operator's terminal.
        logger.info("running: %s",
                    sanitise_for_terminal(" ".join(cmd), max_len=2000))

        try:
            # Repo convention for binary-touching tools (see the
            # binary-oracle's r2/binutils invocations): the JVM
            # analyses an ATTACKER-SUPPLIED binary, so it runs
            # sandboxed — network denied, writes scoped to the
            # working copy + export output.
            from core.sandbox import run as _sandbox_run
            result = _sandbox_run(
                cmd,
                block_network=True,
                target=str(work_path),
                output=str(output_path.parent),
                # The JVM parses attacker-controlled project data —
                # deny reads outside system dirs + the working copy +
                # the Ghidra install tree ($HOME stays invisible).
                restrict_reads=True,
                readable_paths=_install_read_paths(headless),
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                # env comes from RaptorConfig.get_safe_env() above —
                # already allowlist-filtered upstream.
                env_caller_filtered=True,
            )
        except subprocess.TimeoutExpired:
            raise GhidraError(
                f"analyzeHeadless timed out after {timeout}s — "
                f"consider increasing timeout for large projects"
            )
        except OSError as e:
            raise GhidraError(f"failed to run analyzeHeadless: {e}")

    if result.returncode != 0:
        stderr_tail = result.stderr[-500:] if result.stderr else "(no stderr)"
        stdout_tail = result.stdout[-1000:] if result.stdout else ""
        raise GhidraError(
            f"analyzeHeadless exited {result.returncode}:\n{stderr_tail}"
            + (f"\n--- stdout ---\n{stdout_tail}" if stdout_tail else "")
        )

    if not output_path.exists():
        raise GhidraError(
            f"analyzeHeadless completed but output file not created at "
            f"{output_path} — check Ghidra script output:\n"
            f"{result.stdout[-500:]}"
        )

    return output_path


def import_enrichments(
    gpr_path: Path,
    enrichments_path: Path,
    output_gpr: Path,
    *,
    program_name: Optional[str] = None,
    copy_prepared: bool = False,
    timeout: int = 300,
) -> Path:
    """Apply RAPTOR enrichments back to a Ghidra project.

    Copies the original project to *output_gpr* and runs
    ``analyzeHeadless`` with the import script to apply findings.

    Args:
        gpr_path: Path to the original ``.gpr`` file.
        enrichments_path: JSON file with RAPTOR findings to import.
        output_gpr: Where to write the enriched ``.gpr`` copy.
        timeout: Maximum seconds for the headless process.

    Returns:
        The output ``.gpr`` path.

    Raises:
        GhidraError: If Ghidra is not installed or the import fails.
    """
    if output_gpr.name != gpr_path.name:
        raise GhidraError(
            f"output_gpr must keep the source project name "
            f"({gpr_path.name!r}); analyzeHeadless opens the project "
            f"by its on-disk name and would not find "
            f"{output_gpr.name!r}"
        )

    dst_dir = output_gpr.parent
    dst_name = output_gpr.stem

    # Explicit contract instead of inferring from destination
    # existence (a pre-placed copy would otherwise be silently
    # trusted): the bridge sets copy_prepared=True after preparing
    # the copy itself; standalone callers get a fresh copy below and
    # a refusal if something already occupies the destination. All
    # validation runs BEFORE the tool lookup (hermetic on
    # Ghidra-less hosts) and the copy AFTER it (no stray copy when
    # analyzeHeadless is missing).
    if copy_prepared:
        if not output_gpr.exists():
            raise GhidraError(
                f"copy_prepared=True but no working copy at "
                f"{output_gpr}"
            )
    else:
        # The .gpr is only a marker file — the .rep directory holds
        # the actual project data, so a pre-placed .rep (or stale
        # lock) is just as untrustworthy as a pre-placed .gpr.
        for leftover in (
            output_gpr,
            output_gpr.with_suffix(".rep"),
            dst_dir / f"{output_gpr.stem}.lock",
        ):
            if leftover.exists():
                raise GhidraError(
                    f"destination already exists: {leftover} — "
                    "remove it or pass copy_prepared=True if it is "
                    "a working copy you just prepared"
                )

    _refuse_hidden_path_elements(dst_dir, "enriched project copy")
    headless = _find_headless()
    if not copy_prepared:
        dst_dir.mkdir(parents=True, exist_ok=True)
        prepare_working_copy(gpr_path, dst_dir)

    from .import_script_java import IMPORT_SCRIPT_JAVA
    # Script dir + JVM HOME inside the output scope (see
    # export_project for the /tmp-grant rationale).
    with tempfile.TemporaryDirectory(
        prefix="raptor-ghidra-import-", dir=dst_dir,
    ) as script_dir:
        script_path = Path(script_dir) / "ImportRaptor.java"
        script_path.write_text(IMPORT_SCRIPT_JAVA, encoding="utf-8")
        env = _jvm_scoped_env(Path(script_dir))

        proc_project, process_args = _project_process_args(
            dst_name, program_name,
        )
        cmd = [
            headless,
            str(dst_dir),
            proc_project,
            *process_args,
            "-noanalysis",
            "-scriptPath", script_dir,
            "-postScript", "ImportRaptor.java", str(enrichments_path),
        ]

        # The argv embeds project/program names sourced from the
        # hostile project database — scrub control bytes and bound
        # the length before they reach the operator's terminal.
        logger.info("running: %s",
                    sanitise_for_terminal(" ".join(cmd), max_len=2000))

        try:
            # Same sandbox posture as export_project: the JVM opens
            # attacker-influenced project data — network denied,
            # writes scoped to the destination copy + script dir.
            from core.sandbox import run as _sandbox_run
            result = _sandbox_run(
                cmd,
                block_network=True,
                target=str(dst_dir),
                # The destination copy is what analyzeHeadless saves
                # the enriched program into (plus its lock file) — it
                # must be the writable scope. The script dir doubles
                # as the JVM's HOME (config cache) and must be
                # writable too — the mount-namespace sandbox gives
                # children a private /tmp, so host tempdirs are not
                # implicitly writable.
                output=str(dst_dir),
                # Same read posture as export_project; the
                # enrichments JSON sits in dst_dir (bridge flow) or
                # must be readable via these scopes.
                restrict_reads=True,
                readable_paths=_install_read_paths(headless)
                + [str(enrichments_path.parent.resolve())],
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                # env comes from RaptorConfig.get_safe_env() above —
                # already allowlist-filtered upstream.
                env_caller_filtered=True,
            )
        except subprocess.TimeoutExpired:
            raise GhidraError(
                f"analyzeHeadless import timed out after {timeout}s"
            )
        except OSError as e:
            raise GhidraError(f"failed to run analyzeHeadless: {e}")

    if result.returncode != 0:
        stderr_tail = result.stderr[-500:] if result.stderr else "(no stderr)"
        raise GhidraError(
            f"analyzeHeadless import exited {result.returncode}:\n{stderr_tail}"
        )

    # Name-keyed entries resolve inside the script, so applied counts
    # can be lower than submitted — surface the script's own tally.
    for line in (result.stdout or "").splitlines():
        if "RAPTOR import:" in line:
            logger.info("%s", line.strip())
            break

    return output_gpr
