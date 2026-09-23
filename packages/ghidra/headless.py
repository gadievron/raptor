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

logger = logging.getLogger(__name__)


class GhidraError(Exception):
    """Raised when a Ghidra headless operation fails."""


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

    env = _safe_env()

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
        # Ghidra's launcher demands a writable user home (launch
        # prefs, JDK detection cache). $HOME alone is not enough: the
        # JDK derives user.home from the passwd entry, and inside the
        # sandbox user namespace the uid maps to nobody (Debian home
        # /nonexistent). JAVA_TOOL_OPTIONS reaches every JVM the
        # launcher spawns.
        jvm_tmp = work_path / "jvm-tmp"
        jvm_tmp.mkdir()
        env = dict(
            env,
            HOME=str(work_path),
            TMPDIR=str(jvm_tmp),
            XDG_CONFIG_HOME=str(work_path / ".config"),
            XDG_CACHE_HOME=str(work_path / ".cache"),
            JAVA_TOOL_OPTIONS=(
                env.get("JAVA_TOOL_OPTIONS", "")
                + f" -Duser.home={work_path}"
                # Ghidra buffers database work in java.io.tmpdir;
                # host /tmp is not granted under restrict_reads.
                + f" -Djava.io.tmpdir={jvm_tmp}"
                # prepare_working_copy stamps the project OWNER to
                # the invoking OS user; inside the sandbox user
                # namespace the JVM's passwd-derived user.name is
                # nobody, so force it back to the stamped owner or
                # Ghidra refuses the project (NotOwnerException).
                + f" -Duser.name={getpass.getuser()}"
            ).strip(),
        )

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

    env = _safe_env()

    from .import_script_java import IMPORT_SCRIPT_JAVA
    # Script dir + JVM HOME inside the output scope (see
    # export_project for the /tmp-grant rationale).
    with tempfile.TemporaryDirectory(
        prefix="raptor-ghidra-import-", dir=dst_dir,
    ) as script_dir:
        script_path = Path(script_dir) / "ImportRaptor.java"
        script_path.write_text(IMPORT_SCRIPT_JAVA, encoding="utf-8")
        # Writable user home for the JVM launcher (see export_project
        # for the passwd-derivation rationale).
        jvm_tmp = Path(script_dir) / "jvm-tmp"
        jvm_tmp.mkdir()
        env = dict(
            env,
            HOME=str(script_dir),
            TMPDIR=str(jvm_tmp),
            XDG_CONFIG_HOME=str(Path(script_dir) / ".config"),
            XDG_CACHE_HOME=str(Path(script_dir) / ".cache"),
            JAVA_TOOL_OPTIONS=(
                env.get("JAVA_TOOL_OPTIONS", "")
                + f" -Duser.home={script_dir}"
                + f" -Djava.io.tmpdir={jvm_tmp}"
                + f" -Duser.name={getpass.getuser()}"
            ).strip(),
        )

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
