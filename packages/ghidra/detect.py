"""Detect and validate Ghidra projects and installations."""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import defusedxml.ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
    # WARNING, not silence (same rule as project_util._get_xml_parser):
    # this module parses the hostile project's .gpr/.prp XML, and the
    # fallback leaves entity-expansion protection to the host expat.
    logger.warning(
        "defusedxml not installed — falling back to stdlib XML "
        "(install defusedxml for XXE-safe parsing of .gpr projects)"
    )

GHIDRA_MIN_MAJOR = 10


def is_ghidra_project(path: Path) -> bool:
    """Return True if *path* looks like a Ghidra project.

    A Ghidra project is a ``<name>.gpr`` XML file sitting next to a
    ``<name>.rep/`` directory that contains the actual data.  We check
    both: the extension AND the sibling directory.  A bare ``.gpr``
    without a ``.rep/`` is a broken project — we still detect it (so
    the caller can give a useful error) but :func:`validate_project`
    will reject it.
    """
    path = Path(path)
    if not path.is_file():
        return False
    return path.suffix == ".gpr"


def validate_project(path: Path) -> Optional[str]:
    """Validate a ``.gpr`` path for import.

    Returns None on success or an error string explaining what's wrong.
    """
    path = Path(path)
    if not path.exists():
        return f"path does not exist: {path}"
    if not path.is_file():
        return f"not a file: {path}"
    if path.suffix != ".gpr":
        return f"not a .gpr file: {path}"

    rep_dir = path.with_suffix(".rep")
    if not rep_dir.is_dir():
        return (
            f"missing .rep directory alongside {path.name} — "
            f"expected {rep_dir.name}/ in {path.parent}"
        )

    # Ghidra 11.x creates an empty .gpr marker; the real descriptor
    # lives in .rep/project.prp.  Older versions put XML in the .gpr.
    # Accept either: non-empty .gpr must parse as FILE_INFO XML,
    # empty .gpr is valid iff .rep/project.prp exists and parses.
    if path.stat().st_size == 0:
        prp = rep_dir / "project.prp"
        if not prp.is_file():
            return (
                f"empty .gpr and no project.prp in {rep_dir.name}/ — "
                f"project appears corrupt"
            )
        try:
            tree = ET.parse(prp)
            root = tree.getroot()
            if root.tag != "FILE_INFO":
                return f"unexpected root element <{root.tag}> in project.prp"
        except ET.ParseError as e:
            return f"malformed project.prp XML: {e}"
    else:
        try:
            tree = ET.parse(path)
            root = tree.getroot()
            if root.tag != "FILE_INFO":
                return f"unexpected root element <{root.tag}>, expected <FILE_INFO>"
        except ET.ParseError as e:
            return f"malformed .gpr XML: {e}"

    return None


def get_project_name(path: Path) -> str:
    """Extract the project name from a ``.gpr`` path.

    The project name is the stem of the ``.gpr`` file, which Ghidra
    uses as the project identifier in ``analyzeHeadless`` commands.
    """
    return Path(path).stem


def get_project_dir(path: Path) -> Path:
    """Return the directory containing the ``.gpr`` file.

    ``analyzeHeadless`` expects the project directory (containing
    both ``<name>.gpr`` and ``<name>.rep/``), not the ``.gpr`` file
    itself.
    """
    return Path(path).parent


def get_project_version(path: Path) -> Optional[str]:
    """Extract the Ghidra version that created the project, if available.

    Checks the ``.gpr`` XML first, then falls back to
    ``.rep/project.prp`` (Ghidra 11.x stores the descriptor there
    and leaves the ``.gpr`` empty).
    """
    path = Path(path)

    # Try .gpr XML (older Ghidra, or non-empty .gpr)
    try:
        if path.stat().st_size > 0:
            tree = ET.parse(path)
            root = tree.getroot()
            for state in root.iter("STATE"):
                if state.get("NAME") == "GHIDRA_VERSION":
                    return state.get("VALUE")
            for state in root.iter("STATE"):
                name = state.get("NAME", "")
                if name == "OWNER":
                    continue
                val = state.get("VALUE", "")
                if val and "." in val and val[0].isdigit():
                    return val
    except (ET.ParseError, OSError):
        pass

    # Fallback: .rep/project.prp (Ghidra 11.x)
    try:
        prp = path.with_suffix(".rep") / "project.prp"
        if prp.is_file():
            prp_tree = ET.parse(prp)
            for state in prp_tree.iter("STATE"):
                if state.get("NAME") == "GHIDRA_VERSION":
                    return state.get("VALUE")
    except (ET.ParseError, OSError):
        pass

    return None


def _is_hex(text: str) -> bool:
    """True for a non-empty lowercase-hex storage id field."""
    return bool(text) and all(c in "0123456789abcdef" for c in text)


def get_programs(path: Path) -> list[str]:
    """List program names in a Ghidra project (no JVM).

    Reads ``.rep/idata/~index.dat`` — a text index whose entry lines
    are ``<folder-id>:<program name>:<file-id>`` — so the REAL
    program names come back, not the numeric idata folder ids. Falls
    back to scanning the idata subdirectories (ids only) when the
    index is missing or unparseable.
    """
    rep_dir = path.with_suffix(".rep")
    idata = rep_dir / "idata"
    if not idata.is_dir():
        return []

    index = idata / "~index.dat"
    # The index is attacker-controlled and read in-process: refuse
    # symlinks (a hostile project must not turn this into an
    # arbitrary-file read oracle) and cap size/entries.
    if index.is_file() and not index.is_symlink():
        programs = []
        try:
            if index.lstat().st_size > 1024 * 1024:
                raise OSError("index over 1 MiB — refusing")
            for line in index.read_text(
                    encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                # Entry lines are "<hex storage id>:<name>[:<fileId>]"
                # — the fileId is absent on V0 indexes and V1 entries
                # with a null fileId, so 2-field lines are legal. The
                # hex check on field 0 excludes the VERSION=/NEXT-ID:/
                # MD5: header+trailer lines and folder lines.
                parts = line.split(":")
                if len(parts) >= 2 and _is_hex(parts[0]):
                    # Ghidra forbids ":" in names; the rejoin is
                    # belt-and-braces for a hand-edited index.
                    name = (
                        parts[1] if len(parts) == 2
                        else ":".join(parts[1:-1])
                    )
                    if name:
                        programs.append(name)
                if len(programs) >= 4096:
                    break
        except OSError:
            programs = []
        if programs:
            return programs

    programs = []
    for child in sorted(idata.iterdir()):
        if child.is_dir() and not child.name.startswith("."):
            programs.append(child.name)
    return programs


def ghidra_available() -> bool:
    """Return True if ``analyzeHeadless`` is on PATH."""
    return shutil.which("analyzeHeadless") is not None


def pyghidra_available() -> bool:
    """Return True if ``pyghidra`` is importable."""
    from importlib.util import find_spec
    return find_spec("pyghidra") is not None


def get_ghidra_version() -> Optional[str]:
    """Get the installed Ghidra version via ``analyzeHeadless``.

    Parses the version from stderr output (Ghidra prints a banner
    before any real work).  Returns None if Ghidra is not installed
    or the version cannot be determined.
    """
    binary = shutil.which("analyzeHeadless")
    if not binary:
        return None
    try:
        # Sanitised env (the codeql version-probe idiom): Ghidra is a
        # JVM launcher and honours JAVA_TOOL_OPTIONS / _JAVA_OPTIONS
        # from the shell (agent attach at startup).
        from core.security.env_sanitisation import safe_subprocess_env
        r = subprocess.run(
            [binary, "--help"],
            capture_output=True,
            text=True,
            timeout=10,
            env=safe_subprocess_env(strip_target_markers=True),
        )
        # Version appears in stderr banner like "Ghidra 11.1.2 ..."
        for line in (r.stdout + r.stderr).splitlines():
            if "ghidra" in line.lower():
                parts = line.split()
                for part in parts:
                    if part and part[0].isdigit() and "." in part:
                        return part
    except (subprocess.TimeoutExpired, OSError):
        pass
    return None


def check_ghidra_version(version: Optional[str]) -> Optional[str]:
    """Validate a Ghidra version string.

    Returns None if acceptable, or a warning/error message.
    """
    if version is None:
        return "could not determine Ghidra version — proceeding with caution"
    try:
        major = int(version.split(".")[0])
    except (ValueError, IndexError):
        return f"could not parse Ghidra version {version!r}"
    if major < GHIDRA_MIN_MAJOR:
        return (
            f"Ghidra {version} is below minimum supported version "
            f"{GHIDRA_MIN_MAJOR}.0 — upgrade Ghidra"
        )
    return None

def prefer_in_process() -> bool:
    """Should Ghidra work run through in-process pyghidra?

    The in-process JVM parses attacker-controlled project databases
    with the full privileges of the RAPTOR process — no sandbox. The
    subprocess ``analyzeHeadless`` path runs the same work inside
    ``core.sandbox.run`` (network denied, writes scoped), so it is
    the default whenever it is available. pyghidra engages only when
    headless is absent, or when the operator explicitly asserts trust
    via ``RAPTOR_GHIDRA_IN_PROCESS`` (truthy).
    """
    import os
    if not pyghidra_available():
        return False
    opt_in = os.environ.get("RAPTOR_GHIDRA_IN_PROCESS", "").lower() in (
        "1", "true", "yes", "on",
    )
    if opt_in:
        return True
    if not ghidra_available():
        logger.warning(
            "pyghidra runs IN-PROCESS (no sandbox) — analyzeHeadless "
            "was not found on PATH, so there is no sandboxed "
            "alternative for this operation. Install Ghidra's "
            "analyzeHeadless for the sandboxed default."
        )
        return True
    return False
