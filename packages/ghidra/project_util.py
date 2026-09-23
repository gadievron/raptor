"""Shared utilities for Ghidra project file handling.

Used by both ``session.py`` (PyGhidra in-process) and ``headless.py``
(analyzeHeadless subprocess) to avoid duplicating working-copy and
ownership-fix logic.
"""

from __future__ import annotations

import getpass
import logging
import os
import shutil
import stat
from pathlib import Path

from .detect import get_project_name

logger = logging.getLogger(__name__)


def _get_xml_parser():
    """Return defusedxml if available, else stdlib with a warning."""
    try:
        import defusedxml.ElementTree as ET
        return ET
    except ImportError:
        logger.debug(
            "defusedxml not installed — falling back to stdlib XML "
            "(install defusedxml for XXE-safe parsing of .gpr projects)"
        )
        import xml.etree.ElementTree as ET
        return ET


def fix_owner(prp_path: Path) -> bool:
    """Patch the OWNER in a project.prp to the current OS user.

    Ghidra refuses to open projects owned by a different user
    (``NotOwnerException``). Returns True if patched.
    """
    ET = _get_xml_parser()
    try:
        tree = ET.parse(str(prp_path))
        root = tree.getroot()
        for state in root.iter("STATE"):
            if state.get("NAME") == "OWNER":
                old = state.get("VALUE", "")
                current = getpass.getuser()
                if old != current:
                    state.set("VALUE", current)
                    tree.write(
                        str(prp_path),
                        xml_declaration=True,
                        encoding="UTF-8",
                    )
                    logger.info(
                        "patched project owner: %s -> %s", old, current
                    )
                    return True
    except Exception:  # noqa: BLE001 — best-effort patch; a corrupt prp surfaces later as the JVM's NotOwnerException, so name the real cause here
        logger.debug("owner patch failed for %s", prp_path, exc_info=True)
    return False


#: Total-size ceiling for a .rep working copy. A hostile project can
#: otherwise point the copy at /dev/zero-sized content and fill the
#: tempdir (often tmpfs = RAM) before any sandbox engages.
MAX_REP_COPY_BYTES = 4 * 1024 * 1024 * 1024


def prepare_working_copy(gpr_path: Path, work_dir: Path) -> Path:
    """Copy a Ghidra project into *work_dir* and fix ownership.

    Returns the path to the copied ``.gpr`` inside *work_dir*.
    The original project is never modified.

    The .rep directory is attacker-controlled, so the copy walks it
    with ``lstat`` semantics: symlinks and other non-regular entries
    are skipped with a warning (following them would let a hostile
    project exfiltrate arbitrary local files into the working copy —
    which round-trips back into the deliverable — or fill the disk
    from a device node), and the total copied size is capped.
    """
    name = get_project_name(gpr_path)
    dst_gpr = work_dir / gpr_path.name
    if gpr_path.is_symlink():
        raise ValueError(f"refusing symlinked project file: {gpr_path}")

    src_rep = gpr_path.with_suffix(".rep")
    dst_rep = work_dir / f"{name}.rep"
    # Always a CLEAN copy: a pre-existing destination .rep would be
    # merge-overwritten (planted files absent from the source survive
    # into the copy the JVM opens — and into the enriched
    # deliverable).
    if dst_rep.exists():
        shutil.rmtree(dst_rep)
    if dst_gpr.exists():
        dst_gpr.unlink()

    # The .gpr rides the same byte ceiling as the .rep tree: it is a
    # small XML pointer file in any real project, and a hostile
    # multi-GB one would otherwise bypass the tempdir-fill defence the
    # .rep copy already has.
    gpr_size = gpr_path.stat().st_size
    if gpr_size > MAX_REP_COPY_BYTES:
        msg = (
            f"refusing to copy {gpr_path.name}: {gpr_size} bytes "
            f"exceeds the {MAX_REP_COPY_BYTES}-byte project-copy ceiling"
        )
        raise ValueError(msg)
    shutil.copy2(gpr_path, dst_gpr)
    if src_rep.is_dir() and not src_rep.is_symlink():
        _copy_rep_tree(src_rep, dst_rep)

    prp = dst_rep / "project.prp"
    if prp.is_file():
        fix_owner(prp)

    lock = work_dir / f"{name}.lock"
    if lock.exists():
        lock.unlink()

    return dst_gpr


def _copy_rep_tree(src_rep: Path, dst_rep: Path) -> None:
    """Copy a .rep tree, regular files and directories only."""
    copied = 0
    skipped = 0
    for root, dirs, files in os.walk(src_rep, followlinks=False):
        rel = Path(root).relative_to(src_rep)
        (dst_rep / rel).mkdir(parents=True, exist_ok=True)
        # prune symlinked directories from the walk
        kept_dirs = []
        for d in dirs:
            if (Path(root) / d).is_symlink():
                skipped += 1
            else:
                kept_dirs.append(d)
        dirs[:] = kept_dirs
        for f in files:
            src = Path(root) / f
            st = src.lstat()
            if not stat.S_ISREG(st.st_mode):
                skipped += 1
                continue
            copied += st.st_size
            if copied > MAX_REP_COPY_BYTES:
                raise ValueError(
                    f"project .rep exceeds the "
                    f"{MAX_REP_COPY_BYTES >> 30} GiB working-copy cap "
                    f"at {src} — refusing to copy further"
                )
            shutil.copy2(src, dst_rep / rel / f, follow_symlinks=False)
    if skipped:
        logger.warning(
            "working copy of %s: skipped %d symlink/non-regular "
            "entr%s (hostile-project defense)",
            src_rep, skipped, "y" if skipped == 1 else "ies",
        )
