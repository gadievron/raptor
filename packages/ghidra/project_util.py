"""Shared utilities for Ghidra project file handling.

Used by both ``session.py`` (PyGhidra in-process) and ``headless.py``
(analyzeHeadless subprocess) to avoid duplicating working-copy and
ownership-fix logic.
"""

from __future__ import annotations

import getpass
import logging
import os
import tempfile
import stat
from dataclasses import dataclass
from pathlib import Path

from core.atomic_fs import open_exclusive_artifact, rmtree_hardened
from core.atomic_fs.fs_lock import artifact_lock
from core.run.scratch import scratch_dir
from core.source import open_regular_beneath, open_regular_gated

from .detect import get_project_name

logger = logging.getLogger(__name__)


def _get_xml_parser():
    """Return defusedxml if available, else stdlib with a warning."""
    try:
        import defusedxml.ElementTree as ET
        return ET
    except ImportError:
        # WARNING, not debug: entity-expansion protection for hostile
        # .gpr/.prp XML then depends entirely on the host expat — the
        # operator should see the degradation, not discover it.
        logger.warning(
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


# Directory/file count complements bytes: empty trees can exhaust inodes.
# Higher limits admit larger databases at higher disk cost; lower limits may
# refuse legitimate projects. Header and database share both budgets.
MAX_REP_COPY_ENTRIES = 400_000


@dataclass
class _CopyBudget:
    copied: int = 0
    entries: int = 0

    def entry(self):
        self.entries += 1
        if self.entries > MAX_REP_COPY_ENTRIES:
            raise ValueError(f"project working-copy cap: {MAX_REP_COPY_ENTRIES} entries")


def _identity(path, *, version=False):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    identity = (info.st_dev, info.st_ino, info.st_mode)
    return (*identity, info.st_size, info.st_mtime_ns, info.st_ctime_ns) if version else identity


def _copy_stream(stream, destination, budget, *, header=False):
    info = os.fstat(stream.fileno())
    label = "project-copy ceiling" if header else "working-copy cap"
    if info.st_size > MAX_REP_COPY_BYTES - budget.copied:
        raise ValueError(f"{label}: exceeds {MAX_REP_COPY_BYTES} bytes")
    # Let builtin open own the descriptor from its opener onward, including
    # buffer-setup failures, while preserving the shared 0644/umask policy.
    with open(destination, "xb", opener=lambda path, flags: open_exclusive_artifact(path)) as output:
        while True:
            remaining = MAX_REP_COPY_BYTES - budget.copied
            chunk = stream.read(min(1024 * 1024, remaining + 1))
            if not chunk:
                break
            if len(chunk) > remaining:
                raise ValueError(f"{label}: exceeds {MAX_REP_COPY_BYTES} bytes")
            budget.copied += len(chunk)
            output.write(chunk)
    after = os.fstat(stream.fileno())
    if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
            after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError("project source changed while being copied")
    if not header:
        os.chmod(destination, stat.S_IMODE(info.st_mode) & 0o777)
        os.utime(destination, ns=(info.st_atime_ns, info.st_mtime_ns))


def _copy_rep_tree(src_rep: Path, dst_rep: Path, *, budget=None) -> None:
    """Copy regular files beneath a real source root with bounded actual I/O."""
    if not stat.S_ISDIR(src_rep.lstat().st_mode):
        raise ValueError("project .rep root must be a real directory")
    src_rep, dst_rep = src_rep.resolve(), dst_rep.resolve()
    if dst_rep.is_relative_to(src_rep):
        raise ValueError("project destination is inside the source database")
    budget = budget if budget is not None else _CopyBudget()
    skipped = 0
    def failed_walk(exc):
        raise exc
    for root, dirs, files in os.walk(src_rep, followlinks=False, onerror=failed_walk):
        rel = Path(root).relative_to(src_rep)
        if rel == Path("."):
            budget.entry()
        (dst_rep / rel).mkdir(parents=True, exist_ok=True)
        kept = []
        for name in dirs:
            budget.entry()
            if (Path(root) / name).is_symlink():
                skipped += 1
            else:
                kept.append(name)
        dirs[:] = kept
        for name in files:
            budget.entry()
            source = Path(root) / name
            if not stat.S_ISREG(source.lstat().st_mode):
                skipped += 1
                continue
            stream = open_regular_beneath(src_rep, source.relative_to(src_rep), "rb")
            if stream is None:
                raise OSError(f"project file changed or is unreadable: {source}")
            with stream:
                _copy_stream(stream, dst_rep / rel / name, budget)
    if skipped:
        logger.warning("working copy of %r: skipped %d symlink/non-regular entries", src_rep, skipped)


def _remove_node(path):
    try:
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            return rmtree_hardened(path)
        path.unlink()
        return True
    except FileNotFoundError:
        return True
    except OSError:
        logger.warning("project copy cleanup incomplete: %r", path, exc_info=True)
        return False


def _publish_project(staged, destinations, originals):
    staged_ids = [_identity(path) for path in staged]
    backup = None
    if any(original is not None for original in originals):
        backup = Path(tempfile.mkdtemp(prefix=".ghidra-retired-", dir=destinations[0].parent))
    try:
        for destination, original in zip(destinations, originals):
            if original is not None:
                retired = backup / destination.name
                os.rename(destination, retired)
                if _identity(retired) != original:
                    raise ValueError("project destination changed during publication")
        for source, destination, identity in zip(staged, destinations, staged_ids):
            if identity is not None:
                os.rename(source, destination)
    except BaseException:
        # Only remove our newly published nodes. Recovery copies are outside
        # scratch so a rollback failure cannot discard the old deliverable.
        for destination, identity in zip(destinations, staged_ids):
            try:
                if identity is not None and _identity(destination) == identity:
                    _remove_node(destination)
            except OSError:
                logger.warning("cannot inspect failed project publication at %r", destination, exc_info=True)
        if backup is not None:
            for destination in destinations:
                retired = backup / destination.name
                if os.path.lexists(retired):
                    try:
                        if not os.path.lexists(destination):
                            os.rename(retired, destination)
                    except OSError:
                        logger.warning("cannot restore project copy from %r", retired, exc_info=True)
            try:
                if any(backup.iterdir()):
                    logger.warning("previous project copy retained at %r", backup)
                else:
                    _remove_node(backup)
            except OSError:
                logger.warning("project recovery copy retained at %r", backup, exc_info=True)
        raise
    if backup is not None and not rmtree_hardened(backup):
        logger.warning("retired project copy cleanup incomplete: %r", backup)


def copy_project(gpr_path: Path, destination: Path, *, repair_owner=False) -> Path:
    """Stage a bounded project pair and replace the destination with rollback.

    Readers must synchronize separately; two filesystem entries cannot be
    published as one atomic rename. Failed staging leaves the old pair intact.
    """
    gpr_path, destination = Path(gpr_path).absolute(), Path(destination).resolve()
    if gpr_path.is_symlink():
        raise ValueError(f"refusing symlinked project file: {gpr_path}")
    src_rep = gpr_path.with_suffix(".rep")
    name = get_project_name(gpr_path)
    dst_gpr, dst_rep = destination / gpr_path.name, destination / f"{name}.rep"
    source = gpr_path.parent.resolve() / gpr_path.name
    if (destination == source.parent or destination.is_relative_to(src_rep.resolve())
            or source.is_relative_to(dst_rep.resolve())
            or src_rep.resolve().is_relative_to(dst_rep.resolve())):
        raise ValueError("project destination overlaps source inputs")
    source_rep_identity = _identity(src_rep)
    if source_rep_identity is not None and not stat.S_ISDIR(source_rep_identity[2]):
        raise ValueError("project .rep root must be a real directory, not a symlink")
    destination.mkdir(parents=True, exist_ok=True)
    with artifact_lock(destination / ".ghidra-project", required=True,
                       subject="Ghidra project copy"):
        dst_lock = destination / f"{name}.lock"
        destinations = [dst_gpr, dst_rep, dst_lock]
        originals = [_identity(path) for path in destinations]
        versions = [_identity(path, version=True) for path in destinations]
        if originals[0] is not None and stat.S_ISDIR(originals[0][2]):
            raise ValueError("destination .gpr must not be a directory")
        if originals[1] is not None and not stat.S_ISDIR(originals[1][2]):
            raise ValueError("destination .rep must be a real directory")
        if originals[2] is not None and stat.S_ISDIR(originals[2][2]):
            raise ValueError("destination project lock must not be a directory")
        with scratch_dir(".ghidra-copy-", dir=destination) as scratch:
            staged_gpr, staged_rep = scratch / dst_gpr.name, scratch / dst_rep.name
            budget = _CopyBudget()
            budget.entry()
            with open_regular_gated(gpr_path, follow_symlinks=False) as stream:
                _copy_stream(stream, staged_gpr, budget, header=True)
            if source_rep_identity is not None:
                _copy_rep_tree(src_rep, staged_rep, budget=budget)
            if _identity(src_rep) != source_rep_identity:
                raise ValueError("source project database changed during staging")
            prp = staged_rep / "project.prp"
            if repair_owner and prp.is_file():
                fix_owner(prp)
            if [_identity(path, version=True) for path in destinations] != versions:
                raise ValueError("project destination changed during staging")
            _publish_project([staged_gpr, staged_rep, scratch / dst_lock.name], destinations, originals)
        return dst_gpr


def prepare_working_copy(gpr_path: Path, work_dir: Path) -> Path:
    """Prepare a bounded private project copy without modifying the source."""
    return copy_project(gpr_path, work_dir, repair_owner=True)
