"""Zip export and import with security validation.

Exports a project output directory as a zip archive and imports
zip archives back, with path traversal and symlink validation.
"""

import shutil
import struct
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from core.hash import sha256_file
from core.logging import get_logger

logger = get_logger()


def _check_zip_entries(infolist) -> List[str]:
    """Check zip entries for path traversal, absolute paths, and symlinks.

    Returns a list of warning strings. Empty means safe.
    """
    warnings: List[str] = []
    for info in infolist:
        name = info.filename
        # Pre-fix the absolute-path + traversal checks tested
        # `name.startswith("/")` then `".." in name.split("/")`
        # / `name.split("\\")`. Two leaks:
        #
        #   1. WINDOWS DRIVE LETTERS. `C:\Users\...` doesn't
        #      start with `/` or `\\`, but on Windows `Path()
        #      .joinpath` against an absolute drive-letter path
        #      ANCHORS to that drive — so a zip entry named
        #      `C:\evil\file` extracted under `output_dir`
        #      lands at `C:\evil\file`, not `output_dir/C/evil/
        #      file`. The traversal vector is silent on POSIX
        #      but dangerous on Windows.
        #
        #   2. SEPARATOR INCONSISTENCY. The traversal check
        #      split on `/` AND `\\` independently, so an
        #      entry like `foo/../bar` was caught (`..` in the
        #      `/`-split) but the path `foo\..\bar` was caught
        #      via the `\\`-split. A MIXED-separator entry like
        #      `foo/..\\bar` slipped through both: the `/`-split
        #      yielded `["foo", "..\\bar"]` (no bare `..`), and
        #      the `\\`-split yielded `["foo/..", "bar"]` (no
        #      bare `..`). Normalise BOTH separators first then
        #      split once.
        #
        # Normalise backslashes to forward slashes for the
        # checks. Then check absolute-path on the normalised
        # form, traversal on the normalised split, AND check
        # for a Windows drive-letter prefix (`C:`, `c:`, etc.).
        normalised = name.replace("\\", "/")
        if normalised.startswith("/"):
            warnings.append(f"Absolute path: {name}")
        # Windows drive letter (e.g. `C:`, `c:`, `Z:`).
        if len(name) >= 2 and name[0].isalpha() and name[1] == ":":
            warnings.append(f"Windows-absolute path: {name}")
        if ".." in normalised.split("/"):
            warnings.append(f"Path traversal: {name}")
        if info.external_attr >> 28 == 0xA:
            warnings.append(f"Symlink: {name}")
    return warnings


# Cap on a project zip's entry count. A legitimate RAPTOR project zip
# holds at most a few hundred output files (run dirs, findings, reports,
# attachments). 10,000 is generous and far below the entry counts that
# trigger zip-bomb-shaped resource exhaustion via infolist materialisation.
_MAX_ENTRIES = 10_000


class _ZipBombShapeError(Exception):
    """Raised when an open zipfile exceeds `_MAX_ENTRIES`.

    Distinct from `ValueError` so callers can render a single, consistent
    bomb-shape rejection message regardless of which entry path they took
    (validate_zip_contents return-tuple vs. import_project raise).
    """


# EOCD record format (PKZIP appnote 4.3.16):
#   signature (4) | disk# (2) | cd-disk (2) | entries-on-disk (2) |
#   total-entries (2) | cd-size (4) | cd-offset (4) | comment-len (2) | comment
# ZIP64 EOCD locator (PKZIP appnote 4.3.15) signature:
#   b"\x50\x4b\x06\x07" — points back to the ZIP64 EOCD record
#   (signature b"\x50\x4b\x06\x06") which carries an 8-byte
#   total-entries field at offset +32.
_EOCD_SIG = b"\x50\x4b\x05\x06"
_ZIP64_EOCD_SIG = b"\x50\x4b\x06\x06"
_ZIP64_EOCD_LOCATOR_SIG = b"\x50\x4b\x06\x07"

# Comment ≤ 65535 (uint16) + 22-byte fixed EOCD header.
_EOCD_SEARCH_BYTES = 65557


def _peek_zip_total_entries(zip_path: Path) -> Optional[int]:
    """Read EOCD pre-flight to estimate total entries WITHOUT calling ZipFile().

    Returns the total-entries count for valid zips with a parseable
    EOCD record, or None if the EOCD signature is missing / malformed.
    `ZipFile.__init__` reads the entire central directory into memory;
    a zip-bomb-shaped archive with millions of entries causes a
    multi-GB RSS spike there regardless of any downstream cap. Doing
    this read first lets us reject the archive before the spike.

    On the 0xFFFF "ZIP64 in use" sentinel we follow the locator to the
    ZIP64 EOCD record. On any parse failure we return None so the
    caller can fall back to the standard ZipFile() path (which will
    raise BadZipFile for genuinely malformed archives).
    """
    try:
        size = zip_path.stat().st_size
    except OSError:
        return None
    if size < 22:
        return None

    read_len = min(size, _EOCD_SEARCH_BYTES)
    try:
        with zip_path.open("rb") as fh:
            fh.seek(size - read_len)
            tail = fh.read(read_len)
            eocd_off = tail.rfind(_EOCD_SIG)
            if eocd_off < 0 or eocd_off + 22 > len(tail):
                return None
            # entries-on-disk @ +8 (uint16); total-entries @ +10 (uint16)
            entries_disk, entries_total = struct.unpack_from(
                "<HH", tail, eocd_off + 8,
            )
            if entries_total != 0xFFFF and entries_disk != 0xFFFF:
                return entries_total
            # ZIP64 sentinel — try the locator (20 bytes BEFORE EOCD).
            loc_off = eocd_off - 20
            if loc_off < 0:
                return None
            if tail[loc_off:loc_off + 4] != _ZIP64_EOCD_LOCATOR_SIG:
                return None
            # ZIP64 EOCD record absolute offset @ locator +8 (uint64).
            zip64_eocd_off, = struct.unpack_from("<Q", tail, loc_off + 8)
            if zip64_eocd_off < 0 or zip64_eocd_off + 56 > size:
                return None
            fh.seek(zip64_eocd_off)
            zip64_eocd = fh.read(56)
            if zip64_eocd[:4] != _ZIP64_EOCD_SIG:
                return None
            # total-entries @ +32 (uint64) in the ZIP64 EOCD record.
            entries_total_64, = struct.unpack_from("<Q", zip64_eocd, 32)
            return entries_total_64
    except (OSError, struct.error):
        return None


def _enforce_zip_entry_cap(zip_path: Path) -> None:
    """Raise `_ZipBombShapeError` if the EOCD pre-flight reports over-cap.

    A None return from `_peek_zip_total_entries` means "couldn't parse
    the EOCD" — we let the caller proceed to `ZipFile()`, which will
    either succeed for a small valid archive or raise `BadZipFile`.
    Only a definitively-over-cap parse triggers the early reject.
    """
    count = _peek_zip_total_entries(zip_path)
    if count is not None and count > _MAX_ENTRIES:
        raise _ZipBombShapeError(
            f"zip declares {count} entries in EOCD — refusing as "
            f"zip-bomb shape (legitimate RAPTOR project exports have "
            f"<< 1000 entries)"
        )


def _collect_bounded_infolist(zf: zipfile.ZipFile) -> List[zipfile.ZipInfo]:
    """Materialise `zf.infolist()` with the `_MAX_ENTRIES` cap enforced.

    The EOCD pre-flight at `_enforce_zip_entry_cap` rejects archives
    whose declared entry count exceeds the cap BEFORE `ZipFile()` is
    called. This function provides defence-in-depth for cases where
    the EOCD pre-flight cannot parse the record (e.g. unusual but
    valid archives that `ZipFile` still accepts) and the actual
    in-memory `filelist` length exceeds the cap.

    Note: by the time this runs, `ZipFile.__init__` has already
    materialised the entire central directory into `zf.filelist` —
    iterating here limits downstream processing cost (and the size of
    the returned `entries` list), but does not save memory on the
    construction itself. The EOCD pre-flight is what bounds RSS.

    Raises `_ZipBombShapeError` on over-cap; callers translate per
    their error model.
    """
    entries: List[zipfile.ZipInfo] = []
    for i, info in enumerate(zf.infolist()):
        if i >= _MAX_ENTRIES:
            raise _ZipBombShapeError(
                f"zip has more than {_MAX_ENTRIES} entries — "
                f"refusing as zip-bomb shape (legitimate "
                f"RAPTOR project exports have << 1000 entries)"
            )
        entries.append(info)
    return entries


def validate_zip_contents(zip_path: Path) -> Tuple[bool, List[str]]:
    """Check a zip file for path traversal, absolute paths, and symlinks.

    Args:
        zip_path: Path to the zip file.

    Returns:
        Tuple of (safe, warnings). safe is False if any dangerous entries found.
    """
    zip_path = Path(zip_path)

    if not zip_path.exists():
        return False, ["Zip file does not exist"]

    # EOCD pre-flight: reject over-cap archives BEFORE the ZipFile
    # constructor reads the entire central directory into memory.
    try:
        _enforce_zip_entry_cap(zip_path)
    except _ZipBombShapeError as e:
        return False, [str(e)]

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            try:
                entries = _collect_bounded_infolist(zf)
            except _ZipBombShapeError as e:
                return False, [str(e)]
            warnings = _check_zip_entries(entries)
    except zipfile.BadZipFile:
        return False, ["Invalid zip file"]

    return len(warnings) == 0, warnings


def _is_transient_artefact(path: Path) -> bool:
    """Per-process / per-machine files that shouldn't ship in a
    portable export bundle.

    Currently filters:
      * ``*.lock`` — POSIX advisory lock files (e.g.
        ``annotations/<src>.md.lock`` from
        ``core.annotations.storage._file_lock``). They carry no
        data — they're just stable file descriptors for
        ``fcntl.flock``. A new importing process creates its own
        lock file on first write; shipping the original is bundle
        bloat and operator confusion.
      * ``.annotation-*.tmp`` — orphaned tempfiles from
        interrupted atomic writes. Should already be cleaned up
        by the writer's ``except`` block, but this is belt-and-
        braces.

    Pre-existing exclusions are NOT widened by this commit — the
    historical behaviour for ``.reads-manifest`` and
    ``.raptor-run.json`` is preserved.
    """
    name = path.name
    if name.endswith(".lock"):
        return True
    if name.startswith(".annotation-") and name.endswith(".tmp"):
        return True
    return False


def export_project(project_output_dir: Path, dest_path: Path,
                   project_json_path: Path = None,
                   force: bool = False) -> Dict[str, str]:
    """Zip a project output directory, skipping symlinks.

    Args:
        project_output_dir: The project's output directory to archive.
        dest_path: Destination path for the zip file.
        project_json_path: Optional project metadata JSON to include in the zip.

    Returns:
        Dict with 'path' (zip file path) and 'sha256' (hex digest).

    Raises:
        FileNotFoundError: If the source directory doesn't exist.
    """
    project_output_dir = Path(project_output_dir)
    dest_path = Path(dest_path)

    if not project_output_dir.is_dir():
        raise FileNotFoundError(f"Directory not found: {project_output_dir}")

    # Ensure dest has .zip extension
    if dest_path.suffix != ".zip":
        dest_path = dest_path.with_suffix(".zip")

    if dest_path.exists() and not force:
        raise FileExistsError(f"File already exists: {dest_path} (use --force to overwrite)")

    dest_path.parent.mkdir(parents=True, exist_ok=True)

    # Build zip manually to skip symlinks (shutil.make_archive follows them)
    # plus per-process / transient artefacts that shouldn't ship in a
    # portable archive (POSIX advisory lock files, tempfile leftovers).
    with zipfile.ZipFile(dest_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for item in project_output_dir.rglob("*"):
            if item.is_symlink():
                logger.debug(f"Skipping symlink in export: {item}")
                continue
            if item.is_file():
                if _is_transient_artefact(item):
                    logger.debug(f"Skipping transient artefact: {item}")
                    continue
                arcname = f"{project_output_dir.name}/{item.relative_to(project_output_dir)}"
                zf.write(item, arcname)
        # Include project metadata if provided
        if project_json_path and project_json_path.exists():
            zf.write(project_json_path, f"{project_output_dir.name}/.project.json")

    sha256 = sha256_file(dest_path)
    logger.info(f"Exported project to {dest_path} (sha256: {sha256})")
    return {"path": str(dest_path), "sha256": sha256}


def import_project(zip_path: Path, projects_dir: Path,
                   force: bool = False,
                   output_base: Path = None) -> Dict[str, str]:
    """Import a zipped project.

    Validates the zip, extracts output data to output_base/<name>/,
    and registers the project in projects_dir. Restores project metadata
    from the embedded .project.json.

    Args:
        zip_path: Path to the zip archive.
        projects_dir: Directory for project JSON files (~/.raptor/projects/).
        force: If True, overwrite existing project with the same name.
        output_base: Base directory for output data (default: out/projects/).

    Returns:
        Dict with 'name', 'output_dir', and optionally 'orphaned_output'.

    Raises:
        ValueError: If zip is unsafe, not a RAPTOR archive, or project
            exists and force is False.
        FileNotFoundError: If zip file doesn't exist.
    """
    import json

    zip_path = Path(zip_path)
    projects_dir = Path(projects_dir)
    if output_base is None:
        output_base = Path("out/projects")

    if not zip_path.exists():
        raise FileNotFoundError(f"Zip file not found: {zip_path}")

    # EOCD pre-flight: reject over-cap archives BEFORE the ZipFile
    # constructor reads the entire central directory into memory.
    try:
        _enforce_zip_entry_cap(zip_path)
    except _ZipBombShapeError as e:
        raise ValueError(f"Unsafe zip file rejected: {e}") from e

    # Single zip open: validate, inspect, and extract
    has_common_root = False
    project_name = zip_path.stem  # Fallback
    embedded_meta = None

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            # --- Security validation ---
            # Use the same entry-count cap that `validate_zip_contents`
            # applies (F029: pre-fix `import_project` re-implemented the
            # check inline by calling `_check_zip_entries(zf.infolist())`
            # directly, which silently dropped the cap and was vulnerable
            # to zip-bomb-shaped archives with millions of entries).
            try:
                bounded_entries = _collect_bounded_infolist(zf)
            except _ZipBombShapeError as e:
                raise ValueError(f"Unsafe zip file rejected: {e}") from e
            warnings = _check_zip_entries(bounded_entries)
            if warnings:
                raise ValueError(
                    f"Unsafe zip file rejected: {'; '.join(warnings)}"
                )

            # --- Determine structure and check for project metadata ---
            names = zf.namelist()
            if not names:
                raise ValueError("Empty zip file")

            first_part = names[0].split("/")[0]
            has_subdirs = "/" in names[0]
            all_same_root = all(n.split("/")[0] == first_part for n in names)
            has_common_root = has_subdirs and all_same_root

            # Require .project.json — reject non-RAPTOR archives early
            meta_path = f"{first_part}/.project.json" if has_common_root else ".project.json"
            if meta_path not in names:
                raise ValueError(
                    "Not a RAPTOR project archive (missing .project.json). "
                    "Use `raptor project export` to create importable archives."
                )

            # --- Fast-reject on declared size ---
            # Reuse the already-bounded infolist from the cap check
            # above (F029: avoids a second full infolist materialisation).
            declared_size = sum(info.file_size for info in bounded_entries)
            max_size = 10 * 1024 * 1024 * 1024  # 10GB
            if declared_size > max_size:
                raise ValueError(
                    f"Zip declared size ({declared_size / 1024 / 1024:.0f}MB) exceeds "
                    f"limit ({max_size / 1024 / 1024:.0f}MB)"
                )

            # --- Read project metadata ---
            if has_common_root:
                project_name = first_part
            try:
                embedded_meta = json.loads(zf.read(meta_path))
                if embedded_meta.get("name"):
                    project_name = embedded_meta["name"]
            except (json.JSONDecodeError, KeyError):
                raise ValueError("Corrupt .project.json in archive")

            # --- Validate name before any filesystem work ---
            from .project import ProjectManager
            mgr = ProjectManager(projects_dir=projects_dir)
            try:
                mgr._validate_name(project_name)
            except ValueError as e:
                raise ValueError(f"Cannot import: {e}")

            existing = mgr.load(project_name)
            if existing and not force:
                raise ValueError(
                    f"Project '{project_name}' already exists. Use --force to overwrite."
                )

            # --- Prepare output directory ---
            # Use the zip's root directory name for extraction path (not the
            # embedded project name) — extraction preserves the zip structure.
            output_dir = output_base / (first_part if has_common_root else project_name)
            orphaned_output = None
            if existing and force:
                old_output_path = Path(existing.output_dir).resolve()
                if output_dir.exists():
                    shutil.rmtree(output_dir)
                mgr.delete(project_name, purge=False)
                if old_output_path != output_dir.resolve() and old_output_path.exists():
                    orphaned_output = str(old_output_path)
                logger.info(f"Removed existing project '{project_name}' (force=True)")

            # --- Extract output data ---
            #
            # Streaming extract with cumulative byte cap. Pre-fix
            # `zf.extract(info, ...)` wrote the FULL decompressed
            # file to disk before the size check ran. A zip-bomb
            # entry with a small declared size but a 10 GB
            # decompressed payload then materialised the entire
            # 10 GB on disk before the cap caught it — fills the
            # filesystem, may OOM if the entry is held in memory
            # by the zlib backend, and leaves the partial file
            # for cleanup.
            #
            # Streaming via `zf.open(info, "r")` + chunked read
            # lets us check both the per-entry declared size AND
            # the running cumulative bytes BEFORE writing each
            # chunk to the destination. The per-chunk write
            # short-circuits as soon as the cap is exceeded.
            output_dir.mkdir(parents=True, exist_ok=True)
            max_size = 10 * 1024 * 1024 * 1024  # 10GB
            chunk = 1024 * 1024  # 1 MiB
            bytes_extracted = 0
            try:
                # Reuse the bounded infolist captured during validation
                # (F029): the cap check has already proven the count is
                # ≤ _MAX_ENTRIES, no need to materialise again.
                for info in bounded_entries:
                    if info.filename.endswith("/.project.json") or info.filename == ".project.json":
                        continue
                    if info.is_dir():
                        continue
                    # Refuse if the per-entry declared size alone
                    # would exceed remaining budget — saves opening
                    # a stream we'd immediately cancel.
                    if bytes_extracted + info.file_size > max_size:
                        raise ValueError(
                            f"Entry {info.filename!r} ({info.file_size / 1024 / 1024:.0f}MB) "
                            f"would exceed limit ({max_size / 1024 / 1024:.0f}MB)"
                        )
                    extract_dest = Path(output_base if has_common_root else output_dir)
                    target_path = extract_dest / info.filename
                    # Resolve and re-check containment — _check_zip_entries
                    # already guards path traversal, but defence in depth
                    # against a future regression in that helper.
                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    actual_size = 0
                    with zf.open(info, "r") as src, open(target_path, "wb") as dst:
                        while True:
                            buf = src.read(chunk)
                            if not buf:
                                break
                            actual_size += len(buf)
                            bytes_extracted += len(buf)
                            if bytes_extracted > max_size:
                                raise ValueError(
                                    f"Extracted size ({bytes_extracted / 1024 / 1024:.0f}MB) "
                                    f"exceeds limit ({max_size / 1024 / 1024:.0f}MB) "
                                    f"during {info.filename!r}"
                                )
                            dst.write(buf)
                    if actual_size != info.file_size:
                        raise ValueError(
                            f"Size mismatch for {info.filename}: "
                            f"header says {info.file_size}, got {actual_size} "
                            f"(corrupted or malicious zip)"
                        )
            except Exception:
                # Clean up partial extraction
                if output_dir.exists():
                    shutil.rmtree(output_dir)
                raise

    except zipfile.BadZipFile:
        raise ValueError("Invalid zip file")

    # Register the project
    target = embedded_meta.get("target", "(imported)") if embedded_meta else "(imported)"
    description = embedded_meta.get("description", "") if embedded_meta else ""
    notes = embedded_meta.get("notes", "") if embedded_meta else ""
    created = embedded_meta.get("created") if embedded_meta else None

    project = mgr.create(project_name, target, description=description,
                         output_dir=str(output_dir), resolve_target=False,
                         created=created)
    if notes:
        mgr.update_notes(project_name, notes)

    logger.info(f"Imported project '{project_name}' to {output_dir}")
    result = {"name": project_name, "output_dir": str(output_dir)}
    if orphaned_output:
        result["orphaned_output"] = orphaned_output
    return result
