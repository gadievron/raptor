"""Zip export and import with security validation.

Exports a project output directory as a zip archive and imports
zip archives back, with path traversal and symlink validation.
"""

import hashlib
import shutil
import zipfile
from pathlib import Path
from typing import Dict, List, Tuple

from core.logging import get_logger

logger = get_logger()


def _check_zip_entries(infolist) -> List[str]:
    """Check zip entries for path traversal, absolute paths, and symlinks.

    Returns a list of warning strings. Empty means safe.
    """
    warnings: List[str] = []
    for info in infolist:
        name = info.filename
        if name.startswith("/") or name.startswith("\\"):
            warnings.append(f"Absolute path: {name}")
        if ".." in name.split("/") or ".." in name.split("\\"):
            warnings.append(f"Path traversal: {name}")
        if info.external_attr >> 28 == 0xA:
            warnings.append(f"Symlink: {name}")
    return warnings


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

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            warnings = _check_zip_entries(zf.infolist())
    except zipfile.BadZipFile:
        return False, ["Invalid zip file"]

    return len(warnings) == 0, warnings


def _sha256_file(path: Path) -> str:
    """Compute SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def export_project(project_output_dir: Path, dest_path: Path,
                   project_json_path: Path = None) -> Dict[str, str]:
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

    dest_path.parent.mkdir(parents=True, exist_ok=True)

    # Build zip manually to skip symlinks (shutil.make_archive follows them)
    with zipfile.ZipFile(dest_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for item in project_output_dir.rglob("*"):
            if item.is_symlink():
                logger.debug(f"Skipping symlink in export: {item}")
                continue
            if item.is_file():
                arcname = f"{project_output_dir.name}/{item.relative_to(project_output_dir)}"
                zf.write(item, arcname)
        # Include project metadata if provided
        if project_json_path and project_json_path.exists():
            zf.write(project_json_path, f"{project_output_dir.name}/.project.json")

    sha256 = _sha256_file(dest_path)
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

    # Single zip open: validate, inspect, and extract
    has_common_root = False
    project_name = zip_path.stem  # Fallback
    embedded_meta = None

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            # --- Security validation ---
            warnings = _check_zip_entries(zf.infolist())
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
            declared_size = sum(info.file_size for info in zf.infolist())
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
            output_dir.mkdir(parents=True, exist_ok=True)
            max_size = 10 * 1024 * 1024 * 1024  # 10GB
            bytes_extracted = 0
            try:
                for info in zf.infolist():
                    if info.filename.endswith("/.project.json") or info.filename == ".project.json":
                        continue
                    if info.is_dir():
                        continue
                    extract_dest = output_base if has_common_root else output_dir
                    extracted_path = Path(zf.extract(info, extract_dest))
                    actual_size = extracted_path.stat().st_size
                    if actual_size != info.file_size:
                        raise ValueError(
                            f"Size mismatch for {info.filename}: "
                            f"header says {info.file_size}, got {actual_size} "
                            f"(corrupted or malicious zip)"
                        )
                    bytes_extracted += actual_size
                    if bytes_extracted > max_size:
                        raise ValueError(
                            f"Extracted size ({bytes_extracted / 1024 / 1024:.0f}MB) "
                            f"exceeds limit ({max_size / 1024 / 1024:.0f}MB)"
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
