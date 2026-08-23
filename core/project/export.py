"""Zip export and import with security validation.

Exports a project output directory as a zip archive and imports
zip archives back, with path traversal and symlink validation.
"""

import os
import shutil
import zipfile
from pathlib import Path

from core.hash import sha256_file
from core.json import load_json, save_json
from core.logging import get_logger
from core.zip import DEFAULT_MAX_ENTRIES, bomb_shaped_reason, peek_eocd

logger = get_logger()


def _check_zip_entries(infolist) -> list[str]:
    """Check zip entries for path traversal, absolute paths, and symlinks.

    Returns a list of warning strings. Empty means safe.
    """
    warnings: list[str] = []
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


# Cap on a project zip's entry count. The substrate-level constant
# (``core.zip.DEFAULT_MAX_ENTRIES`` = 10 000) is the source of truth;
# the local alias keeps the existing error-message phrasing readable.
# A legitimate RAPTOR project zip holds at most a few hundred output
# files (run dirs, findings, reports, attachments). 10 000 is generous
# and far below the entry counts that trigger zip-bomb-shaped resource
# exhaustion via infolist materialisation.
_MAX_ENTRIES = DEFAULT_MAX_ENTRIES

# Cap on the embedded ``.project.json`` metadata entry. It carries a
# handful of short fields (name, target, description, notes, created)
# — a few KB at most in practice. Import buffers and parses it
# wholesale in the trusted parent BEFORE the streaming per-entry size
# checks of the extraction loop apply, so it needs its own bound; the
# aggregate 10 GiB declared-size fast-reject is far too coarse to
# protect a single-entry read.
_MAX_PROJECT_META_BYTES = 1024 * 1024


class _ZipBombShapeError(Exception):
    """Raised when an open zipfile exceeds ``_MAX_ENTRIES``.

    Distinct from ``ValueError`` so callers can render a single,
    consistent bomb-shape rejection message regardless of which entry
    path they took (``validate_zip_contents`` return-tuple vs.
    ``import_project`` raise).
    """


def _enforce_zip_entry_cap(zip_path: Path) -> None:
    """Raise ``_ZipBombShapeError`` if the EOCD pre-flight reports a
    bomb shape.

    Delegates to :func:`core.zip.peek_eocd` +
    :func:`core.zip.bomb_shaped_reason` (the substrate primitives
    lifted from PR #514): the declared entry count is capped AND
    cross-checked against the declared central-directory size — a
    forged EOCD with a small count in front of a huge real central
    directory would otherwise pass a count-only gate, and
    ``ZipFile()`` then materialises the whole CD anyway (it parses
    until the cd-size buffer is exhausted, ignoring the count). A
    ``None`` peek means "couldn't parse the EOCD" — we let the caller
    proceed to ``ZipFile()``, which will either succeed for a small
    valid archive or raise ``BadZipFile``. Only a definitively
    bomb-shaped parse triggers the early reject.
    """
    summary = peek_eocd(zip_path)
    if summary is None:
        return
    reason = bomb_shaped_reason(summary, max_entries=_MAX_ENTRIES)
    if reason is not None:
        raise _ZipBombShapeError(
            f"{reason} (legitimate RAPTOR project exports have "
            f"<< 1000 entries)"
        )


def _collect_bounded_infolist(zf: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    """Materialise ``zf.infolist()`` with the ``_MAX_ENTRIES`` cap enforced.

    The EOCD pre-flight at ``_enforce_zip_entry_cap`` rejects archives
    whose declared entry count exceeds the cap BEFORE ``ZipFile()``
    is called. This function provides defence-in-depth for cases
    where the EOCD pre-flight cannot parse the record (e.g. unusual
    but valid archives that ``ZipFile`` still accepts) and the
    actual in-memory ``filelist`` length exceeds the cap.

    Note: by the time this runs, ``ZipFile.__init__`` has already
    materialised the entire central directory into ``zf.filelist`` —
    iterating here limits downstream processing cost (and the size
    of the returned ``entries`` list), but does not save memory on
    the construction itself. The EOCD pre-flight is what bounds RSS.

    Raises ``_ZipBombShapeError`` on over-cap; callers translate
    per their error model.
    """
    entries: list[zipfile.ZipInfo] = []
    for i, info in enumerate(zf.infolist()):
        if i >= _MAX_ENTRIES:
            msg = (
                f"zip has more than {_MAX_ENTRIES} entries — "
                f"refusing as zip-bomb shape (legitimate "
                f"RAPTOR project exports have << 1000 entries)"
            )
            raise _ZipBombShapeError(msg)
        entries.append(info)
    return entries


def validate_zip_contents(zip_path: Path) -> tuple[bool, list[str]]:
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
    return bool(name.startswith(".annotation-") and name.endswith(".tmp"))


def export_project(project_output_dir: Path, dest_path: Path,
                   project_json_path: Path | None = None,
                   force: bool = False) -> dict[str, str]:
    """Zip a project output directory, skipping symlinks.

    Args:
        project_output_dir: The project's output directory to archive.
        dest_path: Destination path for the zip file.
        project_json_path: Optional project metadata JSON to include in the zip.
        force: Overwrite dest_path if it already exists.

    Returns:
        Dict with 'path' (zip file path) and 'sha256' (hex digest).

    Raises:
        FileNotFoundError: If the source directory doesn't exist.
        FileExistsError: If dest_path exists and force is False.
    """
    project_output_dir = Path(project_output_dir)
    dest_path = Path(dest_path)

    if not project_output_dir.is_dir():
        msg = f"Directory not found: {project_output_dir}"
        raise FileNotFoundError(msg)

    # Ensure dest has .zip extension
    if dest_path.suffix != ".zip":
        dest_path = dest_path.with_suffix(".zip")

    if dest_path.exists() and not force:
        msg = f"File already exists: {dest_path} (use --force to overwrite)"
        raise FileExistsError(msg)

    dest_path.parent.mkdir(parents=True, exist_ok=True)

    # Build zip manually to skip symlinks (shutil.make_archive follows them)
    # plus per-process / transient artefacts that shouldn't ship in a
    # portable archive (POSIX advisory lock files, tempfile leftovers).
    with zipfile.ZipFile(dest_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for dirpath, dirnames, filenames in os.walk(project_output_dir, followlinks=False):
            dirnames[:] = [d for d in dirnames if not Path(dirpath, d).is_symlink()]
            for fname in filenames:
                item = Path(dirpath, fname)
                if item.is_symlink():
                    logger.debug("Skipping symlink in export: %s", item)
                    continue
                if _is_transient_artefact(item):
                    logger.debug("Skipping transient artefact: %s", item)
                    continue
                arcname = f"{project_output_dir.name}/{item.relative_to(project_output_dir)}"
                zf.write(item, arcname)
        # Include project metadata if provided
        if project_json_path and project_json_path.exists():
            zf.write(project_json_path, f"{project_output_dir.name}/.project.json")

    sha256 = sha256_file(dest_path)
    logger.info("Exported project to %s (sha256: %s)", dest_path, sha256)
    return {"path": str(dest_path), "sha256": sha256}


def _guard_import_output_dir(output_base: Path, project_name: str) -> Path:
    """Resolve the import extraction root and prove it is a strict
    child of ``output_base``.

    ``project_name`` has already passed ``ProjectManager.
    _validate_name`` (no separators, never ``.``/``..``), so this
    can only trip on future drift — but the rmtree call sites below
    (mid-extract cleanup, ``--force`` replacement) and the
    registered ``output_dir`` (later consumed by ``/project delete
    --purge``) are exactly the places a regression would turn into
    cross-project data destruction, so the invariant is
    enforced here rather than assumed.
    """
    output_dir = Path(output_base) / project_name
    base_resolved = Path(output_base).resolve(strict=False)
    dir_resolved = output_dir.resolve(strict=False)
    if dir_resolved == base_resolved or base_resolved not in dir_resolved.parents:
        msg = (
            f"Refusing import: output dir {output_dir} is not a "
            f"strict child of the output base {output_base}"
        )
        raise ValueError(msg)
    return output_dir


def _demote_imported_annotations(output_dir: Path) -> None:
    """Stamp ``provenance=imported`` onto EVERY restored annotation,
    regardless of what stamp the archive shipped.

    The archive is unsigned and its bytes are attacker-authored at
    will: a hostile export can ship ``source=human`` notes pre-stamped
    ``provenance=interactive-tty`` + ``tty=stdin`` — bytes
    indistinguishable from a real operator's CLI write — to mass-mark
    vulnerable functions clean with operator authority after import.
    The stamp is caller-asserted text; nothing binds it to an actual
    TTY, and the zip channel severs whatever provenance the note ever
    had. So the import stamps the channel every note came through:
    ``provenance=imported`` classifies as hint tier and never earns
    human grade (see :mod:`core.annotations.provenance` — the
    ``provenance`` tag wins over any retained ``tty`` key, and every
    elevated-weight reader gates on :func:`is_human_grade`).

    The note's text and other metadata (status, source, tty, custom
    keys) are preserved for display; a pre-existing ``provenance``
    claim is kept visible under ``provenance-claimed`` (a display-only
    key no reader trusts).

    Fail-closed per note: a restored section the write path refuses
    to re-serialise (values that would corrupt the on-disk format)
    is REMOVED rather than left carrying its archive-supplied stamp.
    """
    from core.annotations.models import Annotation
    from core.annotations.provenance import IMPORTED as _IMPORTED
    from core.annotations.provenance import PROVENANCE_KEY as _PROV_KEY
    from core.annotations.storage import (
        iter_all_annotations,
        remove_annotation,
        write_annotation,
    )

    for ann_base in sorted(Path(output_dir).rglob("annotations")):
        if not ann_base.is_dir() or ann_base.is_symlink():
            continue
        for ann in list(iter_all_annotations(ann_base)):
            if ann.metadata.get(_PROV_KEY) == _IMPORTED:
                # Already demoted (idempotent re-run, or the archive
                # self-stamped the demoted tag — nothing to launder).
                continue
            meta = dict(ann.metadata)
            claimed = meta.get(_PROV_KEY)
            if claimed:
                # Keep the archive's claim visible for operator
                # display under a key no reader grades on.
                meta.setdefault("provenance-claimed", claimed)
            meta[_PROV_KEY] = _IMPORTED
            try:
                write_annotation(
                    ann_base,
                    Annotation(file=ann.file, function=ann.function,
                               body=ann.body, metadata=meta),
                )
            except ValueError:
                logger.warning(
                    "import: dropping restored annotation %s:%s — "
                    "cannot re-serialise it with the imported "
                    "provenance stamp",
                    ann.file, ann.function,
                )
                try:
                    remove_annotation(ann_base, ann.file, ann.function)
                except (ValueError, OSError):
                    logger.warning(
                        "import: could not remove unstampable "
                        "annotation %s:%s", ann.file, ann.function,
                    )


# Findings files (relative to a run dir) whose provenance refs get
# namespaced on import. Mirrors core/run/findings.py's _STAMP_PATHS —
# the same files the lifecycle stamper writes canonical refs into.
_IMPORTED_REF_REWRITE_PATHS = ("findings.json", "sca/findings.json")

# Prefix stamped onto every imported provenance ref's run_id. An
# imported archive cannot own ANY run id on this install: a
# pre-seeded ref claiming a local run id (including the very run id
# the restored dir will register under) would otherwise suppress
# canonical stamping (core/run/findings.py skips findings that
# already carry a ref for the current run_id) and read as
# locally-verified work in reports/correlation.
_IMPORTED_REF_PREFIX = "imported:"

def _namespace_imported_provenance_refs(run_dir: Path) -> None:
    """Prefix every provenance ref's ``run_id`` in *run_dir*'s
    findings files with ``imported:`` (idempotent).

    Oversized files are skipped (with a warning) rather than parsed
    wholesale at import time — consumers' loaders refuse files over
    the same bound (:data:`core.project.findings_utils.
    MAX_FINDINGS_JSON_BYTES`), so an unrewritten oversized file never
    feeds a merge fold either.
    """
    from core.project.findings_utils import MAX_FINDINGS_JSON_BYTES

    for rel in _IMPORTED_REF_REWRITE_PATHS:
        path = run_dir / rel
        if not path.is_file() or path.is_symlink():
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > MAX_FINDINGS_JSON_BYTES:
            logger.warning(
                "import: %s is %d bytes — too large to rewrite "
                "provenance refs; loaders refuse it at the same bound",
                path, size,
            )
            continue
        data = load_json(path)
        if isinstance(data, list):
            findings = data
        elif isinstance(data, dict):
            findings = data.get("findings") or data.get("results") or []
        else:
            continue
        changed = False
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            for ref in finding.get("provenance_refs") or ():
                if not isinstance(ref, dict):
                    continue
                run_id = ref.get("run_id")
                if (isinstance(run_id, str) and run_id
                        and not run_id.startswith(_IMPORTED_REF_PREFIX)):
                    ref["run_id"] = _IMPORTED_REF_PREFIX + run_id
                    changed = True
        if changed:
            save_json(path, data)


def _mark_imported_runs(output_dir: Path, archive_sha256: str) -> None:
    """Stamp the persisted imported marker onto the restored project
    root and every restored run directory, and namespace each run's
    provenance refs.

    The marker (:data:`core.project.findings_utils.
    IMPORTED_RUN_MARKER_FILE`) is what merge folds consult to keep
    attacker-selected statuses from an unsigned archive from
    dominating locally-produced ones. Run-dir candidates mirror
    ``Project._list_run_dirs``'s enumeration (top-level dirs, no
    dot/underscore prefix, not the generated ``findings`` dir).
    """
    from datetime import datetime, timezone

    from core.project.findings_utils import IMPORTED_RUN_MARKER_FILE

    payload = {
        "imported": True,
        "imported_at": datetime.now(timezone.utc).isoformat(),
        "archive_sha256": archive_sha256,
    }
    root = Path(output_dir)
    save_json(root / IMPORTED_RUN_MARKER_FILE, payload)
    for child in root.iterdir():
        if child.is_symlink() or not child.is_dir():
            continue
        if child.name.startswith((".", "_")) or child.name == "findings":
            continue
        save_json(child / IMPORTED_RUN_MARKER_FILE, payload)
        _namespace_imported_provenance_refs(child)


# --- Privileged-artifact quarantine ---------------------------------
#
# Restored archives are unsigned; every artifact in them is
# attacker-authored at will. Annotations get a provenance demotion
# (readers already grade the imported tag), but the other
# trust-bearing artifact families have NO import-marker mechanism in
# their consumers — restoring them at their canonical paths would let
# a forged archive mark code reviewed/clean (coverage store, review
# journals), veto feedback, seed prompts with "mechanically-verified"
# exemplars (verified outcomes, labeled attempts), or smuggle
# taint-spec roles and witness manifests as locally-earned evidence.
#
# The seam that requires no consumer edits: move them out of the
# canonical locations into an `_imported-quarantine/` namespace
# (underscore-prefixed — run-dir enumeration skips it) preserving the
# original relative layout for operator inspection. Consumers look up
# these artifacts at fixed canonical paths (project-root
# coverage.json / review-journal-index.json / iris-specs, per-run
# review-journal.jsonl / verified-outcomes.jsonl /
# iris-taint-specs-refined.json, `witnesses/` store roots discovered
# per run dir), so a quarantined artifact is simply never consulted.
_QUARANTINE_DIR_NAME = "_imported-quarantine"

_PRIVILEGED_FILE_NAMES = frozenset({
    "coverage.json",                  # durable coverage store
    "coverage-progress.jsonl",        # store trend sidecar
    "review-journal.jsonl",           # per-run review journal
    "review-journal-index.json",      # project journal index
    "verified-outcomes.jsonl",        # oracle-verified outcome sidecar
    "iris-taint-specs-refined.json",  # per-run IRIS refined specs
})

_PRIVILEGED_DIR_NAMES = frozenset({
    "witnesses",          # WitnessStore roots (manifests + blobs)
    "iris-specs",         # project IRIS spec store
    "labeled_attempts",   # project exemplar pool
})


def _quarantine_dest(qroot: Path, rel: Path) -> Path:
    """Destination for one quarantined artifact, uniquified if the
    archive itself shipped a colliding quarantine entry."""
    dest = qroot / rel
    if not dest.exists():
        return dest
    n = 1
    while True:
        candidate = dest.with_name(f"{dest.name}.imported-{n}")
        if not candidate.exists():
            return candidate
        n += 1


def _quarantine_imported_privileged_artifacts(output_dir: Path) -> list[str]:
    """Move trust-bearing artifacts out of their canonical paths into
    ``_imported-quarantine/`` (layout-preserving). Returns the moved
    relative paths. Idempotent: an existing quarantine dir (re-import
    of a re-exported project) is left untouched, never re-nested."""
    root = Path(output_dir)
    qroot = root / _QUARANTINE_DIR_NAME
    moved: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dp = Path(dirpath)
        if dp == root and _QUARANTINE_DIR_NAME in dirnames:
            dirnames.remove(_QUARANTINE_DIR_NAME)
        for name in list(dirnames):
            if name in _PRIVILEGED_DIR_NAMES:
                src = dp / name
                rel = src.relative_to(root)
                dest = _quarantine_dest(qroot, rel)
                dest.parent.mkdir(parents=True, exist_ok=True)
                src.rename(dest)
                dirnames.remove(name)
                moved.append(str(rel))
        for name in filenames:
            if name in _PRIVILEGED_FILE_NAMES:
                src = dp / name
                rel = src.relative_to(root)
                dest = _quarantine_dest(qroot, rel)
                dest.parent.mkdir(parents=True, exist_ok=True)
                src.rename(dest)
                moved.append(str(rel))
    if moved:
        logger.info(
            "import: quarantined %d privileged artifact(s) under %s "
            "(unsigned archive — coverage/journal/witness/IRIS/outcome "
            "artifacts are not restored as locally-earned trust): %s",
            len(moved), _QUARANTINE_DIR_NAME, ", ".join(sorted(moved)),
        )
    return moved


def import_project(zip_path: Path, projects_dir: Path,
                   force: bool = False,
                   output_base: Path | None = None) -> dict[str, str]:
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
        msg = f"Zip file not found: {zip_path}"
        raise FileNotFoundError(msg)

    # EOCD pre-flight: reject over-cap archives BEFORE the ZipFile
    # constructor reads the entire central directory into memory.
    try:
        _enforce_zip_entry_cap(zip_path)
    except _ZipBombShapeError as e:
        msg = f"Unsafe zip file rejected: {e}"
        raise ValueError(msg) from e

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
                msg = f"Unsafe zip file rejected: {e}"
                raise ValueError(msg) from e
            warnings = _check_zip_entries(bounded_entries)
            if warnings:
                msg = f"Unsafe zip file rejected: {'; '.join(warnings)}"
                raise ValueError(msg)

            # --- Determine structure and check for project metadata ---
            names = zf.namelist()
            if not names:
                msg = "Empty zip file"
                raise ValueError(msg)

            first_part = names[0].split("/")[0]
            has_subdirs = "/" in names[0]
            all_same_root = all(n.split("/")[0] == first_part for n in names)
            has_common_root = has_subdirs and all_same_root

            # Require .project.json — reject non-RAPTOR archives early
            meta_path = f"{first_part}/.project.json" if has_common_root else ".project.json"
            if meta_path not in names:
                msg = (
                    "Not a RAPTOR project archive (missing .project.json). "
                    "Use `raptor project export` to create importable archives."
                )
                raise ValueError(msg)

            # --- Fast-reject on declared size ---
            # Reuse the already-bounded infolist from the cap check
            # above (F029: avoids a second full infolist materialisation).
            declared_size = sum(info.file_size for info in bounded_entries)
            max_size = 10 * 1024 * 1024 * 1024  # 10GB
            if declared_size > max_size:
                msg = (
                    f"Zip declared size ({declared_size / 1024 / 1024:.0f}MB) exceeds "
                    f"limit ({max_size / 1024 / 1024:.0f}MB)"
                )
                raise ValueError(msg)

            # --- Read project metadata ---
            if has_common_root:
                project_name = first_part
            # Per-entry byte cap BEFORE buffering/parsing the metadata
            # in the trusted parent: check the declared size, then
            # bound the actual decompressed read too (the declared
            # size is attacker-controlled and can undersell a huge
            # stored stream).
            meta_info = next(
                info for info in bounded_entries
                if info.filename == meta_path
            )
            if meta_info.file_size > _MAX_PROJECT_META_BYTES:
                raise ValueError(
                    f"Project metadata entry {meta_path!r} declares "
                    f"{meta_info.file_size} bytes — exceeds the "
                    f"{_MAX_PROJECT_META_BYTES}-byte metadata cap"
                )
            with zf.open(meta_path) as meta_fh:
                raw_meta = meta_fh.read(_MAX_PROJECT_META_BYTES + 1)
            if len(raw_meta) > _MAX_PROJECT_META_BYTES:
                raise ValueError(
                    f"Project metadata entry {meta_path!r} exceeds the "
                    f"{_MAX_PROJECT_META_BYTES}-byte metadata cap "
                    f"(declared size was smaller — corrupted or "
                    f"malicious zip)"
                )
            try:
                embedded_meta = json.loads(raw_meta)
                if not isinstance(embedded_meta, dict):
                    msg = "Corrupt .project.json in archive"
                    raise ValueError(msg)
                if embedded_meta.get("name"):
                    project_name = embedded_meta["name"]
            except (json.JSONDecodeError, KeyError):
                msg = "Corrupt .project.json in archive"
                raise ValueError(msg) from None

            # --- Validate name before any filesystem work ---
            from .project import ProjectManager
            mgr = ProjectManager(projects_dir=projects_dir)
            try:
                mgr._validate_name(project_name)
            except ValueError as e:
                msg = f"Cannot import: {e}"
                raise ValueError(msg) from e

            existing = mgr.load(project_name)
            if existing and not force:
                msg = f"Project '{project_name}' already exists. Use --force to overwrite."
                raise ValueError(msg)

            # --- Prepare output directory ---
            # Anchor extraction at output_base/<VALIDATED project
            # name>, stripping the archive's root-dir prefix. The
            # pre-fix code anchored at the zip's own root dir name
            # (`output_base / first_part`) with `first_part` never
            # validated — a hostile archive named its root after a
            # VICTIM project ("victimproj/") to overwrite that
            # project's findings/coverage while registering under an
            # innocuous embedded name, or used a "./"-rooted layout
            # (passes _check_zip_entries: pathlib drops ".") to make
            # output_dir == output_base, arming every later rmtree
            # (mid-extract cleanup, --force replace, /project delete
            # --purge) to destroy EVERY project's output.
            # `project_name` passed _validate_name above (no "/",
            # never "." / ".."), so output_dir is always a strict
            # child of output_base; _guard_import_output_dir keeps
            # that invariant explicit against future drift.
            output_dir = _guard_import_output_dir(
                output_base, project_name,
            )
            # Refuse a same-name destination dir that exists but is
            # NOT a registered project (an orphan from a deleted
            # project, an operator's unrelated dir, debris). Pre-fix
            # the collision check consulted only the registry, so
            # import silently MERGED into the orphan
            # (mkdir exist_ok=True) and any late failure rmtree'd it —
            # destroying data import never created. --force is the
            # explicit operator override: it replaces the dir
            # wholesale (never merges), same as it replaces a
            # registered project's tree.
            if output_dir.exists() and not existing and not force:
                raise ValueError(
                    f"Refusing import: output dir {output_dir} already "
                    f"exists but no project '{project_name}' is "
                    f"registered. Move the directory aside, or pass "
                    f"--force to replace it."
                )

            # --- Stage the extraction ---
            # Extract into a fresh private staging dir and atomically
            # move it into place only after extraction AND the
            # trust-demotion passes succeed. Pre-fix the loop wrote
            # straight into output_dir and the failure cleanup
            # rmtree'd the FINAL path — with --force the old project
            # tree was even deleted before a single byte extracted,
            # so a failed import destroyed the previous data with no
            # rollback. Failure cleanup now only ever removes the
            # staging dir import itself created.
            # Hand-rolled (not scratch_dir, not reaper-listed):
            # publish-by-rename ownership (the staging dir BECOMES the
            # project dir on success), under the project output base,
            # not the system tmp — the tmp reaper only sweeps the
            # system tmp root, so a SIGKILL residue here is
            # operator-visible next to the projects instead.
            import tempfile
            Path(output_base).mkdir(parents=True, exist_ok=True)
            staging_dir = Path(tempfile.mkdtemp(
                prefix=f".import-{project_name}-", dir=str(output_base),
            ))
            # mkdtemp creates 0o700; project output dirs are plain
            # mkdir-default dirs, so widen before the rename publishes
            # the tree (umask still applies to files within).
            os.chmod(staging_dir, 0o755)

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
                    # Strip the archive's common root component so
                    # every entry lands under output_dir regardless
                    # of what the (attacker-chosen) root dir was
                    # called. `partition` rather than `split`: a
                    # bare root entry ("myproj") yields an empty
                    # remainder, which we skip.
                    if has_common_root:
                        arcrel = info.filename.partition("/")[2]
                        if not arcrel:
                            continue
                    else:
                        arcrel = info.filename
                    # Refuse if the per-entry declared size alone
                    # would exceed remaining budget — saves opening
                    # a stream we'd immediately cancel.
                    if bytes_extracted + info.file_size > max_size:
                        msg = (
                            f"Entry {info.filename!r} ({info.file_size / 1024 / 1024:.0f}MB) "
                            f"would exceed limit ({max_size / 1024 / 1024:.0f}MB)"
                        )
                        raise ValueError(msg)
                    extract_dest = staging_dir
                    target_path = extract_dest / arcrel
                    # Resolve and re-check containment.
                    # `_check_zip_entries` already vetted the
                    # filenames upstream, but Python's traversal-
                    # protection in zipfile is version-dependent
                    # (3.6 had bugs around symlink-shaped entries,
                    # 3.11 added stricter checks but still misses
                    # NTFS-style alternate-data-stream filenames
                    # and Windows drive-letter prefixes on POSIX).
                    # Pre-fix this comment claimed "defence in
                    # depth" but performed NO re-check — the
                    # comment was a lie. Add the actual containment
                    # check so any traversal that slipped past
                    # _check_zip_entries (future regression, novel
                    # filename shape, or a Python-version
                    # behavioural difference) is caught here.
                    extract_dest_resolved = extract_dest.resolve(strict=False)
                    target_resolved = target_path.resolve(strict=False)
                    try:
                        target_resolved.relative_to(extract_dest_resolved)
                    except ValueError:
                        msg = (
                            f"Refusing to extract {info.filename!r}: "
                            f"resolved target {target_resolved} escapes "
                            f"destination {extract_dest_resolved}"
                        )
                        raise ValueError(msg) from None
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
                                msg = (
                                    f"Extracted size ({bytes_extracted / 1024 / 1024:.0f}MB) "
                                    f"exceeds limit ({max_size / 1024 / 1024:.0f}MB) "
                                    f"during {info.filename!r}"
                                )
                                raise ValueError(msg)
                            dst.write(buf)
                    if actual_size != info.file_size:
                        msg = (
                            f"Size mismatch for {info.filename}: "
                            f"header says {info.file_size}, got {actual_size} "
                            f"(corrupted or malicious zip)"
                        )
                        raise ValueError(msg)
            except Exception:
                # Clean up the partial extraction — ONLY the staging
                # dir import itself created; never the final path.
                shutil.rmtree(staging_dir, ignore_errors=True)
                raise

    except zipfile.BadZipFile:
        msg = "Invalid zip file"
        raise ValueError(msg) from None

    # Demote ALL restored annotations to hint tier BEFORE the project
    # registers (readers must never see archive-supplied stamps as
    # anything but imported). A failure here fails the import closed:
    # remove the staged tree rather than register a project carrying
    # notes that would read as operator authority.
    try:
        _demote_imported_annotations(staging_dir)
    except Exception as e:
        shutil.rmtree(staging_dir, ignore_errors=True)
        msg = f"Import failed while stamping restored annotations: {e}"
        raise ValueError(msg) from e

    # Stamp the persisted imported marker onto the restored root and
    # every restored run dir, and namespace their provenance refs —
    # merge/report consumers must always be able to tell imported
    # runs from locally-produced ones. Fails the import closed like
    # the annotation pass above.
    try:
        _mark_imported_runs(staging_dir, sha256_file(zip_path))
    except Exception as e:
        shutil.rmtree(staging_dir, ignore_errors=True)
        raise ValueError(
            f"Import failed while marking imported runs: {e}"
        ) from e

    # Quarantine trust-bearing artifacts (coverage store, review
    # journals, witness stores, IRIS specs, verified outcomes,
    # exemplar pools) out of their canonical paths — consumers must
    # never treat archive-supplied copies as locally-earned trust.
    # Fails the import closed like the passes above.
    try:
        _quarantine_imported_privileged_artifacts(staging_dir)
    except Exception as e:
        shutil.rmtree(staging_dir, ignore_errors=True)
        raise ValueError(
            f"Import failed while quarantining privileged artifacts: {e}"
        ) from e

    # --- Publish the staged tree ---
    # Everything below only runs once the staged import is complete
    # and demoted; the pre-existing tree (registered project with
    # --force, or an unregistered orphan the operator --force'd over)
    # is removed at the last moment before the atomic rename.
    orphaned_output = None
    try:
        if existing and force:
            old_output_path = Path(existing.output_dir).resolve()
            mgr.delete(project_name, purge=False)
            if old_output_path != output_dir.resolve() and old_output_path.exists():
                orphaned_output = str(old_output_path)
            logger.info("Removed existing project '%s' (force=True)", project_name)
        if output_dir.exists():
            if not force:
                # The pre-extraction check already refused this shape;
                # reaching it here means the dir appeared mid-import.
                # Refuse rather than delete data import didn't create.
                raise ValueError(
                    f"Refusing import: output dir {output_dir} "
                    f"appeared during import and --force was not given"
                )
            shutil.rmtree(output_dir)
        staging_dir.rename(output_dir)
    except Exception:
        shutil.rmtree(staging_dir, ignore_errors=True)
        raise

    # Register the project
    target = embedded_meta.get("target", "(imported)") if embedded_meta else "(imported)"
    description = embedded_meta.get("description", "") if embedded_meta else ""
    notes = embedded_meta.get("notes", "") if embedded_meta else ""
    created = embedded_meta.get("created") if embedded_meta else None

    mgr.create(project_name, target, description=description,
               output_dir=str(output_dir), resolve_target=False,
               created=created)
    if notes:
        mgr.update_notes(project_name, notes)

    logger.info("Imported project '%s' to %s", project_name, output_dir)
    result = {"name": project_name, "output_dir": str(output_dir)}
    if orphaned_output:
        result["orphaned_output"] = orphaned_output
    return result
