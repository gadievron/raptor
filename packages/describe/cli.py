"""Shared CLI driver for /describe.

Both invocation paths — ``raptor.py describe`` (the dispatcher
mode) and ``libexec/raptor-describe`` (the slash-command shim)
— call into ``describe_main`` here, so target resolution,
archive handling, building the report, and rendering live in
exactly one place. Pre-fix the two paths each had their own
copy of the same logic, which silently drifted (e.g. archive
support landing in only one).

Archive handling reuses ``core.archive`` (the same substrate
that ``raptor.py:_unpack_archive_target`` uses for /scan and
/agentic). Cache hit first: if a prior /scan run already
extracted the same archive into the active project's shared
``_sources/<safe-name>-<sha>/`` cache, /describe uses that
directly — no re-extraction. Cache miss: extract into a temp
directory we own, describe, clean up at the end.

The operator sees one extra line in the render
("Source: archive foo.tar.gz") so the result is unambiguous;
they don't have to wonder whether RAPTOR somehow described a
binary blob.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path
from typing import Optional, Tuple


def describe_main(
    target_arg: Optional[str],
    json_output: bool,
    stderr=sys.stderr,
    stdout=sys.stdout,
) -> int:
    """Resolve target → (optionally extract archive) → build
    report → render. Returns an exit code.

    ``stderr`` / ``stdout`` are injectable for testing; defaults
    use the real streams.
    """
    from core.run.output import resolve_default_target

    target_arg = target_arg or resolve_default_target()
    if target_arg is None:
        stderr.write(
            "✗ --target required (and no active project / "
            "RAPTOR_CALLER_DIR set). "
            "Run: raptor describe --target <path>\n"
        )
        return 1

    raw_path = Path(target_arg).expanduser().resolve()
    if not raw_path.exists():
        stderr.write(
            f"✗ target path does not exist: {raw_path}\n"
        )
        return 1

    # Branch on directory vs file. Archive (file + recognised
    # format) — cache hit reuses an existing extraction; cache
    # miss extracts into a tmp dir we own and clean up.
    tmp_extract_root: Optional[Path] = None
    archive_label: Optional[str] = None
    try:
        if raw_path.is_dir():
            target_path = raw_path
        else:
            resolved = _resolve_archive(raw_path, stderr)
            if resolved is None:
                return 1
            target_path, tmp_extract_root, archive_label = resolved

        from packages.describe.report import (
            build_describe_report, format_json, format_text,
        )
        report = build_describe_report(
            target_path, archive_label=archive_label,
        )
        if json_output:
            stdout.write(format_json(report))
            stdout.write("\n")
        else:
            stdout.write(format_text(report))
            stdout.write("\n")
        return 0
    finally:
        if tmp_extract_root is not None:
            shutil.rmtree(tmp_extract_root, ignore_errors=True)


def _resolve_archive(
    raw_path: Path, stderr,
) -> Optional[Tuple[Path, Optional[Path], str]]:
    """Turn an archive ``raw_path`` into a describable directory.

    Returns ``(target_path, tmp_extract_root, archive_label)``:

    * ``target_path`` — the directory to describe (may be a
      cache hit, a one-shot tmp extract, or a single-subdir
      descent of either).
    * ``tmp_extract_root`` — the tmp dir we own and must clean
      up, or None for cache hits / failed cases.
    * ``archive_label`` — original archive basename, for the
      report header.

    Returns None on any error; writes an operator-actionable
    message to ``stderr``.
    """
    try:
        from core.archive import (
            extract_to_dir, is_archive, safe_cache_name,
        )
    except Exception:  # noqa: BLE001
        stderr.write(
            f"✗ target is not a directory and the archive "
            f"substrate is unavailable: {raw_path}\n"
        )
        return None

    if not is_archive(raw_path):
        stderr.write(
            f"✗ target is a file but not a recognised archive "
            f"(tar, zip, gz, bz2, xz, zst): {raw_path}\n"
        )
        return None

    archive_label = raw_path.name

    # Cache-hit check FIRST: if a prior /scan / /agentic run on
    # the same archive (in the same active project) already
    # extracted to ``<project_output_dir>/_sources/<name>-<sha>/``,
    # describe that — no re-extraction.
    cache_hit = _find_cached_extraction(
        raw_path, safe_cache_name,
    )
    if cache_hit is not None:
        return (_descend_single_subdir(cache_hit), None, archive_label)

    # Miss: one-shot extract to tmp. /describe stays read-only
    # w.r.t. the project — does NOT write into ``_sources/`` (the
    # cache is /scan's to populate; describing alone shouldn't
    # create persistent project state).
    tmp_extract_root = Path(tempfile.mkdtemp(prefix="raptor-describe-"))
    try:
        extract_to_dir(raw_path, tmp_extract_root)
    except Exception as e:  # noqa: BLE001
        # Broad on purpose: extraction runs on attacker-controlled
        # input. ArchiveError, OSError, ValueError, MemoryError
        # on oversized archives — any of them must fail gracefully
        # rather than crash /describe.
        stderr.write(
            f"✗ archive extraction failed for {raw_path}: {e}\n"
        )
        shutil.rmtree(tmp_extract_root, ignore_errors=True)
        return None

    return (
        _descend_single_subdir(tmp_extract_root),
        tmp_extract_root,
        archive_label,
    )


def _find_cached_extraction(
    archive_path: Path, safe_cache_name_fn,
) -> Optional[Path]:
    """Return the cached extraction dir for ``archive_path``
    under the active project's ``_sources/<name>-<sha>/``, or
    None on no active project / no cache hit / snapshot
    failure.

    Mirrors ``raptor.py:_unpack_archive_target``'s cache
    layout: ``<project_output_dir>/_sources/<safe-name>-<sha>``.
    """
    try:
        from core.run.output import _resolve_active_project
        from core.run.provenance import archive_snapshot
    except Exception:  # noqa: BLE001
        return None

    active = _resolve_active_project()
    if active is None:
        return None
    project_output_dir = active[0]

    snap = archive_snapshot(archive_path)
    if snap is None:
        return None

    cache_name = safe_cache_name_fn(snap["archive_name"], snap["archive_sha256"])
    candidate = Path(project_output_dir) / "_sources" / cache_name
    if candidate.is_dir():
        return candidate
    return None


def _descend_single_subdir(root: Path) -> Path:
    """When an extracted archive has the common single-top-level-
    subdir layout (``tar czf proj.tgz proj/`` → extract gives
    ``<root>/proj/<contents>``), descend into that subdir so the
    catalog scorer + build detector see the project's top-level
    markers (configure.ac, package.json, …) where they actually
    are. No-op when the root has multiple entries, none, or when
    the single entry is a symlink (a symlinked single entry could
    escape the extract dir and retarget /describe at host paths;
    refuse to follow).
    """
    try:
        entries = [p for p in root.iterdir() if not p.name.startswith(".")]
    except OSError:
        return root
    if len(entries) != 1:
        return root
    only = entries[0]
    # is_symlink() guard before is_dir() — is_dir() follows
    # symlinks, so a malicious archive with a single entry
    # ``proj`` symlinking to ``/`` would otherwise retarget the
    # whole /describe run at the host filesystem.
    if only.is_symlink():
        return root
    if only.is_dir():
        return only
    return root


__all__ = ["describe_main"]
