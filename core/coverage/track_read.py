"""Track file reads for coverage — Python implementation.

The production hook is libexec/raptor-hook-read (bash+jq, runs async).
This module provides the same logic in Python for:
- Testing (test_record.py)
- Fallback when jq is unavailable
- Direct invocation: python3 -m core.coverage.track_read
"""

import json
import os
import sys
from pathlib import Path

# Ensure repo root is on path regardless of cwd
# core/coverage/track_read.py -> repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

MANIFEST_NAME = ".reads-manifest"

_SOURCE_EXTENSIONS = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx", ".c", ".h", ".cpp", ".hpp",
    ".cc", ".cxx", ".java", ".go", ".rs", ".rb", ".php", ".cs",
    ".swift", ".kt", ".scala", ".sh", ".bash", ".zsh",
})


def _find_active_run():
    """Find the running run directory via project symlink.

    Returns (run_dir, target) or (None, None).
    """
    active_link = Path.home() / ".raptor" / "projects" / ".active"
    if not active_link.is_symlink():
        return None, None

    try:
        link_target = os.readlink(active_link)
        if not link_target.endswith(".json"):
            return None, None
        project_file = active_link.parent / link_target
        if not project_file.exists():
            return None, None

        data = json.loads(project_file.read_text())
        project_dir = data.get("output_dir", "")
        target = data.get("target", "")
        if not project_dir or not Path(project_dir).is_dir():
            return None, None

        # Find most recent running run.
        # `iterdir()` enumerates the directory; the sort key calls
        # `.stat()` separately on each entry. Race: a run that exists
        # at iterdir time can be deleted before `.stat()` runs (parent
        # cleanup process, /project clean concurrent, manual rm), and
        # `.stat()` then raises FileNotFoundError, leaking out of the
        # try/except (OSError catches it but then we lose the WHOLE
        # run discovery for THIS hook fire — the operator sees no
        # tracked read for that file). Same for the `meta_file.exists()`
        # → `read_text()` race below.
        #
        # Materialise the entries-with-mtimes pairs first, skipping
        # any that fail to stat. Sort the surviving pairs only.
        entries = []
        for d in Path(project_dir).iterdir():
            if not d.is_dir() or d.name.startswith((".", "_")):
                continue
            try:
                mtime = d.stat().st_mtime
            except OSError:
                continue  # raced with deletion; skip rather than abort the whole loop
            entries.append((mtime, d))
        for _mtime, d in sorted(entries, key=lambda t: t[0], reverse=True):
            meta_file = d / ".raptor-run.json"
            try:
                # `read_text` raises FileNotFoundError if the file
                # disappeared between the `entries` build above and
                # this read; treat it as "no longer running" rather
                # than aborting.
                meta_text = meta_file.read_text()
            except OSError:
                continue
            try:
                meta = json.loads(meta_text)
            except (json.JSONDecodeError, ValueError):
                continue
            # Pre-fix `meta.get("status")` raised AttributeError if
            # `meta` was not a dict (JSON file legitimately
            # contained `null`, a list, a bare string, or a number).
            # The outer except at line 90 didn't catch
            # AttributeError or TypeError, so a malformed run-meta
            # JSON crashed `_find_active_run` instead of falling
            # through to "no active run found". isinstance-guard so
            # malformed metas degrade gracefully.
            if not isinstance(meta, dict):
                continue
            if meta.get("status") == "running":
                return str(d), target

    except (OSError, json.JSONDecodeError, KeyError, TypeError, AttributeError):
        pass

    return None, None


def main():
    # Find active run via project symlink
    run_dir, target = _find_active_run()
    if not run_dir:
        return

    target = target or ""

    # Read hook payload from stdin. Cap at 1 MB before parsing.
    # Pre-fix `json.load(sys.stdin)` was unbounded — a hostile
    # hook payload (or a Claude Code bug feeding the wrong fd)
    # could pipe gigabytes of data and OOM the hook. Real Read-
    # tool payloads are <2 KB (file_path + cwd + small metadata);
    # 1 MB is a 500x safety margin while bounding pathological
    # input.
    _MAX_STDIN_BYTES = 1 * 1024 * 1024
    try:
        _stdin_text = sys.stdin.read(_MAX_STDIN_BYTES + 1)
    except (OSError, ValueError):
        return
    if len(_stdin_text) > _MAX_STDIN_BYTES:
        return
    try:
        payload = json.loads(_stdin_text or "{}")
    except (json.JSONDecodeError, ValueError):
        return

    file_path = payload.get("tool_input", {}).get("file_path", "")
    if not file_path:
        return

    # Reject paths with NUL or line-terminator characters. The
    # manifest is line-delimited, so a `file_path` containing `\n`
    # (a hostile hook payload, or a rare-but-legal filesystem entry
    # name on platforms that allow newlines) splits into multiple
    # manifest entries — downstream parsers see fictitious paths.
    # NUL gets truncated by various C-level readers (the kernel,
    # some Python file APIs in 3.13+) producing a different path
    # than what the hook reported. Reject either up-front rather
    # than corrupting the manifest.
    if "\x00" in file_path or "\n" in file_path or "\r" in file_path:
        return

    # Skip non-source files
    dot = file_path.rfind(".")
    if dot == -1 or file_path[dot:].lower() not in _SOURCE_EXTENSIONS:
        return

    # Skip files outside the target directory (path-level check, not string prefix).
    # Substitute `file_path` with the symlink-resolved real path so
    # the manifest records the canonical inventory path. Pre-fix the
    # original (possibly symlinked) `file_path` was written, so when
    # an operator's editor opened `target/symlink_to_handler.py`, the
    # manifest carried that symlink name — but the inventory was
    # built from real files, so the downstream lookup against
    # `symlink_to_handler.py` returned no match and the coverage
    # mark was lost. Recording the realpath fixes the join.
    if target:
        try:
            # Resolve symlinks and check proper path containment
            resolved = os.path.realpath(file_path)
            resolved_target = os.path.realpath(target)
            if not resolved.startswith(resolved_target + os.sep) and resolved != resolved_target:
                return
            file_path = resolved
        except (OSError, ValueError):
            return

    # Append to manifest with O_NOFOLLOW. Pre-fix `open(..., "a")`
    # followed any symlink at the manifest path — if an attacker
    # (or a careless test fixture) planted a symlink at
    # `<run_dir>/<MANIFEST_NAME>` pointing elsewhere, our writes
    # went to the symlink target. ELOOP from the kernel when the
    # path is a symlink → fall through to the OSError except and
    # silently skip.
    try:
        manifest_path = os.path.join(run_dir, MANIFEST_NAME)
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(manifest_path, flags, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(file_path + "\n")
    except OSError:
        pass


if __name__ == "__main__":
    main()
