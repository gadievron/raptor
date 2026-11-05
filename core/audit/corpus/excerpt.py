"""Source context retained alongside labelled corpus files."""

from __future__ import annotations

from pathlib import Path
import re

from core.atomic_fs import write_bytes_atomically
from core.source import open_regular_beneath


_QUOTED_C_INCLUDE = re.compile(
    r'^[^\S\n]*#[^\S\n]*include[^\S\n]*"([^"\n]+\.c)"', re.MULTILINE,
)
_MAX_OWNER_BYTES = 1024 * 1024


def copy_c_translation_unit_owners(
    destination: Path, source: Path, labelled_files: set[str],
) -> set[str]:
    """Retain sibling C files that directly include a labelled C file.

    Some projects include implementation files from translation-unit
    wrappers. Keeping only the implementation drops callers defined in
    its wrapper. This bounded sibling search supplies that context;
    it is not a repository-wide reverse-include index. Returned paths
    also seed the forward header closure. Files outside the source
    root, including symlink escapes, are never copied.
    """
    root = source.resolve()
    anchors = {
        (root / rel).resolve()
        for rel in labelled_files if rel.endswith(".c")
    }
    anchors = {p for p in anchors if p.is_relative_to(root) and p.is_file()}
    copied: set[str] = set()
    for directory in sorted({p.parent for p in anchors}):
        for candidate in sorted(directory.glob("*.c")):
            resolved = candidate.resolve()
            if not resolved.is_relative_to(root) or resolved in anchors:
                continue
            try:
                stream = open_regular_beneath(root, resolved.relative_to(root), "rb")
                if stream is None:
                    continue
                with stream:
                    data = stream.read(_MAX_OWNER_BYTES + 1)
            except OSError:
                continue
            if len(data) > _MAX_OWNER_BYTES:
                continue
            includes = _QUOTED_C_INCLUDE.findall(data.decode("utf-8", "replace"))
            if not any((candidate.parent / name).resolve() in anchors
                       for name in includes):
                continue
            rel = candidate.relative_to(root).as_posix()
            target = destination / rel
            if target.exists():
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            write_bytes_atomically(target, data)
            copied.add(rel)
    return copied
