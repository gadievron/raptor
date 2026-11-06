"""Ownership and publication of generated corpus build caches."""

from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
import fnmatch
import logging
import os
from pathlib import Path
import stat

from core.atomic_fs import write_text_atomically
from core.atomic_fs.fs_lock import artifact_lock
from core.source import read_bytes_gated

logger = logging.getLogger(__name__)
_MARKER = "sentinel.ok"
# Version tags are normally one or two bytes; 64 also admits a full SHA.
# Lower would reject useful content-version tags; higher only enlarges an
# untrusted marker read without helping the current cache schema.
_MAX_VERSION_BYTES = 64


def clear_build_paths(paths: Sequence[Path], *, preserve_error: bool = False) -> None:
    """Attempt every owned path; a failed teardown cannot mask a build error."""
    from core.build.artifacts import cleanup_build_paths

    remaining = []
    interrupted = None
    for path in dict.fromkeys(paths):
        pending = [path]
        try:
            cleanup_build_paths(pending)
        except BaseException as exc:
            logger.warning("Corpus build cleanup failed for %s", path, exc_info=True)
            if interrupted is None:
                interrupted = exc
        if pending:
            remaining.append(path)
    if not preserve_error:
        if interrupted is not None:
            raise interrupted
        if remaining:
            raise OSError(f"Could not clear {len(remaining)} corpus build path(s): {remaining[0]}")


def _profiles(root: Path, pattern: str | None) -> list[Path]:
    if pattern is None:
        return []
    with os.scandir(root) as entries:
        return sorted(Path(entry.path) for entry in entries
                      if fnmatch.fnmatchcase(entry.name, pattern))


def _required_files(persistent: Sequence[Path], required: Sequence[Path]) -> bool:
    try:
        if not all(stat.S_ISDIR(path.lstat().st_mode) or stat.S_ISREG(path.lstat().st_mode)
                   for path in persistent):
            return False
        for path in required:
            resolved = path.resolve()
            info = path.stat()
            if (not any(resolved.is_relative_to(slot.resolve()) for slot in persistent)
                    or not stat.S_ISREG(info.st_mode) or info.st_size <= 0):
                return False
        return True
    except (OSError, RuntimeError):
        return False


def has_gcov_data(root: Path) -> bool:
    """O0 gcda counters remain required; unlike merged LLVM raw profiles."""
    return any(not path.is_symlink() and path.is_file() and path.stat().st_size > 0
               for path in root.rglob("*.gcda"))


@contextmanager
def prepared_corpus(
    root: Path, *, version: str, build: Callable[[], None],
    persistent: Sequence[Path], required: Sequence[Path],
    transient: Sequence[Path] = (), profile_pattern: str | None = None,
    ready: Callable[[], bool] | None = None,
) -> Iterator[None]:
    """Serialize preparation, reclaim failures, and publish complete caches.

    Only declared direct children are removable; unrelated cache metadata
    survives. Sources, private downloads, and merged raw profiles are also
    reclaimed on warm cache hits after a previous owner was interrupted.
    Analysis after yielding never invalidates an already committed build.
    """
    from core.project.registry_home import refuse_registry_overlap

    root = Path(root).absolute()
    persistent = tuple(Path(path).absolute() for path in persistent)
    required = tuple(Path(path).absolute() for path in required)
    transient = tuple(Path(path).absolute() for path in transient)
    marker = root / _MARKER
    if not persistent or not required:
        raise ValueError("Corpus cache requires persistent outputs and required artifacts")
    slots = tuple(persistent) + tuple(transient)
    for path in slots:
        if (path.parent.absolute() != root.absolute()
                or path.name in {_MARKER, _MARKER + ".lock", ".", ".."}):
            raise ValueError(f"Corpus build cleanup requires a direct owned child: {path}")
    for path in required:
        if not any(path.is_relative_to(slot) for slot in persistent) or ".." in path.parts:
            raise ValueError(f"Required corpus artifact escapes cache: {path}")
    if (not isinstance(version, str) or not version.strip()
            or version != version.strip() or len(version.encode()) > _MAX_VERSION_BYTES):
        raise ValueError(f"Corpus cache version must be a nonempty tag of at most {_MAX_VERSION_BYTES} bytes")
    if profile_pattern is not None and (
        "/" in profile_pattern or "\\" in profile_pattern
        or not profile_pattern.endswith(".profraw")
    ):
        raise ValueError("Corpus profile pattern must name direct .profraw children")
    refuse_registry_overlap(root)
    root.mkdir(parents=True, exist_ok=True)
    initial = root.lstat()
    if not stat.S_ISDIR(initial.st_mode):
        raise ValueError(f"Corpus cache root must be a real directory: {root}")

    def ensure_root():
        latest = root.lstat()
        if (not stat.S_ISDIR(latest.st_mode)
                or (latest.st_dev, latest.st_ino) != (initial.st_dev, initial.st_ino)):
            raise OSError(f"Corpus cache root changed during preparation: {root}")

    def discard(paths, *, preserve_error=False):
        try:
            ensure_root()
            clear_build_paths(paths, preserve_error=preserve_error)
        except BaseException:
            if not preserve_error:
                raise
            logger.warning("Corpus build cleanup could not retain its root: %s", root, exc_info=True)

    def complete():
        if not _required_files(persistent, required):
            return False
        try:
            return ready is None or ready()
        except (OSError, RuntimeError):
            return False

    with artifact_lock(marker, subject="corpus build", required=True, create_parent=False):
        ensure_root()
        try:
            valid = read_bytes_gated(marker, _MAX_VERSION_BYTES, follow_symlinks=False).decode("utf-8").strip() == version
        except (OSError, ValueError):
            valid = False
        valid = valid and complete()
        if not valid:
            # Remove the marker first: a failed rebuild cannot leave a hit.
            discard([marker, *persistent, *transient, *_profiles(root, profile_pattern)])
            try:
                build()
                ensure_root()
                if not complete():
                    raise RuntimeError(f"Corpus build did not produce its required artifacts: {root}")
                write_text_atomically(marker, version, mode=0o600)
            except BaseException:
                discard([marker, *persistent, *transient], preserve_error=True)
                try:
                    ensure_root()
                    discard(_profiles(root, profile_pattern), preserve_error=True)
                except BaseException:
                    logger.warning("Corpus profile cleanup failed for %s", root, exc_info=True)
                raise
        # Valid binaries/profdata stay committed if only pruning fails. The
        # next warm hit retries cleanup instead of rebuilding them again.
        discard([*transient, *_profiles(root, profile_pattern)])
        yield
