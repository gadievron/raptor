"""Exclusive project-directory relocation with staged cross-filesystem copies."""
import errno
import os
import stat
from pathlib import Path
import shutil

from core.atomic_fs import publish_new_directory, rename_without_replace, rmtree_hardened
from core.logging import get_logger
from core.run.scratch import scratch_dir
from core.source.gated import open_regular_gated
from .import_transaction import _identity, _pin_entry

logger = get_logger()


def move_directory(source: Path, destination: Path) -> bool:
    """Publish at an absent exact path; return whether the source was removed.

    Same-filesystem moves allocate no duplicate tree. Only EXDEV permits a
    copy, which is staged beside the destination and preserves symbolic links.
    Copy/publication failures retain the source. A post-publication source
    cleanup failure leaves both copies and returns False with a recovery warning.
    The caller must ensure the source is quiescent; this is not a snapshot.
    """
    source, destination = Path(source), Path(destination)
    source_root, destination_root = source.resolve(), destination.resolve()
    if (source_root == destination_root or source_root.is_relative_to(destination_root)
            or destination_root.is_relative_to(source_root)):
        raise ValueError('source and destination directory trees overlap')
    with _pin_entry(source, directory=True) as source_id:
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            publish_new_directory(source, destination)
            if _identity(destination) != source_id:
                raise OSError('destination changed during directory relocation')
            return True
        except BaseException as exc:
            try:
                moved = _identity(destination) == source_id and _identity(source) is None
                if moved:
                    rename_without_replace(destination, source)
            except BaseException:
                logger.error('Directory move rollback failed; inspect %s and %s',
                             source, destination, exc_info=True)
                raise exc
            if moved or not isinstance(exc, OSError) or exc.errno != errno.EXDEV:
                raise
        # Refuse occupied destinations before allocating a second tree.
        if _identity(destination) is not None:
            raise FileExistsError(f'directory move destination exists: {destination}')
        with scratch_dir('.move-', dir=destination.parent, keepalive=True) as workspace:
            staged = workspace / 'tree'
            shutil.copytree(source, staged, symlinks=True, copy_function=_regular_copier())
            if _identity(source) != source_id:
                raise OSError('source directory changed during relocation')
            with _pin_entry(staged, directory=True) as staged_id:
                try:
                    publish_new_directory(staged, destination)
                except BaseException:
                    try:
                        if _identity(destination) == staged_id:
                            rename_without_replace(destination, staged)
                    except BaseException:
                        logger.error('Directory copy rollback failed; data retained at %s',
                                     destination, exc_info=True)
                    raise
                if _identity(destination) != staged_id:
                    raise OSError('destination changed during directory publication')
                try:
                    removed = (_identity(source) == source_id
                               and _identity(destination) == staged_id
                               and rmtree_hardened(source))
                except OSError:
                    removed = False
                if not removed:
                    logger.warning('Directory published at %s; source cleanup incomplete at %s. '
                                   'Inspect both paths before removing the retained source.',
                                   destination, source)
                return removed


def _regular_copier():
    """Copy opened regular files and retain intra-tree hardlinks on the new FS."""
    links = {}
    def copy(source, destination):
        with open_regular_gated(source, follow_symlinks=False) as reader:
            info = os.fstat(reader.fileno())
            key = (info.st_dev, info.st_ino)
            previous = links.get(key) if info.st_nlink > 1 else None
            if previous is not None:
                os.link(previous, destination, follow_symlinks=False)
            else:
                with open(destination, 'xb') as writer:
                    shutil.copyfileobj(reader, writer, length=1024 * 1024)
                os.chmod(destination, stat.S_IMODE(info.st_mode))
                os.utime(destination, ns=(info.st_atime_ns, info.st_mtime_ns))
                if info.st_nlink > 1:
                    links[key] = destination
        return destination
    return copy
