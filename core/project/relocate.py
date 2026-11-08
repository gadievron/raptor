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
from core.source.streams import preserving_stream_error
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


_COPY_CHUNK_BYTES = 1024 * 1024
_SEEK_UNSUPPORTED = {errno.EINVAL, errno.ENOSYS, errno.ENOTSUP, errno.EOPNOTSUPP}
_LINK_UNSUPPORTED = {errno.EPERM, errno.ENOSYS, errno.ENOTSUP, errno.EOPNOTSUPP,
                     errno.EXDEV, errno.EMLINK}


def _copy_exact(reader, writer, size):
    """Copy a bounded interval without writing zero-filled chunk edges."""
    while size:
        block = reader.read(min(size, _COPY_CHUNK_BYTES))
        if not block:
            raise OSError('source file shortened during copy')
        content = block.lstrip(b'\x00')
        leading = len(block) - len(content)
        if leading:
            writer.seek(leading, os.SEEK_CUR)
        content = content.rstrip(b'\x00')
        if content and writer.write(content) != len(content):
            raise OSError('incomplete destination write during copy')
        trailing = len(block) - leading - len(content)
        if trailing:
            writer.seek(trailing, os.SEEK_CUR)
        size -= len(block)


def _copy_sparse_contents(reader, writer, size):
    """Preserve extents when supported; otherwise skip zero-filled chunks.

    The captured logical size bounds reads even when a source grows. Extent
    failures indicating unsupported filesystem APIs use a bounded sequential
    fallback; IO errors and cancellation remain failures of the whole copy.
    Buffered stream seeks keep extent probes and buffered reads synchronized.
    """
    offset = 0
    seek_data = getattr(os, 'SEEK_DATA', None)
    seek_hole = getattr(os, 'SEEK_HOLE', None)
    while offset < size:
        if seek_data is None or seek_hole is None:
            reader.seek(offset)
            writer.seek(offset)
            _copy_exact(reader, writer, size - offset)
            break
        probing_data = True
        try:
            data = reader.seek(offset, seek_data)
            if not offset <= data <= size:
                raise OSError('source extent changed during copy')
            if data == size:
                break
            probing_data = False
            hole = reader.seek(data, seek_hole)
            if hole <= data:
                raise OSError('source extent did not advance during copy')
        except OSError as exc:
            if exc.errno == errno.ENXIO and probing_data:
                break  # The remaining interval is a hole.
            if exc.errno not in _SEEK_UNSUPPORTED:
                raise
            reader.seek(offset)
            writer.seek(offset)
            _copy_exact(reader, writer, size - offset)
            break
        end = min(hole, size)
        reader.seek(data)
        writer.seek(data)
        _copy_exact(reader, writer, end - data)
        offset = end
    writer.truncate(size)  # Materialize trailing holes and wholly sparse files.


def _copy_signature(info):
    """Content/metadata snapshot; reads may change atime without changing data."""
    return (info.st_size, info.st_mode, info.st_mtime_ns, info.st_ctime_ns)


def _regular_copier():
    """Copy bounded, stable regular files while retaining holes and hardlinks.

    Callers own private staging and reclaim partial copies on any failure.
    Hardlinks are an optimization: unsupported destination filesystems fall
    back to independent sparse copies. Unknown inode identities never alias.
    """
    links = {}
    def copy(source, destination):
        with preserving_stream_error(open_regular_gated(source, follow_symlinks=False)) as reader:
            info = os.fstat(reader.fileno())
            key = (info.st_dev, info.st_ino)
            signature = _copy_signature(info)
            previous = links.get(key) if info.st_ino and info.st_nlink > 1 else None
            linked = False
            if previous is not None:
                path, previous_signature = previous
                if signature != previous_signature:
                    raise OSError('hardlinked source file changed between copies')
                try:
                    os.link(path, destination, follow_symlinks=False)
                    linked = True
                except OSError as exc:
                    if exc.errno not in _LINK_UNSUPPORTED:
                        raise
            if not linked:
                with preserving_stream_error(open(destination, 'xb')) as writer:
                    _copy_sparse_contents(reader, writer, info.st_size)
            if _copy_signature(os.fstat(reader.fileno())) != signature:
                raise OSError('source file changed during copy')
            if not linked:
                os.chmod(destination, stat.S_IMODE(info.st_mode))
                os.utime(destination, ns=(info.st_atime_ns, info.st_mtime_ns))
            if info.st_ino and info.st_nlink > 1 and previous is None:
                links[key] = (destination, signature)
        return destination
    return copy
