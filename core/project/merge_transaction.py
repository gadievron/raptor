"""Stage a complete merge before exposing its output directory."""
from contextlib import ExitStack
from pathlib import Path
import secrets
import stat

from core.atomic_fs import publish_new_directory, rename_without_replace
from core.atomic_fs.fs_lock import artifact_lock
from core.logging import get_logger
from core.run.scratch import scratch_dir
from .import_transaction import _identity, _pin_entry

logger = get_logger()


def publish_merge(run_dirs, output: Path, build):
    """Publish to an absent or empty real directory; never replace existing data."""
    output = Path(output)
    resolved = output.resolve()
    for source in run_dirs:
        root = source.resolve()
        if resolved == root or resolved.is_relative_to(root) or root.is_relative_to(resolved):
            raise ValueError('output_dir cannot overlap a source run directory')
    output.parent.mkdir(parents=True, exist_ok=True)
    backup = output.with_name(f'.merge-backup-{secrets.token_hex(16)}')
    with artifact_lock(output, required=True, create_parent=False, subject='merge output'), ExitStack() as scope:
        previous = _identity(output)
        mode = None
        if previous is not None:
            info = output.lstat()
            if not stat.S_ISDIR(info.st_mode) or any(output.iterdir()):
                raise ValueError(f'Output directory {output} already contains data or is not a real directory. Use an empty directory.')
            pinned = scope.enter_context(_pin_entry(output, directory=True))
            if pinned != previous:
                raise OSError('merge output changed while acquiring ownership')
            mode = stat.S_IMODE(info.st_mode)
        workspace = scope.enter_context(scratch_dir('.merge-stage-', dir=output.parent, keepalive=True))
        staged = workspace / 'merged'
        result = build(run_dirs, staged)
        if mode is not None:
            staged.chmod(mode)
        staged_id = scope.enter_context(_pin_entry(staged, directory=True))
        try:
            if _identity(output) != previous:
                raise OSError('merge output changed while building')
            if previous is not None:
                rename_without_replace(output, backup)
                if _identity(backup) != previous or any(backup.iterdir()):
                    raise OSError('previous merge output changed before publication')
            publish_new_directory(staged, output)
            if _identity(output) != staged_id:
                raise OSError('merge output changed during publication')
        except BaseException:
            try:
                if _identity(output) == staged_id:
                    rename_without_replace(output, staged)
            except BaseException:
                logger.error('Incomplete merge rollback; inspect retained output at %s', output, exc_info=True)
            try:
                if previous is not None and _identity(backup) == previous:
                    rename_without_replace(backup, output)
            except BaseException:
                logger.error('Previous merge output retained for recovery at %s', backup, exc_info=True)
            try:
                if _identity(backup) is not None:
                    logger.warning('Merge recovery entry retained at %s', backup)
            except BaseException:
                logger.warning('Cannot inspect merge recovery path %s', backup, exc_info=True)
            raise
        if previous is not None:
            try:
                if _identity(backup) != previous:
                    raise OSError('merge recovery directory changed')
                backup.rmdir()  # Never recursively delete a bystander written into the old empty dir.
            except OSError:
                logger.warning('Merge completed; inspect retained previous output at %s', backup)
        return result
