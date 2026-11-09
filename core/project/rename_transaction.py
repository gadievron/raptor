"""Recover project rename failures without replacing another writer's data."""
from contextlib import ExitStack
import os
from pathlib import Path
import secrets
import stat

from core.atomic_fs import rename_without_replace
from core.json import save_json
from core.logging import get_logger
from core.run.scratch import scratch_dir
from .import_transaction import _identity, _pin_entry

logger = get_logger()


def publish_rename(project, old_file: Path, new_file: Path,
                   old_output: Path, new_output: Path | None) -> None:
    """Prepare registration, move output exclusively, then retire the old name.

    Caller holds both registry-name locks and the output-claim lock. Rollback
    handles Python errors and cancellation, including errors after a syscall's
    effect. A failed rollback retains named data and logs its recovery paths.
    """
    backup = old_file.with_name(f'.rename-backup-{secrets.token_hex(16)}.record')
    with ExitStack() as scope:
        old_record_id = scope.enter_context(_pin_entry(old_file))
        output_id = (scope.enter_context(_pin_entry(old_output, directory=True))
                     if new_output is not None and os.path.lexists(old_output) else None)
        workspace = scope.enter_context(scratch_dir('.rename-record-', dir=old_file.parent,
                                                   keepalive=True))
        staged = workspace / 'project.json'
        save_json(staged, project.to_dict())
        mode = stat.S_IMODE(old_file.stat().st_mode)
        staged.chmod(mode if mode & 0o400 else 0o600)
        new_record_id = scope.enter_context(_pin_entry(staged))
        try:
            os.link(old_file, backup, follow_symlinks=False)
            if _identity(backup) != old_record_id:
                raise OSError('project registration changed before rename')
            if new_output is not None and output_id is not None:
                rename_without_replace(old_output, new_output)
                if _identity(new_output) != output_id:
                    raise OSError('project output changed during rename')
            rename_without_replace(staged, new_file)
            if _identity(new_file) != new_record_id or _identity(old_file) != old_record_id:
                raise OSError('project registration changed during rename')
            old_file.unlink()
        except BaseException:
            # Restore registration first; never remove another writer's name.
            try:
                if _identity(old_file) is None and _identity(backup) == old_record_id:
                    rename_without_replace(backup, old_file)
                if _identity(old_file) != old_record_id:
                    raise OSError('old project registration changed during rollback')
                if _identity(new_file) == new_record_id:
                    new_file.unlink()
            except BaseException:
                logger.error('Project rename registry rollback incomplete; inspect %s, %s and %s',
                             old_file, new_file, backup, exc_info=True)
            try:
                if new_output is not None and output_id is not None and _identity(new_output) == output_id:
                    if _identity(old_file) != old_record_id or _identity(new_file) == new_record_id:
                        raise OSError('registration could not be restored before output rollback')
                    rename_without_replace(new_output, old_output)
            except BaseException:
                logger.error('Project rename output rollback incomplete; data retained at %s '
                             '(previous path %s)', new_output, old_output, exc_info=True)
            try:
                if _identity(old_file) == old_record_id:
                    _clear_backup(backup, old_record_id)
            except BaseException:
                logger.warning('Rename recovery registration retained at %s', backup, exc_info=True)
            raise
        _clear_backup(backup, old_record_id)


def _clear_backup(backup, expected):
    try:
        current = _identity(backup)
        if current is not None:
            if current != expected:
                raise OSError('rename recovery record changed')
            backup.unlink()
    except OSError:
        logger.warning('Project rename recovery registration retained at %s', backup)
