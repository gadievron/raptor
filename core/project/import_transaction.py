"""Publish project data and registration with recoverable, rename-only backups."""
from contextlib import ExitStack, contextmanager
import os
from pathlib import Path
import secrets
import stat

from core.atomic_fs import publish_new_directory, rename_without_replace, rmtree_hardened
from core.json import save_json
from core.logging import get_logger
from core.run.scratch import scratch_dir
from .oplock import OP_LOCK_NAME, project_op_lock
from .project import ProjectManager, project_file_lock
from .registry_home import refuse_registry_overlap

logger = get_logger()


def _identity(path: Path) -> tuple[int, int] | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    return info.st_dev, info.st_ino


@contextmanager
def _pin_entry(path: Path, *, directory: bool = False):
    """Hold the inode allocated until publication/rollback ownership ends."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    if directory:
        flags |= os.O_DIRECTORY
    fd = os.open(path, flags)
    failed = False
    try:
        info = os.fstat(fd)
        if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
            raise OSError('cannot pin non-regular import artifact')
        yield info.st_dev, info.st_ino
    except BaseException:
        failed = True
        raise
    finally:
        try:
            os.close(fd)
        except BaseException as exc:
            if not failed and not isinstance(exc, OSError):
                raise


def _rollback(record, record_id, old_record_id, record_backup,
              output, output_id, old_output_id, output_backup, staging):
    """Restore only proven transaction-owned names; never clobber replacements."""
    try:
        current = _identity(record)
        if current == record_id:
            if old_record_id is None:
                record.unlink()
            elif _identity(record_backup) == old_record_id:
                os.replace(record_backup, record)
        elif current != old_record_id:
            raise OSError('registration changed during import rollback')
    except BaseException:
        logger.error('Import registration rollback incomplete; recovery record: %s',
                     record_backup, exc_info=True)
    try:
        if _identity(record) != old_record_id:
            raise OSError('registration could not be restored; retaining published output')
        if _identity(output) == output_id:
            rename_without_replace(output, staging)
    except BaseException:
        logger.error('Import output rollback incomplete; recovery tree: %s',
                     output_backup, exc_info=True)
    try:
        if old_output_id is not None and _identity(output_backup) == old_output_id:
            if _identity(output) is None:
                rename_without_replace(output_backup, output)
            elif _identity(output) != old_output_id:
                raise OSError('output path changed during import rollback')
    except BaseException:
        logger.error('Previous project output retained for recovery at %s',
                     output_backup, exc_info=True)
    try:
        if old_record_id is not None and _identity(record) == old_record_id:
            if _identity(record_backup) == old_record_id:
                record_backup.unlink()
    except BaseException:
        logger.warning('Recovery record retained at %s', record_backup, exc_info=True)
    for path, expected in ((record_backup, old_record_id), (output_backup, old_output_id)):
        try:
            actual = _identity(path)
            if actual is not None and actual != expected:
                logger.error('Unexpected recovery entry retained without modification at %s', path)
        except OSError:
            logger.error('Cannot inspect recovery path %s; retain it for inspection', path)


def publish_import(manager: ProjectManager, name: str, metadata: dict,
                   staging: Path, output: Path, force: bool) -> dict[str, str]:
    """Commit only after data and a complete registration have been prepared.

    Existing output is renamed, never copied. Recovery backups live outside
    disposable staging so a failed rollback cannot delete the previous data.
    Name and output claims stay locked through publication and rollback.
    """
    record = manager.projects_dir / f'{name}.json'
    token = secrets.token_hex(16)
    output_backup = output.with_name(f'.import-backup-{name}-{token}')
    record_backup = record.with_name(f'.import-backup-{name}-{token}.record')
    result = {'name': name, 'output_dir': str(output)}
    with project_file_lock(record, required=True):
        with manager._output_dir_claim_lock(output, required=True), ExitStack() as scope:
            existing = manager.load(name)
            old_record_id = _identity(record)
            if old_record_id is not None and not force:
                raise ValueError(f"Project '{name}' already exists. Use --force to overwrite.")
            if old_record_id is not None:
                info = record.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
                    raise ValueError('Refusing import over non-regular or foreign registration')
            owner = manager._output_dir_owner(output, exclude=name)
            if owner:
                raise ValueError(f"Refusing import: output overlaps project '{owner}'")
            refuse_registry_overlap(output, extra_projects_dir=manager.projects_dir)
            old_output_id = _identity(output)
            if old_output_id is not None:
                if not force:
                    raise ValueError(f'Refusing import: output dir {output} appeared during import')
                if not stat.S_ISDIR(output.lstat().st_mode):
                    raise ValueError('Refusing import over non-directory output')
            if old_output_id is not None:
                pinned = scope.enter_context(_pin_entry(output, directory=True))
                if pinned != old_output_id:
                    raise OSError('output changed while pinning import ownership')
            project = manager._make_project(
                name=name, target=metadata.get('target', '(imported)'),
                description=metadata.get('description', ''), output_dir=str(output),
                resolve_target=False, created=metadata.get('created'), binaries=None)
            project.notes = metadata.get('notes', '')
            # Hold old and destination operation locks before judging liveness.
            resolved_output = output.resolve()
            if existing and existing.output_path.resolve() != resolved_output:
                previous_output = existing.output_path.resolve()
                if (previous_output.is_relative_to(resolved_output)
                        or resolved_output.is_relative_to(previous_output)):
                    raise ValueError('Refusing import: replacement output overlaps previous output')
            roots = {resolved_output: output} if old_output_id is not None else {}
            if existing and existing.output_path.is_dir():
                roots.setdefault(existing.output_path.resolve(), existing.output_path)
            output_lock = None
            for resolved_root, root in sorted(roots.items()):
                held = scope.enter_context(project_op_lock(root, 'project-import', required=True))
                if resolved_root == resolved_output:
                    output_lock = held
            if existing:
                manager._refuse_live_delete(existing, operation='replace during import', force_hint=False)
                if existing.output_path.resolve() != output.resolve() and existing.output_path.exists():
                    result['orphaned_output'] = str(existing.output_path.resolve())
            manager._refuse_live_delete(project, operation='replace during import', force_hint=False)
            if _identity(output) != old_output_id or _identity(record) != old_record_id:
                raise OSError('project changed while preparing import')
            # The new tree must share the held lock inode across its rename.
            if output_lock is not None:
                lock_path = staging / OP_LOCK_NAME
                if os.path.lexists(lock_path):
                    if lock_path.is_dir() and not lock_path.is_symlink():
                        if not rmtree_hardened(lock_path):
                            raise OSError('cannot replace imported operation lock')
                    else:
                        lock_path.unlink()
                os.link(output / OP_LOCK_NAME, lock_path, follow_symlinks=False)
                held = os.fstat(output_lock)
                if _identity(lock_path) != (held.st_dev, held.st_ino):
                    raise OSError('project operation lock changed during import')
            record_stage = scope.enter_context(scratch_dir(
                '.import-record-', dir=manager.projects_dir, keepalive=True))
            staged_record = record_stage / 'project.json'
            save_json(staged_record, project.to_dict())
            mode = stat.S_IMODE(record.stat().st_mode) if old_record_id else 0o600
            staged_record.chmod(mode if mode & 0o400 else 0o600)
            record_id = scope.enter_context(_pin_entry(staged_record))
            output_id = scope.enter_context(_pin_entry(staging, directory=True))
            try:
                if old_record_id is not None:
                    os.link(record, record_backup, follow_symlinks=False)
                    if _identity(record_backup) != old_record_id:
                        raise OSError('registration changed before import backup')
                if old_output_id is not None:
                    rename_without_replace(output, output_backup)
                    if _identity(output_backup) != old_output_id:
                        raise OSError('output changed before import backup')
                publish_new_directory(staging, output)
                if _identity(output) != output_id:
                    raise OSError('output changed during import publication')
                os.replace(staged_record, record)
                if _identity(record) != record_id:
                    raise OSError('registration changed during import publication')
            except BaseException:
                _rollback(record, record_id, old_record_id, record_backup,
                          output, output_id, old_output_id, output_backup, staging)
                raise
            # Publication committed. Cleanup failures retain named recovery
            # data and report it without pretending the new import failed.
            if old_output_id is not None:
                try:
                    actual = _identity(output_backup)
                    if actual is not None:
                        if actual != old_output_id or not rmtree_hardened(output_backup):
                            raise OSError('output recovery backup changed or could not be removed')
                except OSError:
                    result['retained_backup'] = str(output_backup)
                    logger.warning('Imported project; inspect retained output backup at %s', output_backup)
            try:
                if old_record_id is not None:
                    actual = _identity(record_backup)
                    if actual is not None:
                        if actual != old_record_id:
                            raise OSError('registration recovery backup changed')
                        record_backup.unlink()
            except OSError:
                result['retained_registry_backup'] = str(record_backup)
                logger.warning('Imported project; inspect retained registration backup at %s', record_backup)
    return result
