"""Offline outputs refuse contenders created after their initial absence check."""

from pathlib import Path

import pytest

from core.atomic_fs import publish_new_directory
from packages.codeql import offline
from packages.codeql.tests import test_offline as offline_cases

setup = offline_cases.setup


@pytest.mark.parametrize('owner', ['prepare', 'cache-import'])
@pytest.mark.parametrize('shape', ['empty-directory', 'nonempty-directory', 'file', 'symlink', 'dangling'])
def test_offline_publication_preserves_racing_destination(setup, tmp_path, monkeypatch, owner, shape):
    _, _, home, _ = setup
    kit = tmp_path / 'kit'
    if owner == 'cache-import':
        digest = offline.prepare(kit, ['python'], ['standard', 'iris'])
    target = kit if owner == 'prepare' else home / '.codeql/packages/codeql/python-all/1.0.0'
    outside = tmp_path / 'operator'
    outside.mkdir()
    (outside / 'keep').write_text('operator')
    identities = []

    def publish(source, destination):
        destination = Path(destination)
        assert destination == target
        if shape in ('empty-directory', 'nonempty-directory'):
            destination.mkdir()
            if shape == 'nonempty-directory':
                (destination / 'keep').write_text('operator')
        elif shape == 'file':
            destination.write_text('operator')
        else:
            destination.symlink_to(outside if shape == 'symlink' else tmp_path / 'absent', target_is_directory=True)
        info = destination.lstat()
        identities.append((info.st_dev, info.st_ino, info.st_mode))
        publish_new_directory(source, destination)

    monkeypatch.setattr(offline, 'publish_new_directory', publish)
    with pytest.raises(FileExistsError):
        if owner == 'prepare':
            offline.prepare(kit, ['python'], ['standard', 'iris'])
        else:
            offline.import_kit(kit, digest)
    info = target.lstat()
    assert (info.st_dev, info.st_ino, info.st_mode) == identities[0]
    assert (outside / 'keep').read_text() == 'operator'
    assert not list(tmp_path.glob('raptor-codeql-offline-*'))
    assert not list((home / '.codeql').glob('raptor-codeql-import-*'))
