"""SBOM outputs keep private scratch ownership and preserve racing destinations."""

import logging
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.atomic_fs import publish_new_directory, rmtree_hardened
from core.run import scratch
from core.testing.scratch_state import isolated_scratch_keepalive
from packages.sca.sbom_inventory import collection, output
from packages.sca.sbom_inventory.inventory import read_inventory
from packages.sca.sbom_inventory.source import Source
from packages.sca.sbom_inventory.tests.test_collection import image
from packages.sca.sbom_inventory.tests.test_plan import plan
from packages.sca.sbom_inventory.tests.test_verification import verify


OWNERS = ['notices', 'plan', 'verification', 'collection']


@pytest.fixture
def publication(tmp_path, monkeypatch):
    roots = []
    original = tempfile.mkdtemp

    def allocate(*args, **kwargs):
        root = Path(original(*args, **kwargs))
        roots.append(root)
        return str(root)

    monkeypatch.setattr(scratch, 'tempfile', SimpleNamespace(**{**vars(tempfile), 'mkdtemp': allocate}))
    monkeypatch.setattr(scratch, 'logger', logging.Logger('sbom-publication-test'))
    try:
        with isolated_scratch_keepalive() as pins:
            yield SimpleNamespace(roots=roots, pins=pins, target=tmp_path / 'published', base=tmp_path)
            assert all(not root.exists() for root in roots), roots
            assert not pins
    finally:
        for root in roots:
            assert rmtree_hardened(root)


def invocation(case, owner, bundle):
    if owner == 'plan':
        report = plan(case.base)
        return output, lambda: output.write_upgrade_plan(case.target, report)
    if owner == 'verification':
        report = verify()
        return output, lambda: output.write_verification(case.target, report)
    if owner == 'collection':
        syft, layout, _ = image(case.base)
        return collection, lambda: collection.collect_image(syft, case.target, oci_layout=layout)

    def export():
        with Source(bundle) as source:
            inventory, embedded = read_inventory(source)
            return output.export_notices(case.target, inventory, inventory.records,
                source, embedded, include_unassociated=True)
    return output, export


def dirty(case, source):
    root = case.roots[-1]
    assert root != source and source.is_relative_to(root), 'publication must not move its scratch root'
    assert str(root) in case.pins
    child = root / 'restricted-cache'
    child.mkdir()
    (child / 'payload').write_bytes(b'debris' * 1024)
    child.chmod(0)


def contender(target, shape):
    outside = target.parent / 'operator'
    outside.mkdir()
    (outside / 'keep').write_text('operator')
    if shape in ('empty-directory', 'nonempty-directory'):
        target.mkdir()
        if shape == 'nonempty-directory':
            (target / 'keep').write_text('operator')
    elif shape == 'file':
        target.write_text('operator')
    else:
        target.symlink_to(outside if shape == 'symlink' else target.parent / 'absent', target_is_directory=True)
    info = target.lstat()
    return outside, (info.st_dev, info.st_ino, info.st_mode)


@pytest.mark.parametrize('owner', OWNERS)
@pytest.mark.parametrize('shape', ['empty-directory', 'nonempty-directory', 'file', 'symlink', 'dangling'])
def test_racing_destination_is_never_replaced(publication, bundle, monkeypatch, owner, shape):
    module, call = invocation(publication, owner, bundle)
    observed = []

    def publish(source, target):
        dirty(publication, source)
        outside, identity = contender(target, shape)
        observed.append((outside, identity))
        publish_new_directory(source, target)

    monkeypatch.setattr(module, 'publish_new_directory', publish)
    with pytest.raises(FileExistsError):
        call()
    outside, identity = observed[0]
    info = publication.target.lstat()
    assert (info.st_dev, info.st_ino, info.st_mode) == identity
    assert (outside / 'keep').read_text() == 'operator'
    if shape == 'file':
        assert publication.target.read_text() == 'operator'
    elif shape == 'nonempty-directory':
        assert (publication.target / 'keep').read_text() == 'operator'


@pytest.mark.parametrize('owner', OWNERS)
def test_success_keeps_output_and_removes_outer_scratch(publication, bundle, monkeypatch, owner):
    module, call = invocation(publication, owner, bundle)
    sources = []

    def publish(source, target):
        dirty(publication, source)
        sources.append(source)
        publish_new_directory(source, target)
        # The outer root remains private and pinned until teardown, even
        # though the complete bundle now belongs to the caller.
        assert publication.roots[-1].is_dir()
        assert str(publication.roots[-1]) in publication.pins

    monkeypatch.setattr(module, 'publish_new_directory', publish)
    call()
    assert publication.target.is_dir() and any(publication.target.iterdir())
    assert sources and not sources[0].exists()
    assert not publication.roots[-1].exists()
    if owner in ('notices', 'collection'):
        with Source(publication.target) as source:
            inventory, _ = read_inventory(source)
        assert inventory.records


@pytest.mark.parametrize('owner', OWNERS)
@pytest.mark.parametrize('error', [OSError, KeyboardInterrupt, SystemExit])
def test_publication_failure_reclaims_private_scratch(publication, bundle, monkeypatch, owner, error):
    module, call = invocation(publication, owner, bundle)

    def fail(source, target):
        dirty(publication, source)
        raise error('primary publication failure')

    monkeypatch.setattr(module, 'publish_new_directory', fail)
    with pytest.raises(error, match='primary publication failure'):
        call()
    assert not publication.target.exists()


@pytest.mark.parametrize('owner', OWNERS)
@pytest.mark.parametrize('error', [OSError, KeyboardInterrupt, SystemExit])
def test_cleanup_failure_preserves_publication_error(publication, bundle, monkeypatch, owner, error):
    module, call = invocation(publication, owner, bundle)

    def fail(source, target):
        dirty(publication, source)
        raise RuntimeError('primary publication failure')

    def remove(*args, **kwargs):
        raise error('secondary removal failure')

    monkeypatch.setattr(module, 'publish_new_directory', fail)
    with pytest.MonkeyPatch.context() as fault:
        fault.setattr(scratch, 'rmtree_hardened', remove)
        with pytest.raises(RuntimeError, match='primary publication failure'):
            call()
    assert not publication.pins
    for root in publication.roots:
        assert rmtree_hardened(root)
