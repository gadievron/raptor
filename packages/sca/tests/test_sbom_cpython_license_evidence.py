"""CPython's own declaration is distinct from bundled third-party terms."""
from copy import deepcopy
import hashlib
from pathlib import Path

import pytest

from core.oci.notice_paths import cpython_notice_paths, component_notice_paths
from packages.sca.sbom_license_evidence import recover_cpython_license

LAYER = 'sha256:' + 'a' * 64
OTHER = 'sha256:' + 'b' * 64
NOTICE = Path(__file__).parent / 'fixtures/licenses/cpython-LICENSE'


def evidence(version='3.14.10', prefix='/usr/local', abi='3.14'):
    artifact = {'id': 'python', 'name': 'python', 'version': version, 'type': 'binary', 'licenses': [],
                'locations': [{'path': f'{prefix}/bin/python{abi}', 'layerID': LAYER},
                              {'path': f'{prefix}/lib/libpython{abi}.so.1.0', 'layerID': LAYER}]}
    data = NOTICE.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    row = {'path': f'{prefix}/lib/python{abi}/LICENSE.txt', 'catalogue_layer_diff_id': LAYER,
           'layer_blob_digest': OTHER, 'sha256': sha, 'content_kind': 'notice_candidate'}
    return artifact, [row], {sha: data}


@pytest.mark.parametrize(('version', 'prefix', 'abi'), [
    ('3.14.10', '/usr/local', '3.14'), ('3.14.11', '/usr/local', '3.14'),
    ('3.15.0', '/opt/python', '3.15'), ('3.16.0rc1', '/opt/python', '3.16'),
    ('3.14.10', '/usr/local', '3.14t'),
])
def test_unchanged_project_notice_survives_version_and_prefix_updates(version, prefix, abi):
    artifact, files, blobs = evidence(version, prefix, abi)
    before = deepcopy(artifact)
    declaration = recover_cpython_license(artifact, files, blobs)
    assert declaration['expression'] == 'PSF-2.0'
    assert declaration['notice_path'] == files[0]['path']
    assert declaration['notice_sha256'] == files[0]['sha256']
    assert 'third-party' in declaration['scope']
    assert artifact == before
    assert (files[0]['path'], LAYER) in component_notice_paths(artifact)


@pytest.mark.parametrize('problem', ['name', 'version', 'path', 'prefix', 'layer', 'abi', 'kind', 'missing'])
def test_unbound_installations_stay_unresolved(problem):
    artifact, files, blobs = evidence()
    if problem == 'name': artifact['name'] = 'other'
    elif problem == 'version': artifact['version'] = '3.15.0'
    elif problem == 'path': artifact['locations'][0]['path'] = '/usr/local/bin/not-python'
    elif problem == 'prefix': artifact['locations'][1]['path'] = '/opt/lib/libpython3.14.so.1.0'
    elif problem == 'layer': artifact['locations'][1]['layerID'] = OTHER
    elif problem == 'abi': artifact['locations'][1]['path'] = '/usr/local/lib/libpython3.14t.so.1.0'
    elif problem == 'kind': artifact['type'] = 'python'
    else: artifact['locations'] = []
    assert not cpython_notice_paths(artifact)
    assert recover_cpython_license(artifact, files, blobs) is None


@pytest.mark.parametrize('problem', ['changed', 'truncated', 'missing', 'duplicate', 'wrong-layer', 'wrong-kind', 'hash'])
def test_complete_scoped_notice_is_required(problem):
    artifact, files, blobs = evidence()
    sha = files[0]['sha256']
    if problem in {'changed', 'truncated'}:
        data = blobs.pop(sha)
        data = data + b'changed terms' if problem == 'changed' else data[:500]
        sha = hashlib.sha256(data).hexdigest()
        files[0]['sha256'] = sha
        blobs[sha] = data
    elif problem == 'missing': blobs.clear()
    elif problem == 'duplicate': files *= 2
    elif problem == 'wrong-layer': files[0]['catalogue_layer_diff_id'] = OTHER
    elif problem == 'wrong-kind': files[0]['content_kind'] = 'package_metadata'
    else: blobs[sha] += b'tampered'
    assert recover_cpython_license(artifact, files, blobs) is None


@pytest.mark.parametrize('claims', [
    [{'value': 'MIT'}], [{'value': 'UNKNOWN'}, {'value': 'MIT'}],
    [{'value': 'NONE'}], [{'value': 'UNLICENSED'}], ['bad'], None,
])
def test_existing_conflicting_or_non_grant_claims_are_preserved(claims):
    artifact, files, blobs = evidence()
    artifact['licenses'] = claims
    assert recover_cpython_license(artifact, files, blobs) is None
