"""RECORD and directory selection must stay inside the owning distribution."""
import base64
import hashlib
from copy import deepcopy

import pytest

from core.oci.notice_paths import PackageNoticePaths

LAYER = 'sha256:' + 'a' * 64


def artifact():
    return {'id': 'package', 'type': 'python', 'locations': [
        {'path': '/python/pkg-1.dist-info/METADATA', 'layerID': LAYER}],
        'metadata': {'files': [{'path': 'pkg-1.dist-info/licenses/vendor/LICENSE',
            'digest': {'algorithm': 'sha256', 'value': base64.urlsafe_b64encode(hashlib.sha256(b'notice').digest()).rstrip(b'=').decode()}, 'size': '6'}]}}


def test_record_notices_and_nested_vendor_notices():
    package = artifact()
    paths = PackageNoticePaths([package])
    record = paths.records[('/python/pkg-1.dist-info/licenses/vendor/LICENSE', LAYER)]
    assert record == {'sha256': hashlib.sha256(b'notice').hexdigest(), 'size': 6, 'package_ids': {'package'}}
    assert paths.matches('/python/pkg-1.dist-info/licenses/vendor/LICENSE', LAYER) == [('package', 'python_distribution_notice_candidate')]
    assert paths.matches('/python/other-1.dist-info/LICENSE', LAYER) == []
    assert paths.matches('/python/pkg-1.dist-info/LICENSE.py', LAYER) == []


@pytest.mark.parametrize('change', ['escape', 'absolute_inside', 'hash', 'algorithm', 'size', 'conflict', 'location'])
def test_invalid_record_claim_refused(change):
    package = artifact()
    entry = package['metadata']['files'][0]
    if change == 'escape':
        entry['path'] = 'pkg-1.dist-info/licenses/../../etc/LICENSE'
    elif change == 'absolute_inside':
        entry['path'] = 'pkg-1.dist-info//licenses/LICENSE'
    elif change == 'hash':
        entry['digest']['value'] = 'a' * 43 + '===='
    elif change == 'algorithm':
        entry['digest']['algorithm'] = 'md5'
    elif change == 'size':
        entry['size'] = '-1'
    elif change == 'location':
        package['locations'][0]['path'] = '/python/../pkg-1.dist-info/METADATA'
    else:
        duplicate = deepcopy(entry)
        duplicate['size'] = '7'
        package['metadata']['files'].append(duplicate)
    with pytest.raises(ValueError):
        PackageNoticePaths([package])


def test_record_scripts_and_external_paths_are_not_selected():
    package = artifact()
    package['metadata']['files'] = [{'path': '../../../bin/LICENSE'}, {'path': '/etc/LICENSE'}, {'path': 'pkg/module.py'}]
    assert PackageNoticePaths([package]).records == {}


def test_duplicate_locations_do_not_repeat_record_parsing():
    package = artifact()
    package['locations'] *= 100
    paths = PackageNoticePaths([package])
    assert len(paths.records) == len(paths.directories) == 1


def test_npm_filename_variants_and_declared_pointers_do_not_leak_to_children():
    package = {'id': 'npm', 'type': 'npm', 'locations': [{'path': '/node_modules/pkg/package.json', 'layerID': LAYER}],
               'licenses': [{'value': 'SEE LICENSE IN TERMS.txt'}]}
    paths = PackageNoticePaths([package])
    assert paths.matches('/node_modules/pkg/license-MIT', LAYER) == [('npm', 'npm_directory_notice_candidate')]
    assert paths.matches('/node_modules/pkg/TERMS.txt', LAYER) == [('npm', 'declared_notice_pointer')]
    assert paths.matches('/node_modules/pkg/node_modules/child/LICENSE', LAYER) == []
    assert paths.matches('/node_modules/pkg/README.md', LAYER) == []


def test_absolute_record_path_stays_inside_own_metadata_directory():
    package = artifact()
    entry = package['metadata']['files'][0]
    entry['path'] = '/python/' + entry['path']
    entry['size'] = ''
    record = next(iter(PackageNoticePaths([package]).records.values()))
    assert record['size'] is None


def test_leading_dot_record_paths_keep_their_hash_claims():
    package = artifact()
    package['metadata']['files'][0]['path'] = './' + package['metadata']['files'][0]['path']
    assert next(iter(PackageNoticePaths([package]).records.values()))['sha256'] == hashlib.sha256(b'notice').hexdigest()


@pytest.mark.parametrize('path', ['/node_modules/pkg//LICENSE', '/node_modules/pkg/./LICENSE', '/node_modules/pkg/child/../LICENSE'])
def test_discovery_refuses_path_aliases_that_could_shadow_a_notice(path):
    package = {'id': 'npm', 'type': 'npm', 'locations': [{'path': '/node_modules/pkg/package.json', 'layerID': LAYER}]}
    with pytest.raises(ValueError, match='unsafe'):
        PackageNoticePaths([package]).matches(path, LAYER)


@pytest.mark.parametrize('name', ['LICENSES.txt', 'NOTICES', 'CONTRIBUTORS.txt', 'THIRD-PARTY-NOTICES.md', 'custom-terms.txt'])
def test_dedicated_license_directory_includes_nonstandard_basenames(name):
    package = artifact()
    package['metadata']['files'][0]['path'] = 'pkg-1.dist-info/licenses/vendor/' + name
    paths = PackageNoticePaths([package])
    assert ('/python/pkg-1.dist-info/licenses/vendor/' + name, LAYER) in paths.records
    assert paths.matches('/python/pkg-1.dist-info/licenses/vendor/' + name, LAYER)
