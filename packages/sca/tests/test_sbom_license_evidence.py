"""Recover declarations without guessing licence variants or package scope."""
from copy import deepcopy
import hashlib

import pytest

from packages.sca.sbom_license_evidence import declaration_from_metadata


def evidence(headers):
    path = '/env/example-1.2.dist-info/METADATA'
    data = ('Name: example\nVersion: 1.2\n' + headers).encode()
    sha = hashlib.sha256(data).hexdigest()
    artifact = {'type': 'python', 'name': 'example', 'version': '1.2', 'licenses': [],
                'locations': [{'path': path, 'layerID': 'sha256:' + 'd' * 64}]}
    row = {'path': path, 'catalogue_layer_diff_id': 'sha256:' + 'd' * 64,
           'layer_blob_digest': 'sha256:' + 'e' * 64, 'content_kind': 'package_metadata', 'sha256': sha}
    return artifact, [row], {sha: data}


@pytest.mark.parametrize(('classifier', 'expected'), [
    ('MIT License', 'MIT'), ('Mozilla Public License 2.0 (MPL 2.0)', 'MPL-2.0'),
])
def test_unambiguous_trove_declaration_is_recovered(classifier, expected):
    artifact, rows, blobs = evidence('Classifier: License :: OSI Approved :: ' + classifier + '\n')
    result = declaration_from_metadata(artifact, rows, blobs)
    assert result['expression'] == expected and result['metadata_field'] == 'Classifier'
    assert result['metadata_sha256'] == rows[0]['sha256']
    assert result['metadata_path'] == rows[0]['path']


@pytest.mark.parametrize('headers', [
    'Classifier: License :: OSI Approved :: BSD License\n',
    'Classifier: License :: OSI Approved :: Apache Software License\n',
    'Classifier: License :: OSI Approved :: MIT License\nClassifier: License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)\n',
    'License: custom terms\nClassifier: License :: OSI Approved :: MIT License\n',
    'License: UNLICENSED\nClassifier: License :: OSI Approved :: MIT License\n',
    'License: NONE\nClassifier: License :: OSI Approved :: MIT License\n',
    'License-Expression: LicenseRef-UNKNOWN\n',
    'License-Expression: MIT\nLicense: MIT\n',
    'License-Expression: MIT\nLicense-Expression: MIT\n',
])
def test_ambiguous_conflicting_and_non_grant_metadata_is_not_promoted(headers):
    assert declaration_from_metadata(*evidence(headers)) is None


@pytest.mark.parametrize('field', ['License', 'License-Expression'])
def test_exact_spdx_expression_preserves_choice_operator(field):
    result = declaration_from_metadata(*evidence(field + ': BSD-2-Clause OR Apache-2.0\n'))
    assert result['expression'] == 'BSD-2-Clause OR Apache-2.0'
    assert result['metadata_field'] == field


def test_placeholder_is_preserved_with_recovered_publisher_declaration():
    artifact, rows, blobs = evidence('License: UNKNOWN\nClassifier: License :: OSI Approved :: MIT License\n')
    artifact['licenses'] = [{'value': 'UNKNOWN'}]
    result = declaration_from_metadata(artifact, rows, blobs)
    assert result['expression'] == 'MIT'
    assert result['original_catalogue_licenses'] == [{'value': 'UNKNOWN'}]


@pytest.mark.parametrize('change', ['name', 'version', 'duplicate-name', 'layer', 'hash', 'type', 'duplicate-metadata'])
def test_recovery_requires_exact_metadata_identity_and_bytes(change):
    artifact, rows, blobs = evidence('License-Expression: MIT\n')
    if change == 'name':
        artifact['name'] = 'different'
    elif change == 'version':
        artifact['version'] = '2.0'
    elif change == 'duplicate-name':
        raw = next(iter(blobs.values())) + b'Name: different\n'
        sha = hashlib.sha256(raw).hexdigest()
        rows[0]['sha256'] = sha
        blobs = {sha: raw}
    elif change == 'layer':
        rows[0]['catalogue_layer_diff_id'] = 'sha256:' + 'f' * 64
    elif change == 'hash':
        blobs[rows[0]['sha256']] = b'tampered'
    elif change == 'type':
        artifact['type'] = 'binary'
    else:
        rows.append(deepcopy(rows[0]))
    assert declaration_from_metadata(artifact, rows, blobs) is None


def test_known_and_unknown_catalogue_claims_are_not_collapsed_to_one_licence():
    artifact, rows, blobs = evidence('License-Expression: MIT\n')
    artifact['licenses'] = [{'value': 'MIT'}, {'value': 'UNKNOWN'}]
    assert declaration_from_metadata(artifact, rows, blobs) is None


@pytest.fixture
def reviewed(monkeypatch):
    import packages.sca.sbom_license_evidence as module
    artifact, rows, blobs = evidence('Classifier: License :: OSI Approved :: BSD License\n')
    data = b'Complete reviewed licence fixture'
    sha = hashlib.sha256(data).hexdigest()
    row = dict(rows[0], path='/env/example-1.2.dist-info/licenses/LICENSE.txt',
               content_kind='notice_candidate', sha256=sha)
    rows.append(row)
    blobs[sha] = data
    monkeypatch.setattr(module, '_reviewed_rules', lambda: {
        'example': {'expression': 'BSD-3-Clause', 'notices': {'LICENSE': sha}}})
    return module, artifact, rows, blobs


def test_reviewed_complete_text_recovers_specific_variant(reviewed):
    module, artifact, rows, blobs = reviewed
    result = module.recover_distribution_license(artifact, rows, blobs)
    assert result['expression'] == 'BSD-3-Clause'
    assert result['basis'] == 'reviewed_distribution_notices'
    assert result['notice_files'][0]['sha256'] == rows[1]['sha256']


def test_version_bump_reuses_unchanged_reviewed_text(reviewed):
    module, artifact, rows, blobs = reviewed
    artifact['version'] = '2.0'
    data = blobs.pop(rows[0]['sha256']).replace(b'Version: 1.2', b'Version: 2.0')
    rows[0]['sha256'] = hashlib.sha256(data).hexdigest()
    blobs[rows[0]['sha256']] = data
    assert module.recover_distribution_license(artifact, rows, blobs)['expression'] == 'BSD-3-Clause'


@pytest.mark.parametrize('change', ['changed', 'missing', 'extra', 'duplicate', 'outside', 'layer', 'project'])
def test_reviewed_text_requires_complete_exact_package_notice_set(reviewed, change):
    module, artifact, rows, blobs = reviewed
    if change == 'changed':
        blobs[rows[1]['sha256']] += b'Changed terms'
    elif change == 'missing':
        rows.pop()
    elif change == 'extra':
        rows.append(dict(rows[1], path=rows[1]['path'] + '.extra'))
    elif change == 'duplicate':
        rows.append(dict(rows[1]))
    elif change == 'outside':
        rows[1]['path'] = '/other/LICENSE'
    elif change == 'layer':
        rows[1]['catalogue_layer_diff_id'] = 'other-layer'
    else:
        artifact['name'] = 'another-project'
    assert module.recover_distribution_license(artifact, rows, blobs) is None


@pytest.mark.parametrize('headers', ['License: UNLICENSED\n', 'License: custom terms\n',
                                   'License-Expression: MIT\n',
                                   'License: UNKNOWN\nLicense: UNKNOWN\n'])
def test_reviewed_text_does_not_override_conflicting_metadata(reviewed, headers):
    module, artifact, rows, blobs = reviewed
    data = ('Name: example\nVersion: 1.2\n' + headers).encode()
    rows[0]['sha256'] = hashlib.sha256(data).hexdigest()
    blobs[rows[0]['sha256']] = data
    assert module.recover_distribution_license(artifact, rows, blobs) is None
