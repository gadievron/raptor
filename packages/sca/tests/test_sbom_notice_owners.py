"""Enclosing notices never close child gaps or certify ownership/licence scope."""
from copy import deepcopy
import hashlib

import pytest

from packages.sca.sbom_notice_owners import add_owner_context

PATH = '/node_modules/child/package.json'
ORIGIN = 'sha256:' + 'a' * 64


def inputs():
    raw = b'{"name":"child","license":"MIT"}'
    sha = hashlib.sha256(raw).hexdigest()
    digest = hashlib.md5(raw, usedforsecurity=False).hexdigest()
    child = {'id': 'child', 'name': 'child', 'type': 'npm', 'version': '1', 'locations': [
        {'path': PATH, 'layerID': ORIGIN, 'annotations': {'evidence': 'primary'}}]}
    owner = {'id': 'owner', 'name': 'nodejs', 'type': 'deb', 'version': '24', 'metadata': {
        'files': [{'path': PATH, 'digest': {'algorithm': 'md5', 'value': digest}}]}}
    notice = {'path': '/usr/share/doc/nodejs/copyright', 'catalogue_layer_diff_id': ORIGIN,
              'layer_blob_digest': 'sha256:' + 'b' * 64, 'sha256': 'c' * 64, 'size': 10,
              'notice_file': 'notices/sha256/' + 'c' * 64, 'content_kind': 'notice_candidate',
              'visibility': 'catalogue_location', 'reasons': ['catalogue_licence_location']}
    records = [{'id': 'child', 'status': 'metadata_only', 'files': [], 'gaps': ['own notice remains missing']},
               {'id': 'owner', 'status': 'notice_candidate_captured', 'files': [notice], 'gaps': ['owner scope unreviewed']}]
    rows = [{'path': PATH, 'catalogue_layer_diff_id': ORIGIN, 'layer_blob_digest': 'sha256:' + 'b' * 64,
             'visibility': 'catalogue_location', 'sha256': sha, 'notice_file': 'notices/sha256/' + sha}]
    return {'artifacts': [child, owner]}, rows, {sha: raw}, records


def apply(data, **kwargs):
    return add_owner_context(*data, limit=100, **kwargs)


def test_exact_captured_checksum_links_context_without_closing_gap():
    data = inputs()
    original = deepcopy(data)
    stats = apply(data)
    child = data[3][0]
    context = child['distro_owner_context']['checksum_matched_notices'][0]
    assert stats['packages_with_checksum_matched_notice_context'] == 1
    assert context['owner_package_id'] == 'owner'
    assert context['matched_locations'][0]['captured_sha256'] == data[1][0]['sha256']
    assert context['matched_locations'][0]['inventory_digest']['algorithm'] == 'md5'
    assert context['matched_locations'][0]['visibility'] == 'catalogue_location'
    assert context['matched_locations'][0]['layer_blob_digest'] == data[1][0]['layer_blob_digest']
    assert child['status'] == 'metadata_only' and child['gaps'] == ['own notice remains missing']
    assert child['files'] == []
    assert data[:3] == original[:3]
    assert data[3][1] == original[3][1]


@pytest.mark.parametrize('change,status', [
    ('missing_bytes', 'captured_bytes_unavailable'), ('other_layer', 'captured_bytes_unavailable'),
    ('mismatch', 'inventory_checksum_mismatch'), ('unknown_algorithm', 'unsupported_inventory_checksum'),
    ('invalid', 'invalid_inventory_checksum'), ('no_digest', 'inventory_checksum_unavailable'),
    ('malformed', 'invalid_inventory_checksum'), ('conflicting', 'conflicting_inventory_claims')])
def test_unverified_inventory_claims_do_not_link_notices(change, status):
    data = inputs()
    claim = data[0]['artifacts'][1]['metadata']['files'][0]
    if change == 'missing_bytes':
        data[1][0].pop('notice_file')
    elif change == 'other_layer':
        data[1][0]['catalogue_layer_diff_id'] = 'sha256:' + 'f' * 64
    elif change == 'mismatch':
        claim['digest']['value'] = '0' * 32
    elif change == 'unknown_algorithm':
        claim['digest']['algorithm'] = 'md4'
    elif change == 'invalid':
        claim['digest']['value'] = 'not-a-hash'
    elif change == 'no_digest':
        claim.pop('digest')
    elif change == 'malformed':
        claim['digest'] = 'md5=not-structured'
    else:
        other = deepcopy(claim)
        other['digest']['value'] = '0' * 32
        data[0]['artifacts'][1]['metadata']['files'].append(other)
    stats = apply(data)
    context = data[3][0]['distro_owner_context']
    assert not context['checksum_matched_notices']
    assert context['unresolved_locations'][0]['candidates'][0]['verification'] == status
    assert stats['packages_with_unresolved_owner_leads'] == 1


def test_two_matching_owner_versions_are_ambiguous():
    data = inputs()
    owner = deepcopy(data[0]['artifacts'][1])
    owner.update(id='other-owner', version='25')
    data[0]['artifacts'].append(owner)
    data[3].append({**deepcopy(data[3][1]), 'id': 'other-owner'})
    stats = apply(data)
    context = data[3][0]['distro_owner_context']
    assert not context['checksum_matched_notices']
    assert context['unresolved_locations'][0]['reason'] == 'ambiguous_owner_inventory'
    assert stats['ambiguous_locations'] == 1


def test_supporting_location_cannot_substitute_for_unowned_primary():
    data = inputs()
    child = data[0]['artifacts'][0]
    child['locations'][0]['annotations']['evidence'] = 'supporting'
    child['locations'].append({'path': '/unowned/package.json', 'layerID': ORIGIN, 'annotations': {'evidence': 'primary'}})
    stats = apply(data)
    assert stats['packages_with_checksum_matched_notice_context'] == 0
    assert 'distro_owner_context' not in data[3][0]


def test_owner_without_captured_notice_stays_unresolved():
    data = inputs()
    data[3][1]['files'] = []
    apply(data)
    context = data[3][0]['distro_owner_context']
    assert not context['checksum_matched_notices']
    assert context['unresolved_locations'][0]['reason'] == 'matched_owner_has_no_notice_candidate'


def test_duplicate_same_claim_is_not_ambiguous():
    data = inputs()
    files = data[0]['artifacts'][1]['metadata']['files']
    files.append(deepcopy(files[0]))
    assert apply(data)['packages_with_checksum_matched_notice_context'] == 1


def test_context_growth_is_bounded():
    with pytest.raises(ValueError, match='association budget'):
        add_owner_context(*inputs(), limit=1)
    with pytest.raises(ValueError, match='text budget'):
        apply(inputs(), max_chars=1)


def test_sha256_inventory_claim_is_checked_without_changing_scope():
    data = inputs()
    raw = next(iter(data[2].values()))
    claim = data[0]['artifacts'][1]['metadata']['files'][0]
    claim['digest'] = {'algorithm': 'sha256', 'value': hashlib.sha256(raw).hexdigest()}
    assert apply(data)['packages_with_checksum_matched_notice_context'] == 1
    assert data[3][0]['status'] == 'metadata_only'


def test_matching_owner_does_not_hide_another_unverifiable_owner():
    data = inputs()
    other = deepcopy(data[0]['artifacts'][1])
    other['id'] = 'other-owner'
    other['metadata']['files'][0].pop('digest')
    data[0]['artifacts'].append(other)
    data[3].append({**deepcopy(data[3][1]), 'id': 'other-owner'})
    assert apply(data)['ambiguous_locations'] == 1
    assert not data[3][0]['distro_owner_context']['checksum_matched_notices']


def test_mismatching_owner_can_be_ruled_out_without_losing_its_claim():
    data = inputs()
    other = deepcopy(data[0]['artifacts'][1])
    other['id'] = 'other-owner'
    other['metadata']['files'][0]['digest']['value'] = '0' * 32
    data[0]['artifacts'].append(other)
    data[3].append({**deepcopy(data[3][1]), 'id': 'other-owner'})
    assert apply(data)['packages_with_checksum_matched_notice_context'] == 1
    candidates = data[3][0]['distro_owner_context']['checksum_matched_notices'][0]['matched_locations'][0]['inventory_candidates']
    assert {c['verification'] for c in candidates} == {'captured_bytes_match_inventory_checksum', 'inventory_checksum_mismatch'}


def test_supporting_only_locations_do_not_become_primary_by_fallback():
    data = inputs()
    data[0]['artifacts'][0]['locations'][0]['annotations']['evidence'] = 'supporting'
    assert apply(data)['packages_with_checksum_matched_notice_context'] == 0
    assert 'distro_owner_context' not in data[3][0]


def test_transient_verified_bytes_link_context_without_becoming_notice_files():
    data = inputs()
    row = data[1][0]
    raw = data[2][row['sha256']]
    row.pop('notice_file')
    measured = {**row, 'method': 'verified_image_layer', 'content_kind': 'identity'}
    stats = add_owner_context(*data, limit=100, verified_files={(PATH, ORIGIN): (measured, raw)})
    assert stats['packages_with_checksum_matched_notice_context'] == 1
    context = data[3][0]['distro_owner_context']['checksum_matched_notices'][0]
    assert context['matched_locations'][0]['verification'] == 'verified_image_bytes_match_inventory_checksum'
    assert data[3][0]['files'] == [] and data[3][0]['status'] == 'metadata_only'


def python_inputs():
    import base64
    data = inputs()
    child, owner = data[0]['artifacts']
    child['type'] = 'binary'
    owner['type'] = 'python'
    owner['name'] = 'enclosing-wheel'
    owner['locations'] = [{'path': '/node_modules/enclosing.dist-info/METADATA', 'layerID': ORIGIN}]
    owner['metadata']['sitePackagesRootPath'] = '/node_modules'
    raw = next(iter(data[2].values()))
    owner['metadata']['files'] = [{'path': 'child/package.json', 'size': str(len(raw)), 'digest': {
        'algorithm': 'sha256', 'value': base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b'=').decode()}}]
    data[0]['files'] = [{'location': {'path': PATH, 'layerID': ORIGIN},
                        'metadata': {'type': 'RegularFile', 'size': len(raw)},
                        'digests': [{'algorithm': 'sha256', 'value': hashlib.sha256(raw).hexdigest()}]}]
    return data


def test_python_record_catalogue_match_is_explicit_and_never_closes_own_gap():
    data = python_inputs()
    data[1].clear()
    original = deepcopy(data)
    stats = apply(data, owner_kind='python')
    assert stats['packages_with_checksum_matched_notice_context'] == 1
    child = data[3][0]
    context = child['python_record_owner_context']['checksum_matched_notices'][0]
    location = context['matched_locations'][0]
    assert location['verification'] == 'catalogue_sha256_matches_python_record'
    assert location['catalogue_sha256'] == data[0]['files'][0]['digests'][0]['value']
    assert 'captured_sha256' not in location and 'layer_blob_digest' not in location
    assert context['scope'] == 'enclosing_python_distribution_notice_context; component_coverage_unreviewed'
    assert child['status'] == original[3][0]['status']
    assert child['files'] == original[3][0]['files'] and child['gaps'] == original[3][0]['gaps']
    assert data[:3] == original[:3] and data[3][1] == original[3][1]
    assert 'distro_owner_context' not in child


def test_python_record_captured_and_verified_bytes_take_precedence_over_catalogue_claim():
    for transient in (False, True):
        data = python_inputs()
        data[0]['files'][0]['digests'][0]['value'] = '0' * 64
        kwargs = {}
        if transient:
            row = data[1].pop()
            kwargs['verified_files'] = {(PATH, ORIGIN): (row, data[2][row['sha256']])}
        assert apply(data, owner_kind='python', **kwargs)['packages_with_checksum_matched_notice_context'] == 1
        loc = data[3][0]['python_record_owner_context']['checksum_matched_notices'][0]['matched_locations'][0]
        assert loc['verification'] == ('verified_image_bytes_match_inventory_checksum' if transient
                                       else 'captured_bytes_match_inventory_checksum')


@pytest.mark.parametrize('change,expected', [
    ('checksum', 'inventory_checksum_mismatch'), ('size', 'inventory_size_mismatch'),
    ('invalid_size', 'invalid_inventory_size'), ('missing_size', 'invalid_inventory_size'),
    ('digest', 'invalid_inventory_checksum'), ('noncanonical_digest', 'invalid_inventory_checksum'),
    ('algorithm', 'unsupported_inventory_checksum'), ('missing_digest', 'inventory_checksum_unavailable'),
    ('symlink', 'catalogue_file_not_regular'), ('no_native', 'captured_bytes_unavailable'),
    ('native_digest', 'invalid_catalogue_checksum'), ('duplicate', 'conflicting_inventory_claims'),
])
def test_python_record_invalid_or_unverified_claims_remain_leads(change, expected):
    data = python_inputs()
    data[1].clear()
    entry = data[0]['artifacts'][1]['metadata']['files'][0]
    native_file = data[0]['files'][0]
    if change == 'checksum': native_file['digests'][0]['value'] = '0' * 64
    elif change == 'size': native_file['metadata']['size'] += 1
    elif change == 'invalid_size': entry['size'] = '-1'
    elif change == 'missing_size': entry.pop('size')
    elif change == 'digest': entry['digest']['value'] = 'not a digest'
    elif change == 'noncanonical_digest': entry['digest']['value'] = entry['digest']['value'][:-1] + '_'
    elif change == 'algorithm': entry['digest'] = {'algorithm': 'md5', 'value': '0' * 32}
    elif change == 'missing_digest': entry.pop('digest')
    elif change == 'symlink': native_file['metadata']['type'] = 'SymbolicLink'
    elif change == 'no_native': data[0]['files'] = []
    elif change == 'native_digest': native_file['digests'][0]['value'] = 'invalid'
    elif change == 'duplicate':
        other = deepcopy(entry); other['size'] = '0'
        data[0]['artifacts'][1]['metadata']['files'].append(other)
    stats = apply(data, owner_kind='python')
    assert stats['packages_with_checksum_matched_notice_context'] == 0
    ctx = data[3][0]['python_record_owner_context']
    assert ctx['unresolved_locations'][0]['candidates'][0]['verification'] == expected


@pytest.mark.parametrize('path', ['../child/package.json', '/node_modules/child/package.json',
                                 'child/../child/package.json', 'child//package.json',
                                 'child/./package.json', 'child\\package.json'])
def test_python_record_never_normalizes_unsafe_or_external_paths(path):
    data = python_inputs()
    data[0]['artifacts'][1]['metadata']['files'][0]['path'] = path
    assert apply(data, owner_kind='python')['packages_with_checksum_matched_notice_context'] == 0
    assert 'python_record_owner_context' not in data[3][0]


def test_python_record_does_not_link_other_layer_or_nonbinary_occurrences():
    for change in ('owner_layer', 'file_layer', 'nonbinary', 'supporting'):
        data = python_inputs()
        if change == 'owner_layer': data[0]['artifacts'][1]['locations'][0]['layerID'] = 'sha256:' + 'f' * 64
        elif change == 'file_layer':
            data[1].clear(); data[0]['files'][0]['location']['layerID'] = 'sha256:' + 'f' * 64
        elif change == 'nonbinary': data[0]['artifacts'][0]['type'] = 'npm'
        else: data[0]['artifacts'][0]['locations'][0]['annotations']['evidence'] = 'supporting'
        assert apply(data, owner_kind='python')['packages_with_checksum_matched_notice_context'] == 0


def test_python_record_matching_multiple_enclosing_distributions_is_ambiguous():
    data = python_inputs()
    data[1].clear()
    other = deepcopy(data[0]['artifacts'][1]); other['id'] = 'other-owner'
    data[0]['artifacts'].append(other)
    data[3].append({**deepcopy(data[3][1]), 'id': 'other-owner'})
    assert apply(data, owner_kind='python')['ambiguous_locations'] == 1
    assert not data[3][0]['python_record_owner_context']['checksum_matched_notices']


def test_python_record_limits_and_missing_parent_notices():
    with pytest.raises(ValueError, match='association budget'):
        add_owner_context(*python_inputs(), owner_kind='python', limit=1)
    with pytest.raises(ValueError, match='text budget'):
        apply(python_inputs(), owner_kind='python', max_chars=1)
    data = python_inputs(); data[3][1]['files'] = []
    apply(data, owner_kind='python')
    assert data[3][0]['python_record_owner_context']['unresolved_locations'][0]['reason'] == 'matched_owner_has_no_notice_candidate'
