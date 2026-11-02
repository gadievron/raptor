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
