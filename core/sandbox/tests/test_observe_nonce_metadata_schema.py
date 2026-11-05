"""Malformed metadata cannot establish protected nonce delivery or abort parsing."""
import json

import pytest

from core.sandbox import observe_profile as observe


@pytest.fixture
def parse(tmp_path):
    (tmp_path / observe.OBSERVE_FILENAME).write_text(json.dumps({
        'syscall': 'stat', 'path': '/tmp/file', 'nonce': 'trusted'}) + '\n')

    def run(info):
        profile = observe.parse_observe_log(tmp_path, expected_nonce='trusted', sandbox_info=info)
        assert profile.paths_stat == ['/tmp/file']
        return profile

    return run


@pytest.mark.parametrize('delivery', [[], {}, ['anonymous_fd'], {'kind': 'anonymous_fd'}, 1, True])
def test_invalid_delivery_shape_demotes_without_raising(parse, delivery):
    assert parse({'mount_ns_active': False, 'nonce_delivery': delivery}).nonce_trusted is False


@pytest.mark.parametrize('active', ['false', 'true', 1, [True], {'active': True}])
def test_only_boolean_true_establishes_mount_isolation(parse, active):
    assert parse({'mount_ns_active': active}).nonce_trusted is False


@pytest.mark.parametrize('info', [[], ['metadata'], 'metadata', 1, True])
def test_nonobject_metadata_is_unknown_and_untrusted(parse, info):
    assert parse(info).nonce_trusted is False


@pytest.mark.parametrize('info', [
    {'mount_ns_active': True},
    {'backend': 'macos-seatbelt'},
    {'mount_ns_active': False, 'nonce_delivery': 'anonymous_fd'},
    {'mount_ns_active': False, 'nonce_delivery': 'in_process'},
])
def test_valid_protection_metadata_remains_trusted(parse, info):
    assert parse(info).nonce_trusted is True


def test_absent_metadata_preserves_offline_compatibility(parse):
    assert parse(None).nonce_trusted is True
