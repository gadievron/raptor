"""Malformed consumed live metadata counts as loss, ordinary noise does not."""
import json

import pytest

from core.sandbox import seatbelt_audit as audit
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'xdg'))


@pytest.mark.slow
@pytest.mark.parametrize('field,value', [
    ('senderImagePath', []), ('senderImagePath', None),
    ('eventMessage', []), ('eventMessage', None), ('eventMessage', 123),
], ids=['array-sender', 'null-sender', 'array-message', 'null-message', 'integer-message'])
def test_live_malformed_metadata_sets_capture_loss(owned_audit_source, field, value):
    good = {'senderImagePath': audit.SANDBOX_KEXT_SENDER,
            'eventMessage': 'Sandbox: tool(123) deny(1) file-read-data /tmp/retained'}
    bad = dict(good, **{field: value})
    data = ('\n'.join(map(json.dumps, [good, bad, good])) + '\n').encode()
    owner, profile = owned_audit_source(data)
    assert profile.paths_read == ['/tmp/retained']
    assert owner._reader_failed is True
    assert profile.capture_incomplete is True


@pytest.mark.parametrize('entry', [
    {}, {'eventMessage': 'unrelated'},
    {'senderImagePath': audit.SANDBOX_KEXT_SENDER, 'eventMessage': 'unrecognised kext message'},
    {'senderImagePath': '/other', 'eventMessage': 'unrelated', 'timestamp': None},
])
def test_valid_noise_is_not_corrupt(entry):
    assert audit._decode_log_entry(json.dumps(entry)) == entry
