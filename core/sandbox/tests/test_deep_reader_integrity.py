"""Advisory parsing must ground only usable signals and reject ambiguity."""
import json

import pytest

from core.sandbox import telemetry_mac as mac, triage, triage_deep as deep
from core.sandbox.tests.test_triage_deep import _FakeClient
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'xdg'))


REPLY = json.dumps({'assessments': [{'signal_type': 'known', 'judgement': 'tool_noise',
                                    'confidence': 0.7, 'rationale': 'owned response'}],
                    'overall_note': 'owned note'})


@pytest.mark.parametrize('signals', [None, 7, True, 'known', {'type': 'known'}, [None], [7],
                                    [{'type': []}], [{'type': {}}], [{'type': ''}]],
                         ids=['null', 'integer', 'boolean', 'string', 'object',
                              'null-row', 'integer-row', 'array-type', 'object-type', 'empty-type'])
def test_unusable_signal_lists_cannot_ground_assessments(signals):
    assessments, note, dropped = deep._parse_assessments(REPLY, {'signals': signals})
    assert assessments == []
    assert note == 'owned note'
    assert dropped == 1


@pytest.mark.parametrize('bad', [None, 7, [], {'type': []}, {'type': {}}, {'type': ''}],
                         ids=['null', 'integer', 'array', 'array-type', 'object-type', 'empty-type'])
def test_malformed_signal_rows_do_not_hide_valid_neighbors(bad):
    result = deep._parse_assessments(REPLY, {'signals': [bad, {'type': 'known'}]})
    assert result[0] == [{'signal_type': 'known', 'judgement': 'tool_noise',
                          'confidence': 0.7, 'rationale': 'owned response'}]
    assert result[2] == 0


def report_on_disk(run, signals, stamped):
    value = {'run_dir': str(run), 'verdict': 'suspicious', 'signals': signals,
             'inputs': {}, 'caveats': []}
    if stamped:
        value['mac'] = mac.mint(mac.triage_report_fields(
            triage._report_sha256(value), mac.run_binding(run)))
        assert value['mac']
    path = run / triage.TRIAGE_FILE
    path.write_text(json.dumps(value) + '\n')
    return path


@pytest.mark.parametrize('stamped', [False, True], ids=['legacy', 'signed'])
@pytest.mark.parametrize('signals', ['known', {'type': 'known'}, [None], [{'type': []}], [{'type': ''}]],
                         ids=['string', 'object', 'null-row', 'array-type', 'empty-type'])
def test_unusable_reports_skip_client_and_preserve_rules_file(tmp_path, monkeypatch, stamped, signals):
    path = report_on_disk(tmp_path, signals, stamped)
    before = path.read_bytes()
    client = _FakeClient(REPLY)

    def no_factory():
        pytest.fail('invalid report reached the client factory')
    from core.llm import factory
    monkeypatch.setattr(factory, 'get_client', no_factory)
    assert deep.deep_analyse(tmp_path, client=client, allow_legacy=not stamped) is None
    assert client.calls == []
    assert deep.deep_analyse(tmp_path, allow_legacy=not stamped) is None
    assert path.read_bytes() == before
    assert not (tmp_path / deep.DEEP_FILE).exists()


@pytest.mark.parametrize('stamped', [False, True], ids=['legacy', 'signed'])
def test_mixed_signal_report_produces_verified_advice_without_changing_rules(tmp_path, stamped):
    path = report_on_disk(tmp_path, [None, {'type': []}, {'type': 'known'}], stamped)
    before = path.read_bytes()
    client = _FakeClient(REPLY)
    result = deep.deep_analyse(tmp_path, client=client, allow_legacy=not stamped)
    assert len(client.calls) == 1
    assert result['assessments'][0]['signal_type'] == 'known'
    assert result['rules_verdict'] == 'suspicious'
    assert deep.verify_deep_report(result, tmp_path) == 'verified'
    assert json.loads((tmp_path / deep.DEEP_FILE).read_text()) == result
    assert path.read_bytes() == before


DUPLICATES = [
    pytest.param('{"assessments":[],"assessments":[{"signal_type":"known"}]}', id='outer-list'),
    pytest.param('{"overall_note":"first","overall_note":"last","assessments":[]}', id='outer-note'),
    pytest.param('{"assessments":[{"signal_type":"other","signal_type":"known"}]}', id='signal-type'),
    pytest.param('{"assessments":[{"signal_type":"known","judgement":"unclear","judgement":"tool_noise"}]}', id='judgement'),
    pytest.param('{"assessments":[{"signal_type":"known","confidence":0.1,"confidence":0.9}]}', id='confidence'),
    pytest.param('{"assessments":[{"signal_type":"known","rationale":"first","rationale":"last"}]}', id='rationale'),
    pytest.param(r'{"assessments":[{"signal_type":"known","signal_\u0074ype":"known"}]}', id='escaped-key'),
    pytest.param('{"assessments":[{"signal_type":"known","metadata":{"detail":1,"detail":2}}]}', id='nested'),
]


@pytest.mark.parametrize('wrapper', ['raw', 'prose', 'fenced'])
@pytest.mark.parametrize('text', DUPLICATES)
def test_duplicate_response_members_are_rejected_on_every_decode_path(text, wrapper):
    if wrapper == 'prose':
        text = 'prefix ' + text + ' suffix'
    elif wrapper == 'fenced':
        text = '```json\n' + text + '\n```'
    assert deep._parse_assessments(text, {'signals': [{'type': 'known'}]}) == ([], '', 0)


@pytest.mark.parametrize('wrapper', ['raw', 'prose', 'fenced'])
def test_valid_unique_response_keeps_supported_wrappers(wrapper):
    text = REPLY if wrapper == 'raw' else ('prefix ' + REPLY + ' suffix' if wrapper == 'prose'
                                        else '```json\n' + REPLY + '\n```')
    assessments, note, dropped = deep._parse_assessments(text, {'signals': [{'type': 'known'}]})
    assert assessments[0]['signal_type'] == 'known'
    assert note == 'owned note'
    assert dropped == 0


def test_distinct_nested_objects_are_not_duplicates():
    payload = json.loads(REPLY)
    payload['metadata'] = {'left': {'detail': 1}, 'right': {'detail': 2}}
    assert deep._parse_assessments(json.dumps(payload), {'signals': [{'type': 'known'}]})[2] == 0
