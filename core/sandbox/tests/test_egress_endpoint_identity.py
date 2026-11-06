"""Display placeholders must not change endpoint identity or accounting."""
import json

import pytest

from core.sandbox.egress_summary import summarise_egress


@pytest.mark.parametrize('missing', [None, ''], ids=['null', 'empty'])
def test_literal_placeholder_is_separate_from_unknown(tmp_path, missing):
    events = [
        {'host': missing, 'port': 443, 'result': 'denied_host', 'bytes_u2c': 7},
        {'host': '<unknown>', 'port': 443, 'result': 'allowed', 'bytes_u2c': 11},
    ]
    (tmp_path / 'proxy-events.jsonl').write_text('\n'.join(map(json.dumps, events)) + '\n')
    value = summarise_egress(tmp_path)
    assert value['unique_hosts'] == 1
    assert value['total_connections'] == 2
    assert value['total_bytes_in'] == 18
    assert len(value['hosts']) == 2
    assert sorted((row['allowed'], row['denied'], row['bytes_in'], row['reasons'])
                  for row in value['hosts']) == [(0, 1, 7, ['denied_host']), (1, 0, 11, [])]


def test_missing_null_and_empty_hosts_remain_one_unknown_endpoint(tmp_path):
    events = [{'result': 'allowed', 'port': 443},
              {'result': 'allowed', 'port': 443, 'host': None},
              {'result': 'allowed', 'port': 443, 'host': ''}]
    (tmp_path / 'proxy-events.jsonl').write_text('\n'.join(map(json.dumps, events)) + '\n')
    value = summarise_egress(tmp_path)
    assert value['unique_hosts'] == 0
    assert value['hosts'][0]['allowed'] == 3
    assert len(value['hosts']) == 1
