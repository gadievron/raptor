"""Human connection output is sampled while JSON retains the entire profile."""
import json

import pytest

from core.sandbox import observe_cli as cli
from core.sandbox.observe_profile import ConnectTarget, ObserveProfile


@pytest.mark.parametrize('count', [11, 1000], ids=['one-extra', 'many'])
def test_connection_summary_samples_first_ten_and_keeps_total(tmp_path, count):
    targets = [ConnectTarget(f'host-{index}.test', 443, 'AF_INET') for index in range(count)]
    profile = ObserveProfile(connect_targets=targets)
    before = list(targets)
    text = cli._format_summary(profile, run_dir=tmp_path, kept=False, return_code=0)
    assert f'connect targets ({count}):' in text
    for index in range(10):
        assert f'host-{index}.test:443' in text
    assert 'host-10.test:443' not in text
    assert f'+{count - 10} more' in text
    assert '--json for the complete list' in text
    assert len(text) < 3000
    decoded = json.loads(cli._profile_to_json(profile, run_dir=tmp_path, kept=False, return_code=0))
    assert len(decoded['connect_targets']) == count
    assert decoded['connect_targets'][-1]['ip'] == f'host-{count - 1}.test'
    assert profile.connect_targets == before


@pytest.mark.parametrize('count', [0, 1, 10], ids=['empty', 'one', 'exact'])
def test_small_connection_lists_remain_complete(tmp_path, count):
    profile = ObserveProfile(connect_targets=[ConnectTarget(f'host-{i}.test', 443, 'AF_INET')
                                              for i in range(count)])
    text = cli._format_summary(profile, run_dir=tmp_path, kept=False, return_code=0)
    assert f'connect targets ({count}):' in text
    assert 'more' not in text
    if count:
        assert f'host-{count - 1}.test:443' in text
    else:
        assert '(none' in text
