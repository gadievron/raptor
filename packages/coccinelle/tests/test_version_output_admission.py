"""Version text admission with injected results; no live-tool prerequisites."""

import pytest

from core.analysis.rule_versions import rule_version_refusal
from core.run.toolprobe import ToolInfo, _CAPTURE_RETAIN_CHARS
from packages.coccinelle import runner


@pytest.mark.parametrize('channel', ['stdout', 'stderr'])
@pytest.mark.parametrize('offset', [-1, 0, 1])
def test_spatch_version_refuses_potentially_truncated_streams(monkeypatch, channel, offset):
    prefix = 'spatch version 2.0.0\n'
    size = _CAPTURE_RETAIN_CHARS + offset
    payload = prefix + 'x' * (size - len(prefix))
    info = ToolInfo(name='owned', path='owned', returncode=0, **{channel: payload})
    monkeypatch.setattr(runner, '_spatch_path', lambda: 'owned-inert')
    monkeypatch.setattr(runner, 'probe', lambda binary: info)
    answer = runner.version()
    refusal = rule_version_refusal('// raptor-min-version: 2.0.0\n@rule@', runner.version)
    if offset < 0:
        assert answer == '2.0.0'
        assert refusal is None
    else:
        assert answer is None
        assert refusal and 'installed version unknown' in refusal
