"""Opt-in native checks using harmless fixtures, never real accounts or targets."""
import os
import shlex
import sys

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.slow,
              pytest.mark.skipif(os.environ.get('RAPTOR_FUZZ_FLOOR_ACCEPTANCE') != '1',
                                 reason='opt-in native containment acceptance')]


@pytest.mark.parametrize('consumer', ['afl', 'libfuzzer', 'replay', 'synthesized-build'])
def test_native_consumer_restricts_reads_and_writes(tmp_path, monkeypatch, consumer):
    from core.sandbox import context, state
    from core.build import build_detector
    from packages.fuzzing import afl_runner, libfuzzer_runner
    import core.sandbox

    if sys.platform not in ('linux', 'darwin'):
        pytest.skip('Linux or macOS required')
    monkeypatch.setattr(state, '_cli_sandbox_floor', None)
    monkeypatch.setattr(state, '_project_sandbox_floor', None)
    monkeypatch.setattr(state, '_cli_sandbox_disabled', False)
    monkeypatch.setattr(context, '_host_consented_floor', lambda: None)
    monkeypatch.delenv('RAPTOR_ALLOW_DEGRADED_UNTRUSTED', raising=False)
    source, output, outside = (tmp_path / name for name in ('source', 'output', 'outside'))
    for path in (source, output, outside):
        path.mkdir()
    canary = outside / 'canary'
    canary.write_text('disposable private data')
    forbidden = outside / 'forbidden'
    marker = output / 'executed'
    public = source / 'public'
    public.write_text('public')
    harness = source / 'fixture'
    harness.write_text('#!/bin/sh\n'
        + 'test "$(cat ' + shlex.quote(str(public)) + ')" = public || exit 83\n'
        + 'if cat ' + shlex.quote(str(canary)) + ' >/dev/null 2>&1; then exit 81; fi\n'
        + 'if (echo bad >' + shlex.quote(str(forbidden)) + ') 2>/dev/null; then exit 82; fi\n'
        + 'echo ok >' + shlex.quote(str(marker)) + '\n')
    harness.chmod(0o700)
    actual_run = core.sandbox.run
    replies = []
    def observe(*args, **kwargs):
        reply = actual_run(*args, **kwargs)
        replies.append(reply)
        return reply
    if consumer == 'afl':
        monkeypatch.setattr(afl_runner, '_sandbox_run', observe)
        instance = afl_runner._SandboxedAFLInstance(name='fixture', cmd=[str(harness)], env={},
            stdout_path=output/'stdout', stderr_path=output/'stderr', output_dir=output,
            readable_paths=[str(source)], timeout_s=30)
        instance._run()
        if instance.error:
            raise instance.error
    elif consumer == 'libfuzzer':
        monkeypatch.setattr(libfuzzer_runner, '_sandbox_run', observe)
        libfuzzer_runner.LibFuzzerRunner(harness, output_dir=output, max_total_time=1).run()
    elif consumer == 'replay':
        monkeypatch.setattr(core.sandbox, 'run', observe)
        from packages.fuzzing.coverage_bridge import _default_runner
        _default_runner([str(harness)], cwd=output)
    else:
        monkeypatch.setattr(build_detector, '_sandbox_run', observe)
        script = source / 'build.py'
        script.write_text('import pathlib\n'
            'try: pathlib.Path(' + repr(str(canary)) + ').read_bytes()\n'
            'except OSError: pass\nelse: raise AssertionError("private read allowed")\n'
            'try: pathlib.Path(' + repr(str(forbidden)) + ').write_text("bad")\n'
            'except OSError: pass\nelse: raise AssertionError("outside write allowed")\n'
            'pathlib.Path(' + repr(str(source/'executed')) + ').write_text("ok")\n')
        marker = source / 'executed'
        assert build_detector.BuildDetector(source)._dry_run(script, language='c') == []
    assert len(replies) == 1
    assert replies[0].returncode == 0, replies[0].stderr
    info = replies[0].sandbox_info
    required = 'mount-ns' if sys.platform == 'linux' else 'seatbelt'
    assert info['containment_floor'] == required, info
    assert info['containment_tier'] == required, info
    assert marker.read_text().strip() == 'ok'
    assert canary.read_text() == 'disposable private data'
    assert not forbidden.exists()
