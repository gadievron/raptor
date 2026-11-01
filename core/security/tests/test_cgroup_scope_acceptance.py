"""Native delegated-cgroup acceptance. Run inside a disposable delegated scope.

RAPTOR_CGROUP_ACCEPTANCE=1 systemd-run --user --scope -p Delegate=yes python3 -m pytest \
    core/security/tests/test_cgroup_scope_acceptance.py -m integration -q
"""
import os
from pathlib import Path
import select
import signal
import time

import pytest

from core.security.cgroup_scope import Scope

pytestmark = [pytest.mark.integration, pytest.mark.slow, pytest.mark.skipif(
    os.environ.get('RAPTOR_CGROUP_ACCEPTANCE') != '1',
    reason='explicit delegated-cgroup host acceptance')]


@pytest.fixture
def scope():
    try:
        result = Scope.create()
    except OSError as exc:
        pytest.fail(f'delegated cgroup required; run this test in a delegated user scope: {exc}')
    try:
        yield result
    finally:
        result.close_admission()
        try:
            result.stop()
            result.release()
        finally:
            result.close()


def test_gated_attach_and_teardown_cover_daemonized_grandchildren(scope):
    gate_r, gate_w = os.pipe()
    report_r, report_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(gate_w)
            os.close(report_r)
            assert os.read(gate_r, 1) == b'1'
            grandchild = os.fork()
            if grandchild == 0:
                os.setsid()
                time.sleep(60)
            else:
                os.write(report_w, str(grandchild).encode())
                time.sleep(60)
        finally:
            os._exit(0)
    os.close(gate_r)
    os.close(report_w)
    reaped = False
    try:
        scope.attach(pid)
        os.write(gate_w, b'1')
        assert select.select([report_r], [], [], 5)[0], 'payload did not report its descendant'
        assert int(os.read(report_r, 64)) > 0
        assert scope.populated()
        scope.close_admission()
        scope.stop()
        assert not scope.populated()
        _, status = os.waitpid(pid, 0)
        reaped = True
        assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
    finally:
        os.close(gate_w)
        os.close(report_r)
        if not reaped:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)


def test_recovery_rejects_a_reused_or_wrong_scope_identity(scope):
    with pytest.raises(PermissionError):
        Scope.recover(scope.path, [scope.identity[0], scope.identity[1] + 1])
    recovered = Scope.recover(scope.path, scope.identity)
    try:
        assert not recovered.populated()
    finally:
        recovered.close()


def test_session_supervision_stops_members_but_retains_unproven_scratch(tmp_path, monkeypatch):
    import json
    import sys
    from core.security import launch_scratch, scratch_supervisor
    lifecycle = scratch_supervisor.lifecycle
    monkeypatch.setenv('RAPTOR_REGISTRY_HOME', str(tmp_path / 'registry'))
    family = tmp_path / f'raptor-{os.geteuid()}'
    family.mkdir(mode=0o700)
    root = family / f'session-{os.getpid()}-123'
    root.mkdir(mode=0o700)
    metadata = launch_scratch.create(root)
    session_id = lifecycle.register(metadata, os.getpid())
    monkeypatch.setenv('_RAPTOR_SCRATCH_AUTH', launch_scratch.issue(tmp_path / 'authorities', metadata, os.getpid()))
    receipt = tmp_path / 'outside-receipt.json'
    code = r'''
import json,os,pathlib,sys,time
root=pathlib.Path(sys.argv[1])
(root/'tmp/probe').write_text('working')
child=os.fork()
if child==0:
    os.setsid()
    time.sleep(60)
    os._exit(0)
pathlib.Path(sys.argv[2]).write_text(json.dumps({'child':child}))
'''
    assert scratch_supervisor.supervise(metadata, [sys.executable, '-I', '-c', code, str(root), str(receipt)]) == 0
    assert json.loads(receipt.read_text())['child'] > 0
    assert root.exists()
    with lifecycle.locked(session_id) as (_, value):
        assert value['state'] == 'retained'
        assert value['closure'] is None
        assert value['backend'] == 'cgroup-v2-tracking'
        assert not Path(value['scope']['path']).exists()
