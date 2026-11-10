"""Native acceptance on a disposable, namespace-capable delegated-cgroup host.

Uses the existing RAPTOR_CGROUP_ACCEPTANCE opt-in. Configure job_budget.parent
in sandbox.json if the current group is not a delegated, controller-ready parent.
These are actual confined workloads; file-backed unit controls are not substitutes.
"""
import os
import resource
import sys

import pytest

from core.sandbox import run_untrusted
from core.sandbox.job_budget import load_budget
from core.sandbox.python_paths import python_runtime_tool_paths

pytestmark = [pytest.mark.integration, pytest.mark.slow, pytest.mark.linux_native,
              pytest.mark.skipif(sys.platform != 'linux' or os.environ.get('RAPTOR_CGROUP_ACCEPTANCE') != '1',
                                 reason='explicit disposable delegated-cgroup acceptance host')]


@pytest.fixture
def native_job(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "keys"))
    target = tmp_path / 'target'
    output = tmp_path / 'output'
    target.mkdir()
    output.mkdir()
    configured = load_budget(None)
    budget = {'memory_max': 256 * 1024 * 1024, 'pids_max': 16,
              'cpu_max': [50000, 100000]}
    if configured is not None and configured.parent is not None:
        budget['parent'] = str(configured.parent)
    def execute(code, **kwargs):
        result = run_untrusted([sys.executable, '-c', code], target=str(target), output=str(output),
                             job_budget=budget, limits={'memory_mb': 0},
                             tool_paths=python_runtime_tool_paths(), capture_output=True,
                             text=True, timeout=kwargs.pop('timeout', 15), **kwargs)
        assert result.sandbox_info['mount_ns_active'] is True
        return result
    return budget, execute



def test_native_pids_limit_includes_forked_descendants_and_drains(native_job):
    budget, execute = native_job
    result = execute('''import os,time
children=[]
try:
    for _ in range(64):
        pid=os.fork()
        if pid==0:
            time.sleep(30)
            os._exit(0)
        children.append(pid)
except OSError:
    print("pids-budget-enforced",flush=True)
''')
    assert result.returncode == 0, result.stderr
    assert 'pids-budget-enforced' in result.stdout
    record = result.sandbox_info['job_budget']
    assert record['status'] == 'applied'
    assert record['effective']['pids.max'] == str(budget['pids_max'])
    assert record['cleanup'] == 'complete'
    assert record['final_usage']['pids.current'] == 0


def test_native_memory_budget_oom_is_accounted_and_cleaned(native_job):
    budget, execute = native_job
    budget['memory_max'] = 96 * 1024 * 1024
    result = execute('''blocks=[]
while True:
    block=bytearray(8*1024*1024)
    for i in range(0,len(block),4096): block[i]=1
    blocks.append(block)
''')
    assert result.returncode != 0
    record = result.sandbox_info['job_budget']
    assert record['cleanup'] == 'complete'
    assert record['final_usage']['memory.events']['oom_kill'] > 0


def test_native_cpu_quota_throttles_whole_job(native_job):
    budget, execute = native_job
    budget['cpu_max'] = [10000, 100000]
    result = execute('''import os,time
pid=os.fork()
end=time.process_time()+.15
while time.process_time()<end: pass
if pid: os.waitpid(pid,0)
''', timeout=15)
    assert result.returncode == 0, result.stderr
    record = result.sandbox_info['job_budget']
    assert record['cleanup'] == 'complete'
    assert record['final_usage']['cpu.stat']['nr_throttled'] > 0


def test_native_job_budget_does_not_add_virtual_address_cap(native_job):
    _, execute = native_job
    inherited = resource.getrlimit(resource.RLIMIT_AS)
    result = execute('import resource; print(resource.getrlimit(resource.RLIMIT_AS))')
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == str(inherited)


def test_native_owner_death_stops_job_without_parent_finally(native_job, tmp_path):
    import json
    from pathlib import Path
    import subprocess
    import time
    from core.testing.processes import reap_on_exit
    from core.testing.standalone_cli import standalone_cli_env
    budget, _ = native_job
    code = r"""
import json,os,sys,time
from core.sandbox.job_budget import Budget,Job
job=Job(Budget.parse(json.loads(sys.argv[1])),namespace_backend=True,run_dir=sys.argv[2])
r,w=os.pipe()
pid=os.fork()
if pid==0:
    os.close(w)
    if os.read(r,1)==b'G': time.sleep(60)
    os._exit(0)
os.close(r)
job.attach(pid)
os.write(w,b'G')
os.close(w)
print(json.dumps({'path':job.record['path'],'child':pid}),flush=True)
time.sleep(60)
"""
    with standalone_cli_env(data_home=tmp_path / "keys") as env:
        process = subprocess.Popen([sys.executable, '-c', code, json.dumps(budget), str(tmp_path)],
                                   cwd=str(Path(__file__).resolve().parents[3]), env=env,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                   start_new_session=True)
        with reap_on_exit(process, process_group=True):
            import select
            assert select.select([process.stdout], [], [], 10)[0], 'job owner did not announce its scope'
            announced = process.stdout.readline()
            assert announced, 'job owner exited without announcing its scope'
            path = Path(json.loads(announced)['path'])
            assert path.is_dir()
            process.kill()  # exact owned unreaped process; no /proc PID guessing
            process.wait(timeout=5)
            deadline = time.monotonic()+8
            while path.exists() and time.monotonic()<deadline:
                time.sleep(.05)
            assert not path.exists(), 'outside watcher did not empty and retire orphaned job'

    from core.sandbox import evidence, job_budget, telemetry_mac
    raw = evidence.resolve_read_path(tmp_path, job_budget.RECEIPTS_FILE).read_text()
    receipt = json.loads(raw)
    assert receipt['result']['cleanup'] == 'complete'
    assert telemetry_mac.verify(job_budget.receipt_fields(receipt), receipt['mac'])


def test_native_timeout_retains_verified_cleanup_receipt(native_job):
    import subprocess
    _, execute = native_job
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        execute("import time; print('started',flush=True); time.sleep(30)", timeout=1)
    output = caught.value.output or b''
    if isinstance(output, bytes):
        output = output.decode('utf-8', errors='replace')
    assert 'started' in output
    assert caught.value.job_budget['cleanup'] == 'complete'
    assert caught.value.job_budget['final_usage']['pids.current'] == 0


def test_native_asan_reservation_remains_compatible(native_job, tmp_path):
    import shutil
    from core.sandbox import run_trusted
    budget, _ = native_job
    compiler = shutil.which('cc')
    assert compiler is not None, 'native ASAN acceptance requires a C compiler'
    source = tmp_path / 'asan-control.c'
    binary = tmp_path / 'asan-control'
    source.write_text('int main(void) { return 0; }\n')
    built = run_trusted([compiler, '-fsanitize=address', str(source), '-o', str(binary)],
                        capture_output=True, text=True, timeout=30)
    assert built.returncode == 0, built.stderr
    result = run_untrusted([str(binary)], target=str(tmp_path), output=str(tmp_path / 'output'),
                           job_budget=budget, limits={'memory_mb': 0}, capture_output=True,
                           text=True, timeout=15, env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0'})
    assert result.returncode == 0, result.stderr
    assert result.sandbox_info['mount_ns_active'] is True
    assert result.sandbox_info['job_budget']['status'] == 'applied'
    assert result.sandbox_info['job_budget']['cleanup'] == 'complete'
