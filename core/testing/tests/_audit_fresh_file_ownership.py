import argparse, ast, hashlib, json, os, sys, tempfile
from pathlib import Path
from types import SimpleNamespace
parser=argparse.ArgumentParser()
parser.add_argument('root',type=Path)
parser.add_argument('scenario',choices=('error','interrupt','success'))
parser.add_argument('expect',choices=('candidate',))
parser.add_argument('output',type=Path)
a=parser.parse_args()
attempts=[]
def audit(event, values):
    if event.startswith(('subprocess.','socket.','ctypes.dlopen','ctypes.dlsym')) or event in {'os.system','os.fork','os.forkpty','os.posix_spawn','os.exec','pty.spawn'}:
        attempts.append(event)
        raise PermissionError(event)
sys.addaudithook(audit)
p=a.root/'core/sandbox/tests/test_audit_failure_modes.py'
b=p.read_bytes()
assert hashlib.sha256(b).hexdigest() == 'ff43544d61cc07bdf91a5815681e141d2ff2c32a5f174d5ab06af94c0e678a3e'
m=next(n for c in ast.parse(b).body if isinstance(c,ast.ClassDef) for n in c.body if isinstance(n,ast.FunctionDef) and n.name=='test_sweep_keeps_fresh_files')
assert isinstance(m.body[0],ast.Import) and isinstance(m.body[1],ast.ImportFrom)
# Exact allocation-through-cleanup suffix; original sandbox imports excluded.
m.body=m.body[2:]
assert not m.decorator_list
owned=[];closed=[];unlinks=[];writes=[];sweeps=[]
primary=KeyboardInterrupt('owned write interruption') if a.scenario=='interrupt' else OSError('owned write refusal')
def allocate(*args,**kwargs):
    assert not owned
    fd,name=tempfile.mkstemp(*args,**kwargs);owned.append((fd,Path(name)));return fd,name
def write(fd,data):
    assert fd==owned[0][0] and not writes
    n=os.write(fd,data);writes.append(n)
    if a.scenario!='success': raise primary
    return n
def close(fd):
    assert fd==owned[0][0] and not closed
    os.close(fd);closed.append(fd)
def unlink(path):
    assert Path(path)==owned[0][1]
    os.unlink(path);unlinks.append(str(path))
def observe_setup():
    assert closed and owned[0][1].read_bytes()==b'{}'
    sweeps.append('setup reached; real sweep excluded')
ns={'tempfile':SimpleNamespace(mkstemp=allocate,gettempdir=tempfile.gettempdir),'os':SimpleNamespace(write=write,close=close,unlink=unlink,path=os.path),'_sweep_stale_audit_configs':observe_setup}
exec(compile(ast.Module(body=[m],type_ignores=[]),str(p),'exec'),ns)
caught=None;result=None
try:
    try: ns[m.name](None)
    except BaseException as e: caught=e
    assert len(owned)==len(writes)==1
    path=owned[0][1]
    remaining=path.exists()
    fd_open=True
    try: os.fstat(owned[0][0])
    except OSError: fd_open=False
    if a.scenario=='success':
        assert caught is None and len(sweeps)==1 and not remaining and not fd_open
    else:
        assert caught is primary and not sweeps
        assert remaining is (a.expect=='baseline') and fd_open is (a.expect=='baseline')
    assert not attempts
    result={'scenario':a.scenario,'expect':a.expect,'primary_identity':caught is primary if caught else None,'path_remaining_before_rescue':remaining,'descriptor_open_before_rescue':fd_open,'descriptor_close_calls':len(closed),'unlink_calls':len(unlinks),'written_bytes':writes,'setup_observations':sweeps,'forbidden_attempts':attempts}
finally:
    for fd,path in owned:
        if fd not in closed: os.close(fd)
        if path.exists(): path.unlink()
assert result is not None and not attempts
a.output.write_text(json.dumps(result,indent=2)+'\n')
