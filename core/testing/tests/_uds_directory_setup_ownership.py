import argparse, ast, hashlib, json, os, shutil, sys, tempfile
from pathlib import Path
from types import SimpleNamespace
parser=argparse.ArgumentParser()
parser.add_argument('root',type=Path)
parser.add_argument('scenario',choices=('error','interrupt','success'))
parser.add_argument('expect',choices=('candidate',))
parser.add_argument('output',type=Path)
a=parser.parse_args();attempts=[]
def audit(event, values):
    if event.startswith(('subprocess.','socket.','ctypes.dlopen','ctypes.dlsym')) or event in {'os.system','os.fork','os.forkpty','os.posix_spawn','os.exec','pty.spawn'}:
        attempts.append(event);raise PermissionError(event)
sys.addaudithook(audit)
p=a.root/'packages/joern/tests/test_netns_forwarder.py';b=p.read_bytes()
assert hashlib.sha256(b).hexdigest()=='1885372508e8638d7f65a8d1075e492efde5f52873a56feeaa01adbf24220d09'
m=next(n for n in ast.parse(b).body if isinstance(n,ast.FunctionDef) and n.name=='uds_dir')
assert len(m.decorator_list)==1;m.decorator_list=[]
owned=[];removed=[];modes=[];requested=[]
primary=KeyboardInterrupt('owned directory mode interruption') if a.scenario=='interrupt' else OSError('owned directory mode refusal')
def allocate(*args,**kwargs):
    assert not args and kwargs.get('prefix')=='raptor-joern-uds-test-'
    assert set(kwargs)<= {'prefix','dir'} and kwargs.get('dir') in (None,'/tmp') and len(owned)<2
    name=tempfile.mkdtemp(**kwargs);owned.append(Path(name));requested.append(kwargs.get('dir'))
    return name
def remove(path,ignore_errors=False):
    assert Path(path) in owned
    shutil.rmtree(path,ignore_errors=ignore_errors);removed.append(str(path))
def chmod(path,mode):
    assert Path(path)==owned[-1] and mode==0o700 and not modes
    os.chmod(path,mode);modes.append(mode)
    if a.scenario!='success':raise primary
ns={'tempfile':SimpleNamespace(mkdtemp=allocate),'os':SimpleNamespace(fsencode=os.fsencode,path=os.path,chmod=chmod),'shutil':SimpleNamespace(rmtree=remove)}
exec(compile(ast.Module(body=[m],type_ignores=[]),str(p),'exec'),ns)
generator=ns['uds_dir']();caught=None;result=None;yielded=None
try:
    try:yielded=next(generator)
    except BaseException as e:caught=e
    assert len(owned) in (1,2) and len(modes)==1
    assert len(os.fsencode(os.path.join(str(owned[0]),'joern.sock')))>107
    assert len(owned)==2 and requested==[None,'/tmp']
    assert not owned[0].exists()
    if a.scenario=='success':
        assert caught is None and Path(yielded)==owned[-1] and owned[-1].is_dir()
        generator.close()
    else:assert caught is primary
    remaining=owned[-1].exists()
    assert remaining is (a.expect=='baseline' and a.scenario!='success')
    assert not attempts
    result={'scenario':a.scenario,'expect':a.expect,'primary_identity':caught is primary if caught else None,'selected_directory_remaining_before_rescue':remaining,'allocation_count':len(owned),'requested_directory_arguments':requested,'first_long_directory_removed':not owned[0].exists(),'cleanup_calls':len(removed),'mode_effects':modes,'success_yield_then_close':a.scenario=='success','forbidden_attempts':attempts}
finally:
    generator.close()
    for path in owned:
        if path.exists():shutil.rmtree(path)
assert result is not None and not attempts
a.output.write_text(json.dumps(result,indent=2)+'\n')
