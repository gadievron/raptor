import argparse, ast, hashlib, json, shutil, sys, tempfile
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
p=a.root/'core/audit/tests/test_dark_verify.py';b=p.read_bytes()
assert hashlib.sha256(b).hexdigest()=='9f34c616819c50c0bb7a1b59102c88bd970254a20230c39cb7e3b83f3d15e83f'
cls=next(c for c in ast.parse(b).body if isinstance(c,ast.ClassDef) and c.name=='TestSandboxedCompileWriteGrants')
m=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='dirs')
assert len(m.decorator_list)==1 and isinstance(m.body[0],ast.ImportFrom)
m.decorator_list=[];m.body=m.body[1:]
owned=[];removed=[];mkdirs=[]
primary=KeyboardInterrupt('owned target setup interruption') if a.scenario=='interrupt' else OSError('owned target setup refusal')
outer=Path(tempfile.mkdtemp(prefix='owned-compile-fixture-'))
class OwnedPath(type(Path())):
    def mkdir(self,*args,**kwargs):
        assert Path(self)==outer/'target'
        Path.mkdir(self,*args,**kwargs);mkdirs.append(str(self))
        if a.scenario!='success':raise primary
def allocate(*args,**kwargs):
    assert not owned and Path(kwargs['dir'])==outer
    name=tempfile.mkdtemp(*args,**kwargs);owned.append(Path(name));return name
def remove(path,ignore_errors=False):
    assert len(owned)==1 and Path(path)==owned[0]
    shutil.rmtree(path,ignore_errors=ignore_errors);removed.append(str(path))
ns={'Path':OwnedPath,'tempfile':SimpleNamespace(mkdtemp=allocate),'exec_workdir':lambda:outer,'shutil':SimpleNamespace(rmtree=remove)}
exec(compile(ast.Module(body=[m],type_ignores=[]),str(p),'exec'),ns)
generator=ns['dirs'](None,OwnedPath(outer));caught=None;result=None;yielded=None
try:
    try: yielded=next(generator)
    except BaseException as e:caught=e
    assert len(owned)==len(mkdirs)==1
    if a.scenario=='success':
        assert caught is None and len(yielded)==2 and Path(yielded[0])==owned[0]
        assert owned[0].is_dir() and (outer/'target/src.c').read_text()=='int x;\n'
        generator.close()
    else:assert caught is primary
    remaining=owned[0].exists()
    assert remaining is (a.expect=='baseline' and a.scenario!='success')
    assert not attempts
    result={'scenario':a.scenario,'expect':a.expect,'primary_identity':caught is primary if caught else None,'work_directory_remaining_before_rescue':remaining,'cleanup_calls':len(removed),'successful_yield_then_close':a.scenario=='success','forbidden_attempts':attempts}
finally:
    generator.close()
    shutil.rmtree(outer)
assert result is not None and not attempts
a.output.write_text(json.dumps(result,indent=2)+'\n')
