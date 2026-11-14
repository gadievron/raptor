import __future__
import argparse, ast, builtins, hashlib, json, shutil, sys, tempfile
from pathlib import Path
from types import SimpleNamespace
parser=argparse.ArgumentParser()
parser.add_argument('root',type=Path)
parser.add_argument('site',choices=('ffuf','nuclei'))
parser.add_argument('scenario',choices=('error','interrupt','success'))
parser.add_argument('expect',choices=('candidate',))
parser.add_argument('output',type=Path)
a=parser.parse_args();attempts=[]
def audit(event, values):
    if event.startswith(('subprocess.','socket.','ctypes.dlopen','ctypes.dlsym')) or event in {'os.system','os.fork','os.forkpty','os.posix_spawn','os.exec','pty.spawn'}:
        attempts.append(event);raise PermissionError(event)
sys.addaudithook(audit)
pins={'packages/web/tests/test_ffuf_live.py': '09fb3fdc5ae03dd8bd47fdf1881aa9754345f5105b57fd084784bfe4bd55736d', 'packages/web/tests/test_nuclei_live.py': '32ec449bad2ed8827453757b520ca5c354014f0d1c73cc9baf97654771f8b686'}
rel='packages/web/tests/test_'+a.site+'_live.py';p=a.root/rel;b=p.read_bytes()
assert hashlib.sha256(b).hexdigest()==pins[rel]
m=next(n for n in ast.parse(b).body if isinstance(n,ast.FunctionDef) and n.name=='direct_'+a.site)
assert len(m.decorator_list)==1;m.decorator_list=[]
owned=[];removed=[];published=[]
primary=KeyboardInterrupt('owned runner publication interruption') if a.scenario=='interrupt' else OSError('owned runner publication refusal')
def allocate(*args,**kwargs):
    assert not owned
    name=tempfile.mkdtemp(*args,**kwargs);owned.append(Path(name));return name
def remove(path,ignore_errors=False):
    assert len(owned)==1 and Path(path)==owned[0]
    shutil.rmtree(path,ignore_errors=ignore_errors);removed.append(str(path))
def importing(name,globals=None,locals=None,fromlist=(),level=0):
    if name=='tempfile':return SimpleNamespace(mkdtemp=allocate)
    if name=='shutil':return SimpleNamespace(rmtree=remove)
    raise AssertionError('unexpected selected fixture import '+name)
class Publisher:
    def setattr(self,target,callback):
        expected='packages.web.ffuf.run_untrusted_networked' if a.site=='ffuf' else 'packages.web.external_validators.run_untrusted_networked'
        assert target==expected and callable(callback) and len(owned)==1 and owned[0].is_dir()
        if a.scenario!='success':raise primary
        published.append(callback)
ns={'__builtins__':{**vars(builtins),'__import__':importing},'shutil':SimpleNamespace(rmtree=remove)}
# Future annotations retain original parameter/type annotations without importing pytest or packages.
module=ast.Module(body=[m],type_ignores=[])
ast.fix_missing_locations(module)
exec(compile(module,str(p),'exec',flags=__future__.annotations.compiler_flag),ns)
generator=ns[m.name](Publisher());caught=None;result=None;yielded=None
try:
    try:yielded=next(generator)
    except BaseException as e:caught=e
    assert len(owned)==1
    if a.scenario=='success':
        assert caught is None and yielded=={} and len(published)==1 and owned[0].is_dir()
        generator.close()
    else:assert caught is primary and not published
    remaining=owned[0].exists()
    assert remaining is (a.expect=='baseline' and a.scenario!='success')
    assert not attempts
    result={'site':a.site,'scenario':a.scenario,'expect':a.expect,'primary_identity':caught is primary if caught else None,'home_remaining_before_rescue':remaining,'cleanup_calls':len(removed),'successful_publication_then_close':a.scenario=='success','runner_body_calls':0,'forbidden_attempts':attempts}
finally:
    generator.close()
    for path in owned:
        if path.exists():shutil.rmtree(path)
assert result is not None and not attempts
a.output.write_text(json.dumps(result,indent=2)+'\n')
