"""Private source setup projection; no product module imports."""
import argparse, ast, hashlib, json, sys, tempfile, unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
assert sys.flags.isolated and sys.flags.optimize == 0 and sys.dont_write_bytecode
HERE = Path(__file__).resolve().parent
CFG = {'source_sha256': '46a91525dea7db9fa63b981d9701aa1fc6491c2f67b0c55dfc10e08a6e9195ed', 'setup_sha256': 'a97c8a823648059d9cdd44ec2a67b10e56693782e5cf2f34ec3aec905718fc3e'}
parser=argparse.ArgumentParser()
parser.add_argument('root',type=Path)
parser.add_argument('mode',choices=('error','healthy'))
parser.add_argument('output',type=Path)
a=parser.parse_args()
attempts=[]
def audit(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.dlopen','ctypes.dlsym')) or event in {'os.system','os.fork','os.forkpty','os.posix_spawn','os.exec','_posixsubprocess.fork_exec'} or (event=='import' and args and str(args[0]).split('.')[0] in {'core','packages'}):
        attempts.append(event)
        raise PermissionError('outside private resume fixture ownership boundary: '+event)
sys.addaudithook(audit)
source=a.root/'packages/openant/tests/test_resume.py';raw=source.read_bytes()
assert hashlib.sha256(raw).hexdigest()==CFG['source_sha256']
text=raw.decode();cl=next(n for n in ast.parse(text).body if isinstance(n,ast.ClassDef) and n.name=='TestRebaseGatewayFingerprints')
assert [ast.unparse(n) for n in cl.bases]==['unittest.TestCase'] and not cl.decorator_list
assert not any(isinstance(n,ast.FunctionDef) and n.name=='tearDown' for n in cl.body)
setup=next(n for n in cl.body if isinstance(n,ast.FunctionDef) and n.name=='setUp')
assert hashlib.sha256(ast.get_source_segment(text,setup).encode()).hexdigest()==CFG['setup_sha256']
assert not setup.decorator_list and not setup.args.defaults
work=a.output.parent/'owned-work';work.mkdir(mode=0o700)
owned=[];path_calls=[];body_calls=[];teardown_calls=[]
primary=OSError('controlled ordinary setup failure after real Path construction')
record=None
with ExitStack() as rescue:
    def allocate():
        assert not owned
        temporary=tempfile.TemporaryDirectory(dir=work,prefix='owned-resume-fingerprint-')
        owned.append(temporary);rescue.callback(temporary.cleanup)
        return temporary
    def path_after_effect(value):
        assert len(owned)==1 and value==owned[0].name and not path_calls
        actual=Path(value);assert actual.is_dir();path_calls.append(str(actual))
        if a.mode=='error': raise primary
        return actual
    namespace={'Path':path_after_effect,'tempfile':SimpleNamespace(TemporaryDirectory=allocate)}
    exec(compile(ast.Module(body=[setup],type_ignores=[]),str(source),'exec'),namespace)
    def body(self):
        body_calls.append(True)
        assert a.mode=='healthy' and self.scan.is_dir()
    def teardown(self):
        teardown_calls.append(True);unittest.TestCase.tearDown(self)
    class Result(unittest.TestResult):
        def addError(self,test,info):
            self.observed_primary=info[1];super().addError(test,info)
    case_type=type('OwnedResumeFingerprintSetupProjection',(unittest.TestCase,),{'setUp':namespace['setUp'],'tearDown':teardown,'runTest':body})
    case=case_type('runTest');rescue.callback(case.doCleanups);result=Result();case.run(result)
    failed=a.mode=='error'
    assert len(owned)==len(path_calls)==1 and len(result.errors)==int(failed) and not result.failures
    assert (result.observed_primary is primary) if failed else not hasattr(result,'observed_primary')
    assert len(body_calls)==len(teardown_calls)==int(not failed) and not attempts
    assert not Path(owned[0].name).exists(), 'directory must retire before independent rescue'
    record={'mode':a.mode,'primary_identity':True if failed else None,'directory_present_before_rescue':False,'unittest_errors':len(result.errors),'path_effect_calls':len(path_calls),'body_calls':len(body_calls),'teardown_calls':len(teardown_calls),'forbidden_attempts':attempts,'scope':'Private actual setup source and actual unittest runner; ordinary OSError and inert healthy body only; no normal module/class import equivalence, original resume/provider/native body or KBI cleanup proof.'}

assert record is not None and not attempts and not list(work.iterdir())
a.output.write_text(json.dumps(record,indent=2)+'\n')
