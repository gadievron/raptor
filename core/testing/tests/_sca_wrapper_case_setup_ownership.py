# SOURCE-ONLY draft. No normal product imports or original test bodies.
import argparse, ast, hashlib, json, sys, tempfile, unittest
from pathlib import Path
assert sys.flags.isolated and sys.flags.optimize == 0 and sys.dont_write_bytecode
parser=argparse.ArgumentParser()
parser.add_argument('root',type=Path)
parser.add_argument('mode',choices=('error','healthy'))
parser.add_argument('output',type=Path)
a=parser.parse_args()
attempts=[]
def audit(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.dlopen','ctypes.dlsym')) or event in {'os.system','os.fork','os.forkpty','os.posix_spawn','os.exec'} or (event=='import' and args and str(args[0]).split('.')[0] in {'core','packages'}):
        attempts.append(event)
        raise PermissionError('outside private unittest setup boundary: '+event)
sys.addaudithook(audit)
source=a.root/'packages/sca/tests/test_raptor_sca_run.py'
raw=source.read_bytes()
assert hashlib.sha256(raw).hexdigest()=='a15eddf239dc510b2f2b7950eb5cd64fe76f7eab01a1173a553722d0cce89b86'
text=raw.decode()
cl=next(n for n in ast.parse(text).body if isinstance(n,ast.ClassDef) and n.name=='RaptorScaRunWrapperTests')
assert [ast.unparse(b) for b in cl.bases]==['unittest.TestCase'] and not cl.decorator_list
methods=[n for n in cl.body if isinstance(n,ast.FunctionDef) and n.name in {'setUp','tearDown'}]
assert len(methods)==2
for method in methods:
    assert hashlib.sha256(ast.get_source_segment(text,method).encode()).hexdigest()=={'setUp': '0e17aa8d9c952064c2ff0100aa5d2e2e2f28dfa9aebfbbb5e3885c2044e3cf8c', 'tearDown': 'd48fa7d5f9eabb259197616c083eb62d00c5a303eddc154a3037dc0f957639a5'}[method.name]
    assert not method.decorator_list and not method.args.defaults
work=a.output.parent/'owned-work'
work.mkdir(mode=0o700)
owned=[];path_calls=[];body_calls=[];teardown_calls=[]
primary=OSError('controlled ordinary setup failure after real Path construction')
def allocate():
    assert not owned
    temporary=tempfile.TemporaryDirectory(dir=work,prefix='owned-sca-wrapper-case-')
    owned.append(temporary)
    return temporary
def path_after_effect(value):
    assert len(owned)==1 and value==owned[0].name and not path_calls
    actual=Path(value)
    assert actual.is_dir()
    path_calls.append(str(actual))
    if a.mode=='error':raise primary
    return actual
namespace={'Path':path_after_effect,'TemporaryDirectory':allocate}
exec(compile(ast.Module(body=methods,type_ignores=[]),str(source),'exec'),namespace)
def teardown(self):
    teardown_calls.append(True)
    namespace['tearDown'](self)
def body(self):
    body_calls.append(True)
    assert a.mode=='healthy'
    assert self.scratch.is_dir()
class Result(unittest.TestResult):
    def addError(self,test,info):
        self.observed_primary=info[1]
        super().addError(test,info)
case_class=type('OwnedScaWrapperSetupProjection',(unittest.TestCase,),{'setUp':namespace['setUp'],'tearDown':teardown,'runTest':body})
case=case_class('runTest');result=Result();record=None
try:
    case.run(result)
    assert len(owned)==len(path_calls)==1 and not attempts
    failed=a.mode=='error'
    assert len(result.errors)==int(failed)
    assert (result.observed_primary is primary) if failed else not hasattr(result,'observed_primary')
    assert len(body_calls)==len(teardown_calls)==int(not failed)
    directory=Path(owned[0].name)
    assert not directory.exists(), 'candidate must retire directory before independent rescue'
    record={'mode':a.mode,'primary_identity':result.observed_primary is primary if failed else None,'directory_present_before_rescue':False,'teardown_calls':len(teardown_calls),'body_calls':len(body_calls),'unittest_errors':len(result.errors),'path_effect_calls':len(path_calls),'forbidden_attempts':attempts,'scope':'Private source setup/teardown methods using actual unittest runner; inert healthy body only, no normal product imports/original testbody/KBI cleanup claim.'}

finally:
    case.doCleanups()
    for temporary in owned:temporary.cleanup()
assert record is not None and not attempts
assert not list(work.iterdir())
a.output.write_text(json.dumps(record,indent=2)+'\n')
