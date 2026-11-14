"""Private source setup projection; no product module imports."""
import argparse, ast, hashlib, json, sys, tempfile, unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
assert sys.flags.isolated and sys.flags.optimize == 0 and sys.dont_write_bytecode
HERE = Path(__file__).resolve().parent
CFG = {'source_sha256': '111c7309d0f51464cd0abcce65608d09c151817ef279ce8ea16c6134063dc389', 'setup_sha256': '0dccb660ccc577d5fea80747eba50917c77616b559e65122dd947b12d24e6c34', 'helper_sha256': {'_write': '09a1720d01ac9e58c0fee7e5091e358a743a13fa54ceb3bb4faac69e34bf88c8', '_analyze_row': '90625539bb288f31cd1c50b3a0d9f3808d21f2f1d4fa2f221d76be3fae5f8444'}}
parser=argparse.ArgumentParser()
parser.add_argument('root',type=Path)
parser.add_argument('mode',choices=('error','healthy'))
parser.add_argument('output',type=Path)
a=parser.parse_args()
attempts=[]
def audit(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.dlopen','ctypes.dlsym')) or event in {'os.system','os.fork','os.forkpty','os.posix_spawn','os.exec','_posixsubprocess.fork_exec'} or (event=='import' and args and str(args[0]).split('.')[0] in {'core','packages'}):
        attempts.append(event)
        raise PermissionError('outside private resume seed fixture ownership boundary: '+event)
sys.addaudithook(audit)
source=a.root/'packages/openant/tests/test_resume.py';raw=source.read_bytes()
assert hashlib.sha256(raw).hexdigest()==CFG['source_sha256']
text=raw.decode();cl=next(n for n in ast.parse(text).body if isinstance(n,ast.ClassDef) and n.name=='TestSeedScanDir')
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
        temporary=tempfile.TemporaryDirectory(dir=work,prefix='owned-resume-seed-')
        owned.append(temporary);rescue.callback(temporary.cleanup)
        return temporary
    def path_after_effect(value):
        assert len(owned)==1 and value==owned[0].name and not path_calls
        actual=Path(value);assert actual.is_dir();path_calls.append(str(actual))
        if a.mode=='error': raise primary
        return actual
    helpers=[n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name in {'_write','_analyze_row'}]
    assert len(helpers)==2
    for helper in helpers:
        assert not helper.decorator_list and not helper.args.defaults
        assert hashlib.sha256(ast.get_source_segment(text,helper).encode()).hexdigest()==CFG['helper_sha256'][helper.name]
    namespace={'Path':Path,'json':json}
    exec(compile(ast.Module(body=helpers,type_ignores=[]),str(source),'exec'),namespace)
    namespace.update(Path=path_after_effect,tempfile=SimpleNamespace(TemporaryDirectory=allocate))
    exec(compile(ast.Module(body=[setup],type_ignores=[]),str(source),'exec'),namespace)
    def body(self):
        body_calls.append(True)
        assert a.mode=='healthy' and self.base.is_dir() and self.prior.is_dir()
        files=[q for q in self.base.rglob('*') if q.is_file()]
        directories=[q for q in self.base.rglob('*') if q.is_dir()]
        assert len(files)==12 and len(directories)==5
        assert sum(q.stat().st_size for q in files)<=4096
        assert json.loads((self.prior/'dataset.json').read_text())=={'units':[]}
        assert json.loads((self.prior/'analyze_checkpoints/u.json').read_text())=={'id':'a','result':{'verdict':'SAFE','finding':'safe'}}
        assert (self.prior/'openant.stderr.log').read_text()=='noise'
        assert json.loads((self.prior/'openant-xdg/openant/config.json').read_text())=={'secret':True}

    def teardown(self):
        teardown_calls.append(True);unittest.TestCase.tearDown(self)
    class Result(unittest.TestResult):
        def addError(self,test,info):
            self.observed_primary=info[1];super().addError(test,info)
    case_type=type('OwnedResumeSeedSetupProjection',(unittest.TestCase,),{'setUp':namespace['setUp'],'tearDown':teardown,'runTest':body})
    case=case_type('runTest');rescue.callback(case.doCleanups);result=Result();case.run(result)
    failed=a.mode=='error'
    assert len(owned)==len(path_calls)==1 and len(result.errors)==int(failed) and not result.failures
    assert (result.observed_primary is primary) if failed else not hasattr(result,'observed_primary')
    assert len(body_calls)==len(teardown_calls)==int(not failed) and not attempts
    assert not Path(owned[0].name).exists(), 'directory must retire before independent rescue'
    assert hasattr(case,'prior') is (not failed)
    record={'mode':a.mode,'primary_identity':True if failed else None,'directory_present_before_rescue':False,'unittest_errors':len(result.errors),'path_effect_calls':len(path_calls),'body_calls':len(body_calls),'teardown_calls':len(teardown_calls),'forbidden_attempts':attempts,'scope':'Private actual setup/helper source and actual unittest runner; ordinary OSError/inert healthy fixture12files5dirs only; no normal module/class import equivalence, original resume/native/provider/CLI bodies or KBI cleanup proof.'}

assert record is not None and not attempts and not list(work.iterdir())
a.output.write_text(json.dumps(record,indent=2)+'\n')
