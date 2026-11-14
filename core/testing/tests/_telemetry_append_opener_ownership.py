"""Check the private telemetry stream-construction prefix, without campaigns."""
import __future__, argparse, ast, copy, errno, hashlib, json, logging, os, stat, sys, threading, time
from pathlib import Path
from types import ModuleType, SimpleNamespace
from contextlib import ExitStack
assert sys.flags.isolated and sys.flags.optimize == 0 and sys.dont_write_bytecode
CFG = {'source_pins': {'packages/fuzzing/telemetry.py': '12f53d3095eb4b1971939681425c4620c6e8ac87db567f7f1d06fecbd5823702', 'core/atomic_fs/__init__.py': '1321d4a8a54c21fbb7c6a50778c3ce6e14c7c753385b40a3cfdf228b5039650a', 'packages/fuzzing/tests/test_telemetry_start_ownership.py': 'f7346527d4cdfd5fa7753f75b1d6f168d9f6c9f7bc2ffe79f1c23cd97d2e6a33'}, 'helper_sha256': {'_validate_mode': '1e3b4225f23e0848600357491898d8a436719b8547c9affd8a32abb9469d1493', '_close_write_fd': '928a9f8634b2ed595792508ca66d6f756be669ae45a0df7dfddccd63ebcdd96a', 'open_hardened_append': '12604f1fb1b56a5acf1abed5fff45e37cf0719f8402d091d3782fd8ee8f1b94c'}, 'start_sha256': '4a6c206cf9134b442bed0f4ee9c0dc1beb66d34afad5ed2e86c650d2b1f17b48', 'startup_fixture_sha256': '0e4461e9bc8c7d0819855f7c3b81b2021a533cd9a8b325f4932b3acfdd169eac'}
parser=argparse.ArgumentParser()
parser.add_argument('root',type=Path)
parser.add_argument('mode',choices=('error','healthy'))
parser.add_argument('output',type=Path)
a=parser.parse_args();root=a.root
texts={}
for name,digest in CFG['source_pins'].items():
    raw=(root/name).read_bytes();assert hashlib.sha256(raw).hexdigest()==digest;texts[name]=raw.decode()
tt=texts['packages/fuzzing/telemetry.py'];at=texts['core/atomic_fs/__init__.py']
cl=next(n for n in ast.parse(tt).body if isinstance(n,ast.ClassDef) and n.name=='FuzzingTelemetry')
start=next(n for n in cl.body if isinstance(n,ast.FunctionDef) and n.name=='start')
assert hashlib.sha256(ast.get_source_segment(tt,start).encode()).hexdigest()==CFG['start_sha256']
assert len(start.body)==1 and isinstance(start.body[0],ast.With)
assert len(start.body[0].body)==4 and isinstance(start.body[0].body[-1],ast.Try)
prefix=copy.deepcopy(start);prefix.body[0].body=prefix.body[0].body[:-1]
functions=[n for n in ast.parse(at).body if isinstance(n,ast.FunctionDef) and n.name in CFG['helper_sha256']]
assert len(functions)==3
for n in functions:assert hashlib.sha256(ast.get_source_segment(at,n).encode()).hexdigest()==CFG['helper_sha256'][n.name]
constants=[n for n in ast.parse(at).body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id in {'_MODE_MASK','_O_NOFOLLOW','_O_CLOEXEC','_O_NONBLOCK'}]
assert len(constants)==4
namespace={'os':os,'_stat':stat,'logging':logging,'Path':Path,'__name__':'_owned_atomic_declarations'}
exec(compile(ast.Module(body=constants+functions,type_ignores=[]),str(root/'core/atomic_fs/__init__.py'),'exec',flags=__future__.annotations.compiler_flag,dont_inherit=True),namespace)
work=a.output.parent/'owned-work';work.mkdir(mode=0o700);trail=work/'fuzz-events.jsonl'
owned=[];attempts=[];events=[]
primary=OSError('controlled path stream audit refusal before opener allocation')
def open_owned(path):
    assert path==str(trail) and not owned
    fd=namespace['open_hardened_append'](path);owned.append((fd,os.fstat(fd)))
    return fd
consumer=ModuleType('_owned_telemetry_construction_prefix')
original_logger=SimpleNamespace(info=lambda *args,**kwargs:None,debug=lambda *args,**kwargs:None)
consumer.__dict__.update(time=time,open_hardened_append=open_owned,logger=original_logger)
exec(compile(ast.Module(body=[prefix],type_ignores=[]),str(root/'packages/fuzzing/telemetry.py'),'exec',flags=__future__.annotations.compiler_flag,dont_inherit=True),consumer.__dict__)
prefix_fn=consumer.start
subject=SimpleNamespace(_lock=threading.Lock(),stats=SimpleNamespace(),events_path=trail,_events_fp=None)
constructor_calls=[]
def constructor(out_dir,*,fuzzer,on_event):
    assert out_dir==work and fuzzer=='inert' and not constructor_calls
    constructor_calls.append(True);subject.on_event=on_event
    return subject
fixture_text=texts['packages/fuzzing/tests/test_telemetry_start_ownership.py']
fixture_node=next(n for n in ast.parse(fixture_text).body if isinstance(n,ast.FunctionDef) and n.name=='startup_io')
assert hashlib.sha256(ast.get_source_segment(fixture_text,fixture_node).encode()).hexdigest()==CFG['startup_fixture_sha256']
assert [ast.unparse(n) for n in fixture_node.decorator_list]==['pytest.fixture']
fixture_node=copy.deepcopy(fixture_node);fixture_node.decorator_list=[]
fixture_namespace={'consumer':consumer,'FuzzingTelemetry':constructor,'SimpleNamespace':SimpleNamespace}
exec(compile(ast.Module(body=[fixture_node],type_ignores=[]),str(root/'packages/fuzzing/tests/test_telemetry_start_ownership.py'),'exec'),fixture_namespace)
bindings=ExitStack()
class OwnedBindings:
    def setattr(self,target,name,value,raising=True):
        assert target is consumer and name in {'open','logger'}
        present=name in vars(target);old=vars(target).get(name)
        if raising and not present:raise AttributeError(name)
        def restore():
            assert vars(target).get(name) is value
            if present:setattr(target,name,old)
            else:delattr(target,name)
        bindings.callback(restore)
        setattr(target,name,value)
fixture=fixture_namespace['startup_io'](work,OwnedBindings())
state=next(fixture)
assert state['telemetry'] is subject and len(constructor_calls)==1
stream_factory=consumer.open
expected_flags=os.O_WRONLY|os.O_CREAT|os.O_APPEND|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0)|getattr(os,'O_NONBLOCK',0)
def audit(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.dlopen','ctypes.dlsym')) or event in {'os.system','os.fork','os.forkpty','os.posix_spawn','os.exec','_posixsubprocess.fork_exec'} or (event=='import' and args and str(args[0]).split('.')[0] in {'core','packages'}):
        attempts.append(event);raise PermissionError('outside owned stream construction prefix')
    if event=='open' and args[0]==str(trail):
        if args[1]=='a':
            frame=sys._getframe(1)
            assert frame.f_code is stream_factory.__code__ and frame.f_back.f_code is prefix_fn.__code__
            assert not owned and not events
            events.append('path_stream_open')
            if a.mode=='error':raise primary
        elif args[1] is None:
            assert a.mode=='healthy' and not owned and events==['path_stream_open'] and args[2]==expected_flags
            events.append('owned_hardened_path_open')
        else:
            assert a.mode=='healthy' and args[1] in {'r','rb'} and len(owned)==1
sys.addaudithook(audit)
record=None
try:
    if a.mode=='error':
        try:prefix_fn(subject)
        except OSError as actual:assert actual is primary
        else:raise AssertionError('controlled early refusal missing')
        assert not owned and not trail.exists() and subject._events_fp is None
        assert events==['path_stream_open'] and state['native'] is None and state['closes']==0
        closed=None
    else:
        prefix_fn(subject)
        assert len(owned)==1 and events==['path_stream_open','owned_hardened_path_open']
        stream=subject._events_fp;fd,opened=owned[0];current=os.fstat(fd)
        assert state['native'] is not None and state['native'].fileno()==fd
        assert stream.fileno()==fd and not stream.closed and stat.S_ISREG(current.st_mode)
        assert (current.st_dev,current.st_ino)==(opened.st_dev,opened.st_ino)
        assert stream.write('owned-probe\n')==12
        stream.flush();assert trail.read_bytes()==b'owned-probe\n'
        stream.close();assert stream.closed and state['closes']==1
        try:os.fstat(fd)
        except OSError as error:assert error.errno==errno.EBADF
        else:raise AssertionError('owned stream failed to close its descriptor')
        closed=True
    assert not subject._lock.locked() and not attempts
    record={'mode':a.mode,'primary_identity':True if a.mode=='error' else None,'allocation_calls':len(owned),'fixture_wrapper_closes':state['closes'],'constructor_seam_calls':len(constructor_calls),'stream_closed_before_rescue':closed,'events':events,'forbidden_attempts':attempts,'scope':'Exact private stream-construction prefix only. Error is early path-audit refusal with zero allocation, not matched postallocation cleanup; healthy actualhardenedopener+ownedstreamwriteclose. No productmodule/campaign/target/provider/nativeutility/eventbody/KBI or later constructionfailure proof.'}
finally:
    fixture.close()
    bindings.close()
    # Never close an unverified numeric descriptor on unexpected failure.
    # Bounded child retirement owns any pre-assignment process resource.
    trail.unlink(missing_ok=True)
assert record is not None and not attempts and not list(work.iterdir())
assert 'open' not in vars(consumer) and consumer.logger is original_logger and subject._events_fp is None
record['fixture_bindings_restored']=True
a.output.write_text(json.dumps(record,indent=2)+'\n')
