"""Check independent caller join after a consumed holder-close failure."""
import __future__, argparse, ast, builtins, errno, hashlib, json, os, sys, threading
from contextlib import contextmanager, nullcontext
from pathlib import Path
from types import SimpleNamespace
assert sys.flags.isolated and sys.flags.optimize == 0 and sys.dont_write_bytecode
HERE=Path(__file__).resolve().parent
CFG={'source_sha256': '7579af8cdd8bf4c3f7aa41527b7f77c7d4ec4f3c627dd82de3f813ae4f2a2a46', 'function_sha256': 'cd374fcbf48b9aa19ddba69ad9e1e8e7d3ea3df3055c73b2e1a255523fbb5980'}
parser=argparse.ArgumentParser();parser.add_argument('root',type=Path);parser.add_argument('mode',choices=('error','interrupt'));parser.add_argument('output',type=Path)
a=parser.parse_args()
source=a.root/'core/run/tests/test_metadata_lock_bounded.py';raw=source.read_bytes();assert hashlib.sha256(raw).hexdigest()==CFG['source_sha256']
text=raw.decode();fn=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name=='test_wedged_holder_never_blocks_finalisers_unboundedly')
assert not fn.decorator_list and not fn.args.defaults
assert hashlib.sha256(ast.get_source_segment(text,fn).encode()).hexdigest()==CFG['function_sha256']
work=a.output.parent/'owned-work';work.mkdir(mode=0o700);lockpath=work/'.raptor-run.json.lock'
primary=RuntimeError('controlled after-effect Thread.start failure')
secondary=(OSError if a.mode=='error' else KeyboardInterrupt)('controlled after-effect holder close failure')
owned=[];workers=[];close_calls=[];join_calls=[];worker_errors=[];flock_calls=[];clock_calls=[];attempts=[]
entered=threading.Event();release=threading.Event();LOCK_EX=object();fs_lock=SimpleNamespace()
class AnnotationFileError(Exception):pass
class Patch:
    def setattr(self,obj,name,value,raising=True):
        assert obj is fs_lock and name in {'_ACQUIRE_DEADLINE_S','_ACQUIRE_POLL_S'} and raising is False
        setattr(obj,name,value)
def clock_factory(patch,obj):
    assert obj is fs_lock and not clock_calls;clock_calls.append(True)
    return SimpleNamespace(seconds=0,sleeps=[])
@contextmanager
def declared_file_lock(path):
    assert path==work/'.raptor-run.json'
    entered.set();assert release.wait(10), 'owned scheduling gate was not released'
    yield
class Worker(threading.Thread):
    def __init__(self,*args,**kwargs):
        assert not args and not workers and kwargs['daemon'] is True
        original=kwargs['target'];self.original_target=original
        def run_owned():
            try:original()
            except BaseException as error:worker_errors.append(error)
        kwargs['target']=run_owned;super().__init__(*args,**kwargs);workers.append(self)
    def start(self):
        threading.Thread.start(self)
        assert entered.wait(5) and self.is_alive()
        raise primary
    def join(self,*args,**kwargs):
        join_calls.append((args,kwargs));assert not args and kwargs=={'timeout':10}
        release.set()  # Declared scheduling fixture, not real flock release.
        return threading.Thread.join(self,*args,**kwargs)
def open_owned(path,flags,mode):
    assert path==str(lockpath) and flags==os.O_WRONLY|os.O_CREAT and mode==0o600 and not owned
    fd=os.open(path,flags,mode);owned.append((fd,os.fstat(fd)));return fd
def close_owned(fd):
    assert len(owned)==1 and fd==owned[0][0] and not close_calls
    current=os.fstat(fd);opened=owned[0][1]
    assert (current.st_dev,current.st_ino)==(opened.st_dev,opened.st_ino)
    os.close(fd);close_calls.append(fd)
    raise secondary
def record_flock(fd,operation):
    assert len(owned)==1 and fd==owned[0][0] and operation is LOCK_EX and not flock_calls
    flock_calls.append(True)  # Private imported seam; no fcntl or real lock.
def importing(name,globals=None,locals=None,fromlist=(),level=0):
    assert name=='fcntl' and level==0
    return SimpleNamespace(flock=record_flock,LOCK_EX=LOCK_EX)
private={'__builtins__':{**vars(builtins),'__import__':importing},'Path':Path,'os':SimpleNamespace(open=open_owned,close=close_owned,O_WRONLY=os.O_WRONLY,O_CREAT=os.O_CREAT),'threading':SimpleNamespace(Thread=Worker,Event=threading.Event),'fs_lock':fs_lock,'install_poll_clock':clock_factory,'_metadata_lock':declared_file_lock,'AnnotationFileError':AnnotationFileError}
exec(compile(ast.Module(body=[fn],type_ignores=[]),str(source),'exec',flags=__future__.annotations.compiler_flag,dont_inherit=True),private)
def audit(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.dlopen','ctypes.dlsym')) or event in {'os.system','os.fork','os.forkpty','os.posix_spawn','os.exec','_posixsubprocess.fork_exec'} or (event=='import' and args and str(args[0]).split('.')[0] in {'core','packages'}):
        attempts.append(event);raise PermissionError('outside owned caller cleanup witness')
sys.addaudithook(audit)
caplog=SimpleNamespace(at_level=lambda level:nullcontext(),records=[]);record=None
try:
    try:private[fn.name](work,Patch(),caplog)
    except BaseException as observed:
        assert observed is secondary and observed.__context__ is primary
    else:raise AssertionError('expected authoritative close exception absent')
    assert len(owned)==len(workers)==len(close_calls)==len(flock_calls)==len(clock_calls)==1
    assert len(join_calls)==1 and not workers[0].is_alive() and not worker_errors and not attempts
    try:os.fstat(owned[0][0])
    except OSError as error:assert error.errno==errno.EBADF
    else:raise AssertionError('after-effect close did not consume holder')
    record={'mode':a.mode,'close_secondary_identity':True,'start_primary_context_identity':True,'actual_close_calls':1,'caller_join_calls':len(join_calls),'worker_alive_before_rescue':False,'fd_closed_before_rescue':True,'forbidden_attempts':attempts,'scope':'Actual caller function with declared private lock/clock/import/scheduling seams; real ownedregularFD+Thread. Join releases declaredschedulinggate; not real lockrelease. Controlledaftereffectclose OSError/KeyboardInterrupt only; no FDretry/beforeeffect/native lock/fullmodule/universalKBI/originalprimaryprecedence restoration proof.'}
finally:
    release.set()
    for worker in workers:
        if worker.ident is not None:
            threading.Thread.join(worker,timeout=5)
            assert not worker.is_alive(), 'owned worker survived independent rescue'
    # Do not retry numeric descriptor close after unknown consumption.
    # Any unexpected pre-close failure is bounded by child retirement.
    lockpath.unlink(missing_ok=True)
assert record is not None and not worker_errors and not attempts and not list(work.iterdir())
record['independent_worker_rescue_complete']=True
a.output.write_text(json.dumps(record,indent=2)+'\n')
