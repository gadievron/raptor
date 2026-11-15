"""Coverage callers join owned workers after a consumed holder-close fault."""
import __future__, argparse, ast, builtins, errno, hashlib, json, os, sys, threading
from contextlib import ExitStack, contextmanager, nullcontext
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType, SimpleNamespace
assert sys.flags.isolated and sys.flags.optimize==0 and sys.dont_write_bytecode
HERE=Path(__file__).resolve().parent
CFG={'source_sha256': '61238797c0d08a98ba1c646a4392ee7ceba60a66e746332c335bd737b1de8f9f', 'function_names': {'store': 'test_store_lock_degrades_after_bounded_wait', 'journal': 'test_journal_append_fails_loudly_after_bounded_wait'}, 'function_sha256': {'store': 'abb8b44d335a38f0d57df8a839e30cc76978c53b2185298e236955761ec94215', 'journal': 'a695f784773b4d70a414412162bcae31f3db6d0f0abde9f9419eb6e5aaf30fcd'}, 'journal_source_sha256': '95828d362fb2d851d0da489023214072b1ce0420b6f0b0aa7d50908033ba842e', 'journal_class_sha256': 'cd0776b50036b6ddc4164d51ebb283bc0a68661fac5a145fcc0599fd58031aef', 'journal_now_iso_sha256': '8f753969d29c626c25cced7f5cec130ef1df2f7a00e144cd4f84fd5e1e733456', 'schema_source_sha256': '8fb29803d3d131301db2bbe72bbaab5314981664272c6a9d57f2a75684ae1811', 'entry_builder_sha256': '057af476c31e83330f0ce3fce18b292db6223fc0e12e0c42fcfbb6a041af70cf'}
parser=argparse.ArgumentParser();parser.add_argument('root',type=Path);parser.add_argument('case',choices=('store','journal'));parser.add_argument('mode',choices=('error','interrupt'));parser.add_argument('output',type=Path)
a=parser.parse_args()
source=a.root/'core/coverage/tests/test_lock_bounded.py';raw=source.read_bytes();assert hashlib.sha256(raw).hexdigest()==CFG['source_sha256']
text=raw.decode();tree=ast.parse(text);fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name==CFG['function_names'][a.case])
assert not fn.decorator_list and not fn.args.defaults
assert hashlib.sha256(ast.get_source_segment(text,fn).encode()).hexdigest()==CFG['function_sha256'][a.case]
work=a.output.parent/'owned-work';work.mkdir(mode=0o700)
holder=work/('coverage.json.lock' if a.case=='store' else 'review-journal.jsonl')
owned=[];workers=[];closes=[];joins=[];worker_errors=[];flocks=[];clocks=[];entries=[];append_calls=[];initial_streams=[];attempts=[]
entered=threading.Event();release=threading.Event();LOCK_EX=object();fs_lock=SimpleNamespace()
primary=RuntimeError('controlled after-effect Thread.start failure');secondary=(OSError if a.mode=='error' else KeyboardInterrupt)('controlled after-effect holder close failure')
def audit(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.dlopen','ctypes.dlsym')) or event in {'os.system','os.fork','os.forkpty','os.posix_spawn','os.exec','_posixsubprocess.fork_exec'} or (event=='import' and args and str(args[0]).split('.')[0] in {'core','packages'}):
        attempts.append(event);raise PermissionError('outside owned coverage caller witness')
sys.addaudithook(audit)
module_name='_owned_coverage_entry_data';assert module_name not in sys.modules
record=None
with ExitStack() as rescue:
    data=None
    if a.case=='journal':
        jf=a.root/'core/coverage/journal.py';jraw=jf.read_bytes();assert hashlib.sha256(jraw).hexdigest()==CFG['journal_source_sha256']
        jt=jraw.decode();jtree=ast.parse(jt)
        schema=next(n for n in jtree.body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='SCHEMA_VERSION')
        cl=next(n for n in jtree.body if isinstance(n,ast.ClassDef) and n.name=='ReviewJournalEntry')
        now=next(n for n in jtree.body if isinstance(n,ast.FunctionDef) and n.name=='now_iso')
        builder=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='_entry')
        for node,pin,src in [(schema,'schema_source_sha256',jt),(cl,'journal_class_sha256',jt),(now,'journal_now_iso_sha256',jt),(builder,'entry_builder_sha256',text)]:
            assert hashlib.sha256(ast.get_source_segment(src,node).encode()).hexdigest()==CFG[pin]
        assert ast.literal_eval(schema.value)==1 and not cl.bases and not cl.keywords
        assert [ast.unparse(d) for d in cl.decorator_list]==['dataclass']
        fields=[n for n in cl.body if isinstance(n,ast.AnnAssign)];assert len(fields)==56
        factories=[];schema_defaults=[]
        for node in cl.body:
            assert isinstance(node,(ast.Expr,ast.AnnAssign,ast.FunctionDef))
            if isinstance(node,ast.Expr):assert isinstance(node.value,ast.Constant) and isinstance(node.value.value,str)
            if isinstance(node,ast.FunctionDef):
                assert node.name in {'key','index_key','to_dict'} and not node.args.defaults
                assert all(ast.unparse(d)=='property' for d in node.decorator_list)
            if isinstance(node,ast.AnnAssign) and node.value is not None:
                if isinstance(node.value,ast.Call):assert ast.unparse(node.value)=='field(default_factory=list)';factories.append(node)
                elif isinstance(node.value,ast.Name):assert node.value.id=='SCHEMA_VERSION' and ast.unparse(node.target)=='schema_version';schema_defaults.append(node)
                else:ast.literal_eval(node.value)
        assert len(factories)==8 and len(schema_defaults)==1
        assert not now.decorator_list and not now.args.defaults and not builder.decorator_list and not builder.args.defaults
        data=ModuleType(module_name);data.__dict__.update(dataclass=dataclass,field=field,datetime=datetime,timezone=timezone)
        def retire_module():
            assert sys.modules.get(module_name) is data;del sys.modules[module_name]
        rescue.callback(retire_module)
        sys.modules[module_name]=data
        exec(compile(ast.Module(body=[schema,cl,now],type_ignores=[]),str(jf),'exec',flags=__future__.annotations.compiler_flag,dont_inherit=True),data.__dict__)
        exec(compile(ast.Module(body=[builder],type_ignores=[]),str(source),'exec',flags=__future__.annotations.compiler_flag,dont_inherit=True),data.__dict__)
        assert data._entry.__code__.co_filename==str(source)
        assert len(data.ReviewJournalEntry.__dataclass_fields__)==56
    rescue.callback(lambda:holder.unlink(missing_ok=True))
    def retire_workers():
        release.set()
        for worker in workers:
            if worker.ident is not None:
                threading.Thread.join(worker,timeout=5)
                assert not worker.is_alive(), 'owned worker survived independent rescue'
    rescue.callback(retire_workers)
    class Patch:
        def setattr(self,obj,name,value,raising=True):
            assert obj is fs_lock and name in {'_ACQUIRE_DEADLINE_S','_ACQUIRE_POLL_S'} and raising is False
            setattr(obj,name,value)
    def clock_factory(patch,obj):
        assert obj is fs_lock and not clocks;clocks.append(True);return SimpleNamespace(seconds=0,sleeps=[])
    @contextmanager
    def declared_lock(path):
        assert path==work/'coverage.json';entered.set();assert release.wait(10),'owned gate not released';yield
    def actual_entry(i):
        assert data is not None and i==len(entries) and i in (0,1)
        value=data._entry(i);assert type(value) is data.ReviewJournalEntry and value.line_start==i+1
        entries.append(value);return value
    def declared_append(root,entry):
        assert a.case=='journal' and root==work and type(entry) is data.ReviewJournalEntry
        append_calls.append(entry)
        if not workers:
            assert len(append_calls)==1 and entry is entries[0]
            with holder.open('xb') as stream:
                initial_streams.append(stream);assert stream.write(b'')==0
            assert stream.closed
        else:
            assert len(append_calls)==2 and entry is entries[1] and len(initial_streams)==1 and initial_streams[0].closed
            entered.set();assert release.wait(10),'owned append gate not released'
    class Worker(threading.Thread):
        def __init__(self,*args,**kwargs):
            assert not args and not workers and kwargs['daemon'] is True
            original=kwargs['target']
            def run_owned():
                try:original()
                except BaseException as error:worker_errors.append(error)
            kwargs['target']=run_owned;super().__init__(*args,**kwargs);workers.append(self)
        def start(self):
            threading.Thread.start(self);assert entered.wait(5) and self.is_alive();raise primary
        def join(self,*args,**kwargs):
            joins.append((args,kwargs));assert not args and kwargs=={'timeout':10}
            release.set()  # Declared scheduling seam, not actual lock/append release.
            return threading.Thread.join(self,*args,**kwargs)
    def open_owned(path,flags,*mode):
        assert path==str(holder) and not owned
        if a.case=='store':assert flags==os.O_WRONLY|os.O_CREAT and mode==(0o600,)
        else:assert flags==os.O_WRONLY|os.O_APPEND and not mode and len(initial_streams)==1 and initial_streams[0].closed
        fd=os.open(path,flags,*mode);owned.append((fd,os.fstat(fd)));return fd
    def close_owned(fd):
        assert len(owned)==1 and fd==owned[0][0] and not closes
        st=os.fstat(fd);original=owned[0][1];assert (st.st_dev,st.st_ino)==(original.st_dev,original.st_ino)
        os.close(fd);closes.append(fd);raise secondary
    def record_flock(fd,operation):
        assert len(owned)==1 and fd==owned[0][0] and operation is LOCK_EX and not flocks;flocks.append(True)
    def importing(name,globals=None,locals=None,fromlist=(),level=0):
        assert name=='fcntl' and level==0;return SimpleNamespace(flock=record_flock,LOCK_EX=LOCK_EX)
    private={'__builtins__':{**vars(builtins),'__import__':importing},'Path':Path,'os':SimpleNamespace(open=open_owned,close=close_owned,O_WRONLY=os.O_WRONLY,O_CREAT=os.O_CREAT,O_APPEND=os.O_APPEND),'threading':SimpleNamespace(Thread=Worker,Event=threading.Event),'fs_lock':fs_lock,'install_poll_clock':clock_factory,'coverage_store_lock':declared_lock,'append_entry':declared_append,'_entry':actual_entry}
    exec(compile(ast.Module(body=[fn],type_ignores=[]),str(source),'exec',flags=__future__.annotations.compiler_flag,dont_inherit=True),private)
    args={'tmp_path':work,'monkeypatch':Patch()}
    if a.case=='store':args['caplog']=SimpleNamespace(at_level=lambda level:nullcontext(),records=[])
    try:private[fn.name](**args)
    except BaseException as observed:assert observed is secondary and observed.__context__ is primary
    else:raise AssertionError('authoritative close error absent')
    assert len(owned)==len(workers)==len(closes)==len(flocks)==len(clocks)==1
    assert len(joins)==1 and not workers[0].is_alive() and not worker_errors and not attempts
    assert len(initial_streams)==int(a.case=='journal') and all(s.closed for s in initial_streams)
    assert len(entries)==len(append_calls)==(2 if a.case=='journal' else 0)
    try:os.fstat(owned[0][0])
    except OSError as error:assert error.errno==errno.EBADF
    else:raise AssertionError('holder descriptor not consumed')
    record={'case':a.case,'mode':a.mode,'close_secondary_identity':True,'start_primary_context_identity':True,'holder_close_calls':len(closes),'caller_join_calls':len(joins),'worker_alive_before_rescue':False,'holder_fd_closed_before_rescue':True,'initial_file_context_closes':len(initial_streams),'actual_entry_calls':len(entries),'declared_append_calls':len(append_calls),'forbidden_attempts':attempts,'scope':'Actual caller/data declarations with declared private lock/append/clock/flock/scheduling seams; realownedholderFD+Thread. Controlledaftereffectclose and callerjoin withdeclaredgate release only; not realcoverage lock/append/refusal/timestamp behavior, FDretry, universalKBI or originalprimaryprecedence restoration.'}
# No numeric FD close retries; unexpected pre-close resources retire with child.
assert record is not None and not worker_errors and not attempts and not list(work.iterdir())
assert module_name not in sys.modules
record['independent_worker_rescue_complete']=True;record['owned_data_module_restored']=True
a.output.write_text(json.dumps(record,indent=2)+'\n')
