# SOURCE-ONLY UNEXECUTED DRAFT: no interpreter/resource admission inferred.
import __future__
import argparse, ast, builtins, contextlib, hashlib, json, sys, tempfile
from pathlib import Path
from types import SimpleNamespace
parser=argparse.ArgumentParser()
parser.add_argument('root',type=Path)
parser.add_argument('stage',choices=('before','after','success'))
parser.add_argument('output',type=Path)
a=parser.parse_args();attempts=[]
def audit(event,values):
    if event.startswith(('subprocess.','socket.','ctypes.dlopen','ctypes.dlsym')) or event in {'os.system','os.fork','os.forkpty','os.posix_spawn','os.exec','pty.spawn'}:
        attempts.append(event);raise PermissionError(event)
sys.addaudithook(audit)
specs={'fixture': {'path': 'packages/binary_analysis/tests/test_r2_scratch_ownership.py', 'whole_sha256': '649753f6b52fc701e62602406ff8374ff20da02fccfdcd20e4e41bf5765a27ff', 'name': 'session_io', 'node_kind': 'FunctionDef', 'segment_sha256': '19252d2785de6da716fbd2d9c0dd203d3bb6d7dc92f780605befba51eeb44872'}, 'consumer': {'path': 'packages/binary_analysis/radare2_understand.py', 'whole_sha256': '10043e6cf83448b55324a77416cc244e6882b6d85e422521c9113ea3d111b549', 'name': 'BinaryUnderstand', 'node_kind': 'ClassDef', 'segment_sha256': 'a50e0acfbb13a5d3b10c8c092c868aab1bce40971a0df630f9913c457925583d'}, 'scratch': {'path': 'core/run/scratch.py', 'whole_sha256': '3d433d55ce81ae2f6eb8ece7e095cfc773d8df075399c80690d5bda2728c7970', 'name': 'scratch_dir', 'node_kind': 'FunctionDef', 'segment_sha256': 'bc53af927a6d4fc8a85f047510d013ea4582241a636c0957810ebcd5db96a7f7'}}
def source_node(key):
    spec=specs[key];path=a.root/spec['path'];raw=path.read_bytes()
    assert hashlib.sha256(raw).hexdigest()==spec['whole_sha256']
    text=raw.decode();node=next(n for n in ast.parse(text).body if type(n).__name__==spec['node_kind'] and n.name==spec['name'])
    assert hashlib.sha256(ast.get_source_segment(text,node).encode()).hexdigest()==spec['segment_sha256']
    return node,path
def denied_import(*args,**kwargs):
    attempts.append('selected source attempted import');raise AssertionError('normal imports not admitted')
ns={'__name__':'private_owned_source','__builtins__':{**vars(builtins),'__import__':denied_import},'contextlib':contextlib}
cls,consumer_path=source_node('consumer')
assert not cls.bases and not cls.decorator_list
for item in cls.body:
    assert isinstance(item,(ast.Expr,ast.Assign,ast.FunctionDef))
    if isinstance(item,ast.Assign):ast.literal_eval(item.value)
    if isinstance(item,ast.FunctionDef):
        for default in item.args.defaults:ast.literal_eval(default)
        assert all(ast.unparse(d) in {'staticmethod','contextlib.contextmanager'} for d in item.decorator_list)
exec(compile(ast.Module(body=[cls],type_ignores=[]),str(consumer_path),'exec',flags=__future__.annotations.compiler_flag),ns)
Consumer=ns['BinaryUnderstand'];forbidden_codes=set()
for name,value in vars(Consumer).items():
    if isinstance(value,staticmethod):value=value.__func__
    if callable(value):
        original=getattr(value,'__wrapped__',value)
        if hasattr(original,'__code__'):forbidden_codes.add(original.__code__)
def profile(frame,event,arg):
    if event=='call' and frame.f_code in forbidden_codes:
        attempts.append('consumer body '+frame.f_code.co_name)
        raise AssertionError('consumer constructor/method body not admitted')
scratch,scratch_path=source_node('scratch')
assert [ast.unparse(x) for x in scratch.decorator_list]==['contextlib.contextmanager']
exec(compile(ast.Module(body=[scratch],type_ignores=[]),str(scratch_path),'exec',flags=__future__.annotations.compiler_flag),ns)
original_scratch=ns['scratch_dir'];forbidden_codes.add(original_scratch.__wrapped__.__code__)
scratch_view=SimpleNamespace(scratch_dir=original_scratch)
owned=[];changes=[];publications=[];primary=KeyboardInterrupt('controlled private publication interruption')
work=a.output.parent/'owned-work';work.mkdir(mode=0o700)
def temporary_file(*args,**kwargs):
    assert not owned and not args and Path(kwargs['dir'])==work
    stream=tempfile.TemporaryFile(**kwargs);owned.append(stream);return stream
def denied_directory(*args,**kwargs):
    attempts.append('owned scratch callback body invoked');raise AssertionError('scratch body not admitted')
class Publisher:
    def setattr(self,target,name,value):
        assert name in {'_spawn_r2','scratch_dir'} and callable(value)
        assert isinstance(target,Consumer) if name=='_spawn_r2' else target is scratch_view
        assert len(owned)==1 and not owned[0].closed
        if not publications and a.stage=='before':raise primary
        prior=vars(target).get(name);had=name in vars(target)
        changes.append((target,name,prior,had));setattr(target,name,value);publications.append(name)
        if len(publications)==1 and a.stage=='after':raise primary
    def undo(self):
        for target,name,prior,had in reversed(changes):
            if had:setattr(target,name,prior)
            else:delattr(target,name)
fixture,fixture_path=source_node('fixture');assert len(fixture.decorator_list)==1;fixture.decorator_list=[]
ns.update(contextmanager=contextlib.contextmanager,Path=Path,tempfile=SimpleNamespace(TemporaryFile=temporary_file,TemporaryDirectory=denied_directory),consumer=SimpleNamespace(BinaryUnderstand=Consumer),scratch=scratch_view)
exec(compile(ast.Module(body=[fixture],type_ignores=[]),str(fixture_path),'exec',flags=__future__.annotations.compiler_flag),ns)
publisher=Publisher();generator=ns['session_io'](work,publisher);caught=None;result=None
sys.setprofile(profile)
try:
    try:state=next(generator)
    except BaseException as error:caught=error
    assert len(owned)==1 and not attempts
    if a.stage=='success':
        assert caught is None and state['native'] is owned[0] and state['spawn_calls']==0 and len(publications)==2
        generator.close()
        assert owned[0].closed
    else:
        assert caught is primary and owned[0].closed
        assert len(publications)==(1 if a.stage=='after' else 0)
    result={'oracle_mode':'candidate-closed-before-rescue','stage':a.stage,'primary_identity':caught is primary if caught else None,'native_stream_open_before_rescue':not owned[0].closed,'publication_names':publications,'consumer_body_attempts':attempts,'scope':'Exact fixture plus actual source-backed class shape; no constructor/method/scratch body, normal package import or native session execution.'}
finally:
    generator.close()
    publisher.undo()
    sys.setprofile(None)
    for stream in owned:
        if not stream.closed:stream.close()
assert result is not None and not attempts
a.output.write_text(json.dumps(result,indent=2)+'\n')
