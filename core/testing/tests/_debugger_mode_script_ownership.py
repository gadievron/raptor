# UNEXECUTED: proposed exact prefix ownership witness; requires ROOT resource review.
import __future__
import argparse, ast, errno, hashlib, json, os, sys, tempfile
from pathlib import Path
from types import SimpleNamespace
parser=argparse.ArgumentParser()
parser.add_argument('root',type=Path)
parser.add_argument('site',choices=('debugger','crash'))
parser.add_argument('output',type=Path)
a=parser.parse_args()
attempts=[]
def audit(event,values):
    if event.startswith(('subprocess.','socket.','ctypes.dlopen','ctypes.dlsym')) or event in {'os.system','os.fork','os.forkpty','os.posix_spawn','os.exec','pty.spawn'}:
        attempts.append(event)
        raise PermissionError('proposed prefix boundary denied: '+event)
sys.addaudithook(audit)
sites={'debugger': {'path': 'packages/binary_analysis/debugger.py', 'method': 'run_commands', 'whole_sha256': '550f19d5a7afdbc5a8400180658c2a80c74458645dcb3ad9d2afe77ec63c4b36', 'method_segment_sha256': 'c011eaa185dbcd912fe3f5a68b5c20085ce86bb01993b7c0ee9fed6faed6f5fe', 'prefix_statement_count': 7, 'prefix_ast_sha256': 'c52bb3c81f0710820ea1495460648c0f2f66425aed8c34401423414c11a11963', 'last_statement_source': "try:\n            os.fchmod(fd, 0o600)\n        except (OSError, AttributeError):\n            # Some non-Unix filesystems (FAT mounted /tmp on a USB,\n            # Windows path under WSL) don't support POSIX modes;\n            # the chmod failure isn't fatal.\n            pass\n        except BaseException:\n            # No stream has adopted this descriptor yet. Attempt both cleanups\n            # without replacing the operation error or retrying a consumed fd.\n            try:\n                os.close(fd)\n            except BaseException:\n                pass\n            try:\n                script_file.unlink(missing_ok=True)\n            except BaseException:\n                pass\n            raise", 'suffix_excluded': 'fdopen/adoption/write/debugger/sandbox/tool/parser/target body. This is only original top-level acquisition prefix through fchmod handler.'}, 'crash': {'path': 'packages/binary_analysis/crash_analyser.py', 'method': '_write_debugger_script', 'whole_sha256': '6be0756e7c1bad4c93ba2d3f9e220076c97e6b55fd2fbad570e65004c51fe4e1', 'method_segment_sha256': 'c6ad2240aeea3ae89724f1615cfb4ac0af020c22b39c56e51978f509251b00b0', 'prefix_statement_count': 5, 'prefix_ast_sha256': '733202544ca73df5beed3b54f765e57d231230267af74816a28c0ee317714570', 'last_statement_source': "try:\n            os.fchmod(fd, 0o600)\n        except (OSError, AttributeError):\n            # Non-POSIX filesystem — mkstemp's own 0600 default is the\n            # best available; not fatal.\n            pass\n        except BaseException:\n            # No stream has adopted this descriptor yet. Attempt both cleanups\n            # without replacing the operation error or retrying a consumed fd.\n            try:\n                os.close(fd)\n            except BaseException:\n                pass\n            try:\n                script_file.unlink(missing_ok=True)\n            except BaseException:\n                pass\n            raise", 'suffix_excluded': 'fdopen/adoption/write/debugger/sandbox/tool/parser/target body. This is only original top-level acquisition prefix through fchmod handler.'}}
spec=sites[a.site];path=a.root/spec['path'];raw=path.read_bytes();assert hashlib.sha256(raw).hexdigest()==spec['whole_sha256']
text=raw.decode();method=next(n for n in ast.walk(ast.parse(text)) if isinstance(n,ast.FunctionDef) and n.name==spec['method'])
assert hashlib.sha256(ast.get_source_segment(text,method).encode()).hexdigest()==spec['method_segment_sha256']
method.body=method.body[:spec['prefix_statement_count']]
assert hashlib.sha256(ast.dump(ast.Module(body=method.body,type_ignores=[]),include_attributes=False).encode()).hexdigest()==spec['prefix_ast_sha256']
assert not method.decorator_list
work=a.output.parent/'owned-work';work.mkdir(mode=0o700)
owned=[];modes=[];consumed=[];close_calls=[];unlink_calls=[];primary=KeyboardInterrupt('controlled pre-adoption mode interruption')
def allocate(*args,**kwargs):
    assert not args and not owned and Path(kwargs['dir'])==work and kwargs['suffix']=='.txt'
    assert kwargs['prefix'] in {'.raptor_gdb_','.owned_crash_'}
    fd,name=tempfile.mkstemp(**kwargs);st=os.fstat(fd);owned.append((fd,Path(name),st.st_dev,st.st_ino));return fd,name
def mode(fd,value):
    assert len(owned)==1 and fd==owned[0][0] and value==0o600 and not modes
    os.fchmod(fd,value);modes.append(value);raise primary
def forbidden_adoption(*args,**kwargs):
    attempts.append('fdopen reached outside selected prefix')
    raise AssertionError('adoption not admitted')
def consume_close(fd):
    assert len(owned)==1 and fd==owned[0][0] and not consumed
    st=os.fstat(fd)
    assert (st.st_dev,st.st_ino)==owned[0][2:]
    consumed.append(fd)
    close_calls.append(fd)
    os.close(fd)
class ObservedPath(type(Path())):
    def unlink(self,missing_ok=False):
        assert len(owned)==1 and Path(self)==owned[0][1] and not unlink_calls
        unlink_calls.append(str(self))
        return Path.unlink(self,missing_ok=missing_ok)
ns={'Path':ObservedPath,'tempfile':SimpleNamespace(mkstemp=allocate),'os':SimpleNamespace(fchmod=mode,close=consume_close,fdopen=forbidden_adoption)}
exec(compile(ast.Module(body=[method],type_ignores=[]),str(path),'exec',flags=__future__.annotations.compiler_flag),ns)
self=SimpleNamespace(binary=work/'unexecuted-target-label')
caught=None;result=None
try:
    try:
        if a.site=='debugger':ns[spec['method']](self,['owned-command'])
        else:ns[spec['method']](self,['owned-command'],'.owned_crash_')
    except BaseException as error:caught=error
    assert caught is primary and len(owned)==len(modes)==1 and not attempts
    fd,name,dev,ino=owned[0]
    assert consumed==close_calls==[fd] and unlink_calls==[str(name)]
    try:
        os.fstat(fd)
    except OSError as error:
        assert error.errno==errno.EBADF
    else:
        raise AssertionError('candidate did not retire raw descriptor')
    assert not name.exists()
    result={'site':a.site,'status':'PROPOSED_CANDIDATE_PREFIX_WITNESS_IF_INSTALLED_AND_ADMITTED','primary_identity':caught is primary,'raw_descriptor_live_before_rescue':False,'path_present_before_rescue':False,'mode_effects':modes,'source_close_attempts':len(close_calls),'source_unlink_attempts':len(unlink_calls),'raw_descriptor_consumed_before_close':True,'adoption_calls':0,'forbidden_attempts':attempts,'scope':'Exact acquisition prefix only; no full method/adoption/native debugger or sandbox assurance.'}
finally:
    for fd,name,dev,ino in owned:
        if fd not in consumed:
            st=os.fstat(fd)
            assert (st.st_dev,st.st_ino)==(dev,ino),'Ownership changed; never blindly close a recycled descriptor'
            consumed.append(fd)
            os.close(fd)
        name.unlink(missing_ok=True)
assert result is not None and not attempts
a.output.write_text(json.dumps(result,indent=2)+'\n')
