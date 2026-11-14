"""Exercise gateway fixture ownership using private source declarations."""
import __future__
import argparse
import ast
from contextlib import ExitStack
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import ModuleType, SimpleNamespace
from typing import Optional
import unittest

assert sys.flags.isolated and sys.flags.optimize == 0 and sys.dont_write_bytecode
HERE = Path(__file__).resolve().parent
CFG = {'source_pins': {'packages/openant/tests/test_gateway_staging.py': 'd32bcbd871e3a1ebd5025e9cf153b84a8682c280be5de22cdf55f472f3424a92', 'packages/openant/config.py': 'd89b4670d5909580ee6cd0d8ddb0860cf0fa03441f8e8826c912d2b1d93e183e'}, 'setup_sha256': '1c8e7346e3c56950f47a77e3d7536cd847a835149994687a48a55c6c5d19f5f5', 'builder_sha256': 'f70da862691ebce49bee0be730b279acdc7c708f24db8984cc0f28377196e508', 'config_class_sha256': '8670a9538a3303350d6f76f607a57a6c087c78dd66647a4fdec39d661517a956'}
parser = argparse.ArgumentParser()
parser.add_argument('root', type=Path)
parser.add_argument('mode', choices=('error','healthy'))
parser.add_argument('output', type=Path)
a = parser.parse_args()
attempts = []
def audit(event, args):
    if (event.startswith(('subprocess.', 'socket.', 'ctypes.dlopen', 'ctypes.dlsym'))
            or event in {'os.system','os.fork','os.forkpty','os.posix_spawn','os.exec','_posixsubprocess.fork_exec'}
            or (event == 'import' and args and str(args[0]).split('.')[0] in {'core','packages'})):
        attempts.append(event)
        raise PermissionError('outside private gateway fixture ownership boundary: ' + event)
sys.addaudithook(audit)
texts = {}
for name, digest in CFG['source_pins'].items():
    raw = (a.root / name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest
    texts[name] = raw.decode()
source = a.root / 'packages/openant/tests/test_gateway_staging.py'
text = texts['packages/openant/tests/test_gateway_staging.py']
tree = ast.parse(text)
cl = next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name == '_GatewayHarness')
assert [ast.unparse(base) for base in cl.bases] == ['unittest.TestCase'] and not cl.decorator_list
setup = next(n for n in cl.body if isinstance(n,ast.FunctionDef) and n.name == 'setUp')
assert not any(isinstance(n,ast.FunctionDef) and n.name == 'tearDown' for n in cl.body)
assert not setup.decorator_list and not setup.args.defaults
assert hashlib.sha256(ast.get_source_segment(text,setup).encode()).hexdigest() == CFG['setup_sha256']
builder = next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name == '_make_fake_core')
assert not builder.decorator_list and not builder.args.defaults
assert hashlib.sha256(ast.get_source_segment(text,builder).encode()).hexdigest() == CFG['builder_sha256']
config_text = texts['packages/openant/config.py']
config = next(n for n in ast.parse(config_text).body if isinstance(n,ast.ClassDef) and n.name == 'OpenAntConfig')
assert hashlib.sha256(ast.get_source_segment(config_text,config).encode()).hexdigest() == CFG['config_class_sha256']
assert not config.bases and not config.keywords and [ast.unparse(d) for d in config.decorator_list] == ['dataclass']
assert not any(isinstance(n,ast.FunctionDef) and n.name in {'__init__','__post_init__','__setattr__','__getattribute__','__del__'} for n in config.body)
for node in config.body:
    assert isinstance(node,(ast.AnnAssign,ast.FunctionDef))
    if isinstance(node,ast.AnnAssign) and node.value is not None:
        ast.literal_eval(node.value)
    if isinstance(node,ast.FunctionDef):
        assert node.name in {'validate','from_env'}
        assert all(isinstance(d,ast.Name) and d.id == 'classmethod' for d in node.decorator_list)
        for default in node.args.defaults + [x for x in node.args.kw_defaults if x is not None]:
            ast.literal_eval(default)
flags = __future__.annotations.compiler_flag
work = a.output.parent / 'owned-work'
work.mkdir(mode=0o700)
owned, path_calls, body_calls, teardown_calls = [], [], [], []
primary = OSError('controlled ordinary setup failure after real Path construction')
record = None
module_name = '_owned_gateway_config_declaration'
assert module_name not in sys.modules
module = ModuleType(module_name)
module.__dict__.update(dataclass=dataclass, Path=Path, Optional=Optional)
with ExitStack() as rescue:
    def retire_module():
        assert sys.modules.get(module_name) is module
        del sys.modules[module_name]
    rescue.callback(retire_module)  # own registry restoration before publication
    sys.modules[module_name] = module
    exec(compile(ast.Module(body=[config],type_ignores=[]),str(a.root/'packages/openant/config.py'),'exec',flags=flags,dont_inherit=True),module.__dict__)
    config_class = module.OpenAntConfig
    builder_namespace = {'Path':Path}
    exec(compile(ast.Module(body=[builder],type_ignores=[]),str(source),'exec',flags=flags,dont_inherit=True),builder_namespace)
    def allocate():
        assert not owned
        temporary = tempfile.TemporaryDirectory(dir=work,prefix='owned-gateway-setup-')
        owned.append(temporary)
        rescue.callback(temporary.cleanup)
        return temporary
    def path_after_effect(value):
        assert len(owned) == 1 and value == owned[0].name and not path_calls
        actual = Path(value)
        assert actual.is_dir()
        path_calls.append(str(actual))
        if a.mode == 'error':
            raise primary
        return actual
    namespace = {'Path':path_after_effect,'tempfile':SimpleNamespace(TemporaryDirectory=allocate),'_make_fake_core':builder_namespace['_make_fake_core'],'OpenAntConfig':config_class}
    exec(compile(ast.Module(body=[setup],type_ignores=[]),str(source),'exec',flags=flags,dont_inherit=True),namespace)
    def body(self):
        body_calls.append(True)
        assert a.mode == 'healthy'
        assert self.base.is_dir() and self.out.is_dir()
        assert self.core == self.base / 'libs' / 'openant-core'
        assert self.config.core_path == self.core
        assert (self.core / 'core' / 'scanner.py').read_bytes() == b''
        assert self.mint_calls == self.revoke_calls == self.loopback_calls == self.spend_calls == []
    def teardown(self):
        teardown_calls.append(True)
        unittest.TestCase.tearDown(self)  # actual inherited no-op
    class Result(unittest.TestResult):
        def addError(self,test,info):
            self.observed_primary = info[1]
            super().addError(test,info)
    case_type = type('OwnedGatewaySetupProjection',(unittest.TestCase,),{'setUp':namespace['setUp'],'tearDown':teardown,'runTest':body})
    case = case_type('runTest')
    rescue.callback(case.doCleanups)
    result = Result()
    case.run(result)
    failed = a.mode == 'error'
    assert len(owned) == len(path_calls) == 1
    assert len(result.errors) == int(failed) and not result.failures
    assert (result.observed_primary is primary) if failed else not hasattr(result,'observed_primary')
    assert len(body_calls) == len(teardown_calls) == int(not failed) and not attempts
    assert not Path(owned[0].name).exists(), 'cleanup must precede independent rescue'
    assert hasattr(case,'core') is (not failed) and hasattr(case,'config') is (not failed)
    record = {'mode':a.mode,'primary_identity':True if failed else None,'directory_present_before_rescue':False,'unittest_errors':len(result.errors),'path_effect_calls':len(path_calls),'body_calls':len(body_calls),'teardown_calls':len(teardown_calls),'config_instance_constructed':not failed,'owned_fixture_marker_created':not failed,'forbidden_attempts':attempts,'scope':'Private source setup/builder/config declarations and actual unittest runner; no normal module/class import equivalence, original gateway/provider/native bodies or KBI cleanup proof.'}

assert module_name not in sys.modules and not list(work.iterdir())
assert record is not None and not attempts
a.output.write_text(json.dumps(record,indent=2)+'\n')
