"""Memo fixtures preserve borrowed wrappers, aliases and warning state."""
import ast
import builtins
from contextlib import contextmanager
import copy
import functools
import importlib
from pathlib import Path
from types import FunctionType, ModuleType, SimpleNamespace

import pytest
from core.testing.module_state import isolated_module_state

_SITES = [
    ('packages/zkpox/tests/test_proving_deps.py', '_owned_proving_memo', 'packages.zkpox.proving_deps', 'proving_stack_available', 'pd'),
    ('core/sandbox/tests/test_landlock_grant_resolution.py', '_owned_redirect_warnings', 'core.sandbox.landlock', '_grant_redirects_warned', 'landlock'),
    ('core/domains/tests/test_public_suffix.py', '_owned_suffix_rules', 'core.domains.public_suffix', 'load_suffix_rules', None),
]


def _cases():
    for index, row in enumerate(_SITES):
        for warm in (False, True):
            for mode in ('normal', 'body_error', 'body_interrupt'):
                yield pytest.param(index, warm, mode, None, id=f'{index}-{warm}-{mode}')
            for publication in ('module', 'alias') if row[3] != '_grant_redirects_warned' else ('module',):
                for mode in ('setup_error', 'setup_interrupt'):
                    yield pytest.param(index, warm, mode, publication, id=f'{index}-{warm}-{mode}-{publication}')


@pytest.mark.parametrize('index,warm,mode,publication', list(_cases()))
def test_actual_draft_fixture_preserves_borrowed_state(index, warm, mode, publication):
    file, fixture_name, module, field, global_name = _SITES[index]
    real = importlib.import_module(module)
    owner = ModuleType(real.__name__)
    vars(owner).update(vars(real))
    wrapped = field != '_grant_redirects_warned'
    namespace = {}
    if global_name:
        namespace[global_name] = owner
    if wrapped:
        if global_name == 'pd':
            tools = ModuleType('owned_probe_tools')
            tools.which = lambda binary: '/owned/bin/' + binary
            owner.shutil = tools
        original = getattr(real, field)
        body = FunctionType(original.__wrapped__.__code__, vars(owner), argdefs=original.__wrapped__.__defaults__)
        body.__kwdefaults__ = original.__wrapped__.__kwdefaults__
        borrowed = functools.lru_cache(**original.cache_parameters())(body)
        held = functools.lru_cache(**original.cache_parameters())(body)
        if warm:
            for _ in range(3):
                borrowed()
            for _ in range(5):
                held()
        namespace[field] = held
        saved = borrowed.cache_info(), held.cache_info()
    else:
        borrowed = {('/owned/requested', '/owned/resolved')} if warm else set()
        held = None
        saved = copy.deepcopy(borrowed)
    setattr(owner, field, borrowed)
    failure = KeyboardInterrupt('owned interruption') if mode.endswith('interrupt') else RuntimeError('owned failure')
    publications = []

    class Patcher(pytest.MonkeyPatch):
        def setattr(self, obj, name, value, *args, **kwargs):
            super().setattr(obj, name, value, *args, **kwargs)
            if obj is owner and name == field:
                publications.append('module')
                if mode.startswith('setup_') and publication == 'module':
                    raise failure

        def setitem(self, dictionary, name, value):
            super().setitem(dictionary, name, value)
            if dictionary is namespace and name == field:
                publications.append('alias')
                if mode.startswith('setup_') and publication == 'alias':
                    raise failure

    raw = isolated_module_state.__wrapped__
    clone = FunctionType(raw.__code__, {**raw.__globals__, 'pytest': SimpleNamespace(MonkeyPatch=Patcher)}, argdefs=raw.__defaults__)
    clone.__kwdefaults__ = raw.__kwdefaults__
    helper = contextmanager(clone)
    def importing(name, globals=None, locals=None, fromlist=(), level=0):
        if name == 'core.domains':
            return SimpleNamespace(public_suffix=owner)
        if name == 'core.testing.module_state':
            return SimpleNamespace(isolated_module_state=helper)
        return builtins.__import__(name, globals, locals, fromlist, level)
    namespace['__builtins__'] = {**vars(builtins), '__import__': importing}
    path = Path(__file__).resolve().parents[3] / file
    node = next(n for n in ast.parse(path.read_text()).body if isinstance(n, ast.FunctionDef) and n.name == fixture_name)
    node.decorator_list = []
    exec(compile(ast.Module(body=[node], type_ignores=[]), file, 'exec'), namespace)
    reached = []
    def execute():
        patch = Patcher()
        fixture = namespace[fixture_name](patch) if wrapped else namespace[fixture_name]()
        try:
            next(fixture)
            reached.append(True)
            private = getattr(owner, field)
            assert private is not borrowed
            if wrapped:
                assert namespace[field] is private
                assert private.cache_parameters() == borrowed.cache_parameters()
                assert private.cache_info().currsize == 0
                value = private()
                if global_name == 'pd':
                    assert value is True
                else:
                    assert 'com' in value.exact
                patch.setattr(owner, field, lambda: None)
            else:
                assert private == set()
                private.add(('/body/requested', '/body/resolved'))
            if mode.startswith('body_'):
                raise failure
        finally:
            try:
                fixture.close()
            finally:
                patch.undo()
    if mode == 'normal':
        execute()
    else:
        with pytest.raises(type(failure)) as caught:
            execute()
        assert caught.value is failure
    assert bool(reached) is (not mode.startswith('setup_'))
    assert publications
    assert getattr(owner, field) is borrowed
    if wrapped:
        assert namespace[field] is held
        assert borrowed.cache_info() == saved[0]
        assert held.cache_info() == saved[1]
    else:
        assert borrowed == saved


def test_token_fixture_restores_divergent_aliases_after_setup_interrupt(tmp_path):
    import ast
    import builtins
    from contextlib import contextmanager
    import functools
    from types import FunctionType, ModuleType, SimpleNamespace
    import pytest
    from core.concepts import audit_bridge as real
    from core.testing.module_state import isolated_module_state

    owner = ModuleType(real.__name__)
    vars(owner).update(vars(real))
    fields = ('_token_map_for_run', '_load_cached')
    arguments = {'_token_map_for_run': (str(tmp_path), ''), '_load_cached': (str(tmp_path / 'absent.json'),)}
    namespace = {}
    for name in fields:
        original = getattr(real, name)
        borrowed = functools.lru_cache(**original.cache_parameters())(original.__wrapped__)
        held = functools.lru_cache(**original.cache_parameters())(original.__wrapped__)
        for _ in range(3):
            assert borrowed(*arguments[name]) is None
        for _ in range(5):
            assert held(*arguments[name]) is None
        setattr(owner, name, borrowed)
        namespace[name] = held
    originals = {name: getattr(owner, name) for name in fields}
    aliases = {name: namespace[name] for name in fields}
    statistics = {name: (originals[name].cache_info(), aliases[name].cache_info()) for name in fields}
    failure = KeyboardInterrupt('published final alias')
    publications = []

    class Patcher(pytest.MonkeyPatch):
        def setitem(self, dictionary, name, value):
            super().setitem(dictionary, name, value)
            if dictionary is namespace and name in fields:
                publications.append(name)
                assert value is getattr(owner, name)
                if name == '_load_cached':
                    raise failure

    raw = isolated_module_state.__wrapped__
    clone = FunctionType(raw.__code__, {**raw.__globals__, 'pytest': SimpleNamespace(MonkeyPatch=Patcher)}, argdefs=raw.__defaults__)
    clone.__kwdefaults__ = raw.__kwdefaults__
    helper = contextmanager(clone)
    def importing(name, globals=None, locals=None, fromlist=(), level=0):
        if name == 'core.concepts':
            return SimpleNamespace(audit_bridge=owner)
        if name == 'core.testing.module_state':
            return SimpleNamespace(isolated_module_state=helper)
        return builtins.__import__(name, globals, locals, fromlist, level)
    namespace['__builtins__'] = {**vars(builtins), '__import__': importing}
    file = Path(__file__).resolve().parents[3] / 'core/concepts/tests/test_token_map_audit_bridge.py'
    node = next(n for n in ast.parse(file.read_text()).body if isinstance(n, ast.FunctionDef) and n.name == '_owned_token_memos')
    node.decorator_list = []
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(file), 'exec'), namespace)
    patch = Patcher()
    fixture = namespace[node.name](patch)
    try:
        with pytest.raises(KeyboardInterrupt) as caught:
            next(fixture)
        assert caught.value is failure
    finally:
        fixture.close()
        patch.undo()
    assert publications == list(fields)
    for name in fields:
        assert getattr(owner, name) is originals[name]
        assert namespace[name] is aliases[name]
        assert originals[name].cache_info() == statistics[name][0]
        assert aliases[name].cache_info() == statistics[name][1]
