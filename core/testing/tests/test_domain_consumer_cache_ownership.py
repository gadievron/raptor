"""Record, fold, token and suffix fixtures preserve borrowed memo state."""
import ast
import builtins
from collections import OrderedDict
from contextlib import contextmanager
import copy
import functools
import importlib
import json
from pathlib import Path
import threading
from types import FunctionType, ModuleType, SimpleNamespace

import pytest
from core.testing.module_state import isolated_module_state

_SITES = [
    ('core/audit/tests/test_collector.py', '_owned_domain_slice_memos', 'core.concepts.audit_bridge', ('_load_cached', '_slice_memos')),
    ('core/audit/tests/test_verdict_reuse.py', '_owned_domain_slice_memos', 'core.concepts.audit_bridge', ('_load_cached', '_slice_memos')),
    ('core/audit/tests/test_token_map_cli.py', '_owned_token_cli_memos', 'core.concepts.audit_bridge', ('_load_cached', '_token_map_for_run')),
    ('packages/sca/supply_chain/tests/test_typosquat_domain.py', '_owned_suffix_loader', 'core.domains.public_suffix', ('load_suffix_rules',)),
]


def _consume(row, owner, tmp_path):
    if row[2] == 'core.domains.public_suffix':
        assert 'com' in owner.load_suffix_rules().exact
        assert 'com' in owner._test_suffix_consumer.load_suffix_rules().exact
        return
    model = owner._load_cached(str(tmp_path / 'domain-model.json'))
    assert model == {'concepts': [{'id': 'owned', 'description': 'owned model'}]}
    if '_slice_memos' in row[3]:
        assert owner._slice_memo_lock.acquire(blocking=False)
        owner._slice_memo_lock.release()
        memo = owner._slice_memo_for(model)
        assert isinstance(memo, owner._DomainSliceMemo)
        assert memo.model == model and memo.model is not model
    else:
        assert owner._token_map_for_run(str(tmp_path), '') is None


def _owner(row, tmp_path, warm):
    real = importlib.import_module(row[2])
    owner = ModuleType(real.__name__)
    vars(owner).update(vars(real))
    for field in row[3]:
        if field == '_slice_memos':
            owner._slice_memos = OrderedDict()
            owner._slice_memo_lock = threading.Lock()
            owner._slice_memo_for = FunctionType(real._slice_memo_for.__code__, vars(owner))
        else:
            original = getattr(real, field)
            body = FunctionType(original.__wrapped__.__code__, vars(owner), argdefs=original.__wrapped__.__defaults__)
            body.__kwdefaults__ = original.__wrapped__.__kwdefaults__
            setattr(owner, field, functools.lru_cache(**original.cache_parameters())(body))
    if row[2] == 'core.domains.public_suffix':
        consumer = ModuleType('private_typosquat_consumer')
        original = owner.load_suffix_rules
        consumer.load_suffix_rules = functools.lru_cache(**original.cache_parameters())(original.__wrapped__)
        owner._test_suffix_consumer = consumer
    (tmp_path / 'domain-model.json').write_text(json.dumps({'concepts': [{'id': 'owned', 'description': 'owned model'}]}))
    if warm:
        for _ in range(3):
            _consume(row, owner, tmp_path)
    return owner


def _snapshot(value):
    if hasattr(value, 'cache_info'):
        return value.cache_info()
    return [(key, id(memo), copy.deepcopy(memo.model)) for key, memo in value.items()]


def _cases():
    for index, row in enumerate(_SITES):
        for warm in (False, True):
            for mode in ('normal', 'body_error', 'body_interrupt'):
                yield pytest.param(index, warm, mode, None, id=f'{index}-{warm}-{mode}')
            for field in (*row[3], *(["scanner_alias"] if row[2] == "core.domains.public_suffix" else [])):
                for mode in ('setup_error', 'setup_interrupt'):
                    yield pytest.param(index, warm, mode, field, id=f'{index}-{warm}-{mode}-{field}')


@pytest.mark.parametrize('index,warm,mode,fault_field', list(_cases()))
def test_actual_consumer_fixture_preserves_borrowed_state(index, warm, mode, fault_field, tmp_path):
    row = _SITES[index]
    owner = _owner(row, tmp_path, warm)
    borrowed = {name: getattr(owner, name) for name in row[3]}
    saved = {name: _snapshot(value) for name, value in borrowed.items()}
    suffix_alias = owner._test_suffix_consumer.load_suffix_rules if row[2] == 'core.domains.public_suffix' else None
    suffix_statistics = suffix_alias.cache_info() if suffix_alias is not None else None
    failure = KeyboardInterrupt('owned interruption') if mode.endswith('interrupt') else RuntimeError('owned failure')
    publications = []

    class Patcher(pytest.MonkeyPatch):
        def setattr(self, obj, name, value, *args, **kwargs):
            super().setattr(obj, name, value, *args, **kwargs)
            if obj is owner and name in row[3]:
                publications.append(name)
                if mode.startswith('setup_') and name == fault_field:
                    raise failure
            if obj is getattr(owner, '_test_suffix_consumer', None) and name == 'load_suffix_rules':
                publications.append('scanner_alias')
                if mode.startswith('setup_') and fault_field == 'scanner_alias':
                    raise failure

    raw = isolated_module_state.__wrapped__
    clone = FunctionType(raw.__code__, {**raw.__globals__, 'pytest': SimpleNamespace(MonkeyPatch=Patcher)}, argdefs=raw.__defaults__)
    clone.__kwdefaults__ = raw.__kwdefaults__
    helper = contextmanager(clone)
    def importing(name, globals=None, locals=None, fromlist=(), level=0):
        if name == row[2].rsplit('.', 1)[0]:
            return SimpleNamespace(**{row[2].rsplit('.', 1)[1]: owner})
        if name == 'packages.sca.supply_chain' and row[2] == 'core.domains.public_suffix':
            return SimpleNamespace(typosquat_domain=owner._test_suffix_consumer)
        if name == 'core.testing.module_state':
            return SimpleNamespace(isolated_module_state=helper)
        return builtins.__import__(name, globals, locals, fromlist, level)
    namespace = {'__builtins__': {**vars(builtins), '__import__': importing}}
    file = Path(__file__).resolve().parents[3] / row[0]
    node = next(n for n in ast.parse(file.read_text()).body if isinstance(n, ast.FunctionDef) and n.name == row[1])
    node.decorator_list = []
    exec(compile(ast.Module(body=[node], type_ignores=[]), row[0], 'exec'), namespace)
    reached = []
    def execute():
        patch = Patcher()
        fixture = namespace[row[1]](patch)
        try:
            next(fixture)
            reached.append(True)
            for name, original in borrowed.items():
                private = getattr(owner, name)
                assert private is not original
                if hasattr(private, 'cache_parameters'):
                    assert private.cache_parameters() == original.cache_parameters()
                    assert private.cache_info().currsize == 0
                else:
                    assert isinstance(private, OrderedDict) and not private
            if suffix_alias is not None:
                assert owner._test_suffix_consumer.load_suffix_rules is owner.load_suffix_rules
            _consume(row, owner, tmp_path)
            wrapper = row[3][0]
            patch.setattr(owner, wrapper, lambda *args: None)
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
    for name, value in borrowed.items():
        assert getattr(owner, name) is value
        assert _snapshot(value) == saved[name]
    if suffix_alias is not None:
        assert owner._test_suffix_consumer.load_suffix_rules is suffix_alias
        assert suffix_alias.cache_info() == suffix_statistics
