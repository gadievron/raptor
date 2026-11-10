"""Bounded function reuse preserves live adapters and exception precedence."""

import builtins
from pathlib import Path
from types import FunctionType, SimpleNamespace

import pytest

from core.audit import _function_preparation as preparation
from core.audit import _util, detector_cache
from core.audit import fail_open_detector as fail
from core.testing.module_views import module_function_view


SOURCE = '# padding\n' * 500 + '''def fetch():
    try:
        return {}
    except Exception:
        return {}
'''
CONSUMERS = (
    '_detect_optional_not_checked', '_detect_truncation_not_signaled',
    '_detect_error_conflated_with_empty',
)


def _capture(monkeypatch, module=fail):
    contexts = []

    def factory():
        context = preparation.FunctionPreparation()
        contexts.append(context)
        return context

    monkeypatch.setattr(module, 'FunctionPreparation', factory)
    return contexts


def _view(import_hook):
    view = module_function_view(fail, import_hook=import_hook)
    view._PREP_GLOBALS = vars(view)
    view._PREP_BUILTINS = view._extract_functions.__builtins__
    view._PREP_FUNCTION_STATE = {
        name: (getattr(view, name), getattr(view, name).__code__)
        for name in fail._PREP_FUNCTION_STATE
    }
    view._PREP_BINDING_STATE = tuple(
        (name, getattr(view, name)) for name, _ in fail._PREP_BINDING_STATE
    )
    return view


def test_native_findings_and_order_use_one_preparation(monkeypatch):
    expected = []
    for name in CONSUMERS:
        expected.extend(getattr(fail, name)('a.py', SOURCE))
    expected.sort(key=lambda result: (result.file, result.line))
    contexts = _capture(monkeypatch)
    actual = fail.detect_fail_open_patterns({'a.py': SOURCE})
    assert [row.to_dict() for row in actual] == [row.to_dict() for row in expected]
    assert expected
    context, = contexts
    assert (context.misses, context.hits, context.fallbacks) == (1, 2, 0)
    assert context.key is context.rows is None


@pytest.mark.parametrize('adapt', ['source', 'path'])
def test_string_adapters_do_not_create_preparation(monkeypatch, adapt):
    calls = []

    class Adapter(str):
        def split(self, *args):
            calls.append(('split', args))
            return super().split(*args)

        def endswith(self, *args):
            calls.append(('endswith', args))
            return super().endswith(*args)

    source = Adapter(SOURCE) if adapt == 'source' else SOURCE
    path = Adapter('a.py') if adapt == 'path' else 'a.py'
    contexts = _capture(monkeypatch)
    actual = fail.detect_fail_open_patterns({path: source})
    assert actual and not contexts
    assert any(kind == ('split' if adapt == 'source' else 'endswith') for kind, _ in calls)


def test_replacement_wrapper_receives_original_positional_signature(monkeypatch):
    calls = []
    original = fail._extract_functions

    def replacement(source):
        calls.append(source)
        return original(source)

    monkeypatch.setattr(fail, '_extract_functions', replacement)
    contexts = _capture(monkeypatch)
    assert fail.detect_fail_open_patterns({'a.py': SOURCE})
    assert calls == [SOURCE] * 3
    assert contexts[0].hits == 0


@pytest.mark.parametrize('kind', ['function', 'callable', 'code', 'foreign_globals'])
def test_live_export_adapters_are_never_reused(monkeypatch, kind):
    calls = []
    original = _util.extract_functions_from_source
    if kind == 'function':
        def exporter(source):
            calls.append(source)
            return original(source)
    elif kind == 'callable':
        class Exporter:
            @property
            def __globals__(self):
                raise AssertionError('callable metadata must not be inspected')

            def __call__(self, source):
                calls.append(source)
                return original(source)
        exporter = Exporter()
    elif kind == 'code':
        namespace = {}
        exec('def changed(source):\n    _preparation_calls.append(source)\n    return []\n', namespace)
        monkeypatch.setattr(_util, '_preparation_calls', calls, raising=False)
        monkeypatch.setattr(original, '__code__', namespace['changed'].__code__)
        exporter = original
    else:
        class Globals(dict):
            def __iter__(self):
                raise AssertionError('foreign globals iteration')

            def get(self, *args):
                raise AssertionError('foreign globals lookup')
        namespace = {}
        exec('def exporter(source):\n    calls.append(source)\n    return []\n', namespace)
        exporter = FunctionType(namespace['exporter'].__code__, Globals(calls=calls))
    monkeypatch.setattr(_util, 'extract_functions_from_source', exporter)
    contexts = _capture(monkeypatch)
    fail.detect_fail_open_patterns({'a.py': SOURCE})
    assert calls == [SOURCE] * 3
    assert (contexts[0].hits, contexts[0].fallbacks) == (0, 3)


@pytest.mark.parametrize('action', ['normal', 'error', 'missing', 'rebind'])
def test_private_import_view_keeps_each_live_import(monkeypatch, action):
    calls = []
    exports = []
    primary = RuntimeError('import failed')
    original = _util.extract_functions_from_source

    def replacement(source):
        exports.append(source)
        return original(source)

    def importer(name, globals=None, locals=None, fromlist=(), level=0):
        assert globals is vars(view)
        assert (name, fromlist, level) == ('_util', ('extract_functions_from_source',), 1)
        calls.append(name)
        if len(calls) == 2:
            if action == 'error':
                raise primary
            if action == 'missing':
                return SimpleNamespace()
            if action == 'rebind':
                monkeypatch.setattr(_util, 'extract_functions_from_source', replacement)
        return _util

    view = _view(importer)
    assert view._LITERAL_NORMALIZE_IMPL is view._normalise_literal
    contexts = _capture(monkeypatch, view)
    if action in ('error', 'missing'):
        with pytest.raises(RuntimeError if action == 'error' else ImportError) as caught:
            view.detect_fail_open_patterns({'a.py': SOURCE})
        if action == 'error':
            assert caught.value is primary
        assert len(calls) == 2
    else:
        assert view.detect_fail_open_patterns({'a.py': SOURCE})
        assert len(calls) == 3
        assert (contexts[0].misses, contexts[0].hits) == ((1, 2) if action == 'normal' else (1, 0))
        assert len(exports) == (2 if action == 'rebind' else 0)
    assert contexts[0].key is contexts[0].rows is None


@pytest.mark.parametrize('primary_type', [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('cleanup_type', [OSError, MemoryError, KeyboardInterrupt, SystemExit])
def test_cleanup_cannot_replace_primary_with_shadowed_names(monkeypatch, primary_type, cleanup_type):
    primary = primary_type('primary')

    class Context:
        def release(self):
            raise cleanup_type('secondary')

    def unexpected(*args):
        raise AssertionError('shadowed plumbing callback')

    def producer(path, source):
        for name in ('Exception', 'BaseException', 'len', 'isinstance'):
            monkeypatch.setattr(fail, name, unexpected, raising=False)
        raise primary

    monkeypatch.setattr(fail, 'FunctionPreparation', Context)
    monkeypatch.setattr(fail, CONSUMERS[0], producer)
    with pytest.raises(primary_type) as caught:
        fail.detect_fail_open_patterns({'a.py': SOURCE})
    assert caught.value is primary


@pytest.mark.parametrize('cleanup_type', [OSError, MemoryError, KeyboardInterrupt, SystemExit])
def test_successful_leg_keeps_fresh_cleanup_cancellation(monkeypatch, cleanup_type):
    cleanup = cleanup_type('cleanup')

    class Context:
        def release(self):
            raise cleanup

    monkeypatch.setattr(fail, 'FunctionPreparation', Context)
    for name in CONSUMERS:
        monkeypatch.setattr(fail, name, lambda path, source: [])
    if issubclass(cleanup_type, Exception):
        assert fail.detect_fail_open_patterns({'a.py': SOURCE}) == []
    else:
        with pytest.raises(cleanup_type) as caught:
            fail.detect_fail_open_patterns({'a.py': SOURCE})
        assert caught.value is cleanup


@pytest.mark.parametrize('count', [0, 512, 513])
def test_storage_row_bound_never_truncates_or_shares_lists(count):
    source = ''.join(f'def f_{index}():\n    return None\n' for index in range(count))
    context = preparation.FunctionPreparation()
    first = context.get(source, _util.extract_functions_from_source, lambda: True)
    expected = first.copy()
    first.clear()
    second = context.get(source, _util.extract_functions_from_source, lambda: True)
    assert second == expected and len(second) == count and second is not first
    assert (context.misses, context.hits) == ((1, 1) if count <= 512 else (2, 0))
    context.release()
    assert context.key is context.rows is None


@pytest.mark.parametrize('size, reusable', [(499900, True), (500100, False)])
def test_storage_character_bound_returns_complete_body(size, reusable):
    source = 'def f():\n    # ' + 'x' * size + '\n    return None\n'
    context = preparation.FunctionPreparation()
    first = context.get(source, _util.extract_functions_from_source, lambda: True)
    second = context.get(source, _util.extract_functions_from_source, lambda: True)
    assert first == second and 'x' * size in second[0][2]
    assert (context.misses, context.hits) == ((1, 1) if reusable else (2, 0))
    if not reusable:
        assert context.key is context.rows is None


@pytest.mark.parametrize('position', [4, 5, 6])
def test_marker_primitive_admission_does_not_call_adapters(monkeypatch, position):
    def unexpected(*args):
        raise AssertionError('primitive marker adapter called')

    marker = list(_util._FUNCTION_EXTRACTION_NATIVE_STATE)
    marker[position] = unexpected
    monkeypatch.setattr(_util, '_FUNCTION_EXTRACTION_NATIVE_STATE', tuple(marker))
    context = preparation.FunctionPreparation()
    for _ in range(2):
        assert context.get(SOURCE, _util.extract_functions_from_source, lambda: True)
    assert (context.misses, context.hits, context.fallbacks) == (0, 0, 2)


def test_hit_does_not_introduce_all_or_zip_callbacks():
    def unexpected(*args):
        raise AssertionError('new reduction callback')

    namespace = dict(vars(preparation))
    namespace['__builtins__'] = dict(vars(builtins), all=unexpected, zip=unexpected)
    original = preparation.FunctionPreparation.get
    get = FunctionType(original.__code__, namespace, original.__name__, original.__defaults__)
    context = preparation.FunctionPreparation()
    first = get(context, SOURCE, _util.extract_functions_from_source, lambda: True)
    assert get(context, SOURCE, _util.extract_functions_from_source, lambda: True) == first
    assert (context.misses, context.hits) == (1, 1)


def test_dependency_closure_contains_function_preparation_and_exporter():
    closure = detector_cache.import_closure(
        ('core.audit.fail_open_detector',), root=Path(fail.__file__).resolve().parents[2],
    )
    assert 'core.audit._function_preparation' in closure
    assert 'core.audit._util' in closure


def test_replacement_consumer_rebinds_export_for_later_stages(monkeypatch):
    calls = []
    original_consumer = fail._detect_optional_not_checked
    original_export = _util.extract_functions_from_source

    def exporter(source):
        calls.append(source)
        return original_export(source)

    def consumer(path, source):
        result = original_consumer(path, source)
        monkeypatch.setattr(_util, 'extract_functions_from_source', exporter)
        return result

    monkeypatch.setattr(fail, CONSUMERS[0], consumer)
    contexts = _capture(monkeypatch)
    assert fail.detect_fail_open_patterns({'a.py': SOURCE})
    assert calls == [SOURCE, SOURCE]
    assert contexts[0].hits == 0


def test_shadowed_len_falls_back_without_extra_adapter_calls(monkeypatch):
    calls = []

    def adapted_len(value):
        calls.append(value)
        return len(value)

    monkeypatch.setattr(fail, 'len', adapted_len, raising=False)
    expected = []
    for name in CONSUMERS:
        expected.extend(getattr(fail, name)('a.py', SOURCE))
    expected.sort(key=lambda row: (row.file, row.line))
    expected_calls = calls.copy()
    calls.clear()
    contexts = _capture(monkeypatch)
    assert fail.detect_fail_open_patterns({'a.py': SOURCE}) == expected
    assert calls == expected_calls
    assert contexts[0].hits == 0


def test_producer_failure_releases_previously_retained_rows():
    context = preparation.FunctionPreparation()
    context.get(SOURCE, _util.extract_functions_from_source, lambda: True)
    assert context.rows is not None
    primary = RuntimeError('producer failed')

    def exporter(source):
        raise primary

    with pytest.raises(RuntimeError) as caught:
        context.get(SOURCE, exporter, lambda: True)
    assert caught.value is primary
    assert context.key is context.rows is None


@pytest.mark.parametrize('builtin_fallback', [False, True])
def test_removed_consumer_preserves_global_lookup(monkeypatch, builtin_fallback):
    calls = []

    def first(path, source):
        monkeypatch.delattr(fail, CONSUMERS[1])
        calls.append('first')
        return []

    def fallback(path, source):
        calls.append('builtin')
        return []

    monkeypatch.setattr(fail, CONSUMERS[0], first)
    if builtin_fallback:
        monkeypatch.setattr(builtins, CONSUMERS[1], fallback, raising=False)
        fail.detect_fail_open_patterns({'a.py': SOURCE})
        assert calls == ['first', 'builtin']
    else:
        monkeypatch.delattr(builtins, CONSUMERS[1], raising=False)
        with pytest.raises(NameError, match=CONSUMERS[1]):
            fail.detect_fail_open_patterns({'a.py': SOURCE})
        assert calls == ['first']
