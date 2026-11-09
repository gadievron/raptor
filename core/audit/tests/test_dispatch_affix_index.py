"""Native affix indexing preserves routing and observable foreign callbacks."""

from core.audit import dispatch_completeness as dispatch
from core.testing.module_views import module_function_view


def sources(size=40, produced='status_new'):
    keys = [f'status_key_{i:03}' for i in range(size)]
    return {
        'table.py': 'HANDLERS = {' + ','.join(repr(k) + ': handler' for k in keys) + '}\n',
        'producer.py': 'tag = ' + repr(produced) + '\n',
    }


def test_native_wide_table_reaches_index_and_retains_cross_file_gap(monkeypatch):
    original = dispatch._table_affix_index
    indices = []

    def capture(table, native_sites):
        index = original(table, native_sites)
        indices.append(index)
        return index

    monkeypatch.setattr(dispatch, '_table_affix_index', capture)
    gaps = dispatch.find_dispatch_gaps({}, sources())
    assert len(indices) == 1 and indices[0] is not None
    assert [(g.missing_key, g.produced_by, g.confidence) for g in gaps] == [
        ('status_new', 'producer.py:1', 'medium'),
    ]


def test_tiny_table_retains_unindexed_path(monkeypatch):
    original = dispatch._table_affix_index
    indices = []

    def capture(table, native_sites):
        index = original(table, native_sites)
        indices.append(index)
        return index

    monkeypatch.setattr(dispatch, '_table_affix_index', capture)
    assert len(dispatch.find_dispatch_gaps({}, sources(2))) == 1
    assert indices == [None]


def test_stateful_affix_provider_keeps_both_calls(monkeypatch):
    calls = []

    def provider(candidate, keys):
        calls.append(candidate)
        return len(calls) % 2 == 1

    monkeypatch.setattr(dispatch, '_shares_affix', provider)
    assert dispatch.find_dispatch_gaps({}, sources()) == []
    assert calls == ['status_new', 'status_new']


def test_changed_default_keeps_helper_semantics_in_private_view():
    view = module_function_view(dispatch)
    view._AFFIX_CHECK_IMPL = view._shares_affix
    view._AFFIX_SITES_IMPL = view._site_prefixes
    view._AFFIX_GAP_INIT = dispatch.DispatchGap.__init__
    table = dispatch.DispatchTable('table.py', '<module>', 1, {'abc_' + str(i) for i in range(40)}, 'dict')
    assert view._table_affix_index(table, True) is not None
    view._shares_affix.__defaults__ = (0,)
    assert view._table_affix_index(table, True) is None
    data = {
        'table.py': 'HANDLERS = {' + ','.join(repr(k) + ': handler' for k in table.keys) + '}\n',
        'producer.py': 'tag = "zzzz"\n',
    }
    gaps = view.find_dispatch_gaps({}, data)
    assert [g.missing_key for g in gaps] == ['zzzz']
    assert dispatch._shares_affix.__defaults__ == (3,)


def test_foreign_key_set_is_not_enumerated_by_index_builder():
    class Keys(set):
        def __iter__(self):
            raise AssertionError('foreign set enumerated by native eligibility')

    table = dispatch.DispatchTable('table.py', '<module>', 1, Keys(str(i) for i in range(40)), 'dict')
    assert dispatch._table_affix_index(table, True) is None


def test_unicode_prefixes_and_suffixes_keep_character_boundaries():
    keys = {f'αβγ_{i}' for i in range(20)} | {f'{i}_ωψχ' for i in range(20)}
    table = dispatch.DispatchTable('table.py', '<module>', 1, keys, 'dict')
    prefix, suffix = dispatch._table_affix_index(table, True)
    for candidate in ['αβγnew', 'newωψχ', 'αβ', '', 'unrelated']:
        indexed = len(candidate) >= 3 and (candidate[:3] in prefix or candidate[-3:] in suffix)
        assert indexed == dispatch._shares_affix(candidate, keys)


def test_foreign_line_callback_can_mutate_keys_before_next_candidate(monkeypatch):
    tables = []
    extract_tables = dispatch._extract_dict_tables
    producers = dispatch._find_string_producers

    def capture_tables(tree, parents, file):
        rows = extract_tables(tree, parents, file)
        tables.extend(rows)
        return rows

    class Line:
        def __format__(self, spec):
            tables[0].keys.clear()
            return '1'

    def foreign_lines(tree, file):
        rows = producers(tree, file)
        return [(value, Line()) for value, _ in rows] if file == 'producer.py' else []

    monkeypatch.setattr(dispatch, '_extract_dict_tables', capture_tables)
    monkeypatch.setattr(dispatch, '_find_string_producers', foreign_lines)
    data = sources()
    data['producer.py'] += 'other = "status_other_new"\n'
    assert len(dispatch.find_dispatch_gaps({}, data)) == 1
    assert tables[0].keys == set()


def test_foreign_gap_factory_can_mutate_keys_before_next_candidate(monkeypatch):
    original = dispatch.DispatchGap
    calls = []

    def factory(**values):
        calls.append(values['missing_key'])
        gap = original(**values)
        values['table'].keys.clear()
        return gap

    producers = dispatch._find_string_producers
    monkeypatch.setattr(dispatch, '_find_string_producers',
                        lambda tree, file: producers(tree, file) if file == 'producer.py' else [])
    monkeypatch.setattr(dispatch, 'DispatchGap', factory)
    data = sources()
    data['producer.py'] += 'other = "status_other_new"\n'
    assert len(dispatch.find_dispatch_gaps({}, data)) == 1
    assert len(calls) == 1


def test_foreign_all_result_is_not_given_new_truthiness_calls():
    class Truth:
        def __bool__(self):
            raise AssertionError('foreign result received an extra bool call')

    view = module_function_view(dispatch, bindings={'all': lambda values: Truth()})
    assert view.find_dispatch_gaps({}, {'producer.py': 'tag = "status_new"\n'}) == []


def test_fully_handled_table_never_builds_unused_index(monkeypatch):
    def unexpected(*args):
        raise AssertionError('built an index without an unhandled candidate')

    monkeypatch.setattr(dispatch, '_table_affix_index', unexpected)
    data = sources()
    data['producer.py'] = ''
    assert dispatch.find_dispatch_gaps({}, data) == []


def test_foreign_affix_result_keeps_original_temporary_lifetime(monkeypatch):
    import gc

    producers = dispatch._find_string_producers
    monkeypatch.setattr(dispatch, '_find_string_producers',
                        lambda tree, file: producers(tree, file) if file == 'producer.py' else [])
    calls = []

    class Decision:
        def __init__(self, keys, clear):
            self.keys = keys
            self.value = bool(keys)
            self.clear = clear

        def __bool__(self):
            return self.value

        def __del__(self):
            if self.clear:
                self.keys.clear()

    def provider(candidate, keys):
        gc.collect()  # Make liveness independent of immediate reference counting.
        calls.append(candidate)
        return Decision(keys, len(calls) % 2 == 0)

    monkeypatch.setattr(dispatch, '_shares_affix', provider)
    data = sources()
    data['producer.py'] += 'other="status_other_new"\nlast="status_last_new"\n'
    assert len(dispatch.find_dispatch_gaps({}, data)) == 1
    assert len(calls) == 4


def test_wide_index_retains_exact_noise_discard_count(caplog):
    import logging

    data = sources()
    rows = ''.join('tag=' + repr(f'status_new_{i}') + '\n' for i in range(11) for _ in range(100))
    data['producer.py'] = rows
    data['table.py'] += rows
    with caplog.at_level(logging.DEBUG, logger=dispatch.__name__):
        assert dispatch.find_dispatch_gaps({}, data) == []
    assert 'dropping 55 gaps' in caplog.text


def test_constructor_descriptor_is_not_called_by_eligibility(monkeypatch):
    original = dispatch.DispatchGap.__init__

    class Initialiser:
        def __get__(self, instance, owner):
            if instance is None:
                raise AssertionError('eligibility executed constructor descriptor')
            return original.__get__(instance, owner)

    monkeypatch.setattr(dispatch.DispatchGap, '__init__', Initialiser())
    assert len(dispatch.find_dispatch_gaps({}, sources())) == 1


def test_table_field_descriptor_is_not_called_by_eligibility(monkeypatch):
    table = dispatch.DispatchTable('table.py', '<module>', 1, {str(i) for i in range(40)}, 'dict')
    assert dispatch._table_affix_index(table, True) is not None

    def unexpected(instance):
        raise AssertionError('eligibility executed table field descriptor')

    monkeypatch.setattr(dispatch.DispatchTable, 'keys', property(unexpected), raising=False)
    assert dispatch._table_affix_index(table, True) is None


def test_changed_helper_code_keeps_live_provider_semantics():
    view = module_function_view(dispatch)
    view._AFFIX_CHECK_IMPL = view._shares_affix
    view._AFFIX_SITES_IMPL = view._site_prefixes
    view._AFFIX_GAP_INIT = dispatch.DispatchGap.__init__
    table = dispatch.DispatchTable('table.py', '<module>', 1, {'abc_' + str(i) for i in range(40)}, 'dict')
    assert view._table_affix_index(table, True) is not None

    def universal(candidate, keys, min_affix=3):
        return True

    view._shares_affix.__code__ = universal.__code__
    assert view._table_affix_index(table, True) is None
    data = {
        'table.py': 'HANDLERS = {' + ','.join(repr(k) + ': handler' for k in table.keys) + '}\n',
        'producer.py': 'tag = "zzzz"\n',
    }
    assert [g.missing_key for g in view.find_dispatch_gaps({}, data)] == ['zzzz']
