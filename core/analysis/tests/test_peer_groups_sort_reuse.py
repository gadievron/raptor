"""Sort reuse must not suppress foreign callbacks or retain exposed sets."""
import builtins
from pathlib import Path

import pytest

from core.analysis import peer_groups as original
from core.testing.module_views import module_function_view


def _functions(names=('open_alpha', 'close_alpha', 'encode_beta', 'decode_beta')):
    return [{'name': name, 'file': 'owned.c', 'line': line}
            for line, name in enumerate(names, 1)]


def _sort_count(view):
    return len(view._PAIR_PATTERNS) + len(view._SUFFIX_PAIRS)


def test_foreign_sorter_keeps_every_call():
    calls = []

    def sorter(values):
        calls.append(tuple(builtins.sorted(values)))
        return builtins.sorted(values)

    view = module_function_view(original, bindings={'sorted': sorter})
    groups = view._paired_operation_groups(_functions())
    assert len(calls) == _sort_count(view)
    assert [group.group_id for group in groups] == [
        'pair:encode_beta:decode_beta', 'pair:open_alpha:close_alpha',
    ]


def test_foreign_sorter_preserves_later_error_identity():
    calls = []
    sentinel = RuntimeError('owned later-sort failure')

    def sorter(values):
        calls.append(None)
        if len(calls) == 2:
            raise sentinel
        return builtins.sorted(values)

    view = module_function_view(original, bindings={'sorted': sorter})
    with pytest.raises(RuntimeError) as raised:
        view._paired_operation_groups(_functions())
    assert raised.value is sentinel
    assert len(calls) == 2


def test_foreign_sorter_mutation_changes_subsequent_families():
    calls = []

    def sorter(values):
        calls.append(None)
        if len(calls) == 2:
            values.discard('close_alpha')
        return builtins.sorted(values)

    view = module_function_view(original, bindings={'sorted': sorter})
    assert [group.group_id for group in view._paired_operation_groups(_functions())] == [
        'pair:encode_beta:decode_beta',
    ]
    assert len(calls) == _sort_count(view)


def test_restored_sorter_does_not_reenable_cache_after_set_exposure():
    retained = []
    mutated = []
    view = module_function_view(original)

    def sorter(values):
        retained.append(values)
        view.sorted = builtins.sorted
        return builtins.sorted(values)

    class Matcher:
        def match(self, value):
            # The second prefix family runs after a naive native-sort cache
            # could have restarted. The foreign sorter retained this set.
            retained[0].discard('close_alpha')
            mutated.append(None)
            return original._PAIR_PATTERNS[1][0].match(value)

    view.sorted = sorter
    view._PAIR_PATTERNS = list(original._PAIR_PATTERNS)
    view._PAIR_PATTERNS[1] = (Matcher(), original._PAIR_PATTERNS[1][1])
    assert [group.group_id for group in view._paired_operation_groups(_functions())] == [
        'pair:encode_beta:decode_beta',
    ]
    assert len(retained) == 1
    assert mutated


def test_self_restoring_set_builder_cannot_admit_retained_native_set():
    retained = []
    view = module_function_view(original)

    def builder(values=()):
        names = builtins.set(values)
        # _name_index first constructs an ambiguity set. Only expose/restore
        # at the later constructor that receives the native name dictionary.
        if isinstance(values, dict):
            retained.append(names)
            view.set = builtins.set
        return names

    class Matcher:
        def match(self, value):
            retained[0].discard('close_alpha')
            return original._PAIR_PATTERNS[0][0].match(value)

    view.set = builder
    view._PAIR_PATTERNS = list(original._PAIR_PATTERNS)
    view._PAIR_PATTERNS[0] = (Matcher(), original._PAIR_PATTERNS[0][1])
    assert [group.group_id for group in view._paired_operation_groups(_functions())] == [
        'pair:encode_beta:decode_beta',
    ]
    assert len(retained) == 1


def test_foreign_name_collection_is_not_iterated_by_eligibility():
    iterations = []

    class Names:
        def __init__(self, values):
            self.values = builtins.set(values)

        def __iter__(self):
            iterations.append(None)
            return iter(self.values)

        def __contains__(self, name):
            return name in self.values

    def builder(values=()):
        return Names(values) if values else builtins.set()

    view = module_function_view(original, bindings={'set': builder})
    assert len(view._paired_operation_groups(_functions())) == 2
    assert len(iterations) == _sort_count(view)


def test_string_subclass_retains_repeated_comparison_callbacks():
    comparisons = []

    class Name(str):
        def __lt__(self, other):
            comparisons.append(None)
            return str.__lt__(self, other)

    names = [Name(name) for name in ('open_alpha', 'close_alpha', 'encode_beta', 'decode_beta')]
    builtins.sorted(builtins.set(names))
    per_sort = len(comparisons)
    comparisons.clear()
    assert len(original._paired_operation_groups(_functions(names))) == 2
    assert len(comparisons) == per_sort * _sort_count(original)


def test_sorter_adapted_before_private_import_is_not_trusted():
    calls = []

    def sorter(values):
        calls.append(None)
        return builtins.sorted(values)

    namespace = {
        '__name__': original.__name__, '__package__': original.__package__,
        '__builtins__': dict(vars(builtins), sorted=sorter),
    }
    exec(compile(Path(original.__file__).read_text(), original.__file__, 'exec'), namespace)
    assert namespace['_NATIVE_NAME_SORT'] is None
    namespace['_paired_operation_groups'](_functions())
    assert len(calls) == _sort_count(original)


def test_temporary_sorter_released_before_first_match():
    events = []
    retained = []
    view = module_function_view(original)

    class Sorter:
        def __call__(self, values):
            events.append('sort')
            retained.append(values)
            view.sorted = builtins.sorted
            return builtins.sorted(values)

        def __del__(self):
            events.append('release')
            retained[0].discard('close_alpha')

    class Matcher:
        def match(self, value):
            events.append('match')
            return original._PAIR_PATTERNS[0][0].match(value)

    view.sorted = Sorter()
    view._PAIR_PATTERNS = list(original._PAIR_PATTERNS)
    view._PAIR_PATTERNS[0] = (Matcher(), original._PAIR_PATTERNS[0][1])
    groups = view._paired_operation_groups(_functions())
    assert events[:3] == ['sort', 'release', 'match']
    assert [group.group_id for group in groups] == ['pair:encode_beta:decode_beta']
