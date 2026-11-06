"""Caller attribution and bounded formatting before excerpt truncation."""

import pytest

from core.audit import caller_context, context


def edges():
    return {'call_edges': [
        {'caller': 'wrong', 'caller_file': 'wrong.c', 'callee': 'handle', 'callee_file': 'other.c'},
        {'caller': 'right', 'caller_file': 'right.c', 'callee': 'handle', 'callee_file': 'target.c'},
        {'caller': 'legacy', 'caller_file': 'legacy.c', 'callee': 'handle'},
    ]}


def test_fallback_callers_belong_to_the_requested_callee_file():
    callers = context._find_callers(None, 'target.c', 'handle', context_map=edges())
    assert [c['name'] for c in callers] == ['right', 'legacy']


def test_unknown_target_file_preserves_legacy_name_lookup():
    callers = context._find_callers(None, '', 'handle', context_map=edges())
    assert [c['name'] for c in callers] == ['wrong', 'right', 'legacy']


def test_unrelated_callers_do_not_consume_the_public_cap(tmp_path, monkeypatch):
    for name in ['wrong', 'right', 'legacy']:
        (tmp_path / f'{name}.c').write_text(f'void {name}(void) {{ handle(); }}\n')
    reads = []
    real_read = context._read_target_text

    def read(path):
        reads.append(path.name)
        return real_read(path)

    monkeypatch.setattr(context, '_read_target_text', read)
    callers = context.collect_caller_call_sites(
        None, 'target.c', 'handle', tmp_path, max_callers=1, context_map=edges(),
    )
    assert [c['name'] for c in callers] == ['right']
    assert 'void right' in callers[0]['call_site']
    assert reads == ['right.c']


def test_entry_does_not_format_an_entire_long_source_line(tmp_path, monkeypatch):
    formatted_lengths = []

    class Line(str):
        def __getitem__(self, key):
            return Line(super().__getitem__(key))

        def __format__(self, spec):
            formatted_lengths.append(len(self))
            return super().__format__(spec)

    (tmp_path / 'caller.c').write_text('placeholder\n')
    line = Line('x' * (2 * 1024 * 1024))
    monkeypatch.setattr(context, '_read_target_line_window', lambda *args: [line])
    callers = [{'file': 'caller.c', 'name': 'f', 'line_start': 1}]
    inventory = {'files': [{'path': 'caller.c', 'items': [
        {'name': 'f', 'line_start': 1, 'line_end': 1},
    ]}]}
    caller_context.enrich_caller_entries(callers, tmp_path, inventory)
    marker = '\n[truncated]'
    expected = ('   1  ' + 'x' * caller_context.CALLER_ENTRY_CHARS)
    expected = expected[:caller_context.CALLER_ENTRY_CHARS - len(marker)] + marker
    assert callers[0]['caller_entry'] == expected
    assert formatted_lengths
    assert max(formatted_lengths) <= caller_context.CALLER_ENTRY_CHARS + 1


@pytest.mark.parametrize('cap', [16, 31, 1200])
@pytest.mark.parametrize('with_doc', [False, True])
def test_entry_matches_full_format_then_truncate(tmp_path, monkeypatch, cap, with_doc):
    monkeypatch.setattr(caller_context, 'CALLER_ENTRY_CHARS', cap)
    before = ['/** Caller contract. */'] if with_doc else []
    body = ['void f(void) {', '  ' + '界' * 3000, '}', 'unrelated();']
    (tmp_path / 'caller.c').write_text('\n'.join(before + body) + '\n')
    first = len(before) + 1
    callers = [{'file': 'caller.c', 'name': 'f', 'line_start': first}]
    inventory = {'files': [{'path': 'caller.c', 'items': [
        {'name': 'f', 'line_start': first, 'line_end': first + 2},
    ]}]}
    caller_context.enrich_caller_entries(callers, tmp_path, inventory)
    expected = '\n'.join(f'{first + i:4d}  {line}' for i, line in enumerate(body[:3]))
    if with_doc:
        expected = '   1  /** Caller contract. */\n' + expected
    if len(expected) > cap:
        marker = '\n[truncated]'
        expected = expected[:cap - len(marker)] + marker
    assert callers[0]['caller_entry'] == expected
    assert 'unrelated' not in callers[0]['caller_entry']
