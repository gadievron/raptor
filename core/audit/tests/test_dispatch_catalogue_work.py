"""Callback fragments share source preparation while preserving evidence packets."""

import pytest

from core.audit.cross_entry.dispatch import dispatch_catalogue
from core.audit.cross_entry.model import Access, AccessIndex, Call, Function


def catalogue(source, *, calls=True):
    index = AccessIndex()
    index.functions['f'] = Function('f', 'a.c', 'f', 10, 20, 100,
                                    100 + len(source.encode()), '', source, params=['ctx'])
    offset = 0
    for i, line in enumerate(source.split('\n')):
        if 'ctx->' in line:
            start = 100 + offset + len(line[:line.index('ctx->')].encode())
            index.accesses.append(Access(f'a{i}', 'f', 'a.c', 10+i, start, start+6,
                                         'T', 'ctx', 'field', 'write', 'ctx->field',
                                         object_origin='parameter:ctx'))
            if calls:
                index.calls.append(Call('f', 'work', ['ctx->field'], 10+i,
                                        start_byte=100+offset, end_byte=100+offset+len(line.encode()),
                                        argument_kinds=['binary_expression']))
        offset += len(line.encode())+1
    index.declarations['binding'] = {'file': 'setup.c', 'line': 1, 'source': 'ops.run = f;'}
    return index, [{'target': 'f', 'evidence_id': 'binding', 'installer': 'setup'}]


def effects(emitted):
    return [fragment for fragment, _ in emitted if fragment['kind'] == 'effect_fragment']


def test_function_encoding_is_shared_across_call_fragments():
    class Source(str):
        encodes = 0
        def encode(self, *args, **kwargs):
            self.encodes += 1
            return super().encode(*args, **kwargs)

    source = Source('/* café */\nwork(ctx->a);\nwork(ctx->b);\nwork(ctx->c);\n')
    index, rows = catalogue(source)
    source.encodes = 0
    emitted, omitted = dispatch_catalogue(index, rows, 10000)
    assert [f['source'] for f in effects(emitted)] == ['work(ctx->a);', 'work(ctx->b);', 'work(ctx->c);']
    assert source.encodes == 1
    assert omitted == 0


def test_fallback_lines_are_prepared_once(monkeypatch):
    from core.audit.cross_entry import dispatch
    source = '/* header */\nctx->a = 1;\nctx->b = 2;\nctx->c = 3;\n'
    index, rows = catalogue(source, calls=False)
    original = dispatch.split_lines
    prepared = []
    def counted(text):
        prepared.append(text)
        return original(text)
    monkeypatch.setattr(dispatch, 'split_lines', counted)
    emitted, _ = dispatch_catalogue(index, rows, 10000)
    assert [f['line'] for f in effects(emitted)] == [11, 12, 13]
    assert [f['source'] for f in effects(emitted)] == ['ctx->a = 1;', 'ctx->b = 2;', 'ctx->c = 3;']
    assert prepared == [source]


@pytest.mark.parametrize('separator', ['\v', '\f', '\x85', '\u2028', '\r'],
                         ids=['VT', 'FF', 'NEL', 'LS', 'CR'])
def test_fallback_uses_scanner_line_numbers(separator):
    source = f'/* embedded {separator} separator */\nctx->a = 1;\n'
    index, rows = catalogue(source, calls=False)
    emitted, _ = dispatch_catalogue(index, rows, 10000)
    assert [(f['line'], f['source']) for f in effects(emitted)] == [(11, 'ctx->a = 1;')]


def test_calls_choose_smallest_enclosing_span_and_keep_order():
    source = 'outer(inner(ctx->a));\nctx->b = 1;\n'
    index, rows = catalogue(source, calls=False)
    index.calls = [Call('f', 'outer', [], 10, start_byte=100, end_byte=120),
                   Call('f', 'inner', [], 10, start_byte=106, end_byte=119)]
    emitted, _ = dispatch_catalogue(index, rows, 10000)
    assert [f['source'] for f in effects(emitted)] == ['inner(ctx->a)', 'ctx->b = 1;']
