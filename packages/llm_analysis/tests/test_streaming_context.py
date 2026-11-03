"""Finding and dataflow windows preserve legacy formatting and truncation."""

from itertools import product

import pytest

from core.source import read_text_capped, split_lines
from core.source.windows import read_text_line_window_capped
from packages.llm_analysis import agent
from packages.llm_analysis.agent import VulnerabilityContext


def make_context(root):
    return VulnerabilityContext({'finding_id': 'stream', 'rule_id': 'test',
        'file': 'a.c', 'startLine': 1, 'endLine': 1, 'message': 'm', 'tool': 'semgrep'}, root)


def legacy_views(lines, first, last, margin):
    if first:
        start = max(0, first - 1)
        end = min(len(lines), last or first)
        return ('\n'.join(lines[start:end]),
                '\n'.join(lines[max(0, start - margin):min(len(lines), end + margin)]))
    head = '\n'.join(lines[:agent.NO_LINE_INFO_HEAD_LINES])
    return head, head


@pytest.mark.parametrize('raw', [
    b'a\r\nb\n\nc\r\xff\nlast',
    'é🙂\nfirst\nsecond\npartial tail'.encode(),
    b'one giant line without any newline', b'',
])
def test_finding_and_dataflow_differential(tmp_path, monkeypatch, raw):
    path = tmp_path / 'a.c'
    path.write_bytes(raw)
    for cap in (0, 1, 3, 5, 10, 100):
        monkeypatch.setattr(agent, 'read_text_line_window_capped',
            lambda path, start, end: read_text_line_window_capped(path, start, end, max_chars=cap))
        monkeypatch.setattr(agent, 'read_text_capped',
            lambda path, **kw: read_text_capped(path, cap, **kw))
        content, _ = read_text_capped(path, cap, newline='')
        lines = split_lines(content)
        ctx = make_context(tmp_path)
        for first, last, margin in product((None, -2, 0, 1, 3, 100),
                                           (None, -2, 0, 1, 5, 100), (-2, 0, 1, 5)):
            ctx.start_line, ctx.end_line = first, last
            expected = legacy_views(lines, first, last, margin)
            assert ctx.read_vulnerable_code(margin)
            assert (ctx.full_code, ctx.surrounding_context) == expected, (cap, first, last, margin)
        for first, margin in product((-2, 0, 1, 3, 100), (-2, 0, 1, 5)):
            start = max(0, first - margin - 1)
            end = min(len(lines), first + margin)
            expected = '\n'.join(
                f'{">>>" if i == first - 1 else "   "} {i + 1:4d} | {lines[i].rstrip()}'
                for i in range(start, end))
            assert ctx._read_code_at_location('a.c', first, margin) == expected


def test_malformed_context_preserves_partial_state(tmp_path):
    (tmp_path / 'a.c').write_text('a\nb\nc\n')
    ctx = make_context(tmp_path)
    ctx.start_line, ctx.end_line = 2, 2
    ctx.surrounding_context = 'previous'
    assert ctx.read_vulnerable_code('invalid') is False
    assert ctx.full_code == 'b'
    assert ctx.surrounding_context == 'previous'


def test_reread_sees_changed_source(tmp_path):
    path = tmp_path / 'a.c'
    path.write_text('old\n')
    ctx = make_context(tmp_path)
    assert ctx.read_vulnerable_code(0)
    assert ctx.full_code == 'old'
    path.write_text('new\n')
    assert ctx.read_vulnerable_code(0)
    assert ctx.full_code == 'new'


def test_missing_and_traversal_messages_unchanged(tmp_path):
    ctx = make_context(tmp_path)
    assert ctx.read_vulnerable_code() is False
    assert ctx._read_code_at_location('a.c', 1) == '[File not found: a.c]'
    assert ctx._read_code_at_location('../outside.c', 1) == '[Path traversal blocked: ../outside.c]'
