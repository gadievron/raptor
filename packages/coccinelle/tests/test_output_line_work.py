"""Output processing keeps evidence and diagnostics with bounded line work."""

import json

import pytest

from packages.coccinelle import runner


def record(prefix='COCCIRESULT-fresh:', **fields):
    return prefix + json.dumps({'file': 'source.c', 'line': 12, 'col': 3, 'rule': 'sample', **fields})


def test_absent_native_markers_skip_line_processing(monkeypatch):
    def unexpected(*args):
        raise AssertionError('marker-free output was split into lines')

    monkeypatch.setattr(runner, '_output_lines', unexpected)
    output = 'ordinary output\n' * 3000
    diagnostics = []
    assert runner._parse_results(output, 'sample', nonce='fresh', diagnostics=diagnostics) == []
    assert list(runner._forged_marker_lines(output, 'fresh')) == []
    assert diagnostics == []


def test_wrong_nonce_still_reaches_forgery_diagnostics():
    output = record('COCCIRESULT-other:')
    diagnostics = []
    assert runner._parse_results(output, 'sample', nonce='fresh', diagnostics=diagnostics) == []
    assert list(runner._forged_marker_lines(output, 'fresh')) == [output[:200]]
    assert diagnostics == []


def test_dense_native_output_uses_shared_display_iteration(monkeypatch):
    actual = runner.iter_splitlines
    calls = []

    def observed(output):
        calls.append(output)
        return actual(output)

    monkeypatch.setattr(runner, 'iter_splitlines', observed)
    output = 'ordinary output\r\n' * 2000
    assert list(runner._output_lines(output)) == output.splitlines()
    assert len(calls) == 1 and calls[0] is output


@pytest.mark.parametrize('output', ['short\noutput', 'x' * 100000], ids=['short', 'large-single-line'])
def test_small_and_sparse_streams_keep_direct_splitting(monkeypatch, output):
    def unexpected(*args):
        raise AssertionError('sparse output used chunked display splitting')

    monkeypatch.setattr(runner, 'iter_splitlines', unexpected)
    assert list(runner._output_lines(output)) == output.splitlines()


@pytest.mark.parametrize('separator', ['\n', '\r\n', '\r', '\v', '\f', '\x85', '\u2028', '\u2029'],
                         ids=['lf', 'crlf', 'cr', 'vt', 'ff', 'nel', 'ls', 'ps'])
def test_parsers_keep_display_line_boundaries_and_error_counts(separator):
    output = separator.join([
        'ordinary output', record(), record('COCCIRESULT-other:'),
        'COCCIRESULT-fresh:not-json', 'COCCIRESULT-fresh:[]',
        record(file=''), '  syntax error: broken input  ', 'HANDLING: parse error',
    ])
    # Force dense LF-prefix admission, including when payload separators differ.
    output = 'padding\n' * 2200 + output
    diagnostics = []
    matches = runner._parse_results(output, 'sample', nonce='fresh', diagnostics=diagnostics)
    assert len(matches) == 1
    assert matches[0].file == 'source.c' and matches[0].line == 12
    assert diagnostics == ['Coccinelle emitted 3 malformed structured result row(s)']
    assert list(runner._forged_marker_lines(output, 'fresh')) == [record('COCCIRESULT-other:')[:200]]
    assert runner._parse_errors(output) == ['syntax error: broken input']


def test_output_adapter_retains_its_splitlines_override():
    calls = []

    class Output(str):
        def splitlines(self):
            calls.append(self)
            return [record(), record('COCCIRESULT-other:'), 'fatal error: owned']

    output = Output('raw content contains no markers')
    matches = runner._parse_results(output, 'sample', nonce='fresh')
    assert len(matches) == 1 and matches[0].file == 'source.c'
    assert list(runner._forged_marker_lines(output, 'fresh')) == [record('COCCIRESULT-other:')[:200]]
    assert runner._parse_errors(output) == ['fatal error: owned']
    assert len(calls) == 3 and all(value is output for value in calls)
