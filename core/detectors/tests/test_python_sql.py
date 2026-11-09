"""SQL source identity, bounded preparation and staged result contracts."""
import ast
import shutil
import pytest

import json
from pathlib import Path
import re

from core.audit.tests._live_transport import run_pinned_subprocess
from core.detectors import semgrep
from core.testing.module_views import scoped_function_imports
from packages.semgrep import runner
from core.detectors.python_sql import (
    recover_python_sql as recover_batch,
    _prepare_source as prepare,
    _PreparationRefused as ViewRefused,
)


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep executable required")
def test_two_source_batch_uses_one_marker_and_one_native_scan(tmp_path):
    root = tmp_path / 'target'
    root.mkdir()
    sources = {
        'first.py': b'def shadow(cursor, int):\n    cursor.execute(f"SELECT {int(input())}")\n',
        'second.py': (b'def numeric(cursor):\n    cursor.execute(str(int(input())))\n'
                      b'def shadow(cursor):\n    def int(value):\n        return value\n'
                      + '    label="café"; cursor.execute(int(input()))\n'.encode()),
    }
    for name, raw in sources.items():
        (root / name).write_bytes(raw)
    calls, private = [], []

    def transport(cmd, *, capture_output, text, timeout, env):
        assert capture_output and text
        return run_pinned_subprocess(cmd, timeout=timeout, env=env,
                                     context='batched SQL identity prototype', skip_signals=(9,))

    def invoke(target, config, **kwargs):
        calls.append(target)
        private.append(target.parent)
        rule = json.loads(Path(config).read_text())['rules'][0]
        marker = re.search(r'RAPTOR_BUILTIN_INT_[0-9a-f]+_*',
                           rule['pattern-sanitizers'][0]['patterns'][2]['metavariable-regex']['regex'])[0]
        assert all(marker.encode() not in raw for raw in sources.values())
        prepared = list(target.glob('*.py'))
        assert len(prepared) == 2
        assert sum(marker.encode() in path.read_bytes() for path in prepared) == 1
        return runner.run_rule(target, config, subprocess_runner=transport, **kwargs)

    with scoped_function_imports(semgrep, ['_match'], {'packages.semgrep.runner': runner}) as owned:
        getattr(owned, 'packages.semgrep.runner').run_rule = invoke
        result = recover_batch(root, list(sources), out_dir=tmp_path / 'work', expected=sources)
    assert len(calls) == 1
    assert result.status == 'complete', result
    assert result.prepared == 2 and not result.limitations
    assert {(row['file'], row['line']) for row in result.matches} == {('first.py', 2), ('second.py', 6)}
    second = next(row for row in result.matches if row['file'] == 'second.py')
    assert second['column'] == sources['second.py'].splitlines()[5].index(b'int(input())') + 1
    assert second['column_end'] == second['column'] + len(b'int(input())')
    assert not result.verification_authority
    assert all((root / name).read_bytes() == raw for name, raw in sources.items())
    assert all(not path.exists() for path in private)


def test_batch_budgets_and_missing_witness_are_disclosed(tmp_path):
    from packages.semgrep.models import SemgrepResult

    root = tmp_path / 'target'
    root.mkdir()
    raw = b'def shadow(cursor, int):\n    cursor.execute(int(input()))\n'
    for name in ('first.py', 'second.py'):
        (root / name).write_bytes(raw)
    calls, private = [], []

    def invoke(target, config, **kwargs):
        paths = list(target.glob('*.py'))
        calls.append(len(paths))
        private.append(target.parent)
        # A successful engine exit without a scanned witness is incomplete,
        # even when no findings were returned.
        return SemgrepResult(name='draft', config=config, target=str(target), returncode=0,
                             findings=[], files_examined=[])

    with scoped_function_imports(semgrep, ['_match'], {'packages.semgrep.runner': runner}) as owned:
        getattr(owned, 'packages.semgrep.runner').run_rule = invoke
        result = recover_batch(root, ['first.py', 'second.py'], out_dir=tmp_path / 'work', max_files=1)
        assert result.status == 'partial' and result.prepared == 1
        assert result.limitations and 'scanned witness' in result.reason
        assert not result.matches and not result.verification_authority
        result = recover_batch(root, ['first.py'], out_dir=tmp_path / 'work', max_snapshot_bytes=8)
        assert result.status == 'partial' and result.prepared == 0
        assert any('byte budget' in reason for _, reason in result.limitations)
        result = recover_batch(root, [['invalid']], out_dir=tmp_path / 'work')
        assert result.status == 'partial' and result.prepared == 0
    assert calls == [1]
    assert all(not path.exists() for path in private)


def test_cached_coordinate_indexes_preserve_all_origin_points(tmp_path):
    import ast
    from dataclasses import replace

    import pytest
    from packages.semgrep.models import SemgrepFinding, SemgrepResult
    from core.detectors.python_sql import _render_marker
    from core.detectors.python_sql import _prepare_source as prepare, _PreparationRefused as ViewRefused

    root = tmp_path / 'target'
    root.mkdir()
    raw = ('def numeric(cursor):\n    cursor.execute(str(int(input())))\n'
           'def shadow(cursor, int):\n    label="café"; cursor.execute(int(input()))\n').encode()
    (root / 'subject.py').write_bytes(raw)
    original_view = prepare(root, 'subject.py')
    view = _render_marker(original_view, original_view.marker)
    reference = replace(view, span_starts=())
    assert view.span_starts == tuple(span[0] for span in view.spans)
    for offset in range(len(view.prepared) + 1):
        try:
            expected = reference.original_point(offset)
        except ViewRefused:
            with pytest.raises(ViewRefused):
                view.original_point(offset)
        else:
            assert view.original_point(offset) == expected

    def invoke(target, config, **kwargs):
        path = next(target.glob('*.py'))
        tree = ast.parse(path.read_bytes())
        shadow = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'shadow')
        execute = next(node for node in ast.walk(shadow)
                       if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'execute')
        query = execute.args[0]
        finding = SemgrepFinding(file=str(path), line=query.lineno, column=query.col_offset + 1,
                                 line_end=query.end_lineno, column_end=query.end_col_offset + 1,
                                 rule_id='fixture')
        return SemgrepResult(name='draft', config=config, target=str(target), returncode=0,
                             findings=[finding], files_examined=[str(path)])

    with scoped_function_imports(semgrep, ['_match'], {'packages.semgrep.runner': runner}) as owned:
        getattr(owned, 'packages.semgrep.runner').run_rule = invoke
        result = recover_batch(root, ['subject.py'], out_dir=tmp_path / 'work')
    assert result.status == 'complete', result
    assert len(result.matches) == 1
    row = result.matches[0]
    assert (row['file'], row['line'], row['column']) == ('subject.py', 4, raw.splitlines()[3].index(b'int(input())') + 1)


def test_snapshot_admission_and_original_byte_mapping(tmp_path):
    source = ('def builtin(cursor):\n'
              '    label = "café"; cursor.execute(str(int(input())))\n'
              'def shadow(cursor, int):\n'
              '    cursor.execute(int(input()))\n').encode()
    target = tmp_path / 'subject.py'
    target.write_bytes(source)
    view = prepare(tmp_path, 'subject.py', expected=source)
    assert view.has_uncertain_int
    assert view.marker.encode() not in source
    assert ast.dump(ast.parse(view.prepared)) == ast.dump(ast.parse(source))
    query = b'int(input())'
    prepared_start = view.prepared.index(b'int(')
    original_start = source.index(query)
    line_start = source.rfind(b'\n', 0, original_start) + 1
    assert view.original_point(prepared_start) == (2, original_start - line_start + 1)
    prepared_end = view.prepared.index(b'input()))') + len(b'input())')
    assert view.original_point(prepared_end) == (2, original_start - line_start + 1 + len(query))
    view.verify_source()
    for kwargs in ({'cap': 8}, {'node_cap': 2}, {'depth_cap': 2}, {'expected': b'stale'}):
        with pytest.raises(ViewRefused):
            prepare(tmp_path, 'subject.py', **kwargs)
    with pytest.raises(ViewRefused):
        prepare(tmp_path, '../subject.py')
    with pytest.raises(ViewRefused):
        view.original_point(-1)
    target.write_bytes(source + b'# changed\n')
    with pytest.raises(ViewRefused):
        view.verify_source()


def test_stale_source_refusal_and_interrupt_cleanup(tmp_path):
    import pytest

    from packages.semgrep.models import SemgrepResult

    root = tmp_path / 'target'
    root.mkdir()
    subject = root / 'subject.py'
    original = b'def shadow(cursor, int):\n    cursor.execute(int(input()))\n'
    calls, private_paths = [], []
    mode = 'stale'

    def invoke(target, config, **kwargs):
        calls.append(mode)
        assert target.exists() and Path(config).exists()
        private_paths.extend((target, Path(config), target.parent))
        if mode == 'interrupt':
            raise KeyboardInterrupt
        subject.write_bytes(original + b'# changed during match\n')
        return SemgrepResult(name='draft', config=config, target=str(target),
                             returncode=0, findings=[], files_examined=[str(target)])

    with scoped_function_imports(semgrep, ['_match'], {'packages.semgrep.runner': runner}) as owned:
        getattr(owned, 'packages.semgrep.runner').run_rule = invoke
        subject.write_bytes(original)
        result = recover_batch(root, ['subject.py'], out_dir=tmp_path / 'work', expected={'subject.py': original})
        assert result.status == 'error' and 'source changed' in result.reason
        assert not result.matches and not result.verification_authority
        assert all(not path.exists() for path in private_paths)
        mode = 'interrupt'
        subject.write_bytes(original)
        with pytest.raises(KeyboardInterrupt):
            recover_batch(root, ['subject.py'], out_dir=tmp_path / 'work', expected={'subject.py': original})
        assert all(not path.exists() for path in private_paths)
        subject.write_bytes(b'def numeric(cursor):\n    cursor.execute(str(int(input())))\n')
        result = recover_batch(root, ['subject.py'], out_dir=tmp_path / 'work')
        assert result.status == 'skipped' and not result.matches
    assert calls == ['stale', 'interrupt']


def test_tool_error_preview_is_bounded_and_escaped(tmp_path):
    from packages.semgrep.models import SemgrepResult

    root = tmp_path / 'target'
    root.mkdir()
    (root / 'subject.py').write_text('def shadow(cursor, int):\n    cursor.execute(int(input()))\n')
    private = []
    def invoke(target, config, **kwargs):
        private.append(target.parent)
        return SemgrepResult(returncode=2, errors=['\x1b[31m' + 'failure' * 1000] * 10)
    with scoped_function_imports(semgrep, ['_match'], {'packages.semgrep.runner': runner}) as owned:
        getattr(owned, 'packages.semgrep.runner').run_rule = invoke
        result = recover_batch(root, ['subject.py'], out_dir=tmp_path / 'work')
    assert result.status == 'error' and not result.matches
    assert len(result.reason) <= 1000 and '\x1b' not in result.reason
    assert '10 tool error(s)' in result.reason
    assert all(not path.exists() for path in private)


@pytest.mark.parametrize('expression', [
    'f"SELECT {int(input())}"',
    'str(((int))(input()))',
    'str(int \\\n        (input()))',
])
def test_trusted_unsupported_spelling_does_not_trigger_recovery(tmp_path, expression):
    root = tmp_path / 'target'
    root.mkdir()
    (root / 'subject.py').write_text(f'def numeric(cursor):\n    cursor.execute({expression})\n')
    def invoke(*args, **kwargs):
        pytest.fail('genuine builtin conversion should not start a recovery scan')
    with scoped_function_imports(semgrep, ['_match'], {'packages.semgrep.runner': runner}) as owned:
        getattr(owned, 'packages.semgrep.runner').run_rule = invoke
        result = recover_batch(root, ['subject.py'], out_dir=tmp_path / 'work')
    assert result.status == 'skipped' and not result.matches
    assert result.prepared == 0 and not result.limitations


def test_mixed_shadow_and_unsupported_trusted_conversion_discloses_refusal(tmp_path):
    root = tmp_path / 'target'
    root.mkdir()
    (root / 'subject.py').write_text(
        'def numeric(cursor):\n    cursor.execute(f"SELECT {int(input())}")\n'
        'def shadow(cursor, int):\n    cursor.execute(int(input()))\n')
    def invoke(*args, **kwargs):
        pytest.fail('an unfaithful mixed source view must not reach the engine')
    with scoped_function_imports(semgrep, ['_match'], {'packages.semgrep.runner': runner}) as owned:
        getattr(owned, 'packages.semgrep.runner').run_rule = invoke
        result = recover_batch(root, ['subject.py'], out_dir=tmp_path / 'work')
    assert result.status == 'partial' and not result.matches
    assert result.prepared == 0 and any('unsupported syntax' in reason for _, reason in result.limitations)
