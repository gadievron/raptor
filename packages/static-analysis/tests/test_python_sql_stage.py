"""Python SQL stage consumes witnessed paths and discloses preparation loss."""
import importlib.util
import json
from pathlib import Path
import sys
from unittest.mock import patch

import pytest

from core.detectors import python_sql
from core.testing.module_views import scoped_function_imports


@pytest.fixture
def scanner(monkeypatch):
    root = Path(__file__).resolve().parents[3]
    monkeypatch.setenv('RAPTOR_DIR', str(root))
    spec = importlib.util.spec_from_file_location('scoped_sql_scanner', root / 'packages/static-analysis/scanner.py')
    module = importlib.util.module_from_spec(spec)
    with patch.object(sys, 'path', sys.path.copy()):
        spec.loader.exec_module(module)
    return module


def test_stage_selects_only_originally_scanned_sources_and_returns_coverage_summary(tmp_path, scanner):
    root, out = tmp_path / 'target', tmp_path / 'out'
    root.mkdir(); out.mkdir()
    for name in ('selected.py', 'ignored.py'):
        (root / name).write_text('def subject(cursor, int):\n    cursor.execute(int(input()))\n')
    report = out / 'semgrep_injection.sarif'
    report.with_suffix('.json').write_text(json.dumps({
        'version': '1.79.0', 'paths': {'scanned': [str(root / 'selected.py')]}, 'errors': [],
    }))
    calls = []
    def recover(target, files, **kwargs):
        calls.append(files)
        assert target == root and kwargs['out_dir'] == out
        return python_sql.SqlRecoveryResult('complete', matches=({
            'file': 'selected.py', 'line': 2, 'column': 20, 'line_end': 2, 'column_end': 32,
            'rule_id': python_sql.RULE_ID, 'message': 'lead', 'level': 'error', 'source_sha256': 'a' * 64,
        },), selected=1, prepared=1)
    with scoped_function_imports(scanner, ['run_python_sql_stage'], {'core.detectors.python_sql': python_sql}) as owned:
        getattr(owned, 'core.detectors.python_sql').recover_python_sql = recover
        paths, summary = scanner.run_python_sql_stage(root, out, [str(python_sql.RULE_SOURCE.parent)], [str(report)])
    assert calls == [['selected.py']]
    assert summary.record['files_examined'] == [str(root / 'selected.py')]
    data = json.loads(Path(paths[0]).read_text())
    assert data['$schema']
    assert data['runs'][0]['tool']['driver']['rules'][0]['properties']['cwe'] == 'CWE-89'
    finding = data['runs'][0]['results'][0]
    assert finding['locations'][0]['physicalLocation']['artifactLocation']['uri'] == 'selected.py'
    assert finding['locations'][0]['physicalLocation']['region']['startColumn'] == 20
    assert finding['properties']['prepared_view'] == 'python-builtin-int'


def test_operator_config_with_same_id_does_not_activate_stage(tmp_path, scanner):
    config = tmp_path / 'operator.yaml'
    config.write_text(f'rules:\n- id: {python_sql.RULE_ID}\n')
    assert scanner.run_python_sql_stage(tmp_path, tmp_path, [str(config)], []) == ([], None)


def test_missing_original_metadata_is_reported_without_running_recovery(tmp_path, scanner):
    out = tmp_path / 'out'
    out.mkdir()
    paths, summary = scanner.run_python_sql_stage(tmp_path, out, [str(python_sql.RULE_SOURCE)],
                                                 [str(out / 'missing.sarif')])
    assert summary.input_errors == 1
    data = json.loads(Path(paths[0]).read_text())
    assert data['runs'][0]['results'] == []
    assert data['runs'][0]['invocations'][0]['toolExecutionNotifications'][0]['properties']['coverage_limitation']


def test_stage_omits_locations_already_reported_by_the_plain_pass(tmp_path, scanner):
    root, out = tmp_path / 'target', tmp_path / 'out'
    root.mkdir(); out.mkdir()
    source = root / 'subject.py'
    source.write_text('def subject(cursor, int):\n    cursor.execute(int(input()))\n    cursor.execute(int(input()))\n')
    report = out / 'semgrep_injection.sarif'
    report.with_suffix('.json').write_text(json.dumps({
        'version': '1.79.0', 'paths': {'scanned': [str(source)]}, 'errors': [],
        'results': [{'check_id': 'installed.rules.' + python_sql.RULE_ID, 'path': str(source),
                     'start': {'line': 2, 'col': 20}, 'end': {'line': 2, 'col': 32}}],
    }))
    rows = tuple({'file': 'subject.py', 'line': line, 'column': 20, 'line_end': line, 'column_end': 32,
                  'rule_id': python_sql.RULE_ID, 'message': 'lead', 'level': 'error',
                  'source_sha256': 'a' * 64} for line in (2, 3))
    with scoped_function_imports(scanner, ['run_python_sql_stage'], {'core.detectors.python_sql': python_sql}) as owned:
        getattr(owned, 'core.detectors.python_sql').recover_python_sql = lambda *a, **kw: python_sql.SqlRecoveryResult(
            'complete', matches=rows, selected=1, prepared=1)
        paths, summary = scanner.run_python_sql_stage(root, out, [str(python_sql.RULE_SOURCE)], [str(report)])
    results = json.loads(Path(paths[0]).read_text())['runs'][0]['results']
    assert len(summary.result_locations) == 1
    assert [row['locations'][0]['physicalLocation']['region']['startLine'] for row in results] == [3]
