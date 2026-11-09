"""Curated SQL recovery preserves original sweep admission and evidence caps."""

import pytest

from core.audit import sweep
from core.detectors import python_sql
from core.testing.module_views import scoped_function_imports
from packages.semgrep import runner
from packages.semgrep.models import SemgrepResult


def _source(tmp_path):
    target = tmp_path / 'target'
    target.mkdir()
    raw = b'def subject(cursor, int):\n    cursor.execute(int(input()))\n'
    (target / 'subject.py').write_bytes(raw)
    return target, raw


def test_recovered_match_retains_detection_only_outcome_and_original_scope(tmp_path):
    target, raw = _source(tmp_path)
    calls = []

    def base(path, config, **kwargs):
        calls.append('base')
        assert path == target / 'subject.py'
        return SemgrepResult(returncode=0, findings=[], files_examined=[str(path)])

    def recover(root, files, **kwargs):
        calls.append('recovery')
        assert root == target and files == ['subject.py']
        assert kwargs['expected'] == {'subject.py': raw}
        assert kwargs['out_dir'] is None
        return python_sql.SqlRecoveryResult('complete', matches=({
            'file': 'subject.py', 'line': 2, 'column': 20, 'line_end': 2, 'column_end': 32,
            'rule_id': python_sql.RULE_ID, 'message': 'lead', 'prepared_view': 'python-builtin-int',
            'source_sha256': 'a' * 64,
        },), selected=1, prepared=1)

    with scoped_function_imports(sweep, ['run_semgrep_sweep'], {
        'packages.semgrep.runner': runner, 'core.detectors.python_sql': python_sql,
    }) as owned:
        native = getattr(owned, 'packages.semgrep.runner')
        native.is_available = lambda: True
        native.run_rule = base
        getattr(owned, 'core.detectors.python_sql').recover_python_sql = recover
        result = sweep.run_semgrep_sweep(
            target_path=target, file_path='subject.py', function_name='subject',
            rule_config=str(python_sql.RULE_SOURCE), line_start=1, line_end=2,
        )
    assert calls == ['base', 'recovery']
    assert result.outcome == 'inconclusive'
    assert result.matches[0]['line'] == 2
    assert result.matches[0]['prepared_view'] == 'python-builtin-int'
    assert result.details['python_sql_preparation']['prepared'] == 1
    assert 'detection-only' in result.details['reason']


@pytest.mark.parametrize('witness,curated', [(False, True), (True, False)])
def test_unwitnessed_or_operator_rules_do_not_activate_recovery(tmp_path, witness, curated):
    target, _ = _source(tmp_path)
    config = python_sql.RULE_SOURCE
    if not curated:
        config = tmp_path / 'operator.yaml'
        config.write_text(f'rules:\n- id: {python_sql.RULE_ID}\n  pattern: int(...)\n')
    calls = []
    def base(path, config, **kwargs):
        calls.append('base')
        return SemgrepResult(returncode=0, findings=[], files_examined=[str(path)] if witness else [])
    def recover(*args, **kwargs):
        pytest.fail('recovery bypassed config ownership or scanned witness')
    with scoped_function_imports(sweep, ['run_semgrep_sweep'], {
        'packages.semgrep.runner': runner, 'core.detectors.python_sql': python_sql,
    }) as owned:
        native = getattr(owned, 'packages.semgrep.runner')
        native.is_available = lambda: True
        native.run_rule = base
        getattr(owned, 'core.detectors.python_sql').recover_python_sql = recover
        result = sweep.run_semgrep_sweep(target_path=target, file_path='subject.py',
                                        function_name='subject', rule_config=str(config))
    assert calls == ['base']
    assert result.outcome == ('refuted' if witness else 'inconclusive')


def test_partial_preparation_cannot_become_refutation(tmp_path):
    target, _ = _source(tmp_path)
    with scoped_function_imports(sweep, ['run_semgrep_sweep'], {
        'packages.semgrep.runner': runner, 'core.detectors.python_sql': python_sql,
    }) as owned:
        native = getattr(owned, 'packages.semgrep.runner')
        native.is_available = lambda: True
        native.run_rule = lambda path, config, **kwargs: SemgrepResult(
            returncode=0, findings=[], files_examined=[str(path)])
        getattr(owned, 'core.detectors.python_sql').recover_python_sql = lambda *a, **kw: python_sql.SqlRecoveryResult(
            'partial', limitations=(('subject.py', 'source differs from admitted snapshot'),),
            selected=1, prepared=0, reason='no prepared candidate files')
        result = sweep.run_semgrep_sweep(target_path=target, file_path='subject.py',
                                        function_name='subject', rule_config=str(python_sql.RULE_SOURCE))
    assert result.outcome == 'inconclusive' and result.matches == []
    assert result.details['python_sql_preparation']['limitations'] == [('subject.py', 'source differs from admitted snapshot')]


def test_content_probed_python_target_keeps_its_original_filename(tmp_path):
    target, raw = _source(tmp_path)
    (target / 'subject.py').rename(target / 'subject')
    calls = []
    def base(path, config, **kwargs):
        calls.append('base')
        assert path == target / 'subject'
        assert kwargs['extra_args'] == ['--scan-unknown-extensions']
        return SemgrepResult(returncode=0, findings=[], files_examined=[str(path)])
    def recover(root, files, **kwargs):
        calls.append('recovery')
        assert files == ['subject'] and kwargs['expected'] == {'subject': raw}
        return python_sql.SqlRecoveryResult('complete', matches=({
            'file': 'subject', 'line': 2, 'rule_id': python_sql.RULE_ID,
            'prepared_view': 'python-builtin-int',
        },), selected=1, prepared=1)
    with scoped_function_imports(sweep, ['run_semgrep_sweep'], {
        'packages.semgrep.runner': runner, 'core.detectors.python_sql': python_sql,
    }) as owned:
        native = getattr(owned, 'packages.semgrep.runner')
        native.is_available = lambda: True
        native.run_rule = base
        getattr(owned, 'core.detectors.python_sql').recover_python_sql = recover
        result = sweep.run_semgrep_sweep(target_path=target, file_path='subject', function_name='subject',
                                        rule_config=str(python_sql.RULE_SOURCE), language='python')
    assert calls == ['base', 'recovery']
    assert result.outcome == 'inconclusive'
    assert result.matches[0]['file'] == 'subject'


@pytest.mark.parametrize('status', ['partial', 'error', 'unavailable'])
def test_incomplete_recovery_is_not_reused_by_sweep_memo(status):
    from core.audit.sweep_memo import SweepMemo

    memo = SweepMemo()
    key = ('semgrep', (('source', 'fixture'),))
    incomplete = sweep.SweepResult(tool='semgrep', file_path='subject.py', function_name='subject',
                                   outcome='inconclusive',
                                   details={'python_sql_preparation': {'status': status}})
    memo.put(key, incomplete)
    assert memo.get(key) is None
    complete = sweep.SweepResult(tool='semgrep', file_path='subject.py', function_name='subject',
                                 outcome='inconclusive',
                                 details={'python_sql_preparation': {'status': 'complete'}})
    memo.put(key, complete)
    assert memo.get(key).outcome == 'inconclusive'
