"""Stack returns require corroboration, never a frontend warning alone."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

_spec = importlib.util.spec_from_file_location('compiler_stack_tests', Path(__file__).parents[1] / 'compiler_scan.py')
cs = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = cs
_spec.loader.exec_module(cs)


def test_unconfirmed_return_warning_is_not_a_scan_finding(tmp_path, monkeypatch):
    (tmp_path / 'x.c').write_text('int *f(void) { int x; return &x; }\n')
    monkeypatch.setattr(cs, '_gcc_analyzer', lambda: ('/trusted/gcc', 'json'))
    monkeypatch.setattr(cs, '_clang_path', lambda: None)
    monkeypatch.setattr(cs, '_suppression_vet', lambda *a: ('', ''))
    calls = []
    def run(cmd, **kw):
        calls.append(cmd)
        return SimpleNamespace(returncode=0, stderr=json.dumps([{
            'kind': 'warning', 'option': '-Wreturn-local-addr', 'message': 'returns local',
            'locations': [{'caret': {'file': str(tmp_path / 'x.c'), 'line': 1}}],
        }]))
    result = cs.analyze_tu(tmp_path, 'x.c', sandbox_run=run)
    assert result.ok and not result.diagnostics
    assert len(result.stack_return_candidates) == 1 and len(calls) == 1


def test_stack_metadata_survives_sarif_without_changing_other_findings():
    finding = {'rule_id': 'raptor.compiler.stack-return', 'file': 'x.c', 'line': 3,
               'message': 'local returned', 'compiler': 'clang', 'cwe': 'CWE-562',
               'corroborated_by': ['gcc', 'clang'], 'preprocessed_by': 'gcc'}
    report = cs.to_sarif(cs.CompilerScanResult(ok=True, findings=[finding]))
    result = report['runs'][0]['results'][0]
    assert result['properties']['corroborated_by'] == ['gcc', 'clang']
    assert result['properties']['cwe'] == 'CWE-562'
    assert result['properties']['preprocessed_by'] == 'gcc'


@pytest.mark.slow
def test_native_stack_returns_exclude_dead_and_compiler_specific_arms(tmp_path, monkeypatch):
    from core.audit import compiler_sweep
    compiler_sweep._reset_probe_cache()
    gcc, clang = cs._gcc_analyzer(), cs._clang_path()
    if gcc is None or clang is None:
        pytest.skip('requires GCC analyzer and Clang analyzer')
    repo = tmp_path / 'repo'
    repo.mkdir()
    source = '''extern void *malloc(__SIZE_TYPE__);
extern void free(void *);
int global;
int *bad_local(void) { int local=1; return &local; }
int *bad_array(void) { int local[4]={0}; return local; }
int *safe_dead(void) { int local=1; if(0) return &local; return &global; }
#if defined(__clang__)
#define RETURN_LOCAL 1
#else
#define RETURN_LOCAL 0
#endif
int *safe_compiler_branch(void) { int local=1; if(RETURN_LOCAL) return &local; return &global; }
int *safe_static(void) { static int value=1; return &value; }
int *safe_global(void) { return &global; }
int *safe_param(int *value) { return value; }
int *safe_heap(void) { return malloc(sizeof(int)); }
void bad_uaf(int *value) { free(value); *value=1; }
'''
    (repo / 'cases [*].c').write_text(source)
    walks = []
    derive = compiler_sweep._derive_include_dirs
    def include_dirs(target, directory):
        walks.append((target, directory))
        return derive(target, directory)
    monkeypatch.setattr(compiler_sweep, '_derive_include_dirs', include_dirs)
    monkeypatch.setattr(cs, '_derive_include_dirs', include_dirs)
    calls = []
    def run(cmd, **kw):
        calls.append((cmd, kw))
        return subprocess.run(cmd, check=False, **{
            k: kw[k] for k in ('capture_output', 'text', 'timeout', 'cwd') if k in kw
        })
    monkeypatch.setattr(cs, '_sandbox_runner', lambda: run)
    monkeypatch.setattr('core.sandbox.context.run', run)
    # This native leg isolates the stack detector. Memcpy has its own native controls.
    monkeypatch.setattr(cs, 'run_memcpy_overlap', lambda *a, **kw: SimpleNamespace(
        value=SimpleNamespace(diagnostics={}, limitations=[])))
    result = cs.scan_target(repo, out_dir=tmp_path / 'out')
    assert result.ok and result.tus_analyzed == 1 and not result.detector_limitations, result
    returns = [f for f in result.findings if f.get('cwe') == 'CWE-562']
    assert len(returns) == 2, result.findings
    assert {source.splitlines()[f['line']-1].split('(')[0] for f in returns} == {
        'int *bad_local', 'int *bad_array'}
    assert all(f['corroborated_by'] == ['gcc', 'clang'] and f['preprocessed_by'] == 'gcc' for f in returns)
    assert any(f['rule_id'] == '-Wanalyzer-use-after-free' for f in result.findings)
    assert not any(f['rule_id'] == '-Wreturn-local-addr' for f in result.findings)
    clang_calls = [(cmd, kw) for cmd, kw in calls if '--analyze' in cmd]
    assert len(clang_calls) == 1
    assert clang_calls[0][1]['target'] != str(repo)  # analyzes the frozen source view
    assert all(kw['block_network'] for _, kw in calls)
    assert all(not Path(kw['output']).exists() for _, kw in calls)
    assert walks == [(repo, repo)]  # baseline and stack snapshot share discovery


def test_stack_rule_metadata_does_not_reclassify_unrelated_clang_stack_escapes():
    findings = [
        {'rule_id': 'core.StackAddressEscape', 'file': 'a.cpp', 'line': 1, 'message': 'stored in global',
         'compiler': 'clang', 'cwe': None},
        {'rule_id': 'raptor.compiler.stack-return', 'file': 'b.c', 'line': 2, 'message': 'returned',
         'compiler': 'clang', 'cwe': 'CWE-562', 'corroborated_by': ['gcc', 'clang']},
    ]
    report = cs.to_sarif(cs.CompilerScanResult(ok=True, findings=findings))
    rules = {r['id']: r for r in report['runs'][0]['tool']['driver']['rules']}
    assert 'cwe' not in rules['core.StackAddressEscape'].get('properties', {})
    assert rules['raptor.compiler.stack-return']['properties']['cwe'] == 'CWE-562'


def test_stack_limitations_are_not_mislabeled_as_memcpy():
    report = cs.to_sarif(cs.CompilerScanResult(ok=True, detector_limitations=[{
        'tu': 'a.c', 'reason': 'Clang unavailable', 'detector': 'stack_return',
    }]))
    run = report['runs'][0]
    assert not run['results']
    assert run['invocations'][0]['toolExecutionNotifications'][0]['properties']['coverage_limitation'] == 'stack_return'


@pytest.fixture
def scan_setup(tmp_path, monkeypatch):
    (tmp_path / 'x.c').write_text('int *f(void) { int x; return &x; }\n')
    seed = {'id': cs.STACK_RETURN_ID, 'kind': 'warning', 'file': str(tmp_path / 'x.c'), 'line': 1}
    baseline = {'rule_id': '-Wanalyzer-use-after-free', 'file': 'x.c', 'line': 1,
                'message': 'use after free', 'compiler': 'gcc', 'cwe': 'CWE-416', 'tu': 'x.c'}
    item = cs.TuDiagnostics('x.c', ok=True, compiler='gcc', diagnostics=[baseline], stack_return_candidates=[seed])
    monkeypatch.setattr(cs, '_gcc_analyzer', lambda: ('/trusted/gcc', 'json'))
    monkeypatch.setattr(cs, '_clang_path', lambda: '/trusted/clang')
    monkeypatch.setattr(cs, 'analyze_tu', lambda *a, **kw: item)
    monkeypatch.setattr(cs, '_sandbox_runner', lambda: lambda *a, **kw: pytest.fail('unexpected compiler'))
    monkeypatch.setattr(cs, 'run_memcpy_overlap', lambda *a, **kw: SimpleNamespace(
        value=SimpleNamespace(diagnostics={}, limitations=[])))
    return item


def test_stack_detector_failure_preserves_existing_findings(tmp_path, monkeypatch, scan_setup):
    def fail(*a, **kw): raise RuntimeError('test failure')
    monkeypatch.setattr(cs, 'run_stack_return', fail)
    result = cs.scan_target(tmp_path)
    assert result.tus_analyzed == 1 and result.findings == scan_setup.diagnostics
    assert result.detector_limitations[0]['detector'] == 'stack_return'


def test_failed_baseline_does_not_feed_stack_corroboration(tmp_path, monkeypatch, scan_setup):
    scan_setup.ok = False
    monkeypatch.setattr(cs, 'run_stack_return', lambda *a, **kw: pytest.fail('failed TU is ineligible'))
    result = cs.scan_target(tmp_path)
    assert result.tus_failed == 1 and not result.findings and not result.detector_limitations


def test_no_candidate_has_no_corroboration_cost(tmp_path, monkeypatch, scan_setup):
    scan_setup.stack_return_candidates.clear()
    monkeypatch.setattr(cs, 'run_stack_return', lambda *a, **kw: pytest.fail('no candidate'))
    result = cs.scan_target(tmp_path)
    assert result.findings == scan_setup.diagnostics and not result.detector_limitations


def test_missing_clang_preserves_findings_and_reports_only_additional_check(tmp_path, monkeypatch, scan_setup):
    monkeypatch.setattr(cs, '_clang_path', lambda: None)
    result = cs.scan_target(tmp_path)
    assert result.findings == scan_setup.diagnostics
    assert result.detector_limitations == [{'tu': '', 'reason': 'stack-return corroboration requires Clang',
                                            'detector': 'stack_return'}]


def test_another_detector_failure_does_not_block_stack_findings(tmp_path, monkeypatch, scan_setup):
    def fail(*a, **kw): raise RuntimeError('other detector failed')
    monkeypatch.setattr(cs, 'run_memcpy_overlap', fail)
    monkeypatch.setattr(cs, 'run_stack_return', lambda *a, **kw: SimpleNamespace(value=SimpleNamespace(
        diagnostics={'x.c': [{'id': 'core.StackAddressEscape', 'kind': 'warning',
            'file': str(tmp_path / 'x.c'), 'line': 1, 'message': 'local returned to caller'}]},
        limitations=[])))
    result = cs.scan_target(tmp_path)
    assert {f['rule_id'] for f in result.findings} == {'-Wanalyzer-use-after-free', 'raptor.compiler.stack-return'}
    assert result.detector_limitations and len(result.findings) == 2


def test_candidate_warning_cannot_be_promoted_by_a_future_family_mapping(monkeypatch):
    monkeypatch.setattr(cs, '_cwe_for_diag_id', lambda diag_id: 'CWE-562')
    assert not cs._keep_diag_id('-Wreturn-local-addr')
    assert not cs._keep_diag_id('-Wreturn-local-addr=')
