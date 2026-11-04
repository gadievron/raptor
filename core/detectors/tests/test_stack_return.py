"""Only independent, attributable return diagnostics can promote a candidate."""
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from core.audit.preprocessor_view import ExpandedView
from core.detectors.compiler import CompilerRequest
from core.detectors import stack_return as detector


@pytest.fixture
def setup(tmp_path):
    root = tmp_path / 'repo'
    root.mkdir()
    for name in ('a.c', 'b.c'):
        (root / name).write_text('int *f(void) { int x; return &x; }\n')
    state = {'calls': [], 'prepared': [], 'rc': 0, 'raises': None, 'view_ok': True,
             'kind': 'warning', 'id': 'core.StackAddressEscape', 'line': 2,
             'message': 'Address of stack memory associated with local returned to caller',
             'filename': None}

    def seed(tu='a.c'):
        return {'id': detector.CANDIDATE_ID, 'kind': 'warning', 'file': str(root / tu), 'line': 3}

    def locate(diagnostic, tu):
        try:
            path = Path(diagnostic['file']).resolve().relative_to(root)
        except (ValueError, OSError):
            return None
        line = diagnostic.get('line', 0)
        return (path.as_posix(), line) if isinstance(line, int) and not isinstance(line, bool) and line > 0 else None

    def prepare(tu, scratch):
        state['prepared'].append((tu, scratch))
        return ExpandedView(ok=state['view_ok'] and state.get('failed_tu') != tu, file_path=tu, text='header\nreturn\nother\n',
                            line_map=(None, (tu, 3), (tu, 4), None))

    def request(tu, source):
        return CompilerRequest(command=('/trusted/clang', str(source)), target=source.parent,
            timeout=17, caller_label='stack-test', scratch_prefix='clang_', scratch_root=str(source.parent),
            parse=lambda work, stderr: json.loads(stderr))

    def run(cmd, **kw):
        source = Path(cmd[-1])
        assert source.exists() and kw['target'] == str(source.parent)
        assert kw['block_network'] and kw['cwd'] == kw['output']
        assert kw['timeout'] == 17
        state['calls'].append((source, Path(kw['output'])))
        if state['raises']:
            raise state['raises']
        return SimpleNamespace(returncode=state['rc'], stderr=json.dumps([{
            'id': state['id'], 'kind': state['kind'], 'file': state['filename'] or str(source),
            'line': state['line'], 'message': state['message'],
        }]))

    def execute(seeds=None, available=True):
        return detector.run_stack_return(root, seeds or {'a.c': [seed()]},
            request_for=request if available else None, sandbox_run=run, locate=locate,
            prepare_view=prepare, scratch_root=str(tmp_path), max_workers=2)

    return root, state, seed, execute


def test_success_maps_original_location_and_cleans_both_scratch_scopes(setup):
    root, state, _, run = setup
    result = run()
    assert result.status == 'complete' and not result.value.limitations
    assert result.value.diagnostics['a.c'][0]['file'] == str(root / 'a.c')
    assert result.value.diagnostics['a.c'][0]['line'] == 3
    assert len(state['calls']) == 1
    assert all(not p.exists() for pair in state['calls'] for p in pair)
    assert not state['prepared'][0][1].exists()


@pytest.mark.parametrize('change', [
    {'line': 1}, {'line': 3}, {'line': True}, {'line': -1},
    {'filename': '/outside/forged.c'}, {'kind': 'note'},
    {'id': 'core.NullDereference'}, {'message': 'Address stored in a global after function returns'},
])
def test_unmatched_or_other_mechanism_diagnostics_never_promote(setup, change):
    _, state, _, run = setup
    state.update(change)
    result = run()
    assert not result.value.diagnostics['a.c']
    assert not result.value.limitations


@pytest.mark.parametrize('failure', ['compile', 'error_record', 'timeout', 'preparation'])
def test_failures_do_not_export_partial_diagnostics(setup, failure):
    _, state, _, run = setup
    if failure == 'compile': state['rc'] = 1
    if failure == 'error_record': state['kind'] = 'error'
    if failure == 'timeout': state['raises'] = subprocess.TimeoutExpired('clang', 17)
    if failure == 'preparation': state['view_ok'] = False
    result = run()
    assert result.status == 'partial' and result.value.limitations
    assert not result.value.diagnostics
    assert all(not p.exists() for pair in state['calls'] for p in pair)
    assert not state['prepared'][0][1].exists()


@pytest.mark.parametrize('change', [{'id': 'unrelated'}, {'kind': 'note'}, {'file': '/outside/x.c'}, {'line': 0}])
def test_invalid_candidates_do_not_prepare_or_spawn(setup, change):
    _, state, seed, run = setup
    candidate = {**seed(), **change}
    result = run({'a.c': [candidate]})
    assert result.status == 'skipped' and not state['calls'] and not state['prepared']
    assert not result.value.limitations


def test_missing_clang_limits_only_this_detector(setup):
    _, state, _, run = setup
    result = run(available=False)
    assert result.status == 'skipped' and result.value.limitations
    assert not state['calls'] and not state['prepared']


def test_candidate_cap_is_visible_and_never_enlarges_input(setup, monkeypatch):
    _, state, seed, run = setup
    monkeypatch.setattr(detector, '_MAX_TUS', 1)
    result = run({'a.c': [seed('a.c')], 'b.c': [seed('b.c')]})
    assert result.status == 'partial' and result.value.limitations
    assert set(result.value.diagnostics) == {'a.c'} and len(state['calls']) == 1


def test_one_failed_translation_unit_does_not_cost_other_results(setup):
    _, state, seed, run = setup
    state['failed_tu'] = 'b.c'
    result = run({'a.c': [seed('a.c')], 'b.c': [seed('b.c')]})
    assert result.status == 'partial' and set(result.value.diagnostics) == {'a.c'}
    assert [item['tu'] for item in result.value.limitations] == ['b.c']


def test_location_budget_is_visible_and_preserves_collected_evidence(setup, monkeypatch):
    _, _, seed, run = setup
    monkeypatch.setattr(detector, '_MAX_LOCATIONS', 1)
    result = run({'a.c': [seed(), {**seed(), 'line': 4}]})
    assert result.status == 'partial' and result.value.limitations
    assert result.value.diagnostics['a.c'][0]['line'] == 3


def test_incompatible_clang_syntax_is_an_actionable_local_limitation(setup):
    _, state, _, run = setup
    state.update(rc=1, kind='error', message="unknown type name '_Float128'")
    result = run()
    assert result.status == 'partial' and not result.value.diagnostics
    assert "unknown type name '_Float128'" in result.value.limitations[0]['reason']
