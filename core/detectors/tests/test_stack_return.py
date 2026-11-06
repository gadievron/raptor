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
        assert 0 < kw['timeout'] <= 17
        state.setdefault('timeouts', []).append(kw['timeout'])
        state['calls'].append((source, Path(kw['output'])))
        if state['raises']:
            raise state['raises']
        if state.get('advance'):
            state['advance']()
        return SimpleNamespace(returncode=state['rc'], stderr=json.dumps([{
            'id': state['id'], 'kind': state['kind'], 'file': state['filename'] or str(source),
            'line': state['line'], 'message': state['message'],
        }]))

    def execute(seeds=None, available=True, budget=None, workers=2):
        return detector.run_stack_return(root, seeds or {'a.c': [seed()]},
            request_for=request if available else None, sandbox_run=run, locate=locate,
            prepare_view=prepare, scratch_root=str(tmp_path), max_workers=workers, budget=budget)

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


@pytest.mark.parametrize("cap", [0, 1, 7, 50])
@pytest.mark.parametrize("reverse", [False, True])
def test_capped_selection_matches_lexical_order_independently_of_insertion(setup, monkeypatch, cap, reverse):
    root, state, seed, execute = setup
    names = [f"candidate-{index:04d}.c" for index in range(500)]
    # Zigzag insertion also differs from either monotonic order.
    insertion = names[::2] + names[1::2]
    if reverse:
        insertion.reverse()
    seeds = {name: [seed(name)] for name in insertion}
    monkeypatch.setattr(detector, "_MAX_TUS", cap)
    result = execute(seeds, available=False)
    assert list(result.value.candidates) == names[:cap]
    assert result.value.limitations[0] == {
        "tu": "", "reason": f"stack-return candidate cap skipped {len(names) - cap} TU(s)",
    }
    assert list(seeds) == insertion
    assert all(seeds[name][0]["file"] == str(root / name) for name in names)
    assert not state["calls"] and not state["prepared"]


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


def test_stack_deadline_keeps_completed_corroboration_and_skips_remaining_tu(setup, monkeypatch):
    from core.detectors import budget as module
    _, state, seed, execute = setup
    now = [0.0]
    monkeypatch.setattr(module, 'monotonic', lambda: now[0])
    budget = module.WorkBudget(5)
    def advance():
        now[0] = 5
    state['advance'] = advance
    result = execute({'a.c': [seed()], 'b.c': [seed('b.c')]}, budget=budget, workers=1)
    assert result.status == 'partial' and budget.exhausted
    assert set(result.value.diagnostics) == {'a.c'}
    assert len(state['prepared']) == len(state['calls']) == 1 and state['timeouts'] == [5]
    assert any('skipped 1' in item['reason'] for item in result.value.limitations)


@pytest.mark.parametrize("kind", ["stack-return", "memcpy-overlap"])
@pytest.mark.parametrize("status", ["complete", "partial", "skipped", "error", "exception"])
def test_completed_supplementary_detectors_release_execution_inputs(tmp_path, monkeypatch, kind, status):
    import gc
    import weakref
    from core.detectors import memcpy_overlap
    from core.detectors.pipeline import Detector, Stage, StageResult
    from core.detectors.setup import AnalysisSetup

    module = detector if kind == "stack-return" else memcpy_overlap
    states = []
    references = []

    def finish(state):
        states.append(state)
        state.diagnostics["a.c"] = [{"message": "retained"}]
        state.limitations.append({"tu": "a.c", "reason": "retained"})
        if status == "exception":
            raise RuntimeError("stage failed")
        return StageResult(status)

    monkeypatch.setattr(module, "DETECTOR", Detector("lifetime", "1", (Stage("finish", finish),)))

    class Payload:
        def __call__(self, *args, **kwargs):
            pytest.fail("lifetime test must not invoke tools or prepare source")

    def run_owned():
        payload = Payload()
        setup = AnalysisSetup()
        memo = setup.include_dirs_memo
        references.extend([weakref.ref(payload), weakref.ref(setup)])
        seeds = {"a.c": [{"unused": payload}]}
        try:
            if kind == "stack-return":
                result = module.run_stack_return(tmp_path, seeds, request_for=payload,
                    sandbox_run=payload, locate=payload, prepare_view=payload)
            else:
                result = module.run_memcpy_overlap(tmp_path, ("a.c",), request_for=payload,
                    sandbox_run=payload, setup=setup, include_dirs_memo=memo)
        except RuntimeError:
            assert status == "exception"
            result = None
        assert seeds["a.c"][0]["unused"] is payload
        assert setup.include_dirs_memo is memo
        return result

    result = run_owned()
    state = states[0]
    assert state.request_for is None and state.sandbox_run is None
    if kind == "stack-return":
        assert state.seeds == {} and state.prepare_view is None and state.locate is None
    else:
        assert state.files == () and state.setup is None and state.include_dirs_memo is None
    assert state.diagnostics == {"a.c": [{"message": "retained"}]}
    assert state.limitations == [{"tu": "a.c", "reason": "retained"}]
    if result is not None:
        assert result.status == status and result.value is state
    gc.collect(0)
    assert all(reference() is None for reference in references)
