"""Candidate inputs, containment and one shared wall budget across batches."""
from pathlib import Path
from types import SimpleNamespace
import os

import pytest

from core.detectors import memcpy_overlap as overlap


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setattr(overlap, "_expanded_candidates", lambda *args: False)
    root = tmp_path / "repo"
    root.mkdir()
    for name in ("a.c", "b.c", "c.c", "not-selected.c"):
        (root / name).write_text("void f(void) {}\n")
    calls = []
    monkeypatch.setattr("packages.semgrep.runner.is_available", lambda: True)

    def run(first, config, **kwargs):
        paths = (first, *kwargs.get("extra_targets", ()))
        calls.append((paths, kwargs))
        return SimpleNamespace(findings=[SimpleNamespace(file=str(p)) for p in paths], errors=[])

    monkeypatch.setattr("packages.semgrep.runner.run_rule", run)

    def state(files=("a.c", "b.c")):
        return overlap.OverlapAnalysis(root, files, lambda rel: None, lambda *a, **kw: None)

    return root, calls, state


def test_only_eligible_files_are_positional_inputs(setup):
    root, calls, make = setup
    state = make()
    assert overlap._candidates(state).status == "complete"
    assert calls[0][0] == (root / "a.c", root / "b.c")
    assert calls[0][1]["target_root"] == root
    assert root not in calls[0][0]
    assert state.candidates == {"a.c", "b.c"}


def test_literal_file_names_and_duplicate_inputs(setup):
    root, calls, make = setup
    names = ("space [*]?.c", "--option.c", "snow-雪.c")
    for name in names:
        (root / name).write_text("void f(void) {}\n")
    state = make((*names, names[0]))
    overlap._candidates(state)
    assert set(calls[0][0]) == {root / name for name in names}
    assert len(calls[0][0]) == len(names)
    assert state.candidates == set(names)


@pytest.mark.parametrize("invalid", ["../outside.c", "link.c", "missing.c", "directory.c"])
def test_invalid_inputs_never_grant_an_outside_read(setup, tmp_path, invalid):
    root, calls, make = setup
    outside = tmp_path / "outside.c"
    outside.write_text("secret\n")
    (root / "link.c").symlink_to(outside)
    (root / "directory.c").mkdir()
    state = make(("a.c", invalid))
    assert overlap._candidates(state).status == "partial"
    assert calls[0][0] == (root / "a.c",)
    assert state.candidates == {"a.c"}
    assert state.limitations


def test_all_unavailable_inputs_do_not_scan_the_root(setup):
    _, calls, make = setup
    state = make(("missing.c",))
    assert overlap._candidates(state).status == "error"
    assert not calls and not state.candidates


def test_deadline_is_shared_and_keeps_prior_candidates(setup, monkeypatch):
    root, calls, make = setup
    size = max(len(os.fsencode(root / f"{name}.c")) + 1 for name in "abc")
    monkeypatch.setattr(overlap, "_CANDIDATE_ARG_BYTES", size)
    now = [0.0]
    monkeypatch.setattr(overlap, "monotonic", lambda: now[0])

    def run(first, config, **kw):
        calls.append(((first, *kw.get("extra_targets", ())), kw))
        now[0] += 20
        return SimpleNamespace(findings=[SimpleNamespace(file=str(first))], errors=[])

    monkeypatch.setattr("packages.semgrep.runner.run_rule", run)
    state = make(("a.c", "b.c", "c.c"))
    assert overlap._candidates(state).status == "partial"
    assert [kw["timeout"] for _, kw in calls] == [30, 10]
    assert state.candidates == {"a.c", "b.c"}
    assert state.limitations


def test_failed_batch_does_not_hide_later_valid_candidates(setup, monkeypatch):
    root, calls, make = setup
    size = max(len(os.fsencode(root / f"{name}.c")) + 1 for name in "ab")
    monkeypatch.setattr(overlap, "_CANDIDATE_ARG_BYTES", size)

    def run(first, config, **kw):
        calls.append(((first,), kw))
        if first.name == "a.c":
            return SimpleNamespace(findings=[], errors=["parse error"])
        return SimpleNamespace(findings=[SimpleNamespace(file=str(first))], errors=[])

    monkeypatch.setattr("packages.semgrep.runner.run_rule", run)
    state = make()
    assert overlap._candidates(state).status == "partial"
    assert state.candidates == {"b.c"} and len(calls) == 2


def test_argument_budget_counts_encoded_bytes(monkeypatch):
    paths = [Path("/雪/first.c"), Path("/雪/second.c")]
    size = max(len(os.fsencode(p)) + 1 for p in paths)
    monkeypatch.setattr(overlap, "_CANDIDATE_ARG_BYTES", size)
    batches = list(overlap._target_batches(paths))
    assert batches == [(paths[0],), (paths[1],)]
    assert all(sum(len(os.fsencode(p)) + 1 for p in b) <= size for b in batches)
    with pytest.raises(ValueError, match="argument budget"):
        list(overlap._target_batches([Path("/" + "a" * size)]))


def test_raw_parser_coverage_failures_are_reported_but_keep_candidates(setup, monkeypatch):
    root, _, make = setup
    monkeypatch.setattr('packages.semgrep.runner.run_rule', lambda *a, **kw: SimpleNamespace(
        findings=[SimpleNamespace(file=str(root / 'a.c'))], errors=[],
        skipped_summary={'total': 1},
    ))
    state = make(('a.c',))
    assert overlap._candidates(state).status == 'partial'
    assert state.candidates == {'a.c'} and state.limitations



@pytest.fixture
def macro_setup(tmp_path, monkeypatch):
    from core.audit import preprocessor_view as pv
    root = tmp_path / 'repo'
    root.mkdir()
    for name in ('raw.c', 'macro.c', 'clean.c'):
        (root / name).write_text('lower_wrapper();\n')
    prepared = []
    snippets = {'macro.c': 'memcpy(p,b,16);', 'clean.c': 'const char *s="memcpy(p,b,16)";'}

    def expand(**kw):
        prepared.append(kw)
        rel = kw['file_path']
        return pv.ExpandedView(ok=True, file_path=rel,
                               text='typedef __typeof__(nullptr) nullptr_t;\nmemcpy(h,h+1,4);\n'+snippets[rel],
                               line_map=(None, ('copy.h', 2), (rel, 4)))

    monkeypatch.setattr(pv, 'expand_translation_unit', expand)
    monkeypatch.setattr('packages.semgrep.runner.run_rule', lambda *a, **kw: pytest.fail('expanded tokens must not invoke Semgrep'))
    state = overlap.OverlapAnalysis(root, ('raw.c', 'macro.c', 'clean.c'),
        lambda rel: SimpleNamespace(command=('/pinned/gcc',), scratch_root=None), lambda *a: None)
    state.candidates.add('raw.c')
    return state, prepared, snippets, pv


def test_macro_candidates_do_not_need_semgrep_parser_or_header_rewriting(macro_setup):
    state, prepared, _, _ = macro_setup
    assert not overlap._expanded_candidates(state, {state.target / rel for rel in state.files}, overlap.monotonic()+30)
    assert {kw['file_path'] for kw in prepared} == {'macro.c', 'clean.c'}
    assert all(kw['preprocessor'][0] == '/pinned/gcc' for kw in prepared)
    assert state.candidates == {'raw.c', 'macro.c'} and not state.diagnostics
    assert not state.limitations and not prepared[0]['out_dir'].exists()


@pytest.mark.parametrize('source,selected', [
    ("int n=1'000; memcpy(p,b,n);", True),
    ("int n=0xDEAD'BEEF; memcpy(p,b,n);", True),
    ("int n=0b1010'0101; memcpy(p,b,n);", True),
    ("double n=.1'0e+2; memcpy(p,b,4);", True),
    ("int c=u8'm'; memcpy(p,b,4);", True),
    ('(memcpy)(p,b,n);', True),
    ('copy = &memcpy;', True),
    ('memcpy\n(p,b,n);', True),
    ('/* memcpy(p,b,n) */ alias(p,b,n);', False),
    ('"escaped \\\" memcpy(p,b,n)"', False),
    ("'m' 'e' 'm' 'c' 'p' 'y'", False),
    ('memcpy_prefix(p,b,n); prefix_memcpy(p,b,n);', False),
    ('$memcpy(p,b,n); memcpy$(p,b,n);', False),
])
def test_expanded_identifier_selection_is_conservative_not_a_call_judgment(macro_setup, monkeypatch, source, selected):
    state, _, snippets, pv = macro_setup
    snippets['macro.c'] = source
    # Preserve source attribution when the call spans more than one line.
    old_expand = pv.expand_translation_unit
    def expand(**kw):
        view = old_expand(**kw)
        view.line_map += ((kw['file_path'], 5),) * source.count('\n')
        return view
    monkeypatch.setattr(pv, "expand_translation_unit", expand)
    assert not overlap._expanded_candidates(state, {state.target / 'macro.c'}, overlap.monotonic()+30)
    assert ('macro.c' in state.candidates) is selected
    assert not state.diagnostics


def test_failed_macro_preparation_keeps_other_candidates(macro_setup, monkeypatch):
    state, prepared, _, pv = macro_setup
    expand = pv.expand_translation_unit
    def fail(**kw):
        if kw['file_path'] == 'clean.c':
            return pv.ExpandedView(ok=False, file_path='clean.c', errors=['bad include'])
        return expand(**kw)
    monkeypatch.setattr(pv, 'expand_translation_unit', fail)
    assert overlap._expanded_candidates(state, {state.target / rel for rel in state.files}, overlap.monotonic()+30)
    assert state.candidates == {'raw.c', 'macro.c'} and state.limitations
    assert not prepared[0]['out_dir'].exists()


@pytest.mark.parametrize('kind', ['expired', 'during_preparation', 'bytes', 'tu_cap', 'scratch'])
def test_macro_resource_limits_preserve_raw_candidates(macro_setup, monkeypatch, kind):
    state, prepared, _, pv = macro_setup
    now = [0.0]
    monkeypatch.setattr(overlap, 'monotonic', lambda: now[0])
    deadline = 30
    if kind == 'expired': deadline = -1
    if kind == 'during_preparation':
        expand = pv.expand_translation_unit
        def slow(**kw):
            view = expand(**kw)
            now[0] = 31
            return view
        monkeypatch.setattr(pv, 'expand_translation_unit', slow)
    if kind == 'bytes': monkeypatch.setattr(overlap, '_EXPANDED_BYTE_BUDGET', 1)
    if kind == 'tu_cap': monkeypatch.setattr(pv, '_AUGMENT_FILE_CAP', 0)
    if kind == 'scratch':
        def fail(*a, **kw): raise OSError('scratch unavailable')
        monkeypatch.setattr(overlap, 'scratch_dir', fail)
    assert overlap._expanded_candidates(state, {state.target / 'macro.c'}, deadline)
    assert state.candidates == {'raw.c'} and state.limitations
    if prepared: assert not prepared[0]['out_dir'].exists()


@pytest.mark.parametrize('version', ['1.79.0', '', '1.177.0'])
def test_raw_engine_failure_does_not_disable_expanded_candidates(macro_setup, monkeypatch, version):
    state, prepared, _, _ = macro_setup
    state.files = ('macro.c', 'clean.c')
    state.candidates.clear()
    monkeypatch.setattr('packages.semgrep.runner.is_available', lambda: True)
    monkeypatch.setattr('packages.semgrep.runner.run_rule', lambda *a, **kw: SimpleNamespace(
        findings=[], errors=['rule or parser unsupported'], semgrep_version=version,
    ))
    assert overlap._candidates(state).status == 'partial'
    assert state.candidates == {'macro.c'} and len(prepared) == 2
    assert state.limitations and not state.diagnostics
