"""Candidate scope, bounded source reads and parser-independent selection."""
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
        (root / name).write_text("void f(void) { memcpy(d,s,n); }\n")
    calls = []
    original = overlap.read_text_capped
    def read(path, *args, **kwargs):
        calls.append(path)
        return original(path, *args, **kwargs)
    monkeypatch.setattr(overlap, 'read_text_capped', read)
    monkeypatch.setattr("packages.semgrep.runner.run_rule",
                        lambda *a, **kw: pytest.fail('candidate discovery must not launch Semgrep'))
    def state(files=("a.c", "b.c")):
        return overlap.OverlapAnalysis(root, files, lambda rel: None, lambda *a, **kw: None)
    return root, calls, state


def test_only_eligible_files_are_read(setup):
    root, calls, make = setup
    state = make()
    assert overlap._candidates(state).status == "complete"
    assert calls == [root / "a.c", root / "b.c"]
    assert state.candidates == {"a.c", "b.c"}


def test_literal_file_names_and_duplicate_inputs(setup):
    root, calls, make = setup
    names = ("space [*]?.c", "--option.c", "snow-雪.c")
    for name in names:
        (root / name).write_text("memcpy(d,s,n);\n")
    state = make((*names, names[0]))
    overlap._candidates(state)
    assert set(calls) == {root / name for name in names}
    assert len(calls) == len(names) and state.candidates == set(names)


@pytest.mark.parametrize("invalid", ["../outside.c", "link.c", "missing.c", "directory.c", "fifo.c"])
def test_invalid_inputs_never_grant_an_outside_read(setup, tmp_path, invalid):
    root, calls, make = setup
    outside = tmp_path / "outside.c"
    outside.write_text("secret\n")
    (root / "link.c").symlink_to(outside)
    (root / "directory.c").mkdir()
    os.mkfifo(root / 'fifo.c')
    state = make(("a.c", invalid))
    assert overlap._candidates(state).status == "partial"
    assert calls == [root / "a.c"] and state.candidates == {"a.c"}
    assert state.limitations


def test_contained_alias_preserves_eligible_tu_identity(setup):
    root, calls, make = setup
    (root / 'alias.c').symlink_to(root / 'a.c')
    state = make(('alias.c',))
    assert overlap._candidates(state).status == 'complete'
    assert calls == [root / 'a.c'] and state.candidates == {'alias.c'}


def test_all_unavailable_inputs_do_not_scan_the_root(setup):
    _, calls, make = setup
    state = make(("missing.c",))
    assert overlap._candidates(state).status == "error"
    assert not calls and not state.candidates


def test_deadline_is_shared_and_keeps_prior_candidates(setup, monkeypatch):
    root, calls, make = setup
    now = [0.0]
    monkeypatch.setattr(overlap, "monotonic", lambda: now[0])
    original = overlap.read_text_capped
    def read(*args, **kwargs):
        now[0] += 20
        return original(*args, **kwargs)
    monkeypatch.setattr(overlap, 'read_text_capped', read)
    state = make(("a.c", "b.c", "c.c"))
    assert overlap._candidates(state).status == "partial"
    assert calls == [root / 'a.c', root / 'b.c']
    assert state.candidates == {"a.c", "b.c"} and state.limitations


def test_unreadable_input_does_not_hide_later_candidates(setup, monkeypatch):
    root, calls, make = setup
    original = overlap.read_text_capped
    monkeypatch.setattr(overlap, 'read_text_capped', lambda path, *a, **kw:
                        None if path.name == 'a.c' else original(path, *a, **kw))
    state = make()
    assert overlap._candidates(state).status == "partial"
    assert state.candidates == {"b.c"} and calls == [root / 'b.c']


@pytest.mark.parametrize('content,expected,limited', [
    ('memcpy(d,s,n);\n' + 'x' * 100, True, False),
    ('x' * 100 + '\nmemcpy(d,s,n);', False, True),
])
def test_capped_read_selects_known_candidates_and_reports_unknown_tail(setup, monkeypatch, content, expected, limited):
    root, _, make = setup
    (root / 'a.c').write_text(content)
    monkeypatch.setattr(overlap, '_RAW_SOURCE_CHARS', 20)
    state = make(('a.c',))
    overlap._candidates(state)
    assert ('a.c' in state.candidates) is expected
    assert bool(state.limitations) is limited


@pytest.mark.parametrize('content,expected', [
    ('memcpy(d,s,n);', True), ('(memcpy)(d,s,n);', True), ('copy = &memcpy;', True),
    ('mem\\\ncpy(d,s,n);', True), ('// continuation\\\nmemcpy(d,s,n);', False),
    ("int n=1'000; memcpy(d,s,n);", True),
    ("typedef __typeof__(nullptr) nullptr_t; memcpy(d,s,n);", True), ('/* memcpy(d,s,n) */', False),
    ('const char *s="memcpy(d,s,n)";', False), ('memcpy_prefix(d,s,n);', False),
    ('$memcpy(d,s,n); memcpy$(d,s,n);', False),
])
def test_raw_identifier_gate_is_conservative_and_lexically_aware(setup, content, expected):
    root, _, make = setup
    (root / 'a.c').write_text(content)
    state = make(('a.c',))
    overlap._candidates(state)
    assert ('a.c' in state.candidates) is expected and not state.limitations


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


@pytest.mark.parametrize("prefix", ["", "\r", "\f\u2028"])
@pytest.mark.parametrize("candidate", [False, True])
def test_expanded_origin_lookup_only_visits_token_lines(macro_setup, monkeypatch, prefix, candidate):
    state, _, _, pv = macro_setup
    suffix = "memcpy(p,b,n);" if candidate else "alias(p,b,n);"
    text = "memcpy(h,h,1);\n" + "\n" * 10_000 + prefix + suffix
    view = pv.ExpandedView(ok=True, file_path="macro.c", text=text,
                           line_map=(("header.h", 1),) + (None,) * 10_000 + (("macro.c", 4),))
    calls = []
    origin_of = pv.ExpandedView.origin_of

    def origin(instance, line):
        calls.append(line)
        return origin_of(instance, line)

    monkeypatch.setattr(pv.ExpandedView, "origin_of", origin)
    monkeypatch.setattr(pv, "expand_translation_unit", lambda **kwargs: view)
    assert not overlap._expanded_candidates(state, {state.target / "macro.c"}, overlap.monotonic() + 30)
    assert ("macro.c" in state.candidates) is candidate
    assert calls == ([1, 10_002] if candidate else [1])
    assert not state.limitations


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


@pytest.mark.parametrize('available', [False, True])
def test_expanded_candidates_do_not_depend_on_semgrep_availability(macro_setup, monkeypatch, available):
    state, prepared, _, _ = macro_setup
    state.files = ('macro.c', 'clean.c')
    state.candidates.clear()
    monkeypatch.setattr('packages.semgrep.runner.is_available', lambda: available)
    assert overlap._candidates(state).status == 'complete'
    assert state.candidates == {'macro.c'} and len(prepared) == 2
    assert not state.limitations and not state.diagnostics


def test_expanded_alias_keeps_the_supplied_tu_identity(macro_setup, monkeypatch):
    state, _, _, pv = macro_setup
    (state.target / 'alias.c').symlink_to(state.target / 'macro.c')
    state.files = ('alias.c',)
    state.candidates.clear()
    seen = []
    def expand(**kwargs):
        seen.append(kwargs['file_path'])
        return pv.ExpandedView(ok=True, file_path=kwargs['file_path'],
                               text='memcpy(p,b,16);', line_map=(('macro.c', 4),))
    monkeypatch.setattr(pv, 'expand_translation_unit', expand)
    assert overlap._candidates(state).status == 'complete'
    assert state.candidates == {'alias.c'} and seen == ['alias.c']
