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


@pytest.fixture
def macro_setup(tmp_path, monkeypatch):
    from core.audit import expanded_semgrep as es, preprocessor_view as pv
    root = tmp_path / 'repo'
    root.mkdir()
    for name in ('raw.c', 'macro.c', 'clean.c'):
        (root / name).write_text('lower_wrapper();\n')
    requests = []
    prepared = []
    scanned = []

    def request(rel):
        requests.append(rel)
        return SimpleNamespace(command=('/pinned/gcc',), scratch_root=None)

    def expand(**kw):
        prepared.append(kw)
        return pv.ExpandedView(ok=True, file_path=kw['file_path'], text='header\ncopy\n',
                               line_map=(('copy.h', 2), (kw['file_path'], 4)))

    def scan(target, config, **kw):
        scanned.append((target, kw))
        findings = [SimpleNamespace(file=str(target / 'macro.c'), line=line) for line in (1, 2)]
        findings += [SimpleNamespace(file=str(target / 'clean.c'), line=1)]
        return SimpleNamespace(findings=findings, errors=[])

    monkeypatch.setattr(es, 'expand_translation_unit', expand)
    monkeypatch.setattr('packages.semgrep.runner.run_rule', scan)
    state = overlap.OverlapAnalysis(root, ('raw.c', 'macro.c', 'clean.c'), request, lambda *a: None)
    state.candidates.add('raw.c')
    return state, prepared, scanned, es, pv


def test_macro_candidates_are_batched_and_header_noise_dropped(macro_setup):
    state, prepared, scanned, _, _ = macro_setup
    paths = {state.target / rel for rel in state.files}
    assert not overlap._expanded_candidates(state, paths, overlap.monotonic() + 30)
    assert {kw['file_path'] for kw in prepared} == {'macro.c', 'clean.c'}
    assert all(kw['preprocessor'][0] == '/pinned/gcc' for kw in prepared)
    assert len(scanned) == 1 and not scanned[0][0].exists()
    assert state.candidates == {'raw.c', 'macro.c'}
    assert not state.diagnostics and not state.limitations


def test_failed_macro_preparation_keeps_other_candidates(macro_setup, monkeypatch):
    state, prepared, scanned, es, pv = macro_setup
    original = es.expand_translation_unit

    def expand(**kw):
        if kw['file_path'] == 'clean.c':
            return pv.ExpandedView(ok=False, file_path='clean.c', errors=['bad include'])
        return original(**kw)

    monkeypatch.setattr(es, 'expand_translation_unit', expand)
    assert overlap._expanded_candidates(state, {state.target / rel for rel in state.files},
                                         overlap.monotonic() + 30)
    assert state.candidates == {'raw.c', 'macro.c'} and state.limitations


def test_macro_budget_exhaustion_never_scans_unprepared_input(macro_setup, monkeypatch):
    state, prepared, scanned, _, _ = macro_setup
    now = overlap.monotonic()
    assert overlap._expanded_candidates(state, {state.target / 'macro.c'}, now - 1)
    assert not prepared and not scanned and state.candidates == {'raw.c'}


def test_macro_semgrep_failure_retains_raw_candidates_and_cleans_scratch(macro_setup, monkeypatch):
    state, _, scanned, _, _ = macro_setup

    def fail(target, config, **kw):
        scanned.append((target, kw))
        return SimpleNamespace(findings=[], errors=['tool crashed'])

    monkeypatch.setattr('packages.semgrep.runner.run_rule', fail)
    assert overlap._expanded_candidates(state, {state.target / 'macro.c'}, overlap.monotonic() + 30)
    assert state.candidates == {'raw.c'} and state.limitations
    assert not scanned[0][0].exists()


def test_macro_preparation_cannot_start_matching_after_overall_deadline(macro_setup, monkeypatch):
    state, prepared, scanned, es, _ = macro_setup
    now = [0.0]
    monkeypatch.setattr(overlap, 'monotonic', lambda: now[0])
    build = es.build_expanded_corpus
    roots = []

    def slow(*args, **kw):
        corpus = build(*args, **kw)
        roots.append(corpus.root)
        now[0] = 31
        return corpus

    monkeypatch.setattr(es, 'build_expanded_corpus', slow)
    assert overlap._expanded_candidates(state, {state.target / 'macro.c'}, 30)
    assert prepared and not scanned and state.candidates == {'raw.c'}
    assert roots and not roots[0].exists() and state.limitations


def test_partial_macro_matches_are_kept_without_becoming_diagnostics(macro_setup, monkeypatch):
    state, _, scanned, _, _ = macro_setup
    from packages.semgrep.runner import run_rule as scan

    def partial(*args, **kw):
        result = scan(*args, **kw)
        result.errors = ['another file could not be parsed']
        return result

    monkeypatch.setattr('packages.semgrep.runner.run_rule', partial)
    assert overlap._expanded_candidates(state, {state.target / 'macro.c'}, overlap.monotonic() + 30)
    assert state.candidates == {'raw.c', 'macro.c'} and not state.diagnostics
    assert state.limitations and not scanned[0][0].exists()


@pytest.mark.parametrize('metadata', [
    {'files_failed': [{'path': 'macro.c', 'reason': 'parse error'}]},
    {'skipped_summary': {'total': 1}},
])
def test_macro_parser_coverage_failures_are_reported_without_discarding_matches(macro_setup, monkeypatch, metadata):
    from packages.semgrep.runner import run_rule as scan
    state, _, _, _, _ = macro_setup

    def partial(*args, **kw):
        result = scan(*args, **kw)
        for key, value in metadata.items():
            setattr(result, key, value)
        return result

    monkeypatch.setattr('packages.semgrep.runner.run_rule', partial)
    assert overlap._expanded_candidates(state, {state.target / 'macro.c'}, overlap.monotonic() + 30)
    assert state.candidates == {'raw.c', 'macro.c'} and state.limitations


def test_raw_parser_coverage_failures_are_reported_but_keep_candidates(setup, monkeypatch):
    root, _, make = setup
    monkeypatch.setattr('packages.semgrep.runner.run_rule', lambda *a, **kw: SimpleNamespace(
        findings=[SimpleNamespace(file=str(root / 'a.c'))], errors=[],
        skipped_summary={'total': 1},
    ))
    state = make(('a.c',))
    assert overlap._candidates(state).status == 'partial'
    assert state.candidates == {'a.c'} and state.limitations


def test_macro_scratch_failure_preserves_raw_candidates(macro_setup, monkeypatch):
    state, prepared, scanned, _, _ = macro_setup

    def unavailable(*a, **kw):
        raise OSError('scratch unavailable')

    monkeypatch.setattr(overlap, 'scratch_dir', unavailable)
    assert overlap._expanded_candidates(state, {state.target / 'macro.c'}, overlap.monotonic() + 30)
    assert state.candidates == {'raw.c'} and not prepared and not scanned
    assert state.limitations
