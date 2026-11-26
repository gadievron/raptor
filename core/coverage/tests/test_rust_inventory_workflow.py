"""#1077: real Rust checklist -> mark-file -> coverage -> audit gaps."""
from __future__ import annotations

import importlib.util
import json
import sys
from importlib.machinery import SourceFileLoader

import pytest

from core.audit.context import assemble_context
from core.audit.gaps import compute_gaps, gap_for_site, write_gaps
from core.coverage.journal import load_entries
from core.coverage.record import load_records
from core.coverage.tests.summary_cli_support import REPO_ROOT, run_cli
from core.inventory import read_checklist
from core.inventory.extractors import _ts_parser_for


SOURCES = {
    'platform/ffi.rs': (
        '#[repr(C)]\n// C ABI layout\npub struct Api {\n    pub count: usize,\n    pub data: *const u8,\n}\n'
        'pub const ABI_VERSION: u32 = 1;\npub static READY: bool = false;\n'
        'pub enum Mode { Read, Write }\npub union Bits { i: u32, f: f32 }\n'
        'pub type Handle = *mut Api;\n'
    ),
    'limits.rs': 'pub const MAX_ITEMS: usize = 32;\npub static NAME: &str = "demo";\n',
}
EXPECTED = {
    ('platform/ffi.rs', 'Api'), ('platform/ffi.rs', 'ABI_VERSION'),
    ('platform/ffi.rs', 'READY'), ('platform/ffi.rs', 'Mode'),
    ('platform/ffi.rs', 'Bits'), ('platform/ffi.rs', 'Handle'),
    ('limits.rs', 'MAX_ITEMS'), ('limits.rs', 'NAME'),
}


def _build_checklist_cli(tmp_path, monkeypatch):
    parser = _ts_parser_for('rust')
    if parser is None:
        pytest.skip('Rust grammar not installed')
    target = tmp_path / 'crate'
    for name, source in SOURCES.items():
        assert not parser.parse(source.encode()).root_node.has_error
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
    out = tmp_path / 'run'
    monkeypatch.setenv('_RAPTOR_TRUSTED', '1')
    loader = SourceFileLoader('issue1077_build_checklist_cli', str(REPO_ROOT / 'libexec/raptor-build-checklist'))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    with monkeypatch.context() as mp:
        mp.setattr(sys, 'argv', ['raptor-build-checklist', str(target), str(out)])
        mp.setattr(sys, 'path', sys.path.copy())
        loader.exec_module(module)
        module.main()
    (out / '.raptor-run.json').write_text('{}')
    return target, out, read_checklist(out)


def _keys(gaps):
    return {(g['file'], g['name']) for g in gaps}


def test_rust_cli_marks_preserve_examination_review_and_gap_identity(tmp_path, monkeypatch):
    target, out, checklist = _build_checklist_cli(tmp_path, monkeypatch)
    items = {(file['path'], item['name']): item for file in checklist['files'] for item in file['items']}
    assert EXPECTED <= items.keys()
    assert all(items[key]['kind'] in ('class', 'global') for key in EXPECTED)
    initial = compute_gaps(checklist, [])
    assert EXPECTED <= _keys(initial)
    assert all(name not in _keys(compute_gaps(checklist, [], include_kinds={'none'})) for name in EXPECTED)
    api = items['platform/ffi.rs', 'Api']
    assert api['line_start'] == 1 and api['line_end'] == 6
    context = assemble_context(target_path=target, file_path='platform/ffi.rs', function_name='Api',
                               line_start=api['line_start'], line_end=api['line_end'], checklist=checklist)
    assert '#[repr(C)]' in context['source'] and 'pub data: *const u8' in context['source']
    site = gap_for_site(checklist, 'platform/ffi.rs', 5)
    assert site is not None and site['name'] == 'Api'
    write_gaps(initial, out)
    saved = json.loads((out / 'gaps.json').read_text())
    assert EXPECTED <= {(g['file'], g['name']) for g in saved['gaps']}

    marks = tmp_path / 'marks.json'
    marks.write_text(json.dumps([{'file': file, 'item': name} for file, name in sorted(EXPECTED)]))
    mapped = run_cli(str(out), '--mark-file', str(marks), '--map-grade')
    assert mapped.returncode == 0, mapped.stderr
    assert 'unmatched' not in mapped.stderr and 'no checklist item matches' not in mapped.stderr
    examined = json.loads((out / 'coverage-understand.json').read_text())
    assert {(row['file'], row['function']) for row in examined['functions_analysed']} == EXPECTED
    assert not load_entries(out, fresh=True)
    assert EXPECTED <= _keys(compute_gaps(checklist, list(load_records(out)), out_dir=out))
    displayed = run_cli(str(out), '--gaps')
    assert displayed.returncode == 0, displayed.stderr
    assert all(f'{file}:{name}' in displayed.stdout for file, name in EXPECTED)

    reviewed = {('platform/ffi.rs', 'Api'), ('platform/ffi.rs', 'Handle'), ('limits.rs', 'MAX_ITEMS')}
    marks.write_text(json.dumps([{'file': file, 'item': name} for file, name in sorted(reviewed)]))
    # Existing documented operator-context seam: actual CLI, original signing,
    # journal and store paths; no production authority bypass is introduced.
    marked = run_cli(str(out), '--mark-file', str(marks), operator=True)
    assert marked.returncode == 0, marked.stderr
    assert 'unmatched' not in marked.stderr
    entries = load_entries(out, fresh=True)
    assert {(row.file, row.function) for row in entries} == reviewed
    assert all(row.producer == 'mark' and row.source_hash for row in entries)
    remaining = _keys(compute_gaps(checklist, list(load_records(out)), out_dir=out))
    assert EXPECTED - reviewed <= remaining
    assert reviewed.isdisjoint(remaining)
    shown = run_cli(str(out), '--gaps')
    assert shown.returncode == 0, shown.stderr
    assert all(f'{file}:{name}' not in shown.stdout for file, name in reviewed)
    assert all(f'{file}:{name}' in shown.stdout for file, name in EXPECTED - reviewed)
    withdrawn = run_cli(str(out), '--unmark', 'platform/ffi.rs:Api', operator=True)
    assert withdrawn.returncode == 0, withdrawn.stderr
    assert ('platform/ffi.rs', 'Api') in _keys(compute_gaps(checklist, list(load_records(out)), out_dir=out))


def test_method_review_does_not_credit_same_line_trait_or_changed_layout(tmp_path, monkeypatch):
    from core.coverage.store_summary import coverage_view, file_breakdown, _build_store
    from core.inventory import build_inventory

    target, out, checklist = _build_checklist_cli(tmp_path, monkeypatch)
    trait = target / 'trait.rs'
    trait.write_text('pub trait Access { fn read(&self) {} }\n')
    checklist = build_inventory(str(target), str(out), parallel=False)
    reviewed_method = run_cli(str(out), '--mark', 'trait.rs:read', operator=True)
    assert reviewed_method.returncode == 0, reviewed_method.stderr
    assert 'no checklist item matches' not in reviewed_method.stderr
    gaps = _keys(compute_gaps(checklist, list(load_records(out)), out_dir=out))
    assert ('trait.rs', 'Access') in gaps and ('trait.rs', 'read') not in gaps
    view = coverage_view([out], checklist, out / 'coverage.json')
    displayed = {(row['file'], row['function']) for row in view['llm_gap_functions']}
    assert ('trait.rs', 'Access') in displayed and ('trait.rs', 'read') not in displayed
    store = _build_store([out], checklist, out / 'coverage.json')
    trait_row, = [row for row in file_breakdown(store, checklist) if row['path'] == 'trait.rs']
    assert trait_row['reviewable'] == 2 and trait_row['llm'] == 1
    own = run_cli(str(out), '--mark', 'trait.rs:Access', 'platform/ffi.rs:Api', operator=True)
    assert own.returncode == 0, own.stderr
    before = coverage_view([out], checklist, out / 'coverage.json')
    assert ('trait.rs', 'Access') not in {(row['file'], row['function']) for row in before['llm_gap_functions']}
    assert ('platform/ffi.rs', 'Api') not in {(row['file'], row['function']) for row in before['llm_gap_functions']}
    # Persisted interval history and original signed review rows remain on disk.
    # A changed declaration must nevertheless reopen both display and planner.
    source = target / 'platform/ffi.rs'
    source.write_text(source.read_text().replace('pub count: usize', 'pub count: u32'))
    checklist = build_inventory(str(target), str(out), parallel=False)
    after = coverage_view([out], checklist, out / 'coverage.json')
    assert ('platform/ffi.rs', 'Api') in {(row['file'], row['function']) for row in after['llm_gap_functions']}
    assert ('platform/ffi.rs', 'Api') in _keys(compute_gaps(checklist, list(load_records(out)), out_dir=out))
    assert ('trait.rs', 'Access') not in {(row['file'], row['function']) for row in after['llm_gap_functions']}


def test_later_cross_run_withdrawal_wins_independent_of_directory_order(tmp_path, monkeypatch):
    from core.coverage.store_summary import coverage_view

    _, first, checklist = _build_checklist_cli(tmp_path, monkeypatch)
    # Original project-backed CLI paths maintain the real shared journal index.
    (tmp_path / 'checklist.json').write_text(json.dumps(checklist))
    second = tmp_path / 'second'
    second.mkdir()
    (second / '.raptor-run.json').write_text('{}')
    marked = run_cli(str(first), '--mark', 'platform/ffi.rs:Api', operator=True)
    assert marked.returncode == 0, marked.stderr
    before = coverage_view([first, second], checklist, tmp_path / 'coverage.json')
    assert ('platform/ffi.rs', 'Api') not in {(row['file'], row['function']) for row in before['llm_gap_functions']}
    # A real second run has its own coverage record before withdrawing a
    # project-journal assertion; the CLI's unmark path operates on that record.
    unrelated = run_cli(str(second), '--mark', 'platform/ffi.rs:Handle', operator=True)
    assert unrelated.returncode == 0, unrelated.stderr
    withdrawn = run_cli(str(second), '--unmark', 'platform/ffi.rs:Api', operator=True)
    assert withdrawn.returncode == 0, withdrawn.stderr
    latest = load_entries(second, fresh=True)
    assert any(row.function == 'Api' and row.verdict == 'error' and row.producer == 'mark' for row in latest)
    for directories in ([first, second], [second, first]):
        view = coverage_view(directories, checklist, tmp_path / 'coverage.json')
        assert ('platform/ffi.rs', 'Api') in {(row['file'], row['function']) for row in view['llm_gap_functions']}
    restored = run_cli(str(second), '--mark', 'platform/ffi.rs:Api', operator=True)
    assert restored.returncode == 0, restored.stderr
    for directories in ([first, second], [second, first]):
        view = coverage_view(directories, checklist, tmp_path / 'coverage.json')
        assert ('platform/ffi.rs', 'Api') not in {(row['file'], row['function']) for row in view['llm_gap_functions']}


def test_equal_time_signed_mark_withdrawal_is_ambiguous_in_either_order(tmp_path, monkeypatch):
    from dataclasses import replace
    from core.coverage.journal import append_entry
    from core.coverage.store_summary import coverage_view

    _, first, checklist = _build_checklist_cli(tmp_path, monkeypatch)
    assert run_cli(str(first), '--mark', 'platform/ffi.rs:Api', operator=True).returncode == 0
    original, = load_entries(first, fresh=True)
    second = tmp_path / 'equal-time-withdrawal'
    second.mkdir()
    # Original journal writer signs both real mark and exact-site withdrawal.
    # Copying its timestamp models accepted legacy second-precision journals.
    append_entry(second, replace(original, verdict='error', source_hash='',
                                 lesson='unmark — review assertion withdrawn', integrity=None))
    for directories in ([first, second], [second, first]):
        view = coverage_view(directories, checklist, tmp_path / 'coverage.json')
        assert ('platform/ffi.rs', 'Api') in {(row['file'], row['function']) for row in view['llm_gap_functions']}
