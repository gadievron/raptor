"""One bounded pass reconciles language-specific Semgrep pack metadata."""
import gc
import json
import weakref
from pathlib import Path

import pytest

from core.coverage import record as coverage


def _write(tmp_path, name, data):
    path = tmp_path / name
    path.write_text(json.dumps(data))
    return path


def test_pack_union_reads_unique_outputs_once_and_preserves_errors(tmp_path, monkeypatch):
    first = _write(tmp_path, 'python.json', {'version': '1.177.0', 'paths': {
        'scanned': ['a.py', 'a.py'], 'skipped': [{'path': 'vendor/x.c', 'reason': 'excluded'}],
    }, 'errors': [{'path': 'a.py', 'message': 'timeout', 'type': ['Timeout', {}]}]})
    second = _write(tmp_path, 'cpp.json', {'paths': {
        'scanned': ['b.c'], 'skipped': [{'path': 'vendor/x.c', 'reason': 'excluded'}],
    }, 'errors': [{'path': 'a.py', 'message': 'timeout', 'type': 'Timeout'},
                  {'path': 'b.c', 'message': 'oom', 'type': 'OutOfMemory'}]})
    reads = []
    load = coverage.load_json

    def track(path, **kwargs):
        reads.append(path)
        assert kwargs['max_bytes'] == coverage.RUN_ARTIFACT_MAX_BYTES
        return load(path, **kwargs)
    monkeypatch.setattr(coverage, 'load_json', track)
    summary = coverage.read_semgrep_outputs([first, second, first], rules_applied=['python', 'c'])
    assert reads == [first, second]
    assert summary.record['files_examined'] == ['a.py', 'b.c']
    assert summary.record['rules_applied'] == ['python', 'c']
    assert summary.record['files_failed'] == [{'path': 'a.py', 'reason': 'timeout'},
                                              {'path': 'b.c', 'reason': 'oom'}]
    assert summary.dropped_files == {'a.py': ['Timeout'], 'b.c': ['OutOfMemory']}
    assert summary.skipped_paths == {'excluded': 1}
    assert summary.input_errors == 0


def test_legacy_builder_unions_examined_files_from_other_packs(tmp_path):
    first = _write(tmp_path, 'first.json', {'paths': {'scanned': []}})
    second = _write(tmp_path, 'second.json', {'paths': {'scanned': ['b.c']}})
    result = coverage.build_from_semgrep(tmp_path, first, extra_error_json_paths=[first, second])
    assert result['files_examined'] == ['b.c']


@pytest.mark.parametrize('damaged', [None, [], {'paths': []}, {'paths': {'scanned': 'a.c'}},
    {'paths': {'scanned': [None]}}, {'paths': {'scanned': ['']}}, {'errors': {}}, {'errors': [None]},
    {'paths': {'skipped': {}}}, {'paths': {'skipped': [None]}},
])
def test_damaged_metadata_does_not_erase_other_packs(tmp_path, damaged):
    bad = _write(tmp_path, 'bad.json', damaged)
    good = _write(tmp_path, 'good.json', {'paths': {'scanned': ['good.c']}})
    summary = coverage.read_semgrep_outputs([bad, good])
    assert summary.record['files_examined'] == ['good.c']
    assert summary.input_errors == 1


def test_missing_oversized_and_corrupt_outputs_are_visible(tmp_path, monkeypatch):
    oversized = tmp_path / 'big.json'
    oversized.write_text(' ' * 129)
    invalid = tmp_path / 'invalid.json'
    invalid.write_text('not-json')
    monkeypatch.setattr(coverage, 'RUN_ARTIFACT_MAX_BYTES', 128)
    summary = coverage.read_semgrep_outputs([tmp_path / 'missing.json', oversized, invalid])
    assert summary.record is None
    assert summary.input_errors == 3
    assert coverage.build_from_semgrep(tmp_path, oversized) is None


def test_raw_results_are_released_before_reading_the_next_pack(monkeypatch):
    class Payload:
        pass
    references = []

    def load(path, **kwargs):
        # These acyclic fixture objects need no scan of unrelated old generations.
        gc.collect(0)
        assert all(reference() is None for reference in references)
        payload = Payload()
        references.append(weakref.ref(payload))
        return {'results': payload, 'paths': {'scanned': [str(path) + '.c']}}
    monkeypatch.setattr(coverage, 'load_json', load)
    summary = coverage.read_semgrep_outputs([Path('first'), Path('second')])
    gc.collect(0)
    assert summary.record['files_examined'] == ['first.c', 'second.c']
    assert all(reference() is None for reference in references)



def test_partial_parse_failures_survive_even_without_a_positive_coverage_record(tmp_path):
    path = _write(tmp_path, 'partial.json', {'paths': {'scanned': []}, 'errors': [
        {'path': 'partial.c', 'type': 'PartialParsing', 'level': 'warn', 'message': 'unsupported construct'},
    ]})
    summary = coverage.read_semgrep_outputs([path])
    assert summary.record is None  # no invented examined-file claim
    assert summary.files_failed == [{'path': 'partial.c', 'reason': 'unsupported construct'}]
    assert summary.dropped_files == {}
