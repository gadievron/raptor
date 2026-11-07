"""Derived metadata can reuse source-report decoding without retaining it."""
import gc
import json
import weakref

import pytest

from core.sarif import parser


def test_observer_receives_original_reports_once_not_filtered_combined_data(tmp_path):
    combined, original = tmp_path / 'combined.sarif', tmp_path / 'raw.sarif'
    for path, count in [(combined, 1), (original, 3)]:
        path.write_text(json.dumps({'runs': [{'results': [{'ruleId': 'example'}] * count}]}))
    observed = []
    metrics = parser.generate_scan_metrics([str(combined)], file_count_paths=[str(original)] * 2,
        on_source_report=lambda path, data: observed.append((path, len(data['runs'][0]['results']))))
    assert observed == [(str(original), 3)]
    assert metrics['total_findings'] == 1


def test_observer_does_not_keep_the_previous_decoded_report_alive(monkeypatch):
    class Payload:
        pass
    references = []

    def load(path):
        # These acyclic fixture objects need no scan of unrelated old generations.
        gc.collect(0)
        assert all(reference() is None for reference in references)
        payload = Payload()
        references.append(weakref.ref(payload))
        return {'runs': [], 'unused_payload': payload}
    monkeypatch.setattr(parser, 'load_sarif', load)
    observed = []
    parser.generate_scan_metrics(['a', 'b'], on_source_report=lambda path, data: observed.append(path))
    gc.collect(0)
    assert observed == ['a', 'b']
    assert all(reference() is None for reference in references)


def test_observer_errors_are_not_silently_converted_into_valid_metrics(tmp_path):
    report = tmp_path / 'report.sarif'
    report.write_text('{"runs": []}')
    def broken(path, data):
        raise ValueError('observer failed')
    with pytest.raises(ValueError, match='observer failed'):
        parser.generate_scan_metrics([str(report)], on_source_report=broken)
