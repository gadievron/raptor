"""Optional bounded location projection preserves ordinary coverage facts."""
import json

from core.coverage import record

RULE = 'raptor.injection.sql.taint.python'


def _hit(line=2, column=5, *, rule=RULE):
    return {'check_id': 'installed.rules.' + rule, 'path': 'subject.py',
            'start': {'line': line, 'col': column}, 'end': {'line': line, 'col': column + 4}}


def test_requested_locations_are_derived_during_the_single_metadata_read(tmp_path, monkeypatch):
    path = tmp_path / 'pack.json'
    path.write_text(json.dumps({'version': '1.79.0', 'paths': {'scanned': ['subject.py']},
                                'results': [_hit(), _hit(rule='other')], 'errors': []}))
    calls = []
    load = record.load_json
    def counted(path, **kwargs):
        calls.append(path)
        return load(path, **kwargs)
    monkeypatch.setattr(record, 'load_json', counted)
    summary = record.read_semgrep_outputs([path, path], location_rule_ids=frozenset({RULE}))
    assert calls == [path]
    assert summary.result_locations == frozenset({(RULE, 'subject.py', 2, 5, 2, 9)})
    assert summary.record['files_examined'] == ['subject.py']
    assert summary.location_rows_rejected == 0 and not summary.locations_truncated
    plain = record.read_semgrep_outputs([path])
    assert not plain.result_locations and not plain.location_rows_rejected


def test_projection_rejections_and_caps_do_not_erase_valid_coverage(tmp_path):
    path = tmp_path / 'pack.json'
    backwards = _hit()
    backwards['end']['col'] = 1
    path.write_text(json.dumps({'version': '1.79.0', 'paths': {'scanned': ['subject.py']},
                                'results': [_hit(), _hit(line=3), _hit(column=0),
                                            _hit(column=False), backwards], 'errors': []}))
    summary = record.read_semgrep_outputs([path], location_rule_ids=frozenset({RULE}), location_limit=1)
    assert len(summary.result_locations) == 1
    assert summary.location_rows_rejected == 4 and summary.locations_truncated
    assert summary.input_errors == 0
    assert summary.record['files_examined'] == ['subject.py']
