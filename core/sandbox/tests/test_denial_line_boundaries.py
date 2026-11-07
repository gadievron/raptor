"""JSON string characters do not create additional evidence records."""
import json

import pytest

from core.testing.module_bindings import patch_module_attribute

from core.sandbox import summary


@pytest.fixture
def capture_summary(monkeypatch):
    captured = {}
    monkeypatch.setattr(summary, 'reassert_audit_degraded', lambda run: False)
    patch_module_attribute(monkeypatch, summary, '_evidence', 'resolve_read_path', lambda run, name: run / name)
    monkeypatch.setattr(summary, '_evidence_handle', None)

    def assemble(run, **kwargs):
        captured.update(kwargs)
        return {'total_denials': len(kwargs['records'])}

    monkeypatch.setattr(summary, '_assemble_and_write_summary', assemble)
    return captured


@pytest.mark.parametrize('separator', ['\u0085', '\u2028', '\u2029'])
def test_unicode_separator_inside_json_string(tmp_path, capture_summary, separator):
    record = {'type': 'write', 'path': '/tmp/first' + separator + 'second'}
    evidence = tmp_path / summary.DENIALS_FILE
    evidence.write_text(json.dumps(record, ensure_ascii=False) + '\n', encoding='utf-8')
    assert summary.summarize_and_write(tmp_path) == {'total_denials': 1}
    assert capture_summary['records'] == [record]
    assert capture_summary['corrupt_lines'] == 0
    assert not list(tmp_path.glob(summary.DENIALS_FILE + '*'))


@pytest.mark.parametrize('newline', ['\n', '\r\n', '\r'])
@pytest.mark.parametrize('terminated', [True, False])
def test_file_newlines_and_unterminated_final_record(
        tmp_path, capture_summary, newline, terminated):
    records = [{'type': 'write', 'path': '/tmp/one'}, {'type': 'network'}]
    text = newline.join(json.dumps(record) for record in records)
    if terminated:
        text += newline
    (tmp_path / summary.DENIALS_FILE).write_bytes(text.encode())
    summary.summarize_and_write(tmp_path)
    assert capture_summary['records'] == records
    assert capture_summary['corrupt_lines'] == 0


def test_blank_and_invalid_lines_still_count_as_corruption(tmp_path, capture_summary):
    (tmp_path / summary.DENIALS_FILE).write_bytes(b'{}\n \ninvalid\n{}\n')
    summary.summarize_and_write(tmp_path)
    assert capture_summary['records'] == [{}, {}]
    assert capture_summary['corrupt_lines'] == 2


def test_growth_past_read_bound_remains_flagged(tmp_path, capture_summary, monkeypatch):
    (tmp_path / summary.DENIALS_FILE).write_bytes(b'{}\n')
    monkeypatch.setattr(summary, '_MAX_DENIALS_BYTES', 4)
    chunks = iter([b'{}\n', b'{}\n'])
    patch_module_attribute(monkeypatch, summary, 'os', 'read', lambda fd, count: next(chunks))
    summary.summarize_and_write(tmp_path)
    assert capture_summary['records'] == []
    assert capture_summary['planted_object'] == 'grew past the size bound mid-read'
