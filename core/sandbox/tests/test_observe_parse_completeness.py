"""Parse losses remain visible in best-effort observation profiles."""
import errno
import json

from core.sandbox import observe_profile as observe


def write_log(tmp_path, data):
    path = tmp_path / observe.OBSERVE_FILENAME
    path.write_bytes(data)
    return path


def test_malformed_record_preserves_valid_records_and_marks_incomplete(tmp_path):
    records = [{'syscall': 'stat', 'path': '/tmp/first'},
               {'syscall': 'stat', 'path': '/tmp/last'}]
    write_log(tmp_path, json.dumps(records[0]).encode() + b'\ninvalid\n'
              + json.dumps(records[1]).encode() + b'\n')
    profile = observe.parse_observe_log(tmp_path)
    assert profile.paths_stat == ['/tmp/first', '/tmp/last']
    assert profile.capture_incomplete is True
    assert profile.budget_truncated is False


def test_oversized_file_refusal_marks_incomplete(tmp_path, monkeypatch):
    write_log(tmp_path, b'{}\n' * 10)
    monkeypatch.setattr(observe, '_MAX_OBSERVE_BYTES', 4)
    assert observe.parse_observe_log(tmp_path).capture_incomplete is True


def test_read_failure_marks_incomplete(tmp_path, monkeypatch):
    write_log(tmp_path, b'{}\n')

    def fail(*args, **kwargs):
        raise OSError(errno.EIO, 'read failed')

    monkeypatch.setattr(observe, 'read_capped', fail)
    assert observe.parse_observe_log(tmp_path).capture_incomplete is True


def test_oversized_line_does_not_hide_following_valid_record(tmp_path, monkeypatch):
    monkeypatch.setattr(observe, '_MAX_RECORD_BYTES', 64)
    write_log(tmp_path, b'x' * 65 + b'\n{"syscall":"stat","path":"/tmp/valid"}\n')
    profile = observe.parse_observe_log(tmp_path)
    assert profile.paths_stat == ['/tmp/valid']
    assert profile.capture_incomplete is True


def test_clean_summary_does_not_erase_parse_loss(tmp_path):
    write_log(tmp_path, b'invalid\n{"type":"audit_summary","reader_drained":true}\n')
    assert observe.parse_observe_log(tmp_path).capture_incomplete is True


def test_clean_input_remains_complete(tmp_path):
    write_log(tmp_path, b'{"syscall":"stat","path":"/tmp/valid"}\n')
    assert observe.parse_observe_log(tmp_path).capture_incomplete is False
