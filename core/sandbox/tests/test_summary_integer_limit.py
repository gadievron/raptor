"""Oversized JSON integers do not abort denial summary finalisation."""

import json
import sys

from core.sandbox import summary


def test_integer_limit_keeps_surrounding_valid_denials(tmp_path, monkeypatch):
    from core.testing.state_isolation import pin_user_state_dirs
    pin_user_state_dirs(monkeypatch, tmp_path)
    previous = sys.get_int_max_str_digits()
    try:
        sys.set_int_max_str_digits(640)
        source = tmp_path / summary.DENIALS_FILE
        valid = {"type": "network", "host": "example.invalid", "cmd": "test"}
        source.write_text(
            json.dumps(valid) + "\n"
            + '{"value":' + "9" * 641 + '}\n'
            + json.dumps(valid) + "\n", encoding="utf-8",
        )
        result = summary.summarize_and_write(tmp_path)
        assert result is not None
        assert result["corrupt_lines"] == 1
        assert result["total_denials"] == 2
        saved = json.loads((tmp_path / summary.SUMMARY_FILE).read_text())
        assert saved["corrupt_lines"] == 1
        assert saved["total_denials"] == 2
        assert not source.exists()
    finally:
        sys.set_int_max_str_digits(previous)
