"""Summary finalisation distinguishes rename races from storage failures."""

import errno
import logging

import pytest

from core.sandbox import summary


@pytest.mark.parametrize("error", [errno.EACCES, errno.EIO, errno.ENOSPC])
def test_rename_failure_warns_and_preserves_evidence_for_retry(
    tmp_path, monkeypatch, caplog, error,
):
    source = tmp_path / summary.DENIALS_FILE
    content = '{"type":"network","host":"example.invalid"}\n'
    source.write_text(content, encoding="utf-8")

    with monkeypatch.context() as patch:
        def refuse_rename(*args, **kwargs):
            raise OSError(error, "injected rename failure")

        patch.setattr(summary.os, "replace", refuse_rename)
        with caplog.at_level(logging.WARNING, logger=summary.__name__):
            assert summary.summarize_and_write(tmp_path) is None

    assert "failed to rename denial evidence" in caplog.text
    assert source.read_text(encoding="utf-8") == content
    assert not (tmp_path / summary.SUMMARY_FILE).exists()
    assert summary.summarize_and_write(tmp_path) is not None
    assert (tmp_path / summary.SUMMARY_FILE).is_file()


def test_missing_input_race_stays_quiet(tmp_path, monkeypatch, caplog):
    source = tmp_path / summary.DENIALS_FILE
    source.write_text('{}\n', encoding="utf-8")

    def lost_race(*args, **kwargs):
        raise FileNotFoundError(errno.ENOENT, "sibling claimed input")

    monkeypatch.setattr(summary.os, "replace", lost_race)
    with caplog.at_level(logging.WARNING, logger=summary.__name__):
        assert summary.summarize_and_write(tmp_path) is None
    assert not caplog.records
