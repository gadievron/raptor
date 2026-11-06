"""Scoped text owns closed files and preserves primary failures."""

from pathlib import Path

import pytest

from core.run import scratch


def test_scoped_utf8_file_uses_requested_directory_and_private_mode(tmp_path):
    with scratch.temporary_text("caf\N{LATIN SMALL LETTER E WITH ACUTE}", dir=tmp_path, prefix="input-", suffix=".txt") as path:
        assert path.parent == tmp_path
        assert path.read_bytes() == "café".encode()
        assert path.stat().st_mode & 0o777 == 0o600
    assert not path.exists()


def test_missing_parent_is_not_recreated(tmp_path):
    missing = tmp_path / "removed-run"
    with pytest.raises(FileNotFoundError):
        with scratch.temporary_text("text", dir=missing, prefix="input-", suffix=".txt"):
            pytest.fail("allocation should fail")
    assert not missing.exists()


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_body_failure_removes_file(tmp_path, error):
    with pytest.raises(error, match="primary failure"):
        with scratch.temporary_text("payload", dir=tmp_path, prefix="input-", suffix=".txt"):
            raise error("primary failure")
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("action", ["rename", "unlink"])
def test_body_can_transfer_or_remove_the_file(tmp_path, action):
    final = tmp_path / "published"
    with scratch.temporary_text("payload", dir=tmp_path, prefix="input-", suffix=".txt") as path:
        if action == "rename":
            path.rename(final)
        else:
            path.unlink()
    assert not path.exists()
    assert final.exists() == (action == "rename")


@pytest.fixture
def failed_unlink(tmp_path, monkeypatch):
    # Override only the consumer's Path constructor; leave pathlib and
    # unrelated users unchanged. Always clean the intentionally retained file.
    error = [OSError]
    allocated = []

    class FaultPath(type(tmp_path)):
        def unlink(self, *args, **kwargs):
            raise error[0]("cleanup failure")

    allocate = scratch.write_temp_text

    def tracked(*args, **kwargs):
        path = allocate(*args, **kwargs)
        allocated.append(Path(path))
        return FaultPath(path)

    monkeypatch.setattr(scratch, "write_temp_text", tracked)
    try:
        yield error
    finally:
        for path in allocated:
            path.unlink(missing_ok=True)


@pytest.mark.parametrize("body_error", [OSError, KeyboardInterrupt])
@pytest.mark.parametrize("cleanup_error", [OSError, KeyboardInterrupt])
def test_cleanup_does_not_replace_body_failure(tmp_path, failed_unlink, body_error, cleanup_error):
    failed_unlink[0] = cleanup_error
    with pytest.raises(body_error, match="primary failure"):
        with scratch.temporary_text("payload", dir=tmp_path, prefix="input-", suffix=".txt"):
            raise body_error("primary failure")


@pytest.mark.parametrize("cleanup_error", [OSError, KeyboardInterrupt])
def test_new_cleanup_failure_propagates(tmp_path, failed_unlink, cleanup_error):
    failed_unlink[0] = cleanup_error
    with pytest.raises(cleanup_error, match="cleanup failure"):
        with scratch.temporary_text("payload", dir=tmp_path, prefix="input-", suffix=".txt"):
            pass


def test_best_effort_cleanup_preserves_success(tmp_path, failed_unlink, caplog):
    with scratch.temporary_text("payload", dir=tmp_path, prefix="input-", suffix=".txt", strict_cleanup=False) as path:
        result = path.read_text()
    assert result == "payload"
    assert any("Temporary text cleanup failed" in record.getMessage() for record in caplog.records)


@pytest.mark.parametrize("error", [KeyboardInterrupt, RuntimeError])
def test_best_effort_cleanup_does_not_swallow_control_or_programming_errors(tmp_path, failed_unlink, error):
    failed_unlink[0] = error
    with pytest.raises(error, match="cleanup failure"):
        with scratch.temporary_text("payload", dir=tmp_path, prefix="input-", suffix=".txt", strict_cleanup=False):
            pass


@pytest.mark.parametrize("errors", ["strict", "replace"])
def test_encoding_error_policy_retains_expanded_source_contract(tmp_path, errors):
    def write():
        with scratch.temporary_text("prefix\udcffsuffix", dir=tmp_path, prefix="input-", suffix=".c", errors=errors) as path:
            return path.read_bytes()
    if errors == "strict":
        with pytest.raises(UnicodeEncodeError):
            write()
    else:
        assert write() == b"prefix?suffix"
    assert not list(tmp_path.iterdir())
