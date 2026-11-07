"""Cache diagnostics cannot override best-effort I/O or cancellation."""

import pytest

from core.sandbox import calibrate as cal


@pytest.fixture
def cache(tmp_path, monkeypatch):
    directory = tmp_path / "cache"
    directory.mkdir()
    monkeypatch.setattr(cal, "_CACHE_DIR", directory)
    return directory


def profile():
    return cal.SandboxProfile(
        binary_path="/owned/tool", binary_sha256="digest",
        env_signature="env", captured_at="timestamp",
    )


def fail_at(monkeypatch, cache, route, error):
    def fail(*args, **kwargs):
        raise error

    if route == "directory":
        class UnavailableDirectory(type(cache)):
            def mkdir(self, *args, **kwargs):
                raise error
        monkeypatch.setattr(cal, "_CACHE_DIR", UnavailableDirectory(cache))
    elif route == "write":
        monkeypatch.setattr(cal, "write_text_atomically", fail)
    else:
        monkeypatch.setattr(cal, "_read_cache_profile", fail)


@pytest.mark.parametrize("route", ["directory", "write", "read"])
@pytest.mark.parametrize("formatting", ["runtime", "type", "non-string"])
def test_cache_failure_remains_best_effort(cache, monkeypatch, caplog, route, formatting):
    attempts = []

    class BrokenError(OSError):
        def __str__(self):
            attempts.append("str")
            if formatting == "non-string":
                return None
            if formatting == "type":
                raise TypeError("message unavailable")
            raise RuntimeError("message unavailable")

        def __repr__(self):
            raise AssertionError("diagnostics must not try repr")

    path = cache / "entry.json"
    original = profile().to_json()
    path.write_text(original)
    with monkeypatch.context() as patch:
        fail_at(patch, cache, route, BrokenError())
        if route == "read":
            assert cal._load_from_cache("entry") is None
        else:
            assert cal._save_to_cache("entry", profile()) is None
    assert attempts == ["str"]
    assert "exception message unavailable" in caplog.text
    assert path.read_text() == original
    # The cache remains usable once the owned fault is removed.
    replacement = profile()
    replacement.captured_at = "retry"
    cal._save_to_cache("entry", replacement)
    assert cal._load_from_cache("entry") == replacement
    assert list(cache.iterdir()) == [path]


@pytest.mark.parametrize("route", ["directory", "write", "read"])
@pytest.mark.parametrize("kind", [KeyboardInterrupt, SystemExit], ids=["interrupt", "exit"])
def test_cache_cancellation_retains_identity(cache, monkeypatch, route, kind):
    error = kind("stop")
    with monkeypatch.context() as patch:
        fail_at(patch, cache, route, error)
        with pytest.raises(kind) as caught:
            if route == "read":
                cal._load_from_cache("entry")
            else:
                cal._save_to_cache("entry", profile())
    assert caught.value is error
    assert not list(cache.iterdir())


def test_cache_warning_sanitises_ordinary_error(cache, monkeypatch, caplog):
    with monkeypatch.context() as patch:
        fail_at(patch, cache, "write", OSError("bad\x1b[31m\ncache"))
        assert cal._save_to_cache("entry", profile()) is None
    assert "\x1b" not in caplog.text
    assert cal._load_from_cache("entry") is None
