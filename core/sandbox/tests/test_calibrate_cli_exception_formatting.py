"""Calibration CLI failures retain their exit status and cleanup results."""

from contextlib import contextmanager

import pytest

from core.sandbox import calibrate as cal
from core.sandbox import calibrate_cli as cli


ROUTES = [
    "clear-all", "clear-one", "partial-all", "partial-one", "expand",
    "inspect", "hash", "missing", "probe-os", "probe-runtime",
]


@pytest.fixture
def owned(tmp_path, monkeypatch):
    binary = tmp_path / "tool"
    binary.write_bytes(b"owned binary; never executed")
    cache = tmp_path / "cache"
    cache.mkdir()
    monkeypatch.setattr(cal, "_CACHE_DIR", cache)

    def no_probe(*args, **kwargs):
        raise AssertionError("diagnostic tests must never spawn a probe")

    monkeypatch.setattr(cal, "load_or_calibrate", no_probe)
    return binary, cache


def configure(monkeypatch, owned, route, error):
    binary, cache = owned
    args = ["--bin", str(binary)]

    def fail(*args, **kwargs):
        raise error

    if route in {"clear-all", "clear-one"}:
        @contextmanager
        def unavailable(**kwargs):
            raise error
            yield  # pragma: no cover
        monkeypatch.setattr(cal, "_cache_entry_paths", unavailable)
    elif route in {"partial-all", "partial-one"}:
        profile = cal.SandboxProfile(
            binary_path=str(binary), binary_sha256=cal._sha256_file(binary),
            env_signature="env", captured_at="timestamp",
        )
        for name in ["bad.json", "good.json"]:
            (cache / name).write_text(profile.to_json())

        class RefusedEntry(type(cache)):
            def unlink(self, *args, **kwargs):
                raise error

        @contextmanager
        def entries(**kwargs):
            yield (RefusedEntry(cache / "bad.json"), cache / "good.json")

        monkeypatch.setattr(cal, "_cache_entry_paths", entries)
    elif route in {"expand", "inspect"}:
        class UnavailablePath(type(binary)):
            def expanduser(self):
                if route == "expand":
                    raise error
                return self

            def exists(self):
                if route == "inspect":
                    raise error
                return super().exists()

        monkeypatch.setattr(cli, "Path", UnavailablePath)
    elif route == "hash":
        monkeypatch.setattr(cal, "_sha256_file", fail)
        args += ["--show"]
    else:
        monkeypatch.setattr(cal, "load_or_calibrate", fail)
    if route in {"clear-all", "partial-all"}:
        args = ["--clear-all"]
    elif route in {"clear-one", "partial-one"}:
        args += ["--clear"]
    return args


def error_base(route):
    if route == "missing":
        return FileNotFoundError
    if route in {"expand", "probe-runtime"}:
        return RuntimeError
    return OSError


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("formatting", ["runtime", "type", "non-string"])
def test_cli_failure_keeps_status(owned, monkeypatch, capsys, route, formatting):
    attempts = []

    class BrokenError(error_base(route)):
        def __str__(self):
            attempts.append("str")
            if formatting == "non-string":
                return None
            if formatting == "type":
                raise TypeError("message unavailable")
            raise RuntimeError("message unavailable")

        def __repr__(self):
            raise AssertionError("diagnostics must not try repr")

    with monkeypatch.context() as patch:
        argv = configure(patch, owned, route, BrokenError())
        expected = cli._USAGE_EX if route in {"expand", "missing"} else cli._SOFTWARE_EX
        assert cli._cli_main(argv) == expected
    output = capsys.readouterr()
    assert attempts == ["str"]
    assert "exception message unavailable" in output.err
    assert "Traceback" not in output.err
    if route.startswith("partial"):
        assert "cleared 1 profile(s)" in output.out
        assert "1 cache operation(s) failed" in output.err
        binary, cache = owned
        assert "bad.json" in output.err
        assert (cache / "bad.json").is_file()
        assert not (cache / "good.json").exists()
        # Removing the fault allows the real CLI to finish cleanup.
        retry = ["--clear-all"] if route == "partial-all" else ["--bin", str(binary), "--clear"]
        assert cli._cli_main(retry) == 0
        assert not list(cache.iterdir())
    else:
        assert output.out == ""
        assert not list(owned[1].iterdir())


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("kind", [KeyboardInterrupt, SystemExit], ids=["interrupt", "exit"])
def test_cli_cancellation_retains_identity(owned, monkeypatch, route, kind):
    error = kind("stop")
    with monkeypatch.context() as patch:
        argv = configure(patch, owned, route, error)
        with pytest.raises(kind) as caught:
            cli._cli_main(argv)
    assert caught.value is error


def test_cli_ordinary_error_is_sanitised(owned, monkeypatch, capsys):
    with monkeypatch.context() as patch:
        argv = configure(patch, owned, "probe-os", OSError("bad\x1b[31m\nmessage"))
        assert cli._cli_main(argv) == cli._SOFTWARE_EX
    output = capsys.readouterr()
    assert "\x1b" not in output.err
    assert output.out == ""
