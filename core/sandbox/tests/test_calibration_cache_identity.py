"""Calibration memo and disk cache retain the inputs they measured."""

import hashlib
import os
import threading
from types import SimpleNamespace

import pytest

from core.sandbox import calibrate as cal
from core.sandbox import calibrated_hosts as memo


@pytest.fixture(autouse=True)
def isolated_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(cal, "_CACHE_DIR", tmp_path / "profiles")
    monkeypatch.setattr(memo, "_CACHE", {})


@pytest.fixture
def binary(tmp_path):
    path = tmp_path / "tool"
    path.write_bytes(b"one")
    return path


def stub_probe(monkeypatch):
    calls = []

    def probe(path, args, *, timeout, extra_env):
        calls.append((list(args), extra_env))
        return cal.SandboxProfile(
            binary_path=str(path), binary_sha256="", env_signature="",
            captured_at="test", probe_args=list(args), paths_read=["/observed"],
        ), 0

    monkeypatch.setattr(cal, "_spawn_probe", probe)
    return calls


def test_disk_cache_separates_probe_argv(monkeypatch, binary):
    calls = stub_probe(monkeypatch)
    first = cal.load_or_calibrate(binary, probe_args=["--first"])
    second = cal.load_or_calibrate(binary, probe_args=["--second"])
    assert first.probe_args == ["--first"]
    assert second.probe_args == ["--second"]
    assert cal.load_or_calibrate(binary, probe_args=["--first"]).probe_args == ["--first"]
    assert len(calls) == 2
    assert len(list(cal._CACHE_DIR.glob("*.json"))) == 2
    assert cal.clear_cache(binary) == 2


@pytest.mark.parametrize("api", [cal.calibrate_binary, cal.load_or_calibrate])
def test_generators_reach_both_fingerprint_and_probe(monkeypatch, binary, api):
    monkeypatch.setenv("CAL_IDENTITY_TEST", "configured")
    calls = stub_probe(monkeypatch)
    profile = api(
        binary, probe_args=(arg for arg in ["--inspect"]),
        env_keys=(key for key in ["CAL_IDENTITY_TEST"]),
    )
    assert calls[0][0] == ["--inspect"]
    assert calls[0][1]["CAL_IDENTITY_TEST"] == "configured"
    assert profile.env_signature == cal._env_signature(["CAL_IDENTITY_TEST"])
    assert profile.probe_args == ["--inspect"]


@pytest.mark.parametrize("field,value", [
    ("env_signature", "incorrect"), ("probe_args", ["--different"]),
])
def test_mismatched_disk_metadata_recalibrates(monkeypatch, binary, field, value):
    calls = stub_probe(monkeypatch)
    sha = cal._sha256_file(binary)
    env = cal._env_signature(())
    profile = cal.SandboxProfile(
        binary_path=str(binary), binary_sha256=sha, env_signature=env,
        captured_at="stale", probe_args=["--version"], paths_read=["/stale"],
    )
    setattr(profile, field, value)
    cal._save_to_cache(cal._fingerprint(sha, env), profile)
    fresh = cal.load_or_calibrate(binary)
    assert fresh.captured_at == "test"
    assert len(calls) == 1


def test_memo_refreshes_declared_environment_values(monkeypatch, binary):
    calls = []

    def load(*args, **kwargs):
        result = SimpleNamespace(proxy_hosts=[os.environ.get("CAL_IDENTITY_TEST", "unset")])
        calls.append(result)
        return result

    monkeypatch.setattr(cal, "load_or_calibrate", load)
    monkeypatch.setenv("CAL_IDENTITY_TEST", "first")
    first = memo.calibrated_profile(str(binary), ["CAL_IDENTITY_TEST"])
    assert memo.calibrated_profile(str(binary), ["CAL_IDENTITY_TEST"]) is first
    monkeypatch.setenv("CAL_IDENTITY_TEST", "second")
    second = memo.calibrated_profile(str(binary), ["CAL_IDENTITY_TEST"])
    assert second.proxy_hosts == ["second"]
    monkeypatch.setenv("CAL_UNRELATED_TEST", "ignored")
    assert memo.calibrated_profile(str(binary), ["CAL_IDENTITY_TEST"]) is second
    monkeypatch.delenv("CAL_IDENTITY_TEST")
    assert memo.calibrated_profile(str(binary), ["CAL_IDENTITY_TEST"]).proxy_hosts == ["unset"]
    assert len(calls) == 3
    assert len(memo._CACHE) == 1


@pytest.mark.parametrize("update", ["edit", "replace"])
def test_memo_refreshes_binary_updates(monkeypatch, binary, update):
    calls = []

    def load(*args, **kwargs):
        result = SimpleNamespace(proxy_hosts=[binary.read_text()])
        calls.append(result)
        return result

    monkeypatch.setattr(cal, "load_or_calibrate", load)
    first = memo.calibrated_profile(str(binary), ())
    if update == "edit":
        binary.write_bytes(b"updated")
    else:
        before = binary.stat()
        replacement = binary.with_name("replacement")
        replacement.write_bytes(b"two")
        os.utime(replacement, ns=(before.st_atime_ns, before.st_mtime_ns))
        replacement.replace(binary)
    fresh = memo.calibrated_profile(str(binary), ())
    assert fresh is not first
    assert fresh.proxy_hosts == [binary.read_text()]
    assert memo.calibrated_profile(str(binary), ()) is fresh
    assert len(calls) == 2
    assert len(memo._CACHE) == 1


def test_missing_binary_memo_retries_when_binary_appears(monkeypatch, tmp_path):
    binary = tmp_path / "appearing-tool"
    profile = SimpleNamespace(proxy_hosts=["configured.example"])
    calls = []

    def load(*args, **kwargs):
        calls.append(True)
        if not binary.exists():
            raise FileNotFoundError(binary)
        return profile

    monkeypatch.setattr(cal, "load_or_calibrate", load)
    assert memo.calibrated_profile(str(binary), ()) is None
    binary.write_text("available")
    assert memo.calibrated_profile(str(binary), ()) is profile
    assert len(calls) == 2


def test_waiter_timeout_does_not_cancel_or_replace_owner(monkeypatch, binary):
    started, release, waiter_done = threading.Event(), threading.Event(), threading.Event()
    owner_results, waiter_results, errors = [], [], []
    profile = SimpleNamespace(proxy_hosts=["ready.example"])

    def load(*args, **kwargs):
        started.set()
        assert release.wait(5)
        return profile

    def call(results, timeout, done=None):
        try:
            results.append(memo.calibrated_profile(str(binary), (), timeout=timeout))
        except BaseException as exc:
            errors.append(exc)
        finally:
            if done is not None:
                done.set()

    monkeypatch.setattr(cal, "load_or_calibrate", load)
    owner = threading.Thread(target=call, args=(owner_results, 20), daemon=True)
    waiter = threading.Thread(target=call, args=(waiter_results, 0, waiter_done), daemon=True)
    owner.start()
    try:
        assert started.wait(5)
        waiter.start()
        assert waiter_done.wait(5), "waiter ignored its own advisory timeout"
        assert waiter_results == [None]
        assert owner.is_alive()
    finally:
        release.set()
        owner.join(5)
        if waiter.ident is not None:
            waiter.join(5)
    assert not errors
    assert owner_results == [profile]
    assert memo.calibrated_profile(str(binary), (), timeout=0) is profile


def test_old_waiters_do_not_receive_or_overwrite_new_generation(monkeypatch, binary):
    old_started, release_old = threading.Event(), threading.Event()
    waiting, new_done = threading.Event(), threading.Event()
    old = SimpleNamespace(proxy_hosts=["old.example"])
    new = SimpleNamespace(proxy_hosts=["new.example"])
    old_results, waiter_results, new_results, errors, calls = [], [], [], [], []

    def load(*args, **kwargs):
        value = os.environ["CAL_IDENTITY_TEST"]
        calls.append(value)
        if value == "old":
            old_started.set()
            assert release_old.wait(5)
            return old
        return new

    def call(results, done=None):
        try:
            results.append(memo.calibrated_profile(str(binary), ["CAL_IDENTITY_TEST"]))
        except BaseException as exc:
            errors.append(exc)
        finally:
            if done is not None:
                done.set()

    monkeypatch.setattr(cal, "load_or_calibrate", load)
    monkeypatch.setenv("CAL_IDENTITY_TEST", "old")
    owner = threading.Thread(target=call, args=(old_results,), daemon=True)
    waiter = threading.Thread(target=call, args=(waiter_results,), daemon=True)
    newer = threading.Thread(target=call, args=(new_results, new_done), daemon=True)
    owner.start()
    try:
        assert old_started.wait(5)
        entry = next(iter(memo._CACHE.values()))
        real_wait = entry.ready.wait

        def observed_wait(*args, **kwargs):
            waiting.set()
            return real_wait(*args, **kwargs)

        monkeypatch.setattr(entry.ready, "wait", observed_wait)
        waiter.start()
        assert waiting.wait(5)
        monkeypatch.setenv("CAL_IDENTITY_TEST", "new")
        newer.start()
        assert new_done.wait(5), "new inputs blocked behind an obsolete generation"
        assert new_results == [new]
    finally:
        release_old.set()
        for thread in (owner, waiter, newer):
            if thread.ident is not None:
                thread.join(5)
    assert not errors
    assert old_results == [None]
    assert waiter_results == [None]
    assert memo.calibrated_profile(str(binary), ["CAL_IDENTITY_TEST"]) is new
    assert calls == ["old", "new"]
    assert len(memo._CACHE) == 1


def test_cli_show_uses_requested_probe_args(monkeypatch, binary, capsys):
    from core.sandbox.calibrate_cli import _cli_main
    calls = stub_probe(monkeypatch)
    cal.load_or_calibrate(binary, probe_args=["--first"])
    cal.load_or_calibrate(binary, probe_args=["--second"])
    assert _cli_main([
        "--bin", str(binary), "--probe-args=--second", "--show", "--json",
    ]) == 0
    import json
    assert json.loads(capsys.readouterr().out)["probe_args"] == ["--second"]
    assert len(calls) == 2


@pytest.mark.parametrize("args", [["--version"], ["--custom"]])
def test_compatible_legacy_cache_does_not_trigger_probe(monkeypatch, binary, args):
    sha = cal._sha256_file(binary)
    env = cal._env_signature(())
    legacy = hashlib.sha256((sha + "\0" + env).encode("ascii")).hexdigest()
    profile = cal.SandboxProfile(
        binary_path=str(binary), binary_sha256=sha, env_signature=env,
        captured_at="legacy", probe_args=args, paths_read=["/legacy"],
    )
    cal._save_to_cache(legacy, profile)
    calls = stub_probe(monkeypatch)
    result = cal.load_or_calibrate(binary, probe_args=args)
    assert result.captured_at == "legacy"
    assert calls == []


def test_legacy_cache_with_other_args_is_not_reused(monkeypatch, binary):
    sha = cal._sha256_file(binary)
    env = cal._env_signature(())
    legacy = hashlib.sha256((sha + "\0" + env).encode("ascii")).hexdigest()
    cal._save_to_cache(legacy, cal.SandboxProfile(
        binary_path=str(binary), binary_sha256=sha, env_signature=env,
        captured_at="legacy", probe_args=["--old"], paths_read=["/legacy"],
    ))
    calls = stub_probe(monkeypatch)
    result = cal.load_or_calibrate(binary, probe_args=["--new"])
    assert result.probe_args == ["--new"]
    assert len(calls) == 1


def test_inputs_changed_during_measurement_are_not_memoised(monkeypatch, binary):
    profile = SimpleNamespace(proxy_hosts=["measured.example"])
    monkeypatch.setenv("CAL_IDENTITY_TEST", "before")
    calls = []

    def changing_load(*args, **kwargs):
        calls.append(True)
        monkeypatch.setenv("CAL_IDENTITY_TEST", "after")
        return profile

    monkeypatch.setattr(cal, "load_or_calibrate", changing_load)
    assert memo.calibrated_profile(str(binary), ["CAL_IDENTITY_TEST"]) is None
    assert not memo._CACHE
    monkeypatch.setenv("CAL_IDENTITY_TEST", "before")
    monkeypatch.setattr(cal, "load_or_calibrate", lambda *a, **kw: profile)
    assert memo.calibrated_profile(str(binary), ["CAL_IDENTITY_TEST"]) is profile
    assert len(calls) == 1
