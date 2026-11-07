"""Tool probes retain their outcomes while owning all temporary artifacts."""

import os
import subprocess
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.config import RaptorConfig
from core.run import scratch, toolprobe, tmp_reaper
from core.startup import doctor
from core.testing.module_bindings import patch_module_attribute
from core.testing.module_state import isolated_module_state
from core.testing.scratch_state import isolated_scratch_keepalive
from packages.fuzzing import capability, cargofuzz_runner


@pytest.fixture(autouse=True)
def owned_scratch():
    with isolated_module_state(tmp_reaper, {
        "_RUNTIME_DIR_PREFIXES": set(tmp_reaper._RUNTIME_DIR_PREFIXES),
    }), isolated_scratch_keepalive():
        yield


@pytest.fixture(params=["toolprobe", "doctor", "version", "sanitizer", "afl", "cargo"])
def probe_case(request, tmp_path, monkeypatch):
    roots = []
    state = SimpleNamespace(error=None)
    original = scratch.scratch_dir

    @contextmanager
    def workspace(prefix, **kwargs):
        with original(prefix, **kwargs) as root:
            roots.append(root)
            yield root

    for consumer in (toolprobe, doctor, capability, cargofuzz_runner):
        monkeypatch.setattr(consumer, "scratch_dir", workspace)

    def run(argv, **kwargs):
        root = roots[-1]
        assert str(root) in scratch._keepalive_paths
        env = kwargs["env"]
        if request.param == "doctor":
            assert Path(kwargs["cwd"]) == root
            assert argv[1] == "-I"
        else:
            assert env["HOME"] == str(root)
            assert isinstance(env["HOME"], str)
        if request.param in {"version", "sanitizer", "afl"}:
            assert env["TMPDIR"] == str(root)
        if request.param == "toolprobe":
            assert all(Path(env[key]).is_dir() for key in ("XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME"))
        nested = root / "restricted"
        nested.mkdir()
        (nested / "intermediate.o").write_bytes(b"partial")
        nested.chmod(0)
        if state.error is not None:
            raise state.error
        return subprocess.CompletedProcess(argv, 0, "clang version 19.0.0-nightly", "")

    for consumer in (toolprobe, doctor, capability, cargofuzz_runner):
        patch_module_attribute(monkeypatch, consumer, "subprocess", "run", run)
    patch_module_attribute(monkeypatch, toolprobe, "shutil", "which", lambda name: "/fixture/tool")
    monkeypatch.setattr(toolprobe, "safe_subprocess_env", lambda **kwargs: {"TMPDIR": str(tmp_path)})
    monkeypatch.setattr(capability, "exec_workdir", lambda: tmp_path)
    monkeypatch.setattr(cargofuzz_runner, "exec_workdir", lambda: tmp_path)
    monkeypatch.setattr(cargofuzz_runner, "_probe_env", lambda: {"PATH": os.defpath})
    monkeypatch.setattr(RaptorConfig, "TOOL_DEPS", {"fixture": {"module": "json", "affects": "test"}})
    monkeypatch.setattr(RaptorConfig, "get_safe_env", staticmethod(lambda: {"PATH": os.defpath}))

    def invoke():
        if request.param == "toolprobe":
            info = toolprobe.probe("fixture", isolated_home=True)
            return info.returncode
        if request.param == "doctor":
            return doctor._module_dep_warnings()
        if request.param == "version":
            return capability._probe_version("/fixture/tool", ["--version"])
        if request.param == "sanitizer":
            return capability._probe_clang_sanitiser("/fixture/tool", "address")
        if request.param == "afl":
            return capability._check_macos_afl_shmem("/fixture/tool")
        return cargofuzz_runner.nightly_toolchain_arg("/fixture/tool")

    expected = {"toolprobe": 0, "doctor": [], "version": "clang version 19.0.0-nightly", "sanitizer": True, "afl": True, "cargo": ""}
    failed = {"toolprobe": None, "doctor": [], "version": "", "sanitizer": False, "afl": True, "cargo": None}
    return state, invoke, roots, expected[request.param], failed[request.param]


def reclaimed(roots):
    assert roots and all(not root.exists() for root in roots)
    assert not scratch._keepalive_paths


@pytest.mark.parametrize("error_type", [None, OSError, subprocess.TimeoutExpired, KeyboardInterrupt, SystemExit])
def test_probe_success_failure_and_cancellation_release_scratch(probe_case, error_type):
    state, invoke, roots, expected, failed = probe_case
    if error_type is subprocess.TimeoutExpired:
        state.error = error_type("fixture", 10)
    elif error_type:
        state.error = error_type("probe failed")
    if error_type in {KeyboardInterrupt, SystemExit}:
        with pytest.raises(error_type) as caught:
            invoke()
        assert caught.value is state.error
    else:
        assert invoke() == (failed if error_type else expected)
    reclaimed(roots)


def test_cleanup_oserror_preserves_successful_probe(probe_case, monkeypatch):
    state, invoke, roots, expected, failed = probe_case
    remove = scratch.rmtree_hardened

    def cleanup(root):
        assert remove(root)
        raise OSError("cleanup failed")

    monkeypatch.setattr(scratch, "rmtree_hardened", cleanup)
    assert invoke() == expected
    reclaimed(roots)


@pytest.mark.parametrize("error_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("cleanup_type", [OSError, KeyboardInterrupt, SystemExit])
def test_probe_cancellation_survives_cleanup_failure(probe_case, monkeypatch, error_type, cleanup_type):
    state, invoke, roots, expected, failed = probe_case
    state.error = error_type("probe interrupted")
    remove = scratch.rmtree_hardened

    def cleanup(root):
        assert remove(root)
        raise cleanup_type("cleanup interrupted")

    monkeypatch.setattr(scratch, "rmtree_hardened", cleanup)
    with pytest.raises(error_type) as caught:
        invoke()
    assert caught.value is state.error
    reclaimed(roots)
