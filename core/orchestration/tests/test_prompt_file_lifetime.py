"""Anonymous prompt ownership across setup, dispatch and interruption."""

import subprocess
import tempfile
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

import core.orchestration.skill_dispatch as sd
from core.testing.module_bindings import patch_module_attribute
from core.testing.module_views import scoped_function_imports

pytestmark = pytest.mark.usefixtures("cc_spawn_machinery_enabled")


@pytest.fixture
def dispatch_imports():
    import core.llm.cc_adapter as adapter
    import core.llm.cc_probe as probe
    import core.security.rule_of_two as rule

    with scoped_function_imports(sd, ("run_skill_dispatch",), {
        "core.llm.cc_adapter": adapter,
        "core.llm.cc_probe": probe,
        "core.security.rule_of_two": rule,
    }) as imports:
        yield (
            getattr(imports, "core.llm.cc_adapter"),
            getattr(imports, "core.llm.cc_probe"),
            getattr(imports, "core.security.rule_of_two"),
        )


@pytest.fixture
def dispatch(monkeypatch, tmp_path, dispatch_imports):
    adapter, probe, rule = dispatch_imports
    monkeypatch.delenv("RAPTOR_NO_CLAUDE", raising=False)
    monkeypatch.setenv(sd._CC_CREDENTIAL_MODE_ENV, "proxy")
    monkeypatch.setattr(rule, "require_human_or_sandbox_for_agentic_pass", lambda _: None)
    monkeypatch.setattr(adapter, "resolve_claude_cli", lambda _: "/owned/claude")
    monkeypatch.setattr(probe, "probe_cc_session_model", lambda _: "test-model")
    monkeypatch.setattr(adapter, "cc_subprocess_env", lambda **_: {})
    monkeypatch.setattr(adapter, "build_cc_command", lambda *_, **__: ["/owned/claude"])
    monkeypatch.setattr(adapter, "system_prompt_file_for", lambda _: nullcontext(None))
    monkeypatch.setattr(sd, "_readable_paths_for_cc_dispatch", lambda _: [])
    monkeypatch.setattr(sd, "_proxy_hosts_for_cc_dispatch", lambda *_, **__: ())
    creds = SimpleNamespace(base_url="http://127.0.0.1:1", token="test", bridges={})
    monkeypatch.setattr(sd, "_setup_cc_proxy_credentials", lambda *args: creds)
    failures, completed, settled, calls = [], [], [], []
    monkeypatch.setattr(sd, "start_lifecycle", lambda *_, **__: sd.LifecycleStart(tmp_path))
    monkeypatch.setattr(sd, "fail_lifecycle", lambda rd, reason: failures.append(reason))
    monkeypatch.setattr(sd, "complete_lifecycle", lambda rd: completed.append(rd))
    monkeypatch.setattr(sd, "_settle_cc_proxy_credentials", lambda *args: settled.append(args))

    def run(*args, **kwargs):
        calls.append(kwargs)
        if "stdin" in kwargs:
            assert not kwargs["stdin"].closed
            assert kwargs["stdin"].read() == "operator context: café".encode()
        return subprocess.CompletedProcess(args[0], 0, "", "")

    monkeypatch.setattr(sd, "run_untrusted_networked", run)
    return SimpleNamespace(
        invoke=lambda: sd.run_skill_dispatch(
            command="understand", target=tmp_path, tools="Read", budget_usd="1",
            timeout_s=60, caller_label="test", log_label="test",
            build_prompt=lambda _: "operator context: café",
        ),
        failures=failures, completed=completed, settled=settled, calls=calls,
    )


@pytest.fixture
def streams(monkeypatch, tmp_path):
    owned = []
    real_temporary = tempfile.TemporaryFile

    def install(operation=None, error=None, close_error=None):
        class Stream:
            def __init__(self, raw):
                self.raw = raw
                self.reached = []
                owned.append(self)

            @property
            def closed(self):
                return self.raw.closed

            def __getattr__(self, name):
                return getattr(self.raw, name)

            def act(self, name, *args):
                self.reached.append(name)
                if name == operation:
                    raise error
                return getattr(self.raw, name)(*args)

            def write(self, data):
                return self.act("write", data)

            def flush(self):
                return self.act("flush")

            def seek(self, offset):
                return self.act("seek", offset)

            def close(self):
                self.reached.append("close")
                self.raw.close()
                if close_error is not None:
                    raise close_error

        patch_module_attribute(monkeypatch, sd, "tempfile", "TemporaryFile",
                               lambda *a, **kw: Stream(real_temporary(*a, dir=tmp_path, **kw)))
        return owned

    yield install
    for stream in owned:
        stream.raw.close()


@pytest.mark.parametrize("operation", ["write", "flush", "seek"])
@pytest.mark.parametrize("error_type", [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_setup_failure_closes_prompt_and_settles(dispatch, streams, operation, error_type):
    error = error_type("prompt setup")
    owned = streams(operation, error)
    with pytest.raises(error_type) as caught:
        dispatch.invoke()
    assert caught.value is error
    assert owned and operation in owned[0].reached
    assert owned[0].closed
    assert dispatch.calls == []
    assert dispatch.completed == []
    assert dispatch.failures
    assert len(dispatch.settled) == 1


def test_proxy_prompt_is_rewound_and_closed_after_dispatch(dispatch, streams):
    owned = streams()
    assert dispatch.invoke().ran
    assert owned[0].closed
    assert "input" not in dispatch.calls[0]
    assert dispatch.completed and len(dispatch.settled) == 1


def test_env_prompt_uses_input_without_allocating_file(dispatch, streams, monkeypatch):
    monkeypatch.setenv(sd._CC_CREDENTIAL_MODE_ENV, "env")
    owned = streams()
    assert dispatch.invoke().ran
    assert owned == []
    assert dispatch.calls[0]["input"] == "operator context: café"
    assert "stdin" not in dispatch.calls[0]
    assert dispatch.settled == []


def test_close_failure_preserves_active_setup_error(dispatch, streams):
    primary = KeyboardInterrupt("setup interrupted")
    owned = streams("flush", primary, OSError("close failed"))
    with pytest.raises(KeyboardInterrupt) as caught:
        dispatch.invoke()
    assert caught.value is primary
    assert owned[0].closed
    assert owned[0].reached[-1] == "close"
    assert dispatch.failures and len(dispatch.settled) == 1


def test_close_failure_after_success_is_reported(dispatch, streams):
    error = OSError("close failed")
    owned = streams(close_error=error)
    with pytest.raises(OSError) as caught:
        dispatch.invoke()
    assert caught.value is error
    assert owned[0].closed
    assert dispatch.calls and not dispatch.completed
    assert dispatch.failures and len(dispatch.settled) == 1


@pytest.mark.parametrize("error_type", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_dispatch_error_survives_secondary_close_failure(
    dispatch, streams, monkeypatch, error_type,
):
    error = error_type("dispatch failed")
    owned = streams(close_error=OSError("close failed"))

    def fail(*args, **kwargs):
        assert kwargs["stdin"].read() == "operator context: café".encode()
        raise error

    monkeypatch.setattr(sd, "run_untrusted_networked", fail)
    with pytest.raises(error_type) as caught:
        dispatch.invoke()
    assert caught.value is error
    assert owned[0].closed
    assert dispatch.failures and len(dispatch.settled) == 1
