"""Consumed-attempt wire setup owns dispatcher, token FD and partial state."""

import errno
import os
import socket
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from core.llm.tests import test_consumed_attempt_e2e as module
from core.testing import fds as support


def _owned(fd, identity):
    try:
        stat = os.fstat(fd)
    except OSError as exc:
        if exc.errno == errno.EBADF:
            return False
        raise
    return (stat.st_dev, stat.st_ino) == identity


@pytest.mark.parametrize(
    "stage,error,previous_socket",
    [
        (stage, error, "previous-socket")
        for stage in ("rule", "allocate", "read", "env", "cache", "none")
        for error in (OSError, KeyboardInterrupt)
    ]
    + [
        pytest.param(stage, error, None, id=f"{stage}-{error.__name__}-absent")
        for stage in ("env", "cache")
        for error in (OSError, KeyboardInterrupt)
    ],
)
def test_wire_failure_releases_resources_and_partial_state(
    stage, error, previous_socket, tmp_path, monkeypatch
):
    owned = socket.socket()
    read_fd, write_fd = os.pipe()
    stat = os.fstat(read_fd)
    identity = (stat.st_dev, stat.st_ino)
    os.write(write_fd, b"owned-token")
    os.close(write_fd)
    allocated = False
    failure = error("injected wire setup failure")
    dispatcher = SimpleNamespace(
        _rules={
            "anthropic": SimpleNamespace(
                name="anthropic",
                inject_headers={},
                strip_request_headers=(),
            )
        },
        socket_path=tmp_path / "owned.sock",
        shutdown=Mock(side_effect=owned.close),
    )

    def allocate(**kwargs):
        nonlocal allocated
        if stage == "allocate":
            raise failure
        allocated = True
        return "unused", read_fd

    dispatcher.allocate_worker = allocate
    real_read = os.read

    def read(fd, size):
        if stage == "read":
            raise failure
        return real_read(fd, size)

    filesystem = SimpleNamespace(**vars(os))
    filesystem.read = read
    cache = SimpleNamespace(_cached_token="previous-token")
    try:
        with monkeypatch.context() as patcher:
            if previous_socket is None:
                patcher.delenv("RAPTOR_LLM_SOCKET", raising=False)
            else:
                patcher.setenv("RAPTOR_LLM_SOCKET", previous_socket)
            patcher.setattr(module, "os", filesystem)
            patcher.setattr(support, "os", filesystem)
            patcher.setattr(module, "dispatcher_client", cache)
            patcher.setattr(module, "LLMDispatcher", Mock(return_value=dispatcher))
            patcher.setattr(
                module,
                "ProviderRule",
                Mock(side_effect=failure if stage == "rule" else None),
            )

            class SetupPatch:
                def setenv(self, *args, **kwargs):
                    patcher.setenv(*args, **kwargs)
                    if stage == "env":
                        raise failure

                def setattr(self, *args, **kwargs):
                    patcher.setattr(*args, **kwargs)
                    if stage == "cache":
                        raise failure

            if stage == "none":
                assert (
                    module._wire(
                        None,
                        tmp_path,
                        SimpleNamespace(base_url="http://unused.invalid"),
                        SetupPatch(),
                    )
                    is dispatcher
                )
                assert owned.fileno() != -1
                assert os.environ["RAPTOR_LLM_SOCKET"] == str(dispatcher.socket_path)
                assert cache._cached_token == "owned-token"
                dispatcher.shutdown()
            else:
                with pytest.raises(error, match="injected wire setup failure"):
                    module._wire(
                        None,
                        tmp_path,
                        SimpleNamespace(base_url="http://unused.invalid"),
                        SetupPatch(),
                    )
                assert owned.fileno() == -1, "wire setup left dispatcher resource open"
                assert os.environ.get("RAPTOR_LLM_SOCKET") == previous_socket
                assert cache._cached_token == "previous-token"
            if allocated:
                assert not _owned(read_fd, identity), (
                    "wire setup left its token descriptor open"
                )
    finally:
        owned.close()
        if _owned(read_fd, identity):
            os.close(read_fd)


@pytest.mark.parametrize(
    "name",
    [
        "test_mid_response_death_upstream_processes_exactly_once",
        "test_pre_response_death_keeps_worker_retry",
        "test_escape_hatch_resends_through_the_real_stack",
    ],
)
@pytest.mark.parametrize("stage", ["wire", "upstream_shutdown"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_consumed_caller_failure_releases_acquired_resources(
    name, stage, error, tmp_path, monkeypatch
):
    import inspect

    upstream_socket = socket.socket()
    dispatcher_socket = socket.socket()
    failure = error("injected consumed caller failure")

    def close_upstream():
        upstream_socket.close()
        if stage == "upstream_shutdown":
            raise failure

    upstream = SimpleNamespace(shutdown=close_upstream)
    dispatcher = SimpleNamespace(shutdown=dispatcher_socket.close)
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "MockUpstream", Mock(return_value=upstream))
            patcher.setattr(
                module,
                "_wire",
                Mock(
                    side_effect=failure if stage == "wire" else None,
                    return_value=dispatcher,
                ),
            )
            patcher.setattr(module, "_llm_client", Mock(side_effect=failure))
            caller = getattr(module.TestConsumedAttemptE2E(), name)
            kwargs = {
                parameter: {"tmp_path": tmp_path, "monkeypatch": patcher}.get(parameter)
                for parameter in inspect.signature(caller).parameters
            }
            with pytest.raises(error, match="injected consumed caller failure"):
                caller(**kwargs)
        assert upstream_socket.fileno() == -1, (
            "caller left upstream acquired before wire failure"
        )
        if stage == "upstream_shutdown":
            assert dispatcher_socket.fileno() == -1, (
                "upstream teardown failure skipped dispatcher cleanup"
            )
    finally:
        upstream_socket.close()
        dispatcher_socket.close()
