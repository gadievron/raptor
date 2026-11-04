"""Dispatcher helper resources stay owned when setup or token reads fail."""

import errno
import importlib
import os
from types import SimpleNamespace

import pytest

from core.llm.dispatcher.auth import CredentialStore

_FACTORIES = [
    ("test_body_limits", False),
    ("test_child_ledger_vetoed_death", True),
    ("test_child_tokens", False),
    ("test_error_row_provenance", False),
    ("test_orphan_cancel", False),
    ("test_stream_stall_watchdog", False),
    ("test_upstream_stale_retry", False),
    ("test_upstream_state_header", True),
    ("test_usage_scan_integrity", False),
    ("test_usage_scan_seam", False),
]
_TOKENS = [
    "test_body_limits",
    "test_child_ledger_vetoed_death",
    "test_child_tokens",
    "test_error_row_provenance",
    "test_orphan_cancel",
    "test_stream_stall_watchdog",
    "test_upstream_stale_retry",
    "test_upstream_state_header",
]


@pytest.mark.parametrize(
    "module_name,uses_url", _FACTORIES, ids=[name for name, _ in _FACTORIES]
)
@pytest.mark.parametrize("fault", ["lookup", "construction"])
def test_failed_rule_setup_reclaims_dispatcher(
    module_name,
    uses_url,
    fault,
    tmp_path,
    monkeypatch,
):
    module = importlib.import_module(f"core.llm.dispatcher.tests.{module_name}")
    dispatchers = []
    real_dispatcher = module.LLMDispatcher
    creds = CredentialStore.__new__(CredentialStore)
    creds._keys = {"anthropic": "fixture-key", "openai": None, "gemini": None}

    class RefusingRules(dict):
        def __getitem__(self, key):
            raise RuntimeError("injected rule lookup failure")

    def dispatcher(*args, **kwargs):
        instance = real_dispatcher(*args, **kwargs)
        dispatchers.append(instance)
        if fault == "lookup":
            instance._rules = RefusingRules(instance._rules)
        return instance

    def rule(**kwargs):
        raise RuntimeError("injected rule construction failure")

    upstream = SimpleNamespace(base_url="http://127.0.0.1:1")
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "LLMDispatcher", dispatcher)
            if fault == "construction":
                patcher.setattr(module, "ProviderRule", rule)
            with pytest.raises(RuntimeError, match=f"injected rule {fault} failure"):
                module._make_dispatcher(
                    creds, tmp_path, upstream.base_url if uses_url else upstream
                )
        assert len(dispatchers) == 1
        instance = dispatchers[0]
        assert not instance._thread.is_alive(), "failed setup left dispatcher running"
        assert instance._server.socket.fileno() == -1
        assert not instance.socket_path.exists()
    finally:
        for instance in dispatchers:
            instance.shutdown()


@pytest.mark.parametrize("module_name", _TOKENS)
@pytest.mark.parametrize("fault", ["read", "decode", "none"])
def test_worker_token_always_closes_descriptor(module_name, fault, monkeypatch):
    module = importlib.import_module(f"core.llm.dispatcher.tests.{module_name}")
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, b"\xff" if fault == "decode" else b"fixture-token\n")
    finally:
        os.close(write_fd)

    def read(fd, size):
        raise OSError("injected token read failure")

    dispatcher = SimpleNamespace(allocate_worker=lambda **kwargs: ("worker", read_fd))
    try:
        with monkeypatch.context() as patcher:
            if fault == "read":
                patcher.setattr(
                    module, "os", SimpleNamespace(read=read, close=os.close)
                )
            if fault == "none":
                assert module._worker_token(dispatcher) == "fixture-token"
            else:
                with pytest.raises(OSError if fault == "read" else UnicodeDecodeError):
                    module._worker_token(dispatcher)
        with pytest.raises(OSError) as error:
            os.fstat(read_fd)
        assert error.value.errno == errno.EBADF
    finally:
        try:
            os.close(read_fd)
        except OSError:
            pass
