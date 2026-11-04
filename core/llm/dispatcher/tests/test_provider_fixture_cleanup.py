"""Provider fixtures own servers, dispatchers, and token descriptors."""

import errno
import inspect
import os
from types import SimpleNamespace

import pytest

from core.llm.dispatcher.tests import test_providers as providers
from core.llm.dispatcher.tests import test_stream_stall_watchdog as watchdog
from core.llm.dispatcher.tests import test_usage_scan_integrity as integrity

_NATIVE = ("anthropic", "openai", "gemini", "cohere", "mistral", "azure_openai")
_PROVIDERS = _NATIVE + tuple(b.name for b in providers.MODEL_BROKERS)
_CALLERS = (
    [
        pytest.param(
            "test_registry_broker_roundtrip", {"broker": b}, id=f"registry-{b.name}"
        )
        for b in providers.MODEL_BROKERS
    ]
    + [
        pytest.param(path, {}, id=path)
        for path in (
            "TestAnthropicProvider.test_x_api_key_injected_dummy_stripped",
            "TestAnthropicProvider.test_caller_anthropic_version_honoured",
            "TestOpenAIProvider.test_authorization_bearer_injected",
            "TestGeminiProvider.test_x_goog_api_key_injected_dummy_stripped",
            "TestAzureOpenAIProvider.test_api_key_header_injected_dummy_stripped",
        )
    ]
    + [
        pytest.param(
            "test_bearer_provider_authorization_injected",
            {"provider": p, "path_tail": tail, "expected_key": key},
            id=p,
        )
        for p, tail, key in providers._BEARER_PROVIDERS
    ]
)
_TOKEN_CALLERS = _CALLERS + [
    pytest.param(
        "TestUnconfiguredProvider.test_provider_with_unset_key_returns_503",
        {},
        id="unset-key",
    ),
    pytest.param(
        "TestUnknownProviderPath.test_unknown_path_prefix_returns_404",
        {},
        id="unknown-prefix",
    ),
    pytest.param(
        "TestNewProvidersUnconfiguredKeyReturns503.test_unconfigured_provider_returns_503",
        {"provider": "cohere"},
        id="unset-new-provider",
    ),
]


def _method(module, path):
    if "." not in path:
        return getattr(module, path)
    cls, method = path.split(".", 1)
    return getattr(getattr(module, cls)(), method)


def _invoke(module, path, extras, creds, tmp_path):
    function = _method(module, path)
    available = {
        "all_providers_creds": creds,
        "fake_creds": creds,
        "tmp_path": tmp_path,
        **extras,
    }
    return function(**{n: available[n] for n in inspect.signature(function).parameters})


@pytest.fixture
def fixture_creds():
    return providers.all_providers_creds.__wrapped__()


@pytest.mark.parametrize("provider", _PROVIDERS)
@pytest.mark.parametrize("fault", ["lookup", "construction"])
def test_provider_rule_failure_reclaims_dispatcher(
    provider, fault, fixture_creds, tmp_path, monkeypatch
):
    _check_rule_failure(
        providers, provider, fault, fixture_creds, tmp_path, monkeypatch
    )


@pytest.mark.parametrize("fault", ["lookup", "construction"])
def test_watchdog_rule_failure_reclaims_dispatcher(
    fault, fixture_creds, tmp_path, monkeypatch
):
    _check_rule_failure(
        watchdog, "anthropic", fault, fixture_creds, tmp_path, monkeypatch
    )


def _check_rule_failure(module, provider, fault, creds, tmp_path, monkeypatch):
    dispatchers = []
    real_dispatcher = module.LLMDispatcher

    class RefusingRules(dict):
        def __getitem__(self, key):
            raise RuntimeError("injected rule lookup failure")

    def dispatcher(*args, **kwargs):
        instance = real_dispatcher(*args, **kwargs)
        dispatchers.append(instance)
        if fault == "lookup":
            instance._rules = RefusingRules(instance._rules)
        return instance

    def fail_rule(**kwargs):
        raise RuntimeError("injected rule construction failure")

    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "LLMDispatcher", dispatcher)
            if fault == "construction":
                patcher.setattr(module, "ProviderRule", fail_rule)
            with pytest.raises(RuntimeError, match=f"injected rule {fault} failure"):
                if module is providers:
                    providers._setup_with_provider_redirected(
                        creds, tmp_path, provider, "http://127.0.0.1:1"
                    )
                else:
                    watchdog.TestRelayWiring()._recorded_watcher_stall(
                        creds, tmp_path, patcher, watchdog._STREAMING_BODY
                    )
        assert len(dispatchers) == 1
        d = dispatchers[0]
        assert not d._thread.is_alive(), "rule setup left dispatcher running"
        assert d._server.socket.fileno() == -1
        assert not d.socket_path.exists()
    finally:
        for d in dispatchers:
            d.shutdown()


@pytest.mark.parametrize("path,extras", _CALLERS)
def test_provider_setup_failure_reclaims_upstream(
    path, extras, fixture_creds, tmp_path, monkeypatch
):
    _check_caller(
        providers,
        "_CaptiveUpstream",
        "_setup_with_provider_redirected",
        path,
        extras,
        fixture_creds,
        tmp_path,
        monkeypatch,
    )


@pytest.mark.parametrize(
    "header", ["accept-encoding", "Accept-Encoding", "ACCEPT-ENCODING"]
)
def test_encoding_setup_failure_reclaims_upstream(
    header, fixture_creds, tmp_path, monkeypatch
):
    _check_caller(
        integrity,
        "_EchoUpstream",
        "_make_dispatcher",
        "TestIdentityEncodingForced.test_client_accept_encoding_replaced",
        {"client_header": header},
        fixture_creds,
        tmp_path,
        monkeypatch,
    )


def _check_caller(module, name, setup_name, path, extras, creds, tmp_path, monkeypatch):
    upstreams = []
    real_upstream = getattr(module, name)

    def upstream(*args, **kwargs):
        instance = real_upstream(*args, **kwargs)
        upstreams.append(instance)
        return instance

    def fail(*args, **kwargs):
        raise RuntimeError("injected dispatcher setup failure")

    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, name, upstream)
            patcher.setattr(module, setup_name, fail)
            with pytest.raises(RuntimeError, match="injected dispatcher setup failure"):
                _invoke(module, path, extras, creds, tmp_path)
        assert len(upstreams) == 1
        assert upstreams[0]._server.socket.fileno() == -1, (
            "later setup left upstream open"
        )
    finally:
        for instance in upstreams:
            instance.shutdown()


@pytest.mark.parametrize("path,extras", _TOKEN_CALLERS)
@pytest.mark.parametrize("fault", ["read", "decode"])
def test_provider_token_failure_closes_descriptor(
    path, extras, fault, fixture_creds, tmp_path, monkeypatch
):
    allocated = []
    dispatchers = []
    real_dispatcher = providers.LLMDispatcher

    def dispatcher(*args, **kwargs):
        d = real_dispatcher(*args, **kwargs)
        dispatchers.append(d)
        allocate = d.allocate_worker

        def worker(**options):
            result = allocate(**options)
            fd = result[1]
            stat = os.fstat(fd)
            allocated.append((fd, stat.st_dev, stat.st_ino))
            return result

        d.allocate_worker = worker
        return d

    def read(fd, count):
        if fault == "decode":
            return b"\xff"
        raise OSError("injected token read failure")

    def still_owned(item):
        fd, device, inode = item
        try:
            stat = os.fstat(fd)
        except OSError as error:
            assert error.errno == errno.EBADF
            return False
        return (stat.st_dev, stat.st_ino) == (device, inode)

    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(providers, "LLMDispatcher", dispatcher)
            patcher.setattr(
                providers, "os", SimpleNamespace(**(vars(os) | {"read": read}))
            )
            with pytest.raises(OSError if fault == "read" else UnicodeDecodeError):
                _invoke(providers, path, extras, fixture_creds, tmp_path)
        assert len(allocated) == 1
        assert not any(still_owned(item) for item in allocated), (
            "token read left descriptor open"
        )
    finally:
        for d in dispatchers:
            d.shutdown()
        for item in allocated:
            if still_owned(item):
                os.close(item[0])
